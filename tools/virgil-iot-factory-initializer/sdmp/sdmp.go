//   Copyright (C) 2015-2019 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package sdmp

/*
#cgo LDFLAGS: -lsdmp-factory -lfactory-initializer-hal
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/prvs.h>
#include <virgil/iot/initializer/hal/ti_netif_udp_bcast.h>
#include <virgil/iot/initializer/hal/sdmp/ti_prvs_implementation.h>
*/
import "C"
import (
    "bytes"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "strings"
    "unsafe"

    "../common"
    "../converters"
)


const (
    DEFAULT_TIMEOUT_MS = 7000
    ETH_ADDR_LEN       = int(C.ETH_ADDR_LEN)
    // algorithm, which is used by device in sign operations and signing device:
    DEVICE_HASH_ALGO   = common.VS_HASH_SHA_256
    FACTORY_KEY_TYPE   = 4
)

type Processor struct {
    ProvisioningInfo    *common.ProvisioningInfo

    DeviceCount         int
    devicesList         C.vs_sdmp_prvs_dnid_list_t
}

type DeviceProcessor struct {
    ProvisioningInfo       *common.ProvisioningInfo
    DeviceSigner           common.SignerInterface
    deviceInfo             C.vs_sdmp_prvs_dnid_element_t

    DeviceID               [32]uint8
    DeviceMacAddr          [6]byte
    Manufacturer           [16]uint8
    Model                  uint32
    DevicePublicKey        common.Go_vs_pubkey_t
    Signature              common.Go_vs_sign_t
}

func (p *Processor) NewDeviceProcessor(i int, deviceSigner common.SignerInterface) *DeviceProcessor {
    device := p.devicesList.elements[i]

    fmt.Println("Device type:", device.device_type)
    var macParts []string
    for part:=0; part < ETH_ADDR_LEN; part++ {
        hex := fmt.Sprintf("%02x", device.mac_addr.bytes[part])
        macParts = append(macParts, hex)
    }
    mac := strings.Join(macParts, ":")
    fmt.Println("Device MAC:", mac)

    processor := DeviceProcessor{
        ProvisioningInfo: p.ProvisioningInfo,
        DeviceSigner:     deviceSigner,
        deviceInfo:       p.devicesList.elements[i],
    }
    return &processor
}

func (p *DeviceProcessor) Process() error {

    if p.ProvisioningInfo.TlOnly {
        if err := p.SetTrustList(); err != nil {
            return err
        }
    } else {
        if !p.ProvisioningInfo.CardOnly {
            if err := p.InitDevice(); err != nil {
                return err
            }
            if err := p.SetKeys(); err != nil {
                return err
            }
            if err := p.SignDevice(); err != nil {
                return err
            }
            if err := p.SetTrustList(); err != nil {
                return err
            }
        }
        if err := p.GetProvisionInfo(); err != nil {
            return err
        }
    }
    fmt.Println("OK: Device initialization done successfully.")
    return nil
}

func (p *Processor) DiscoverDevices() error {
    list := C.vs_sdmp_prvs_dnid_list_t{}

    if 0 != C.vs_sdmp_prvs_uninitialized_devices(nil, &list, DEFAULT_TIMEOUT_MS) {
        return fmt.Errorf("can't find SDMP:PRVS uninitialized devices")
    }

    p.devicesList = list
    p.DeviceCount = int(list.count)
    fmt.Printf("Got %d devices\n", p.DeviceCount)

    return nil
}

func (p Processor ) ConnectToPLCBus() error {

    // Use UDP Broadcast as transport
    if 0 != C.vs_sdmp_init(C.vs_hal_netif_udp_bcast()) {
        return fmt.Errorf("can't start SDMP communication")
    }

    // Use PLC simulator as transport
//     if 0 != C.vs_sdmp_init(C.vs_hal_netif_plc_sim()) {
//         return fmt.Errorf("can't start SDMP communication")
//     }

    if 0 != C.vs_sdmp_register_service(C.vs_sdmp_prvs_service()) {
        return fmt.Errorf("can't register SDMP:PRVS service")
    }

    if 0 != C.vs_sdmp_prvs_configure_hal(C.vs_prvs_impl()) {
        return fmt.Errorf("can't configure SDMP:PRVS HAL")
    }

    return nil
}

func (p Processor) DisconnectFromPLCBus(){
    fmt.Printf("DisconnectFromPLCBus\n")
    C.vs_sdmp_deinit()
}

func (p *DeviceProcessor) SetTrustList() error {
    trustList, err := common.NewTrustList(p.ProvisioningInfo.TrustList)
    if err != nil {
        return err
    }
    var binBuf bytes.Buffer

    mac := p.deviceInfo.mac_addr

    // Set TL header
    fmt.Println("Upload TrustList Header")

    if err := binary.Write(&binBuf, binary.BigEndian, trustList.Header); err != nil {
        return fmt.Errorf("failed to write TrustList header to buffer")
    }

    headerBytes := binBuf.Bytes()
    headerPtr := (*C.uchar)(unsafe.Pointer(&headerBytes[0]))

    if 0 != C.vs_sdmp_prvs_set_tl_header(nil,
                                         &mac,
                                         headerPtr,
                                         C.uint16_t(len(headerBytes)),
                                         DEFAULT_TIMEOUT_MS) {
        return fmt.Errorf("failed to set TrustList header")
    }


    // Set TL chunks
    for index, chunk := range trustList.TlChunks {
        chunkBytes, err := chunk.ToBytes()
        if err != nil {
            return err
        }
        name := fmt.Sprintf("TrustList chunk %d", index)
        if err := p.uploadData(C.VS_PRVS_TLC, chunkBytes, name); err != nil {
            return err
        }
    }

    // Set TL Footer
    binBuf.Reset()  // reset buffer
    if err := binary.Write(&binBuf, binary.BigEndian, trustList.Footer.TLType); err != nil {
        return fmt.Errorf("failed to write TrustList footer tl_type to buffer")
    }
    for index, signature := range trustList.Footer.Signatures {
        signatureBytes, err := signature.ToBytes()
        if err != nil {
            return err
        }
        if _, err := binBuf.Write(signatureBytes); err != nil {
            return fmt.Errorf("failed to write footer signature #%d to buffer: %v", index, err)
        }
    }

    fmt.Println("Upload TrustList Footer")

    footerBytes := binBuf.Bytes()
    dataPtr := (*C.uchar)(unsafe.Pointer(&footerBytes[0]))

    if 0 != C.vs_sdmp_prvs_set_tl_footer(nil,
                                       &mac,
                                       dataPtr,
                                       C.uint16_t(len(footerBytes)),
                                       DEFAULT_TIMEOUT_MS) {
        return fmt.Errorf("failed to set TrustList footer")
    }

    fmt.Println("OK: Trust List set successfully.")

    return nil
}

func (p *DeviceProcessor) InitDevice() error {
    const bufSize = 512
    var asavInfoBuf [bufSize]uint8
    asavInfoPtr := (*C.uchar)(unsafe.Pointer(&asavInfoBuf[0]))
    mac := p.deviceInfo.mac_addr

    if 0 != C.vs_sdmp_prvs_save_provision(nil, &mac, asavInfoPtr, bufSize, DEFAULT_TIMEOUT_MS) {
        return fmt.Errorf("InitDevice: vs_sdmp_prvs_save_provision error")
    }

    pubKeyT := common.Go_vs_pubkey_t{}
    if _, err := pubKeyT.FromBytes(asavInfoBuf[:]); err != nil {
        return err
    }

    p.DevicePublicKey = pubKeyT
    return nil
}

// Calls vs_sdmp_prvs_set
func (p *DeviceProcessor) uploadData(element C.vs_sdmp_prvs_element_e, data []byte, name string) error {
    fmt.Println("Upload", name)

    mac := p.deviceInfo.mac_addr
    dataPtr := (*C.uchar)(unsafe.Pointer(&data[0]))
    if 0 != C.vs_sdmp_prvs_set(nil,
                               &mac,
                               element,
                               dataPtr,
                               C.uint16_t(len(data)),
                               DEFAULT_TIMEOUT_MS) {
        fmt.Println("Failed: upload", name)
        return fmt.Errorf("failed to set %s on device (vs_sdmp_prvs_set)", name)
    }
    fmt.Println("Success: upload", name)
    return nil
}

func (p *DeviceProcessor) SetKeys() error {
    // Recovery public keys
    if err := p.uploadData(C.VS_PRVS_PBR1, p.ProvisioningInfo.RecPubKey1, "Recovery key 1"); err != nil {
        return err
    }

    if err := p.uploadData(C.VS_PRVS_PBR2, p.ProvisioningInfo.RecPubKey2, "Recovery key 2"); err != nil {
        return err
    }

    // Auth Public keys
    if err := p.uploadData(C.VS_PRVS_PBA1, p.ProvisioningInfo.AuthPubKey1, "Auth key 1"); err != nil {
        return err
    }

    if err := p.uploadData(C.VS_PRVS_PBA2, p.ProvisioningInfo.AuthPubKey2, "Auth key 2"); err != nil {
        return err
    }

    // Firmware public keys
    if err := p.uploadData(C.VS_PRVS_PBF1, p.ProvisioningInfo.FwPubKey1, "Firmware key 1"); err != nil {
        return err
    }

    if err := p.uploadData(C.VS_PRVS_PBF2, p.ProvisioningInfo.FwPubKey2, "Firmware key 2"); err != nil {
        return err
    }

    // TrustList public keys
    if err := p.uploadData(C.VS_PRVS_PBT1, p.ProvisioningInfo.TlPubKey1, "TrustList key 1"); err != nil {
        return err
    }

    if err := p.uploadData(C.VS_PRVS_PBT2, p.ProvisioningInfo.TlPubKey2, "TrustList key 2"); err != nil {
        return err
    }

    return nil
}

func (p *DeviceProcessor) SignDevice() error {
    fmt.Println("Sign device by Factory key")

    virgilHashType := common.HsmHashTypeToVirgil(DEVICE_HASH_ALGO)

    // Prepare signature for device: sign vs_pubkey_t of device by Factory key
    dataToSign, err := p.DevicePublicKey.ToBytes()
    if err != nil {
        return fmt.Errorf("failed to prepare data for sign: %v", err)
    }
    virgilSignature, err := p.DeviceSigner.Sign(dataToSign)
    if err != nil {
        return err
    }

    if len(virgilSignature) == 0 {
        return fmt.Errorf("signature is empty")
    }

    // Convert virgil signature to raw
    var rawSignature []byte
    rawSignature, err = converters.VirgilSignToRaw(virgilSignature, p.ProvisioningInfo.FactoryKeyECType)
    if err != nil {
        return err
    }

    // Prepare raw public Factory key
    virgilPubKey, err := p.DeviceSigner.PublicKeyFull()
    if err != nil {
        return fmt.Errorf("failed to get full Factory public key: %v", err)
    }
    rawPubKey, err := converters.VirgilPubKeyToRaw(virgilPubKey, p.ProvisioningInfo.FactoryKeyECType)
    if err != nil {
        return fmt.Errorf("failed to prepare raw Factory public key: %v", err)
    }

    // Prepare structure with sign
    signatureStruct := common.Go_vs_sign_t{
        SignerType:   FACTORY_KEY_TYPE,
        ECType:       p.ProvisioningInfo.FactoryKeyECType,
        HashType:     DEVICE_HASH_ALGO,
        RawSignature: rawSignature,
        RawPubKey:    rawPubKey,
    }

    fmt.Println("Device key type", p.DevicePublicKey.KeyType)
    fmt.Println("Device key EC type", p.DevicePublicKey.ECType)
    fmt.Println("Device public key (raw):", base64.StdEncoding.EncodeToString(p.DevicePublicKey.RawPubKey))
    fmt.Println("Signature (raw):", base64.StdEncoding.EncodeToString(rawSignature))

    // Verify prepared signature
    // - get device public key in Virgil format
    pubKeyFull, err := p.DeviceSigner.PublicKeyFull()
    if err != nil {
        return err
    }
    fmt.Println("Device public key (virgil):", base64.StdEncoding.EncodeToString(pubKeyFull))

    // - verify
    if p.DeviceSigner.Verify(dataToSign, virgilSignature, pubKeyFull, virgilHashType) != nil {
        return fmt.Errorf("verification of created Device signature failed")
    }

    // Upload signature to device
    uploadBytes, err := signatureStruct.ToBytes()
    if err != nil {
        return err
    }

    if err := p.uploadData(C.VS_PRVS_SGNP, uploadBytes, "Device signature"); err != nil {
        return err
    }

    return nil
}

func (p *DeviceProcessor) GetProvisionInfo() error {
    const bufSize = 512
    var devInfoBuf [bufSize]uint8
    deviceInfoPtr := (*C.vs_sdmp_prvs_devi_t)(unsafe.Pointer(&devInfoBuf[0]))
    mac := p.deviceInfo.mac_addr

    if 0 != C.vs_sdmp_prvs_device_info(nil,
                                       &mac,
                                       deviceInfoPtr,
                                       C.uint16_t(bufSize),
                                       DEFAULT_TIMEOUT_MS) {
        return fmt.Errorf("failed to get device info (vs_sdmp_prvs_device_info)")
    }

    // Convert to Go struct
    deviceInfo := Go_vs_sdmp_prvs_devi_t{}
    if err := deviceInfo.FromBytes(devInfoBuf[:]); err != nil {
        return err
    }

    p.DevicePublicKey = deviceInfo.PubKey
    p.Signature = deviceInfo.Signature
    p.DeviceID = deviceInfo.UdidOfDevice
    p.DeviceMacAddr = deviceInfo.MacAddress
    p.Manufacturer = deviceInfo.Manufacturer
    p.Model = deviceInfo.Model

    return nil
}

func (p *DeviceProcessor) SignDataInDevice(data []byte) ([]byte, error) {
    const signatureBufSize = 512
    var signatureBuf [signatureBufSize]uint8
    var requestBytes []byte
    var err error
    signature_sz := C.uint16_t(0)

    // Prepare signing request
    signRequestStruct := Go_vs_sdmp_prvs_sgnp_req_t{
        HashType: DEVICE_HASH_ALGO,
        Data:     data,
    }

    requestBytes, err = signRequestStruct.ToBytes()
    if err != nil {
        return nil, err
    }

    mac := p.deviceInfo.mac_addr
    signaturePtr := (*C.uchar)(unsafe.Pointer(&signatureBuf[0]))
    dataPtr := (*C.uchar)(unsafe.Pointer(&requestBytes[0]))

    signRes := C.vs_sdmp_prvs_sign_data(nil,
                                        &mac,
                                        dataPtr,
                                        C.uint16_t(len(requestBytes)),
                                        signaturePtr,
                                        C.uint16_t(signatureBufSize),
                                        &signature_sz,
                                        DEFAULT_TIMEOUT_MS)
    if signRes != 0 {
        return nil, fmt.Errorf("failed to sign data in device")
    }

    signature := common.Go_vs_sign_t{}
    if _, err = signature.FromBytes(signatureBuf[:]); err != nil {
        return nil, err
    }

    // Verify signature on full data
    // - prepare signature in Virgil format
    var virgilSignature []byte
    virgilSignature, err = converters.RawSignToVirgil(signature.RawSignature, signature.ECType, DEVICE_HASH_ALGO)
    if err != nil {
        return nil, err
    }

    // - prepare public key in Virgil format
    var virgilPubKey []byte
    virgilPubKey, err = converters.RawPubKeyToVirgil(signature.RawPubKey, signature.ECType)
    if err != nil {
        return nil, err
    }

    // - verify
    virgilHashType := common.HsmHashTypeToVirgil(DEVICE_HASH_ALGO)
    if err := p.DeviceSigner.Verify(data, virgilSignature, virgilPubKey, virgilHashType); err != nil {
      return nil, fmt.Errorf("failed to verify signature of data signed inside device: %v", err)
    }

    return signature.RawSignature, nil
}
