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
#cgo CFLAGS: -I${SRCDIR}/../../../protocols/sdmp/include -I${SRCDIR}/../c_libs/include
#cgo LDFLAGS: -L${SRCDIR}/../lib -lsdmp -lnetif_plc_sim
#include <virgil/iot/protocols/sdmp.h>
#include <virgil/iot/protocols/sdmp/PRVS.h>
#include <virgil/iot/initializer/hal/ti_netif_plc_sim.h>
#include <virgil/iot/initializer/hal/sdmp/ti_prvs_implementation.h>
*/
import "C"
import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "strings"
    "unsafe"

    "../common"
)


const (
    DEFAULT_WAIT_TIME_MS = 200
    ETH_ADDR_LEN         = int(C.ETH_ADDR_LEN)
    PUBKEY_MAX_SZ        = int(C.PUBKEY_MAX_SZ)
)

type Processor struct {
    ProvisioningInfo    *common.ProvisioningInfo

    DeviceCount         int
    devicesList         C.vs_sdmp_prvs_dnid_list_t
}

type DeviceProcessor struct {
    ProvisioningInfo    *common.ProvisioningInfo
    DeviceSigner        common.SignerInterface
    deviceInfo          C.vs_sdmp_prvs_dnid_element_t

    DevicePublicKeyTiny []byte
    DeviceID            [32]uint8
    DeviceMacAddr       [6]byte
    DevicePublicKey     []byte
    SignerId            uint16
    Signature           []byte
    Manufacturer        uint32
    Model               uint32
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

    if 0 != C.vs_sdmp_prvs_uninitialized_devices(nil, &list, DEFAULT_WAIT_TIME_MS* 10) {
        return fmt.Errorf("can't find SDMP:PRVS uninitialized devices")
    }

    p.devicesList = list
    p.DeviceCount = int(list.count)
    fmt.Printf("Got %d devices\n", p.DeviceCount)

    return nil
}

func (p Processor ) ConnectToPLCBus() error {
    if 0 != C.vs_sdmp_init(C.vs_hal_netif_plc_sim()) {
        return fmt.Errorf("can't start SDMP communication")
    }

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

    // Set TL header
    if err := binary.Write(&binBuf, binary.LittleEndian, trustList.Header); err != nil {
        return fmt.Errorf("failed to write TrustList header to buffer")
    }

    if err := p.uploadData(C.VS_PRVS_TLH, binBuf.Bytes(), "TrustList Header"); err != nil {
        return err
    }

    // Set TL chunks
    for index, chunk := range trustList.TlChunks {
        binBuf.Reset()  // reset buffer
        if err := binary.Write(&binBuf, binary.LittleEndian, chunk); err != nil {
            return fmt.Errorf("failed to write TrustList chunk to buffer")
        }
        name := fmt.Sprintf("TrustList chunk %d", index)
        if err := p.uploadData(C.VS_PRVS_TLC, binBuf.Bytes(), name); err != nil {
            return err
        }
    }

    // Set TL Footer
    binBuf.Reset()  // reset buffer
    if err := binary.Write(&binBuf, binary.LittleEndian, trustList.Footer); err != nil {
        return fmt.Errorf("failed to write TrustList footer to buffer")
    }
    fmt.Println("Upload TrustList Footer")
    mac := p.deviceInfo.mac_addr
    footerBytes := binBuf.Bytes()
    dataPtr := (*C.uchar)(unsafe.Pointer(&footerBytes[0]))
    if 0 != C.vs_sdmp_prvs_finalize_tl(nil,
                                       &mac,
                                       dataPtr,
                                       C.ulong(len(footerBytes)),
                                       DEFAULT_WAIT_TIME_MS* 5) {
        return fmt.Errorf("failed to set TrustList footer")
    }

    fmt.Println("OK: Trust List set successfully.")

    return nil
}

func (p *DeviceProcessor) InitDevice() error {
    const bufSize = 512
    var asavInfoBuf [bufSize]uint8
    asavInfoPtr := (*C.vs_sdmp_pubkey_t)(unsafe.Pointer(&asavInfoBuf[0]))
    mac := p.deviceInfo.mac_addr

    if 0 != C.vs_sdmp_prvs_save_provision(nil, &mac, asavInfoPtr, DEFAULT_WAIT_TIME_MS) {
        return fmt.Errorf("InitDevice: vs_sdmp_prvs_save_provision error")
    }

    pubKeyT := Go_vs_sdmp_pubkey_t{}
    if err := pubKeyT.fromBytes(asavInfoBuf[:]); err != nil {
        return err
    }

    tinyOffset := len(pubKeyT.PubKey) - 64
    p.DevicePublicKeyTiny = pubKeyT.PubKey[tinyOffset:]
    return nil
}

// Calls vs_sdmp_prvs_set
func (p *DeviceProcessor) uploadData(element C.vs_sdmp_prvs_element_t, data []byte, name string) error {
    fmt.Println("Upload", name)

    mac := p.deviceInfo.mac_addr
    dataPtr := (*C.uchar)(unsafe.Pointer(&data[0]))
    if 0 != C.vs_sdmp_prvs_set(nil,
                               &mac,
                               element,
                               dataPtr,
                               C.ulong(len(data)),
                               DEFAULT_WAIT_TIME_MS) {
        return fmt.Errorf("failed to set %s on device (vs_sdmp_prvs_set)", name)
    }
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
    // Prepare signature for device
    signature, err := p.DeviceSigner.Sign(p.DevicePublicKeyTiny)
    if err != nil {
        return err
    }

    if len(signature) == 0 {
        return fmt.Errorf("signature is empty")
    }

    pubKeyFull, err := p.DeviceSigner.PublicKeyFull()
    if err != nil {
        return err
    }

    if p.DeviceSigner.Verify(p.DevicePublicKeyTiny, signature, pubKeyFull) != nil {
        return fmt.Errorf("signature verification failed")
    }

    signerId, err := p.DeviceSigner.SignerId()
    if err != nil {
        return err
    }

    fmt.Println("Signer ID:", signerId)
    fmt.Println("Signer public key (full):", base64.StdEncoding.EncodeToString(pubKeyFull))
    fmt.Println("Device public key (tiny):", base64.StdEncoding.EncodeToString(p.DevicePublicKeyTiny))
    fmt.Println("Signature:", base64.StdEncoding.EncodeToString(signature))

    signatureStruct := Go_vs_sdmp_prvs_signature_t{
        Id:    signerId,
        ValSz: uint8(len(signature)),
        Val:   signature,
    }
    uploadBytes, err := signatureStruct.toBytes()
    if err != nil {
        return err
    }

    // Upload signature to device
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
                                       C.size_t(bufSize),
                                       DEFAULT_WAIT_TIME_MS) {
        return fmt.Errorf("failed to get device info (vs_sdmp_prvs_device_info)")
    }

    // Convert to Go struct
    deviceInfo := Go_vs_sdmp_prvs_devi_t{}
    if err := deviceInfo.fromBytes(devInfoBuf[:]); err != nil {
        return err
    }

    pubKeyFull := deviceInfo.OwnKey.PubKey[:deviceInfo.OwnKey.PubKeySz]

    p.DevicePublicKey = pubKeyFull
    p.SignerId = deviceInfo.Signature.Id
    p.Signature = deviceInfo.Signature.Val
    p.DeviceID = deviceInfo.UdidOfDevice
    p.DeviceMacAddr = deviceInfo.MacAddress
    p.Manufacturer = deviceInfo.Manufacturer
    p.Model = deviceInfo.Model

    return nil
}

func (p *DeviceProcessor) SignDataInDevice(data []byte) ([]byte, error) {
    const signatureBufSize = 512
    var signatureBuf [signatureBufSize]uint8
    signature_sz := C.size_t(0)

    // Calculate hash - device does not calculate hash, only signs data
    dataHash := sha256.Sum256(data)

    mac := p.deviceInfo.mac_addr
    signaturePtr := (*C.uchar)(unsafe.Pointer(&signatureBuf[0]))
    dataPtr := (*C.uchar)(unsafe.Pointer(&dataHash[0]))

    signRes := C.vs_sdmp_prvs_sign_data(nil,
                                        &mac,
                                        dataPtr,
                                        C.ulong(len(dataHash)),
                                        signaturePtr,
                                        C.ulong(signatureBufSize),
                                        &signature_sz,
                                        DEFAULT_WAIT_TIME_MS)
    if signRes != 0 {
        return nil, fmt.Errorf("failed to sign data in device")
    }

    signature := signatureBuf[:signature_sz]

    // Verify signature on full data
    if err := p.DeviceSigner.Verify(data, signature, p.DevicePublicKey); err != nil {
      return nil, fmt.Errorf("failed to verify signature of data signed inside device: %v", err)
    }

    return signature, nil
}
