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

package initializer

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "path/filepath"

    "../common"
    "../request"
    "../snap"

    "gopkg.in/urfave/cli.v2"
    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

var (
    crypto = virgil_crypto_go.NewVirgilCrypto()
)


type FactoryInitializer struct {
    OutputFile                       string
    DeviceInfoFile                   string
    DeviceSignPrivateKey             []byte
    DeviceSignPrivateKeyPassword     string
    ProvisioningInfo                 *common.ProvisioningInfo
}


func New(context *cli.Context) (*FactoryInitializer, error) {
    var param string
    fInit := new(FactoryInitializer)
    provInfo := new(common.ProvisioningInfo)

    // output
    if param = context.String("output"); param == "" {
        return nil, fmt.Errorf("output file isn't specified")
    }
    fInit.OutputFile = filepath.Clean(param)
    // device_info_output
    if param = context.String("device_info_output"); param == "" {
        return nil, fmt.Errorf("device info output file isn't specified")
    }
    fInit.DeviceInfoFile = filepath.Clean(param)
    // auth_pub_key_1
    if err := readFileFromContext(context, &provInfo.AuthPubKey1, "auth_pub_key_1"); err != nil {
        return nil, err
    }
    // auth_pub_key_2
    if err := readFileFromContext(context, &provInfo.AuthPubKey2, "auth_pub_key_2"); err != nil {
        return nil, err
    }
    // rec_pub_key_1
    if err := readFileFromContext(context, &provInfo.RecPubKey1, "rec_pub_key_1"); err != nil {
        return nil, err
    }
    // rec_pub_key_2
    if err := readFileFromContext(context, &provInfo.RecPubKey2, "rec_pub_key_2"); err != nil {
        return nil, err
    }
    // tl_pub_key_1
    if err := readFileFromContext(context, &provInfo.TlPubKey1, "tl_pub_key_1"); err != nil {
        return nil, err
    }
    // tl_pub_key_2
    if err := readFileFromContext(context, &provInfo.TlPubKey2, "tl_pub_key_2"); err != nil {
        return nil, err
    }
    // fw_pub_key_1
    if err := readFileFromContext(context, &provInfo.FwPubKey1, "fw_pub_key_1"); err != nil {
        return nil, err
    }
    // fw_pub_key_2
    if err := readFileFromContext(context, &provInfo.FwPubKey2, "fw_pub_key_2"); err != nil {
        return nil, err
    }
    // trust_list
    if err := readFileFromContext(context, &provInfo.TrustList, "trust_list"); err != nil {
        return nil, err
    }
    // factory_key
    if err := readFileFromContext(context, &fInit.DeviceSignPrivateKey, "factory_key"); err != nil {
        return nil, err
    }

    // create_card_only
    provInfo.CardOnly = context.Bool("create_card_only")

    // trust_list_only
    provInfo.TlOnly = context.Bool("trust_list_only")

    fInit.ProvisioningInfo = provInfo

    return fInit, nil
}

func (initializer *FactoryInitializer) InitializeDevices() error {
    // Import keys
    deviceSignerPrivateKey, err := crypto.ImportPrivateKey(
        initializer.DeviceSignPrivateKey, initializer.DeviceSignPrivateKeyPassword)
    if err != nil {
        return fmt.Errorf("failed to import device signer private key: %v", err)
    }

    // Prepare persistent managers
    deviceInfoPersistenceManager := PersistenceManager{
        FileName:             initializer.DeviceInfoFile,
    }

    requestsPersistenceManager := PersistenceManager{
        FileName:             initializer.OutputFile,
    }

    // Prepare device signer
    deviceSigner := &common.VirgilCryptoSigner{
        PrivateKey: deviceSignerPrivateKey,
    }

    // Prepare SNAP processor
    snapProcessor := &snap.Processor{
        ProvisioningInfo: initializer.ProvisioningInfo,
    }

    // Connect to PLC bus
    if err:= snapProcessor.ConnectToPLCBus(); err != nil {
        return err
    }
    defer snapProcessor.DisconnectFromPLCBus()

    // Discover uninitialized devices
    err = snapProcessor.DiscoverDevices()
    if err != nil {
        return err
    }

    // Process each device
    for i := 0; i < snapProcessor.DeviceCount; i++ {
        deviceProcessor := snapProcessor.NewDeviceProcessor(i, deviceSigner)
        if err:= deviceProcessor.Process(); err != nil {
            return err
        }

        if !initializer.ProvisioningInfo.TlOnly {
            signer := &snap.Signer{Processor: deviceProcessor}
            requestBuilder := request.Builder{
                Signer:          signer,
                DeviceProcessor: deviceProcessor,
            }

            // Save device info
            deviceInfo, err := requestBuilder.GetDeviceInfo()
            if err != nil {
                return err
            }
            fmt.Println("Device info:", base64.StdEncoding.EncodeToString(deviceInfo))
            if err := deviceInfoPersistenceManager.Persist((string)(deviceInfo)); err != nil {
                return err
            }

            // Save card request
            cardRequest, err := requestBuilder.BuildRequest()
            if err != nil {
                return err
            }
            fmt.Println("Card request:", cardRequest)
            if err := requestsPersistenceManager.Persist(cardRequest); err != nil {
                return err
            }
        }
    }

    return nil
}


// Read file as bytes
func readFileFromContext(context *cli.Context, readTo *[]byte, flagName string) error {
    var filePath string
    if filePath = context.Path(flagName); filePath == "" {
        return fmt.Errorf("file path for %s isn't set", flagName)
    }
    fileBytes, err := getFileBytes(filePath)
    if err != nil {
        return err
    }
    *readTo = fileBytes
    return nil
}

func getFileBytes(filePath string) ([]byte, error){
    cleanPath := filepath.Clean(filePath)
    fileBytes, err := ioutil.ReadFile(cleanPath)
    if err != nil {
        return nil, fmt.Errorf("can`t read file (%s): %s", cleanPath, err)
    }
    return fileBytes, nil
}
