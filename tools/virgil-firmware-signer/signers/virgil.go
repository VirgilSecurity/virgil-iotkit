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

package signers

import (
    "encoding/json"
    "fmt"
    "io/ioutil"

    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"

    "../converters"
    "../firmware"
)

var (
    crypto = virgil_crypto_go.NewVirgilCrypto()
)

func init() {
    crypto.UseSha256Fingerprints = true
}

const (
    // TODO: remove hardcoded EC type after KeyManager support of different EC types
    SIGNER_KEY_EC_TYPE = converters.VS_KEYPAIR_EC_SECP256R1
)

type VirgilCryptoSigner struct {
    FileKeys     []FileKey
}

type FileKey struct {
    FilePath    string `json:"path"`
    KeyType     uint8  `json:"key_type"`
}

func NewVirgilCryptoSigner(keysConfigPath string) (signer VirgilCryptoSigner, err error) {
    var cfgBytes []byte
    if cfgBytes, err = ioutil.ReadFile(keysConfigPath); err != nil {
        return signer, fmt.Errorf("failed to read config json: %v", err)
    }

    var keys []FileKey
    if err = json.Unmarshal(cfgBytes, &keys); err != nil {
        return signer, fmt.Errorf("failed to deserialize config json: %v", err)
    }
    signer.FileKeys = keys
    return signer, nil
}

func (s VirgilCryptoSigner) Sign(data []byte) (signatures []firmware.Signature, err error){
    for _, fileKey := range s.FileKeys {
        fmt.Printf("Signing data by %s\n", fileKey.FilePath)

        // Read key from file
        keyFileBytes, err := ioutil.ReadFile(fileKey.FilePath)
        if err != nil {
            return nil, fmt.Errorf("failed to read key at path %s: %v", fileKey.FilePath, err)
        }
        privateKey, err := crypto.ImportPrivateKey(keyFileBytes, "")
        if err != nil {
            return nil, fmt.Errorf("failed to import private key %s: %v", fileKey.FilePath, err)
        }

        // Sign data and get signature in Virgil format
        virgilSignature, err := crypto.Sign(data, privateKey)
        if err != nil {
            return nil, fmt.Errorf("failed to sign data: %v", err)
        }

        // Convert signature to raw format
        var rawSignature []byte
        rawSignature, err = converters.VirgilSignToRaw(virgilSignature, SIGNER_KEY_EC_TYPE)
        if err != nil {
            return nil, err
        }

        // Extract public key
        publicKey, err := crypto.ExtractPublicKey(privateKey)
        if err != nil {
            return nil, fmt.Errorf("failed to extract public key: %v", err)
        }
        virgilPubKey, err := crypto.ExportPublicKey(publicKey)
        if err != nil {
            return nil, fmt.Errorf("failed to export public key: %v", err)
        }

        // Convert public key to raw format
        rawPubKey, err := converters.VirgilPubKeyToRaw(virgilPubKey, SIGNER_KEY_EC_TYPE)
        if err != nil {
            return nil, fmt.Errorf("failed to prepare raw public key: %v", err)
        }

        signature := firmware.Signature{
            SignerType:       fileKey.KeyType,
            ECType:           SIGNER_KEY_EC_TYPE,
            HashType:         converters.VS_HASH_SHA_256,
            Sign:             rawSignature,
            SignerPublicKey:  rawPubKey,
        }

        signatures = append(signatures, signature)
        fmt.Printf("Signature added: %+v\n", signature)
    }
    fmt.Println("Data signed successfully:")


    return signatures, nil
}

func (s VirgilCryptoSigner) SignerKeyEcTypes() []uint8 {
    types := make([]uint8, len(s.FileKeys))
    for i := range types {
        types[i] = SIGNER_KEY_EC_TYPE
    }
    return types
}
