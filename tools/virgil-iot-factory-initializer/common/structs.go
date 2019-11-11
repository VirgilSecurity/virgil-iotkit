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

package common

import (
    "bytes"
    "encoding/binary"
    "fmt"
)

type ProvisioningInfo struct {
    TlOnly            bool
    CardOnly          bool
    AuthPubKey1       []byte
    AuthPubKey2       []byte
    RecPubKey1        []byte
    RecPubKey2        []byte
    TlPubKey1         []byte
    TlPubKey2         []byte
    FwPubKey1         []byte
    FwPubKey2         []byte
    TrustList         []byte
}

type Go_vs_pubkey_dated_t struct {
    StartDate  uint32
    ExpireDate uint32
    PubKey     Go_vs_pubkey_t
}

type Go_vs_pubkey_t struct  {
    KeyType         uint8
    ECType          uint8
    MetadataSize    uint16
    Metadata        []byte
    RawPubKey       []byte // raw public key, size of element depends on @ec_type
}

func (g *Go_vs_pubkey_dated_t) ToBytes() ([]byte, error) {
    buf := new(bytes.Buffer)

    if err := binary.Write(buf, SystemEndian, g.StartDate); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_dated_t StartDate: %v", err)
    }
    if err := binary.Write(buf, SystemEndian, g.ExpireDate); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_dated_t ExpireDate: %v", err)
    }

    // Public key
    if pubKeyBytes, err := g.PubKey.ToBytes(); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_dated_t PubKey: %v", err)
    } else {
        buf.Write(pubKeyBytes)
    }

    return buf.Bytes(), nil
}

func (g *Go_vs_pubkey_dated_t) FromBytes(b []byte) (n int, err error) {
    buf := bytes.NewBuffer(b)

    if err := binary.Read(buf, binary.LittleEndian, &g.StartDate); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_pubkey_dated_t StartDate: %v", err)
    }
    if err := binary.Read(buf, binary.LittleEndian, &g.ExpireDate); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_pubkey_dated_t ExpireDate: %v", err)
    }
    n += len(b) - len(buf.Bytes())

    pubKeyT := Go_vs_pubkey_t{}
    if pubKeyLen, err := pubKeyT.FromBytes(buf.Bytes()); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_pubkey_dated_t PubKey: %v", err)
    } else {
        n += pubKeyLen
    }
    g.PubKey = pubKeyT
    return n, nil
}

func (g *Go_vs_pubkey_t) FromBytes(b []byte) (n int, err error) {
    buf := bytes.NewBuffer(b)
    if err := binary.Read(buf, SystemEndian, &g.KeyType); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_pubkey_t KeyType: %v", err)
    }
    if err := binary.Read(buf, SystemEndian, &g.ECType); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_pubkey_t ECType: %v", err)
    }
    if err := binary.Read(buf, binary.BigEndian, &g.MetadataSize); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_pubkey_t MetadataSize: %v", err)
    }

    // Get Meta data
    g.Metadata = buf.Next(int(g.MetadataSize))

    // Get Public key
    pubKeySize := GetPublicKeySizeByECType(g.ECType)
    pubKey := buf.Next(pubKeySize)
    if len(pubKey) != pubKeySize {
        return 0, fmt.Errorf(
            "failed to deserialize vs_pubkey_t PubKey: got %d bytes instead of %d", len(pubKey), pubKeySize)
    }
    g.RawPubKey = pubKey
    return len(b) - len(buf.Bytes()), nil
}

func (g *Go_vs_pubkey_t) ToBytes() ([]byte, error) {
    buf := new(bytes.Buffer)

    if err := binary.Write(buf, SystemEndian, g.KeyType); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_t KeyType: %v", err)
    }
    if err := binary.Write(buf, SystemEndian, g.ECType); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_t ECType: %v", err)
    }
    if err := binary.Write(buf, binary.BigEndian, g.MetadataSize); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_t MetadataSize: %v", err)
    }

    // Meta data
    if _, err := buf.Write(g.Metadata); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_t Metadata: %v", err)
    }

    // Public key
    if _, err := buf.Write(g.RawPubKey); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_pubkey_t RawPubKey: %v", err)
    }

    return buf.Bytes(), nil
}

type Go_vs_sign_t struct {
    SignerType uint8
    ECType     uint8
    HashType   uint8

    // Size of elements depends on ECType:
    RawSignature  []byte
    RawPubKey     []byte
}

func (g *Go_vs_sign_t) FromBytes(b []byte) (n int, err error) {
    buf := bytes.NewBuffer(b)

    if err := binary.Read(buf, SystemEndian, &g.SignerType); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_sign_t SignerType: %v", err)
    }
    if err := binary.Read(buf, SystemEndian, &g.ECType); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_sign_t ECType: %v", err)
    }
    if err := binary.Read(buf, SystemEndian, &g.HashType); err != nil {
        return 0, fmt.Errorf("failed to deserialize vs_sign_t HashType: %v", err)
    }

    // Signature
    signatureSize := GetSignatureSizeByECType(g.ECType)
    signature := buf.Next(signatureSize)
    if len(signature) != signatureSize {
        return 0, fmt.Errorf(
            "failed to deserialize vs_sign_t Signature: got %d bytes instead of %d", len(signature), signatureSize)
    }
    g.RawSignature = signature

    // Public key
    pubKeySize := GetPublicKeySizeByECType(g.ECType)
    pubKey := buf.Next(pubKeySize)
    if len(pubKey) != pubKeySize {
        return 0, fmt.Errorf(
            "failed to deserialize vs_sign_t PubKey: got %d bytes instead of %d", len(pubKey), pubKeySize)
    }
    g.RawPubKey = pubKey

    return len(b) - len(buf.Bytes()), nil
}

func (g *Go_vs_sign_t) ToBytes() ([]byte, error) {
    buf := new(bytes.Buffer)

    if err := binary.Write(buf, SystemEndian, g.SignerType); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_sign_t SignerType: %v", err)
    }
    if err := binary.Write(buf, SystemEndian, g.ECType); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_sign_t ECType: %v", err)
    }
    if err := binary.Write(buf, SystemEndian, g.HashType); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_sign_t HashType: %v", err)
    }

    // Signature
    if _, err := buf.Write(g.RawSignature); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_sign_t Signature: %v", err)
    }

    // Public key
    if _, err := buf.Write(g.RawPubKey); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_sign_t PubKey: %v", err)
    }

    return buf.Bytes(), nil
}
