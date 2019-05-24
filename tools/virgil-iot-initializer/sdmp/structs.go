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

import (
    "bytes"
    "encoding/binary"
    "fmt"

    "../common"
)

// TODO: use BigEndian instead of common.SystemEndian after correct serialization support from C side
// Otherwise there could be problems if device/initializer are using different byte order

type Go_vs_sdmp_pubkey_t struct  {
    PubKey   [PUBKEY_MAX_SZ]uint8
    PubKeySz uint8
}

func (g *Go_vs_sdmp_pubkey_t) fromBytes(b []byte) error {
    buf := bytes.NewBuffer(b)
    if err := binary.Read(buf, common.SystemEndian, g); err != nil {
        return fmt.Errorf("failed to deserialize vs_sdmp_pubkey_t: %v", err)
    }
    return nil
}

type Go_vs_sdmp_prvs_signature_t struct {
    Id    uint16
    ValSz uint8
    Val   []byte
}

func (g *Go_vs_sdmp_prvs_signature_t) fromBytes(b []byte) error {
    buf := bytes.NewBuffer(b)

    if err := binary.Read(buf, common.SystemEndian, &g.Id); err != nil {
        return fmt.Errorf("failed to deserialize signature Id: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.ValSz); err != nil {
        return fmt.Errorf("failed to deserialize signature ValSz: %v", err)
    }
    // Rest of buffer contains signature value
    rest := buf.Bytes()
    valueBytes := rest[:g.ValSz]
    g.Val = valueBytes

    return nil
}

func (g *Go_vs_sdmp_prvs_signature_t) toBytes() ([]byte, error) {
    buf := new(bytes.Buffer)

    if err := binary.Write(buf, common.SystemEndian, g.Id); err != nil {
        return nil, fmt.Errorf("failed to serialize signature Id: %v", err)
    }
    if err := binary.Write(buf, common.SystemEndian, g.ValSz); err != nil {
        return nil, fmt.Errorf("failed to serialize signature ValSz: %v", err)
    }
    // Write signature value
    _, err := buf.Write(g.Val)
    if err != nil {
        return nil, fmt.Errorf("failed to serialize signature Val: %v", err)
    }

    return buf.Bytes(), nil
}

type Go_vs_sdmp_prvs_devi_t struct {
    Manufacturer uint32
    Model        uint32
    MacAddress   [6]byte
    UdidOfDevice [32]uint8

    OwnKey    Go_vs_sdmp_pubkey_t
    Signature Go_vs_sdmp_prvs_signature_t
}

func (g *Go_vs_sdmp_prvs_devi_t) fromBytes(b []byte) error {
    buf := bytes.NewBuffer(b)
    if err := binary.Read(buf, common.SystemEndian, &g.Manufacturer); err != nil {
        return fmt.Errorf("failed to deserialize vs_sdmp_prvs_devi_t Manufacturer: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.Model); err != nil {
        return fmt.Errorf("failed to deserialize vs_sdmp_prvs_devi_t Model: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.MacAddress); err != nil {
        return fmt.Errorf("failed to deserialize vs_sdmp_prvs_devi_t MacAddress: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.UdidOfDevice); err != nil {
        return fmt.Errorf("failed to deserialize vs_sdmp_prvs_devi_t UdidOfDevice: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.OwnKey); err != nil {
        return fmt.Errorf("failed to deserialize vs_sdmp_prvs_devi_t OwnKey: %v", err)
    }
    signature := Go_vs_sdmp_prvs_signature_t{}
    if err := signature.fromBytes(buf.Bytes()); err != nil {
        return err
    }
    g.Signature = signature

    return nil
}
