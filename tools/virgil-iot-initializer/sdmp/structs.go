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
)

type Go_vs_sdmp_pubkey_t struct  {
    PubKey   [PUBKEY_MAX_SZ]uint8
    PubKeySz uint8
}

type Go_vs_sdmp_prvs_signature_t struct {
    Id    uint16
    ValSz uint8
    Val   []byte
}

func (g *Go_vs_sdmp_prvs_signature_t) fromBytes(b []byte) error {
    buf := bytes.NewBuffer(b)

    if err := binary.Read(buf, binary.LittleEndian, &g.Id); err != nil {
        return fmt.Errorf("failed to read Id: %v", err)
    }
    if err := binary.Read(buf, binary.LittleEndian, &g.ValSz); err != nil {
        return fmt.Errorf("failed to read ValSz: %v", err)
    }
    // signature value
    rest := buf.Bytes()
    valBuf := new(bytes.Buffer)
    if err := binary.Write(valBuf, binary.LittleEndian, rest[:g.ValSz]); err != nil {
        return fmt.Errorf("failed to write Signature: %v", err)
    }
    g.Val = valBuf.Bytes()

    return nil
}

func (g *Go_vs_sdmp_prvs_signature_t) toBytes() ([]byte, error) {
    buf := new(bytes.Buffer)

    if err := binary.Write(buf, binary.BigEndian, g.Id); err != nil {
        return nil, fmt.Errorf("failed to serialize Id: %v", err)
    }
    if err := binary.Write(buf, binary.BigEndian, g.ValSz); err != nil {
        return nil, fmt.Errorf("failed to serialize ValSz: %v", err)
    }
    if err := binary.Write(buf, binary.BigEndian, g.Val); err != nil {
        return nil, fmt.Errorf("failed to serialize Val: %v", err)
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
    if err := binary.Read(buf, binary.LittleEndian, &g.Manufacturer); err != nil {
        return fmt.Errorf("failed to read Manufacturer: %v", err)
    }
    if err := binary.Read(buf, binary.LittleEndian, &g.Model); err != nil {
        return fmt.Errorf("failed to read Model: %v", err)
    }
    if err := binary.Read(buf, binary.LittleEndian, &g.MacAddress); err != nil {
        return fmt.Errorf("failed to read MacAddress: %v", err)
    }
    if err := binary.Read(buf, binary.LittleEndian, &g.UdidOfDevice); err != nil {
        return fmt.Errorf("failed to read UdidOfDevice: %v", err)
    }
    if err := binary.Read(buf, binary.LittleEndian, &g.OwnKey); err != nil {
        return fmt.Errorf("failed to read OwnKey: %v", err)
    }
    signature := Go_vs_sdmp_prvs_signature_t{}
    if err := signature.fromBytes(buf.Bytes()); err != nil {
        return err
    }
    g.Signature = signature

    return nil
}
