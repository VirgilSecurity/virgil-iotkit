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

package snap

import (
    "bytes"
    "encoding/binary"
    "fmt"

    "../common"
)

type Go_vs_snap_prvs_devi_t struct {
    Manufacturer [16]uint8
    Model        [4]uint8
    MacAddress   [6]byte
    Serial       [32]uint8
    DataSz       uint16

    PubKey       common.Go_vs_pubkey_t
    Signature    common.Go_vs_sign_t
}

func (g *Go_vs_snap_prvs_devi_t) FromBytes(b []byte) error {
    buf := bytes.NewBuffer(b)
    if err := binary.Read(buf, common.SystemEndian, &g.Manufacturer); err != nil {
        return fmt.Errorf("failed to deserialize vs_snap_prvs_devi_t Manufacturer: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.Model); err != nil {
        return fmt.Errorf("failed to deserialize vs_snap_prvs_devi_t Model: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.Serial); err != nil {
            return fmt.Errorf("failed to deserialize vs_snap_prvs_devi_t Serial: %v", err)
        }
    if err := binary.Read(buf, common.SystemEndian, &g.MacAddress); err != nil {
        return fmt.Errorf("failed to deserialize vs_snap_prvs_devi_t MacAddress: %v", err)
    }
    if err := binary.Read(buf, common.SystemEndian, &g.DataSz); err != nil {
        return fmt.Errorf("failed to deserialize vs_snap_prvs_devi_t DataSz: %v", err)
    }

    // Rest of buffer holds vs_pubkey_t + vs_sign_t
    data := buf.Bytes()

    // Public key
    publicKey := common.Go_vs_pubkey_t{}
    signatureOffset, err := publicKey.FromBytes(data)
    if err != nil {
        return err
    }
    g.PubKey = publicKey

    // Signature
    signature := common.Go_vs_sign_t{}
    if _, err := signature.FromBytes(data[signatureOffset:]); err != nil {
        return err
    }
    g.Signature = signature

    return nil
}

type Go_vs_snap_prvs_sgnp_req_t struct {
    HashType uint8
    Data     []byte
}

func (g *Go_vs_snap_prvs_sgnp_req_t) ToBytes() ([]byte, error) {
    buf := new(bytes.Buffer)

    if err := binary.Write(buf, common.SystemEndian, g.HashType); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_snap_prvs_sgnp_req_t HashType: %v", err)
    }

    if _, err := buf.Write(g.Data); err != nil {
        return nil, fmt.Errorf("failed to serialize vs_snap_prvs_sgnp_req_t Data: %v", err)
    }

    return buf.Bytes(), nil
}
