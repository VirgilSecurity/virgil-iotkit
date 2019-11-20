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

package firmware

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	HEADER_SIZE         = 59
	DESCRIPTOR_SIZE     = 42
	FOOTER_META_SIZE    = DESCRIPTOR_SIZE + 1 // descriptor + signatures size
	SIGNATURE_META_SIZE = 3                   // ec type + key type + hash type
)

// Size: 4 + 4 + 4 + 4 + 1 + 42 = 59
type Header struct {
	CodeOffset      uint32
	CodeLength      uint32
	FooterOffset    uint32
	FooterLength    uint32
	SignaturesCount uint8
	Descriptor      Descriptor
}

// Size: 16 + 4 + 11 + 1 + 2 + 4 + 4 = 42
type Descriptor struct {
	ManufactureID  [16]byte
	DeviceType     [4]byte
	Version        Version
	Padding        uint8
	ChunkSize      uint16
	FirmwareLength uint32
	AppSize        uint32
}

// Size: 1 + 1 + 1 + 4 + 4 = 11
type Version struct {
	Major     uint8
	Minor     uint8
	Patch     uint8
	Build     uint32
	Timestamp uint32
}

type Footer struct {
	SignaturesCount uint8
	Descriptor      Descriptor
	Signatures      []Signature
}

type Signature struct {
	SignerType      uint8
	ECType          uint8
	HashType        uint8
	Sign            []byte
	SignerPublicKey []byte
}

func (s *Signature) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	if err := binary.Write(buf, binary.BigEndian, s.SignerType); err != nil {
		return nil, fmt.Errorf("failed to serialize Signature SignerType: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, s.ECType); err != nil {
		return nil, fmt.Errorf("failed to serialize Signature ECType: %v", err)
	}
	if err := binary.Write(buf, binary.BigEndian, s.HashType); err != nil {
		return nil, fmt.Errorf("failed to serialize Signature HashType: %v", err)
	}

	// Signature
	if _, err := buf.Write(s.Sign); err != nil {
		return nil, fmt.Errorf("failed to serialize Signature Sign: %v", err)
	}

	// Public key
	if _, err := buf.Write(s.SignerPublicKey); err != nil {
		return nil, fmt.Errorf("failed to serialize Signature SignerPublicKey: %v", err)
	}

	return buf.Bytes(), nil
}

type UpdateFile struct {
	Header       Header
	FirmwareCode []byte
	Footer       Footer
}

type ProgFile struct {
	FirmwareCode []byte
	Filler       []byte
	Footer       Footer
}
