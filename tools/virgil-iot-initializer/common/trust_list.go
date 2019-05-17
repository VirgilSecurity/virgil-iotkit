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

type Go_trust_list_header_t struct {
	TLSize        uint32
	Version       uint16
	PubKeysCount  uint16
	Reserved      [24]uint8
}

type Go_trust_list_footer_t struct {
	AuthKeyId     uint16
	AuthSign      [64]uint8
	TLServiceId   uint16
	TLServiceSign [64]uint8
	TLType        uint8
	Reserved      [32]uint8
}

type Go_trust_list_pub_key_meta_t struct {
	Id            uint16
	TlType        uint16
	Reserved      [28]uint8
}

type Go_trust_list_pub_key_t struct {
	Val           [64]uint8
	Meta          Go_trust_list_pub_key_meta_t
}


type trustList struct {
	Header        Go_trust_list_header_t
	TlChunks      []*Go_trust_list_pub_key_t
	Footer        Go_trust_list_footer_t
}

func NewTrustList(tlData []byte) (*trustList, error){
	tl := new(trustList)
	tlBytes := bytes.NewBuffer(tlData)

	// Read TL header
	if err := binary.Read(tlBytes, binary.LittleEndian, &tl.Header); err != nil {
		return nil, fmt.Errorf("failed to serialize TrustList header from data: %v", err)
	}

	// Read TL chunks
	for i := 0; i < int(tl.Header.PubKeysCount); i++ {
		tlChunk := Go_trust_list_pub_key_t{}
		if err := binary.Read(tlBytes, binary.LittleEndian, &tlChunk); err != nil {
			return nil, fmt.Errorf("failed to serialize TrustList chunk from data: %v", err)
		}
		tl.TlChunks = append(tl.TlChunks, &tlChunk)
	}

	// Read TL Footer
	if err := binary.Read(tlBytes, binary.LittleEndian, &tl.Footer); err != nil {
		return nil, fmt.Errorf("failed to serialize TrustList footer from data: %v", err)
	}

	extraBytes := tlBytes.Bytes()
	if len(extraBytes) > 0 {
		return nil, fmt.Errorf("wrong TrustList size: %d extra bytes", len(extraBytes))
	}

	return tl, nil
}
