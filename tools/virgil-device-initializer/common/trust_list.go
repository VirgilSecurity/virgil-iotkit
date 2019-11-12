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

type Go_file_version_t struct {
    Major           uint8
    Minor           uint8
    Patch           uint8
    Build           uint32
    Timestamp       uint32
}

type Go_trust_list_header_t struct {
	WholeTLSize         uint32
	Version				Go_file_version_t
	PubKeysCount        uint16
	SignaturesCount     uint8
}

type Go_trust_list_footer_t struct {
	TLType        uint8
	Signatures    []*Go_vs_sign_t
}

type trustList struct {
	Header        Go_trust_list_header_t
	TlChunks      []*Go_vs_pubkey_dated_t
	Footer        Go_trust_list_footer_t
}

func NewTrustList(tlData []byte) (*trustList, error){
	var err error
	var processedDataOffset int

	tl := new(trustList)
	tlBytesBuf := bytes.NewBuffer(tlData)

	// Read TL header
	if err := binary.Read(tlBytesBuf, binary.BigEndian, &tl.Header); err != nil {
		return nil, fmt.Errorf("failed to serialize TrustList header from data: %v", err)
	}

	// Read TL chunks
	remainedData := tlBytesBuf.Bytes()
	tlWithoutHeaderLen := len(remainedData)
	for i := 0; i < int(tl.Header.PubKeysCount); i++ {
		tlChunk := Go_vs_pubkey_dated_t{}
		if processedDataOffset, err = tlChunk.FromBytes(remainedData); err != nil {
			return nil, fmt.Errorf("failed to serialize TrustList chunk from data: %v", err)
		}
		tl.TlChunks = append(tl.TlChunks, &tlChunk)
		remainedData = remainedData[processedDataOffset:]
	}

	// Update buffer offset
	bodyLen := tlWithoutHeaderLen - len(remainedData)
	tlBytesBuf.Next(bodyLen)

	// Read TL Footer
	// - tl type
	if err = binary.Read(tlBytesBuf, binary.BigEndian, &tl.Footer.TLType); err != nil {
		return nil, fmt.Errorf("failed to serialize TrustList footer, tl_type from data: %v", err)
	}
	// - signatures
	remainedData = tlBytesBuf.Bytes()
	for i := 0; i < int(tl.Header.SignaturesCount); i++ {
		signature := Go_vs_sign_t{}
		if processedDataOffset, err = signature.FromBytes(remainedData); err != nil {
			return nil, fmt.Errorf("failed to serialize TrustList signature from data: %v", err)
		}
		tl.Footer.Signatures = append(tl.Footer.Signatures, &signature)
		remainedData = remainedData[processedDataOffset:]
	}

	if len(remainedData) != 0 {
		return nil, fmt.Errorf("wrong TrustList size: %d extra bytes", len(remainedData))
	}

	return tl, nil
}
