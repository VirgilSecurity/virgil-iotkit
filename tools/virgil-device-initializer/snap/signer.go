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
    "fmt"

    "../converters"

    "gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

type Signer struct {
    Processor *DeviceProcessor
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
    rawSignature, err := s.Processor.SignDataInDevice(data)
    if err != nil {
        return nil, err
    }

    // Convert signature to Virgil format
    var virgilSignature []byte
    virgilSignature, err = converters.RawSignToVirgil(rawSignature, s.Processor.DevicePublicKey.ECType, DEVICE_HASH_ALGO)
    if err != nil {
        return nil, err
    }

    return virgilSignature, nil
}

func (s *Signer) Verify(data []byte,
                        signature []byte,
                        pubKeyBytes []byte,
                        hash virgil_crypto_go.VirgilCryptoFoundationVirgilHashAlgorithm) error {
    return fmt.Errorf("not implemented for snap signer")
}

func (s *Signer) PublicKeyFull() ([]byte, error) {
    return nil, fmt.Errorf("not implemented for snap signer")
}
