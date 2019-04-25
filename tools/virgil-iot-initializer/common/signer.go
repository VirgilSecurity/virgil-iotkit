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
	"fmt"

	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

var (
	crypto = virgil_crypto_go.NewVirgilCrypto()
)

func init() {
	crypto.UseSha256Fingerprints = true
}

type SignerInterface interface {
	Sign(data []byte) ([]byte, error)
	Verify(data []byte, signature []byte, publicKeyBytes []byte) error
	SignerId() (uint16, error)
	PublicKeyFull() ([]byte, error)
}

type VirgilCryptoSigner struct {
	PrivateKey []byte
	PrivateKeyPassword string
}

func (s *VirgilCryptoSigner) Sign(data []byte) ([]byte, error){
	key, err := crypto.ImportPrivateKey(s.PrivateKey, s.PrivateKeyPassword)
	if err != nil {
		return nil, fmt.Errorf("failed import private key: %v", err)
	}
	signature, err := crypto.Sign(data, key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}
	return signature, nil
}

func (s *VirgilCryptoSigner) Verify(data []byte, signature []byte, publicKeyBytes []byte) error {
	publicKey, err := crypto.ImportPublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed import public key: %v", err)
	}

	if err := crypto.VerifySignature(data, signature, publicKey); err != nil {
		return fmt.Errorf("error with VerifySignature: %v", err)
	}
	return nil
}

func (s *VirgilCryptoSigner) SignerId() (uint16, error) {
	fullPubKeyBytes, err := s.PublicKeyFull()
	if err != nil {
		return 0, err
	}
	tinyOffset := len(fullPubKeyBytes) - 64
	tinyPubKeyBytes := fullPubKeyBytes[tinyOffset:]
	return Crc(tinyPubKeyBytes), nil
}

func (s *VirgilCryptoSigner) PublicKeyFull() ([]byte, error) {
	privateKey, err := crypto.ImportPrivateKey(s.PrivateKey, s.PrivateKeyPassword)
	if err != nil {
		return nil, fmt.Errorf("failed import private key: %v", err)
	}
	publicKey, err := crypto.ExtractPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %v", err)
	}
	pubKeyBytes, err := crypto.ExportPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %v", err)
	}
	return pubKeyBytes, nil
}
