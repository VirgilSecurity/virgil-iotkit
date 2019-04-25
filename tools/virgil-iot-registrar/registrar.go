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

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

var (
	crypto = virgil_crypto_go.NewVirgilCrypto()
	tokenSigner = virgil_crypto_go.NewVirgilAccessTokenSigner()
)

func (r *CardsRegistrar) processRequests(cardsService *CardsServiceInfo) error {
	f, err := os.OpenFile(r.dataFile, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	getRequest, err := r.requestProvider(f)
	if err != nil {
		return err
	}

	for requestNumber := 1; ; requestNumber++ {
		decryptedRequest, err := getRequest()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		fmt.Println("\nProcessing request number", requestNumber)
		fmt.Println("Input: ", decryptedRequest)
		if err := cardsService.registerCard(decryptedRequest); err != nil {
			return err
		}
	}
	fmt.Println("OK: card requests processing done successfully")

	return nil
}

func (cardsService *CardsServiceInfo) registerCard(decryptedRequest string) error {
	// import api private key
	apiPrivateKey, err := crypto.ImportPrivateKey(cardsService.apiPrivateKey, "")
	if err != nil {
		return err
	}

	// Generate raw card from request
	rawSignedModel, err := sdk.GenerateRawSignedModelFromString(decryptedRequest)
	if err != nil {
		return fmt.Errorf("GenerateRawSignedModelFromString error: %s", err)
	}
	var rawCardContent *sdk.RawCardContent
	err = sdk.ParseSnapshot(rawSignedModel.ContentSnapshot, &rawCardContent)
	if err != nil {
		return fmt.Errorf("parse snapshot error: %s", err)
	}

	// Generate JWT token
	ttl := time.Minute * 5
	jwtGenerator := sdk.NewJwtGenerator(apiPrivateKey, cardsService.apiKeyID, tokenSigner, cardsService.appID, ttl)
	identity := rawCardContent.Identity
	jwtToken, err := jwtGenerator.GenerateToken(identity, nil)
	if err != nil {
		return fmt.Errorf("jwtToken generation error: %s", err)
	}
	jwtString := jwtToken.String()

	// Publish card
	publishedCard, err := cardsService.cardsClient.PublishCard(rawSignedModel, jwtString)
	if err != nil {
		return fmt.Errorf("publish card error: %s", err)
	}

	// Print results
	var rawCardResponse *sdk.RawCardContent
	err = sdk.ParseSnapshot(publishedCard.ContentSnapshot, &rawCardResponse)
	if err != nil {
		return fmt.Errorf("response snapshot parse error: %s", err)
	}
	fmt.Printf("Card registered. identity: %s, createdAt: %d, version: %s\n",
		rawCardResponse.Identity, rawCardResponse.CreatedAt, rawCardResponse.Version)

	return nil
}

// get and decrypt each card request from file line by line
func (r *CardsRegistrar) requestProvider(f *os.File) (func() (string, error), error) {
	reader := bufio.NewReader(f)

	// Import private key
	privateKey, err := crypto.ImportPrivateKey(r.filePrivateKey, r.filePrivateKeyPass)
	if err != nil {
		return nil, fmt.Errorf("filePrivateKey import error: %s", err)
	}

	// Import public key
	publicKey, err := crypto.ImportPublicKey(r.filePublicSenderKey)
	if err != nil {
		return nil, fmt.Errorf("filePublicSenderKey import error: %s", err)
	}

	// Return a function, each call of which will return decrypted line
	return func() (string, error) {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		data, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return "", fmt.Errorf("b64 decode error: %s, line: %s", err, line)
		}
		decryptedData, err := crypto.DecryptThenVerify(data, privateKey, publicKey)
		if err != nil {
			return "", fmt.Errorf("DecryptThenVerify error: %s", err)
		}
		return string(decryptedData), nil
	}, nil
}
