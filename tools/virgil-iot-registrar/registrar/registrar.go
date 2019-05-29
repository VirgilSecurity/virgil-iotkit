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

package registrar

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"gopkg.in/urfave/cli.v2"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/virgil.v5/cryptoapi"
	"gopkg.in/virgil.v5/sdk"
	"gopkg.in/virgilsecurity/virgil-crypto-go.v5"
)

var (
	crypto = virgil_crypto_go.NewVirgilCrypto()
	cardCrypto  = virgil_crypto_go.NewVirgilCardCrypto()
	tokenSigner = virgil_crypto_go.NewVirgilAccessTokenSigner()
)

type cardsRegistrar struct {
	dataFile             string                // file with card requests
	filePrivateKey       cryptoapi.PrivateKey  // private key for file decryption
	filePublicSenderKey  cryptoapi.PublicKey   // public key of file sender to verify signature
	iotPrivateKey        cryptoapi.PrivateKey  // private key for adding IoT Registrar signature to card request
	cardService          *cardsServiceInfo
	failedRequestsFile   string

	processingErrors     []string
	failedRequests       []string
}

type cardsServiceInfo struct {
	appID               string
	apiKeyID            string
	apiPrivateKey       cryptoapi.PrivateKey
	cardsClient         *sdk.CardClient
}

func NewRegistrar(context *cli.Context) (*cardsRegistrar, error){
	var param string
	var err error

	registrar := new(cardsRegistrar)
	// data
	if param = context.String("data"); param == "" {
		return nil, cli.Exit("Data file does't specified.", 1)
	}
	registrar.dataFile = filepath.Clean(param)

	// file for requests which failed to be registered
	registrar.failedRequestsFile = filepath.Join(filepath.Dir(registrar.dataFile), "card_requests_failed.txt")

	// file_key
	if param = context.String("file_key"); param == "" {
		return nil, cli.Exit("Private key for file decryption doesn't specified.", 1)
	}
	registrar.filePrivateKey, err = importPrivateKey(param, context.String("file_key_pass"))
	if err != nil {
		return nil, err
	}
	// file_sender_key
	if param = context.String("file_sender_key"); param == "" {
		return nil, cli.Exit("File with public key of data sender doesn't specified.", 1)
	}
	registrar.filePublicSenderKey, err = importPublicKey(param)
	if err != nil {
		return nil, err
	}
	// iot_priv_key
	if param = context.String("iot_priv_key"); param == "" {
		return nil, cli.Exit("File with private key of IoT registrar doesn't specified.", 1)
	}
	registrar.iotPrivateKey, err = importPrivateKey(param, context.String("iot_priv_key_pass"))
	if err != nil {
		return nil, err
	}

	// Fill cardsServiceInfo struct
	cardsService := new(cardsServiceInfo)
	// app_id
	if param = context.String("app_id"); param == "" {
		return nil, cli.Exit("Application ID does't specified.", 1)
	}
	cardsService.appID = param
	// api_key_id
	if param = context.String("api_key_id"); param == "" {
		return nil, cli.Exit("Api key Id does't specified.", 1)
	}
	cardsService.apiKeyID = param
	// base_url
	if param = context.String("base_url"); param == "" {
		return nil, cli.Exit("Card service base url does't specified.", 1)
	}
	cardsService.cardsClient = sdk.NewCardsClient(param)
	// api_key
	if param = context.String("api_key"); param == "" {
		return nil, cli.Exit("Api private key file doesn't specified.", 1)
	}
	cardsService.apiPrivateKey, err = importPrivateKey(param, "")
	if err != nil {
		return nil, err
	}

	registrar.cardService = cardsService

	return registrar, nil
}

func (r *cardsRegistrar) ProcessRequests() error {
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
		lineNumber := requestNumber - 1

		// Get encrypted request line from file
		encryptedRequest, err := getRequest()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err // failed to read line from file - exit immediately
		}

		// Decrypt then verify request
		fmt.Println("\nProcessing request number", requestNumber)
		decryptedRequest, err := r.decryptThenVerifyRequest(encryptedRequest)
		if err != nil {
			r.processError(err, lineNumber)
			r.failedRequests = append(r.failedRequests, encryptedRequest)
			continue
		}
		fmt.Println("Input: ", decryptedRequest)

		// Register card
		if err := r.registerCard(decryptedRequest); err != nil {
			r.processError(err, lineNumber)
			r.failedRequests = append(r.failedRequests, encryptedRequest)
			continue
		}
	}

	// Process errors
	if len(r.processingErrors) > 0 {
		log.Println("FAILED: Errors occurred during cards requests processing")
		if err := r.saveFailedRequests(); err != nil {
			log.Println("Failed to save failed requests to file")
		} else {
			log.Println("Failed requests have been saved to file:", r.failedRequestsFile)
		}
		return fmt.Errorf(strings.Join(r.processingErrors, "\n"))
	}
	fmt.Println("OK: cards requests processing done successfully")
	return nil
}

// log error to stderr and save it`s text for further usage
func (r *cardsRegistrar) processError(err error, line int) {
	errorText := fmt.Sprintf(
		"%s line#%d: %s", filepath.Base(r.dataFile), line, err.Error())
	log.Println(errorText)
	r.processingErrors = append(r.processingErrors, errorText)
}

// get each card request from file line by line
func (r *cardsRegistrar) requestProvider(f *os.File) (func() (string, error), error) {
	reader := bufio.NewReader(f)

	// Return a function, each call of which will return decrypted line
	return func() (string, error) {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return line, nil
	}, nil
}

func (r *cardsRegistrar) decryptThenVerifyRequest(request string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(request)
	if err != nil {
		return "", fmt.Errorf("b64 decode error: %s, line: %s", err, request)
	}
	decryptedData, err := crypto.DecryptThenVerify(data, r.filePrivateKey, r.filePublicSenderKey)
	if err != nil {
		return "", fmt.Errorf("DecryptThenVerify error: %s", err)
	}
	return string(decryptedData), nil
}

func (r *cardsRegistrar) registerCard(decryptedRequest string) error {

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

	// Add IoT registrar signature
	extraFields := []byte{}
	modelSigner := sdk.NewModelSigner(cardCrypto)
	if err := modelSigner.SignRaw(rawSignedModel, "iot_registrator", r.iotPrivateKey, extraFields); err != nil {
		return fmt.Errorf("failed to sign by IoT registrar key %v", err)
	}

	// Generate JWT token
	ttl := time.Minute * 5
	jwtGenerator := sdk.NewJwtGenerator(
		r.cardService.apiPrivateKey, r.cardService.apiKeyID, tokenSigner, r.cardService.appID, ttl)
	identity := rawCardContent.Identity
	jwtToken, err := jwtGenerator.GenerateToken(identity, nil)
	if err != nil {
		return fmt.Errorf("jwtToken generation error: %s", err)
	}
	jwtString := jwtToken.String()

	// Publish card
	prepared, err := rawSignedModel.ExportAsBase64EncodedString()
	if err != nil {
		return fmt.Errorf("failed to export rawSignedModel as base 64: %v", err)
	}
	fmt.Printf("Prepared card: %s\n", prepared)
	publishedCard, err := r.cardService.cardsClient.PublishCard(rawSignedModel, jwtString)
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

func (r *cardsRegistrar) saveFailedRequests() error {
	// Create file
	var file, err = os.Create(r.failedRequestsFile)
	if err != nil {
		return fmt.Errorf("failed to create file for failed requests: %v", err)
	}
	defer file.Close()

	// Write failed requests (encrypted) to file
	for _, request := range r.failedRequests {
		if _, err := fmt.Fprint(file, request); err != nil {
			return fmt.Errorf("failed to write failed request to file: %v", err)
		}
	}

	return nil
}

func importPrivateKey(keyPath string, keyPass string) (cryptoapi.PrivateKey, error) {
	keyBytes, err := getKeyFileBytes(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := crypto.ImportPrivateKey(keyBytes, keyPass)
	if err != nil {
		return nil, fmt.Errorf("failed to import private key %s: %v", keyPath, err)
	}

	return key, nil
}

func importPublicKey(keyPath string) (cryptoapi.PublicKey, error) {
	keyBytes, err := getKeyFileBytes(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := crypto.ImportPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to import public key %s: %v", keyPath, err)
	}

	return key, nil
}


func getKeyFileBytes(keyPath string) ([]byte, error){
	cleanPath := filepath.Clean(keyPath)
	fileKeyBytes, err := ioutil.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("can`t read key (%s): %s", cleanPath, err)
	}
	return fileKeyBytes, nil
}
