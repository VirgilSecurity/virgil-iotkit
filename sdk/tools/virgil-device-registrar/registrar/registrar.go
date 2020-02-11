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
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/urfave/cli.v2"
)

const registrationEP  = "/things/card/iot"

type cardsRegistrar struct {
	dataFile             string             // file with card requests
	cardService          *cardsServiceInfo
	failedRequestsFile   string

	httpClient           *http.Client

	processingErrors     []string
	failedRequests       []string
}

type cardsServiceInfo struct {
	ApiUrl               string
	AppToken             string  // application token used for authorization on service
}

func NewRegistrar(context *cli.Context) (*cardsRegistrar, error){
	var param string

	registrar := new(cardsRegistrar)
	// data
	if param = context.String("data"); param == "" {
		return nil, cli.Exit("Data file does't specified.", 1)
	}
	registrar.dataFile = filepath.Clean(param)

	// file for requests which failed to be registered
	registrar.failedRequestsFile = filepath.Join(filepath.Dir(registrar.dataFile), "card_requests_failed.txt")

	// Fill cardsServiceInfo struct
	cardsService := new(cardsServiceInfo)
	// app_token
	if param = context.String("app_token"); param == "" {
		return nil, cli.Exit("Virgil application token does't specified.", 1)
	}
	cardsService.AppToken = param
	// api_url
	if param = context.String("api_url"); param == "" {
		return nil, cli.Exit("URL used for Cards registration does't specified.", 1)
	}
	cardsService.ApiUrl = param

	registrar.cardService = cardsService

	// Prepare http client
	registrar.httpClient = &http.Client{}
	registrar.httpClient.Timeout = time.Second * 10

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

		// Get request line from file
		requestB64, err := getRequest()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err // failed to read line from file - exit immediately
		}
		fmt.Println("Input: ", requestB64)

		// Register card
		if err := r.registerCard(requestB64); err != nil {
			r.processError(err, lineNumber)
			r.failedRequests = append(r.failedRequests, requestB64)
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

func (r *cardsRegistrar) registerCard(requestB64 string) error {
	// Decode base 64
	cardRequest, err := base64.StdEncoding.DecodeString(requestB64)
	if err != nil {
		return fmt.Errorf("failed to decode b64 request string: %v", err)
	}

	// Prepare request
	sendBytes := bytes.NewBuffer(cardRequest)
	req, err := http.NewRequest("POST", r.cardService.ApiUrl + registrationEP, sendBytes)
	req.Header.Set("AppToken", r.cardService.AppToken)

	// Send
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send card request error: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Verify response
    if resp.StatusCode != 200 {
		return fmt.Errorf("publish card error, status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Print results
	fmt.Println("Card registered. Response:", base64.StdEncoding.EncodeToString(body))

	return nil
}

func (r *cardsRegistrar) saveFailedRequests() error {
	// Create file
	var file, err = os.Create(r.failedRequestsFile)
	if err != nil {
		return fmt.Errorf("failed to create file for failed requests: %v", err)
	}
	defer file.Close()

	// Write failed requests to file
	for _, request := range r.failedRequests {
		if _, err := fmt.Fprint(file, request); err != nil {
			return fmt.Errorf("failed to write failed request to file: %v", err)
		}
	}

	return nil
}
