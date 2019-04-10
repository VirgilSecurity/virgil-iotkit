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
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/sdk"
)

var version = "0.1.0"

type CardsServiceInfo struct {
	appID               string
	apiKeyID            string
	apiPrivateKey       []byte
	cardsClient         *sdk.CardClient
}

type CardsRegistrar struct {
	dataFile             string
	filePrivateKey       []byte
	filePrivateKeyPass   string
	filePublicSenderKey  []byte
}

func main()  {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:    "data",
			Aliases: []string{"d"},
			Usage:   "File with encrypted data",
		},
		&cli.StringFlag{
			Name:    "file_key",
			Aliases: []string{"k"},
			Usage:   "File with private key to decrypt received data file",
		},
		&cli.StringFlag{
			Name:    "file_key_pass",
			Aliases: []string{"p"},
			Usage:   "Password file with private key to decrypt received data file",
		},
		&cli.StringFlag{
			Name:    "file_sender_key",
			Aliases: []string{"s"},
			Usage:   "Public key of sender of data file",
		},
		&cli.StringFlag{
			Name:    "app_id",
			Aliases: []string{"a"},
			Usage:   "Virgil Application ID",
		},
		&cli.StringFlag{
			Name:    "api_key_id",
			Aliases: []string{"t"},
			Usage:   "Virgil Api key Id",
		},
		&cli.StringFlag{
			Name:    "api_key",
			Aliases: []string{"y"},
			Usage:   "Virgil Api private key",
		},
		&cli.StringFlag{
			Name:    "base_url",
			Aliases: []string{"b"},
			Usage:   "Card service base url",
		},
	}

	app := &cli.App{
		Name:    "virgil-iot-registrar",
		Usage:   "Virgil Security utility for registration of Cards at Virgil IoT Cloud.",
		Version: version,
		Flags:   flags,
		Action:  func(context *cli.Context) error {
			return registrarFunc(context)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func registrarFunc(context *cli.Context) error {

	var param string

	// Fill CardsRegistrar struct
	registrar := new(CardsRegistrar)
    // data
	if param = context.String("data"); param == "" {
		return cli.Exit("Data file does't specified.", 1)
	}
	registrar.dataFile = filepath.Clean(param)
    // file_key
	if param = context.String("file_key"); param == "" {
		return cli.Exit("Private key for file decryption doesn't specified.", 1)
	}
	filePrivateKeyKeyBytes, err := getKeyFileBytes(param)
	if err != nil {
		return err
	}
	registrar.filePrivateKey = filePrivateKeyKeyBytes
    // file_sender_key
	if param = context.String("file_sender_key"); param == "" {
		return cli.Exit("File with public key of data sender doesn't specified.", 1)
	}
	filePublicSenderKeyBytes, err := getKeyFileBytes(param)
	if err != nil {
		return err
	}
	registrar.filePublicSenderKey = filePublicSenderKeyBytes
	// file_key_pass
	registrar.filePrivateKeyPass = context.String("file_key_pass")

	// Fill CardsServiceInfo struct
	cardsService := new(CardsServiceInfo)
    // app_id
	if param = context.String("app_id"); param == "" {
		return cli.Exit("Application ID does't specified.", 1)
	}
	cardsService.appID = param
    // api_key_id
	if param = context.String("api_key_id"); param == "" {
		return cli.Exit("Api key Id does't specified.", 1)
	}
	cardsService.apiKeyID = param
    // base_url
	if param = context.String("base_url"); param == "" {
		return cli.Exit("Card service base url does't specified.", 1)
	}
	cardsService.cardsClient = sdk.NewCardsClient(param)
    // api_key
	if param = context.String("api_key"); param == "" {
		return cli.Exit("Api private key file doesn't specified.", 1)
	}
	apiPrivateKeyBytes, err := getKeyFileBytes(param)
	if err != nil {
		return err
	}
	cardsService.apiPrivateKey = apiPrivateKeyBytes

	return registrar.processRequests(cardsService)
}

func getKeyFileBytes(keyPath string) ([]byte, error){
	cleanPath := filepath.Clean(keyPath)
	fileKeyBytes, err := ioutil.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("can`t read key (%s): %s", cleanPath, err)
	}
	return fileKeyBytes, nil
}
