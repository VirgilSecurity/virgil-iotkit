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
	"log"
	"os"

	"./registrar"

	"gopkg.in/urfave/cli.v2"
)

var version = "0.1.0"



func main()  {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:    "data",
			Aliases: []string{"d"},
			Usage:   "File with data",
		},
		&cli.StringFlag{
			Name:    "app_token",
			Aliases: []string{"t"},
			Usage:   "Virgil application token",
		},
		&cli.StringFlag{
			Name:    "api_url",
			Aliases: []string{"b"},
			Usage:   "API URL, used for cards registration",
		},
	}

	app := &cli.App{
		Name:    "virgil-iot-registrar",
		Usage:   "Virgil Security utility for registration of Cards at Virgil IoT Cloud.",
		Version: version,
		Flags:   flags,
		Action:  func(context *cli.Context) error {
			r, err := registrar.NewRegistrar(context)
			if err != nil {
				return err
			}
			return r.ProcessRequests()
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
