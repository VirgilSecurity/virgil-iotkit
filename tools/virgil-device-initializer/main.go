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

    "./initializer"

    "gopkg.in/urfave/cli.v2"
)

var version = "0.1.0"


func main()  {
    flags := []cli.Flag{
        &cli.StringFlag{
            Name:    "output",
            Aliases: []string{"o"},
            Usage:   "Output file",
        },
        &cli.StringFlag{
            Name:    "device_info_output",
            Aliases: []string{"i"},
            Usage:   "Device info output file",
        },
        &cli.StringFlag{
            Name:    "auth_pub_key_1",
            Aliases: []string{"u"},
            Usage:   "File with 1st auth public key",
        },
        &cli.StringFlag{
            Name:    "auth_pub_key_2",
            Aliases: []string{"p"},
            Usage:   "File with 2nd auth public key",
        },
        &cli.StringFlag{
            Name:    "rec_pub_key_1",
            Aliases: []string{"e"},
            Usage:   "File with 1st recovery public key",
        },
        &cli.StringFlag{
            Name:    "rec_pub_key_2",
            Aliases: []string{"c"},
            Usage:   "File with 2nd recovery public key",
        },
        &cli.StringFlag{
            Name:    "tl_pub_key_1",
            Aliases: []string{"b"},
            Usage:   "File with 1st trust list public key",
        },
        &cli.StringFlag{
            Name:    "tl_pub_key_2",
            Aliases: []string{"k"},
            Usage:   "File with 2nd trust list public key",
        },
        &cli.StringFlag{
            Name:    "fw_pub_key_1",
            Aliases: []string{"w"},
            Usage:   "File with 1st firmware public key",
        },
        &cli.StringFlag{
            Name:    "fw_pub_key_2",
            Aliases: []string{"x"},
            Usage:   "File with 2nd firmware public key",
        },
        &cli.StringFlag{
            Name:    "trust_list",
            Aliases: []string{"f"},
            Usage:   "File with trust list",
        },
        &cli.BoolFlag{
            Name:    "create_card_only",
            Aliases: []string{"d"},
            Usage:   "Create card request only",
        },
        &cli.BoolFlag{
            Name:    "trust_list_only",
            Aliases: []string{"y"},
            Usage:   "Use Trust List only",
        },
        &cli.StringFlag{
            Name:    "factory_key",
            Aliases: []string{"z"},
            Usage:   "File with Factory private key",
        },
    }

    app := &cli.App{
        Name:    "virgil-iot-initializer",
        Usage:   "Virgil Security utility for IoT devices initialization.",
        Version: version,
        Flags:   flags,
        Action:  func(context *cli.Context) error {
            i, err := initializer.New(context)
            if err != nil {
                return err
            }
            return i.InitializeDevices()
        },
    }

    err := app.Run(os.Args)
    if err != nil {
        log.Fatal(err)
    }
}
