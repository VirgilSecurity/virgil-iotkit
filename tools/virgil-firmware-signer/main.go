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
    "log"
    "os"

    "./signers"
    "./utility"

    "gopkg.in/urfave/cli.v2"
)

var version = "0.1.0"


func main()  {
    flags := []cli.Flag{
        &cli.PathFlag{
            Name:    "config",
            Aliases: []string{"c"},
            Usage:   "Path to config file",
        },
        &cli.PathFlag{
            Name:    "input",
            Aliases: []string{"i"},
            Usage:   "Input file",
        },
        &cli.IntFlag{
            Name:    "file-size",
            Aliases: []string{"s"},
            Usage:   "Output _Prog.bin file size in bytes",
        },
        &cli.StringFlag{
            Name:    "fw-version",
            Usage:   "Firmware version",
        },
        &cli.StringFlag{
            Name:    "manufacturer",
            Aliases: []string{"a"},
            Usage:   "Manufacturer",
        },
        &cli.StringFlag{
            Name:    "model",
            Aliases: []string{"d"},
            Usage:   "Model",
        },
        &cli.IntFlag{
            Name:    "chunk-size",
            Aliases: []string{"k"},
            Usage:   "Chunk size",
        },
    }

    app := &cli.App{
        Name:    "virgil-signer",
        Usage:   "Virgil Security util for signing firmware",
        Version: version,
        Flags:   flags,
        Action:  func(context *cli.Context) error {
            return signerFunc(context)
        },
    }

    err := app.Run(os.Args)
    if err != nil {
        log.Fatal(err)
    }
}

func signerFunc(context *cli.Context) (err error) {
    // Create signer
    var fwSigner signers.SignerInterface
    fwSigner, err = signers.NewVirgilCryptoSigner(context.Path("config"))

    signerUtil := &utility.SignerUtility{
        Signer:             fwSigner,
        FirmwarePath:       context.Path("input"),
        ProgFileSize:       context.Int("file-size"),
        FirmwareVersion:    context.String("fw-version"),
        Manufacturer:       context.String("manufacturer"),
        Model:              context.String("model"),
        ChunkSize:          context.Int("chunk-size"),
    }

    err = signerUtil.CreateSignedFirmware()
    if err != nil {
        msg := fmt.Sprintf("Error during signed firmware creation: %v", err)
        return cli.Exit(msg, 1)
    }

    return nil
}
