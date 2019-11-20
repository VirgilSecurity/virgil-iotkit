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
    "./signers"
    "./utility"
    "fmt"
    "log"
    "os"

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
            Usage:   "Firmware version ([0-255].[0-255].[0-255].[0-4294967295])",
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
    signerUtil := new(utility.SignerUtility)
    var stat os.FileInfo

    // Create signer
    var fwSigner signers.SignerInterface
    if fwSigner, err = signers.NewVirgilCryptoSigner(context.Path("config")); err != nil {
        return err
    }
    signerUtil.Signer = fwSigner

    // Verify and set input parameters
    // --input
    var inputFile string
    if inputFile = context.Path("input"); inputFile == "" {
        return fmt.Errorf("--input isn't specified")
    }
    if stat, err = os.Stat(inputFile); err != nil {
        if os.IsNotExist(err) {
            return fmt.Errorf("input file by given path %s doesn't exist", inputFile)
        }
        return err
    }
    signerUtil.FirmwarePath = inputFile

    // --file-size
    var progFileSize int
    if progFileSize = context.Int("file-size"); progFileSize == 0 {
        return fmt.Errorf("--file-size isn't specified")
    }
    if int64(progFileSize) <= stat.Size() {
        return fmt.Errorf("--file-size (%d) cannot be" +
            " lesser than --input file size (%d)", progFileSize, stat.Size())
    }
    signerUtil.ProgFileSize = progFileSize

    // --fw-version
    fwVersion := context.String("fw-version")
    if fwVersion == "" {
        return fmt.Errorf("--fw-version isn't specified")
    }
    signerUtil.FirmwareVersion = fwVersion

    // --manufacturer
    manufacturer := context.String("manufacturer")
    if manufacturer == "" {
        return fmt.Errorf("--manufacturer isn't specified")
    }
    signerUtil.Manufacturer = manufacturer

    // --model
    model := context.String("model")
    if model == "" {
        return fmt.Errorf("--model isn't specified")
    }
    signerUtil.Model = model

    // --chunk-size
    signerUtil.ChunkSize = context.Int("chunk-size")

    // Sign
    err = signerUtil.CreateSignedFirmware()
    if err != nil {
        msg := fmt.Sprintf("Error during signed firmware creation: %v", err)
        return cli.Exit(msg, 1)
    }

    return nil
}
