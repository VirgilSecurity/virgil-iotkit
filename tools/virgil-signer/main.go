package main

import (
    "fmt"
    "gopkg.in/ini.v1"
    "log"
    "os"
    "strconv"

    "./signers"

    "gopkg.in/urfave/cli.v2"
)

var version = "0.1.0"


func main()  {
    flags := []cli.Flag{
        &cli.StringFlag{
            Name:    "config",
            Aliases: []string{"c"},
            Usage:   "Path to config file",
        },
        &cli.StringFlag{
            Name:    "input",
            Aliases: []string{"i"},
            Usage:   "Input file",
        },
        &cli.StringFlag{
            Name:    "build-time",
            Aliases: []string{"b"},
            Usage:   "Build time",
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
        &cli.StringFlag{
            Name:    "app-type",
            Aliases: []string{"t"},
            Usage:   "Application Type",
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

func signerFunc(context *cli.Context) error {
    cfg, err := ini.Load(context.Path("config"))
    if err != nil {
        msg := fmt.Sprintf("Fail to read config file: %v", err)
        return cli.Exit(msg, 1)
    }

    fileSize, _ := strconv.Atoi(context.Path("file-size"))
    chunkSize, _ := strconv.Atoi(context.Path("chunk-size"))

    signer := &signers.Signer{
        FirmwarePath:       context.Path("input"),
        FirmwareKeyPath:    cfg.Section("MAIN").Key("firmware_key_path").String(),
        AuthKeyPath:        cfg.Section("MAIN").Key("auth_key_path").String(),
        ProgFileSize:       fileSize,
        FirmwareVersion:    context.Path("fw-version"),
        Manufacturer:       context.Path("manufacturer"),
        Model:              context.Path("model"),
        ChunkSize:          chunkSize,
        ApplicationType:    context.Path("app-type"),
        BuildTime:          context.Path("build-time"),
    }
    fmt.Printf("Signer created: %+v \n", signer)

    err = signer.CreateSignedFirmware()
    if err != nil {
        msg := fmt.Sprintf("Error during signed firmware creation: %v", err)
        return cli.Exit(msg, 1)
    }

    return nil
}
