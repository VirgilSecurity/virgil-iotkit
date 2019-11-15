# Virgil Firmware Signer
Virgil Firmware Signer is a CLI that allows you to sign a firmware using private keys.

Virgil Firmware Signer is a CLI that allows you to sign a firmware using Auth Private Key and Firmware Private Key generated in the Virgil Trust Provisioner in order to provide firmware integrity before distributing it.

## Content
- [Setting up Firmware Signer](#setting-up-virgil-firmware-signer)
- [Command Reference](#command-reference)
- [Firmware Structure](#firmware-structure)


## Setting up Firmware Signer
This section demonstrates on how to install and configure Virgil Firmware Signer for preferred platform.

### Install Firmware Signer
This section provides instructions for installing Virgil Firmware Signer.

#### Linux OS
Virgil Firmware Signer is distributed as a package.

In order to download and install the Virgil Firmware Signer on Linux, use the YUM package manager and the following command:

```bash
yum -y install virgil-iot-sdk-tools
```

### Configure Virgil Firmware Signer
After the Virgil Firmware Signer is installed, you need to set up the configuration file (```conf.json```).

#### Config File Structure
By default, ```conf.json``` file is placed in root folder of Virgil Firmware Signer repository. The Virgil Firmware Signer configuration file has the following format:

```bash
[
  {
    "path": "./keys/auth_54192_1auth.key",
    "key_type": 1,
    "ec_type": 3
  },
  {
    "path": "./keys/firmware_16364_1fw.key",
    "key_type": 3,
    "ec_type": 3
  }
]
```
#### Configurable Variables

| Variable | Description                                      |
|----------|--------------------------------------------------|
| path     | The path to Auth or Firmware keys                |
| key_type | Type of the private key                          |
| ec_type  | Type of key generation algorithm (elyptic curve) |

**Key Type**

| Key type          | Value |
|-------------------|-------|
| Recovery Key      | 0     |
| Auth Key          | 1     |
| TrustList Key     | 2     |
| Firmware Key      | 3     |
| Factory Key       | 4     |
| IoT device        | 5     |
| User device       | 6     |
| Cloud Service Key | 9     |

**Elliptic Curve Type**

| Key type      | Value |
|---------------|-------|
| EC_SECP192R1  | 1     |
| EC_SECP224R1  | 2     |
| EC_SECP256R1  | 3     |
| EC_SECP384R1  | 4     |
| EC_SECP521R1  | 5     |
| EC_SECP192K1  | 6     |
| EC_SECP224K1  | 7     |
| EC_SECP256K1  | 8     |
| EC_CURVE25519 | 9     |
| EC_ED25519    | 10    |
| RSA_2048      | 11    |

## Command Reference
Here is the list of possible commands for Virgil Firmware Signer.

### Syntax
The CLI has the following syntax.

```bash
virgil-firmware-signer [global options] command [command options] [arguments...]
```
Use ```virgil-firmware-signer --help``` to view list of available arguments.

### Signing Firmware
The command below allows you to sign firmware using Auth and Firmware private key.

| Command                                                                          | Result                                            |
|----------------------------------------------------------------------------------|---------------------------------------------------|
| virgil-firmware-signer [global options] command [command options] [arguments...] | Signed firmware (_Update.bin and _Prog.bin files) |

After executing firmware signing command, Virgil Firmware Signer generates 2 files: ```_Update.bin``` and ```_Prog.bin```.

```_Update.bin``` file is uploaded to a Firmware Service for further distribution to IoT devices.

```_Prog.bin``` file is delivered directly to IoT devices  (e.g. for testing purpose).

The difference between these files is that ```_Update.bin``` file has a ```header``` with additional information about firmware and 0xFF zone. The header helps to notify which will get the Firmware.

**Example**

```bash
virgil-firmware-signer --input “./keys/fw-VRGL-Cf01" --config “./conf.json” --file-size 1000000 --fw-version 0.1.2.3456 --manufacturer VRGL --model Cf01 --chunk-size 64000
```
| Command                        | Description                                      |
|--------------------------------|--------------------------------------------------|
| --config value, -c value       | Path to config file                              |
| --input value, -i value        | Input file                                       |
| --file-size value, -s value    | Output _Prog.bin file size in bytes (default: 0) |
| --fw-version value             | Firmware version                                 |
| --manufacturer value, -a value | Manufacturer name                                |
| --model value, -d value        | Model name                                       |
| --chunk-size value, -k value   | Chunk size (default: 0)                          |
| --help, -h                     | Show help (default: false)                       |
| --version, -v                  | Print the version (default: false)               |

## Firmware Structure
This section contains information about the structure of signed firmware.

The structure below contains information about signed firmware structure of the ```_Update.bin file```.

```bash
type FirmwareContainer struct {
    Header       FirmwareHeader
    Firmware     []byte
    Footer       FirmwareFooter
}

type FirmwareHeader struct {
    CodeOffset       uint32
    CodeLength       uint32
    FooterOffset     uint32
    FooterLength     uint32
    SignaturesCount  uint8
    Descriptor       FirmwareDescriptor
}

type FirmwareDescriptor struct {
    ManufactureID    [16]byte
    DeviceType       [4]byte
    Version          FileVersion
    Padding          uint8
    ChunkSize        uint16
    FirmwareLength   uint32
    AppSize          uint32
}

type FileVersion struct {
    Major           uint8
    Minor           uint8
    Patch           uint8
    Build           uint32
    Timestamp       uint32
}

type FirmwareFooter struct {
    SignaturesCount  uint8
    Descriptor       FirmwareDescriptor
    Signatues        []Signature
}

type Signature struct {
    SignerType       uint8
    ECType           uint8
    Hash_type        uint8
    Sign             [SignSize]byte
    SignerPublicKey  []byte
}
```
