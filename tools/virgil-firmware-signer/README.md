# Virgil Firmware Signer
Virgil Firmware Signer is a CLI utility that allows you to sign firmware using an Auth private key and a Firmware private key that have been generated with the Virgil Trust Provisioner in order to provide a mechanism for verifying firmware integrity before distributing it.

## Content
- [Setting up Firmware Signer](#setting-up-firmware-signer)
  - [Linux OS](#linux-os)
  - [Ubuntu OS, Debian OS](#ubuntu-os-debian-os)
  - [CentOS, Fedora OS](#centos-fedora-os)
  - [Mac OS](#mac-os)
  - [Windows OS](#windows-os)
- [Command Reference](#command-reference)
- [Firmware Distribution](#firmware-distribution)
- [Firmware Structure](#firmware-structure)

## Setting up Firmware Signer
This section demonstrates how to install and configure the Virgil Firmware Signer for your platform of choice.

### Install Firmware Signer
This section provides instructions for installing the Virgil Firmware Signer.

#### Linux OS
Virgil Firmware Signer is distributed as a package.

In order to download and install the Virgil Firmware Signer on Linux, use the YUM package manager and run the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```

#### Ubuntu OS, Debian OS
Virgil Firmware Signer is distributed as a package.

In order to download and install the Virgil Firmware Signer on Ubuntu, Debian, use the YUM package manager and run the following command:
```bash
$ sudo apt-get install virgil-iot-sdk-tools
```

#### CentOS, Fedora OS
Virgil Firmware Signer is distributed as a package.

In order to download and install the Virgil Firmware Signer on CentOS, Fedora, use the YUM package manager and run the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```

#### Mac OS
At this moment we don't provide a built package for Mac OS, so you'll have to build and run it by yourself using [cmake](https://cmake.org).

```bash
$ git clone --recursive https://github.com/VirgilSecurity/virgil-iot-sdk.git
$ cd virgil-iot-sdk
$ mkdir build && cd build
$ cmake ..
$ make vs-tool-virgil-firmware-signer
```

#### Windows OS
Virgil Firmware Signer package for Windows OS is currently in development. To join our mailing list to receive information on updates, please contact our support team at support@VirgilSecurity.com.

### Configure Virgil Firmware Signer
After the Virgil Firmware Signer is installed, you need to set up the configuration file (```conf.json```).

#### Config File Structure
By default, ```conf.json``` file is placed in root folder of the Virgil Firmware Signer repository. The Virgil Firmware Signer configuration file has the following format:

```bash
[
  {
    "path": "./keys/auth_54192_1auth.key",
    "key_type": 1,

  },
  {
    "path": "./keys/firmware_16364_1fw.key",
    "key_type": 3,

  }
]
```
#### Configurable Variables

| Variable | Description                                      |
|----------|--------------------------------------------------|
| path     | The path to Auth or Firmware keys                |
| key_type | The type of private key                          |


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

## Command Reference
Here is the list of commands for the Virgil Firmware Signer:

### Syntax
The CLI has the following syntax:

```bash
virgil-firmware-signer [global options] command [command options] [arguments...]
```
Use ```virgil-firmware-signer --help``` to view a list of the available arguments.

### Signing Firmware
The command below allows you to sign firmware using the Auth and Firmware private keys.

| Command                                                                          | Result                                            |
|----------------------------------------------------------------------------------|---------------------------------------------------|
| virgil-firmware-signer [global options] command [command options] [arguments...] | Signed firmware (_Update.bin and _Prog.bin files) |

After executing firmware signing command, Virgil Firmware Signer generates 2 files: ```_Update.bin``` and ```_Prog.bin```.

```_Update.bin``` file is uploaded to the firmware Service for further distribution to IoT devices.

```_Prog.bin``` file is delivered directly to IoT devices (e.g. for testing purpose).

The difference between these files is that ```_Update.bin``` file has a ```header``` with additional information about firmware. The header helps to inform which device will get the firmware.

**Example**

```bash
virgil-firmware-signer --input “fw-VRGL-Cf01" --config “./conf.json” --file-size 1000000 --fw-version 0.1.2.3456 --manufacturer VRGL --model Cf01 --chunk-size 64000
```
| Command                        | Description                                      |
|--------------------------------|--------------------------------------------------|
| --config value, -c value       | Path to config file                              |
| --input value, -i value        | Input file                                       |
| --file-size value, -s value    | Output _Prog.bin file size in bytes (default: 0) |
| --fw-version value             | Firmware version ([0-255].[0-255].[0-255].[0-4294967295]) |
| --manufacturer value, -a value | Manufacturer name                                |
| --model value, -d value        | Model name                                       |
| --chunk-size value, -k value   | Chunk size (default: 0)                          |
| --help, -h                     | Show help (default: false)                       |
| --version, -v                  | Print the version (default: false)               |

## Firmware Distribution
This section describes how to distribute a signed firmware to IoT devices.

Once you signed your firmware using the Virgil Firmware Signer, you are able to distribute it to IoT gateway or IoT devices via the Virgil Cloud. IoT devices get notification about the new firmware at the moment they get online. In order to upload firmware to the Virgil Cloud you have to run the `publish-firmware.sh` script from the scripts folder of Virgil IoTKit.

Here is how it works:
- First of all you have to install [jq](https://stedolan.github.io/jq/download/) library.
- Then navigate to your terminal (CLI) and run the `publish-firmware.sh` from [scripts folder](https://github.com/VirgilSecurity/virgil-iotkit/tree/master/scripts).

```bash
$ ./scripts/publish-firmware.sh --update-file [path to firmware *_update file] --app-token [Virgil AppToken]
```

- Once the firmware uploaded to the Virgil Cloud, an IoT gateway gets notification about available update.
- The IoT gateway downloads a new firmware and verifies its signatures (signatures of Firmware and Auth Keys).
- After firmware signatures are validated:
  - IoT gateway accepts a new firmware in case it is intended for it,
  - Or sends the firmware to IoT devices. IoT device also verifies received firmware and update it.


## Firmware Structure
This section contains information about the structure of the signed firmware.

The structure below contains information about signed firmware structure of the `_Update.bin file`.

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
