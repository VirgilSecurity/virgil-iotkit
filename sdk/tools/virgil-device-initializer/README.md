# Virgil Device Initializer
The Virgil Device Initializer is a CLI utility used to handle IoT device provisioning and create the devices' digital cards.

## Content
- [Overview](#Overview)
- [Setting up Device Initializer](#setting-up-device-initializer)
  - [Linux OS](#linux-os)
  - [Ubuntu OS, Debian OS](#ubuntu-os-debian-os)
  - [CentOS, Fedora OS](#centos-fedora-os)
  - [Mac OS](#mac-os)
  - [Windows OS](#windows-os)
- [Command Reference](#command-reference)

## Overview
To make each IoT device identifiable, verifiable and trusted by each party within the complete IoT solution, you need to provide them with specific provisioning files, generate private keys and create the digital cards for device registration on the Virgil Cloud.

The Virgil Device Initializer allows you to handle IoT device provisioning and prepare your IoT device (by creating its digital card) for its registration on the Virgil Cloud.

## How It Works
The IoT device provisioning process consists of 2 steps: preparation and initialization.

The **preparation** step requires the collection of all the required information (e.g. provisioning files) and preparation of your IoT device for further initialization.

The **initialization** step includes uploading provisioning files, generating device key pair, and creating device digital card request.

### Prerequisites
In order to perform the provisioning of the IoT device, you have to prepare the following:
- TrustList
- Factory private key
- Upper Level public keys (Auth, Recovery, TrustList, Firmware)

### Initialization
In order to perform device initialization, the following steps need to be performed:
- Device generates its key pair. Device Initializer is given the device public key.
- Device Initializer uploads public keys to the device.
- Device Initializer signs th device public key with the factory key and uploads signature to the device.
- Device Initializer uploads TrustList to the device.
- And finally, Device Initializer creates the device's digital card request and stores it in the file with other card requests.

Initialization of each device is individually performed one by one.

## Setting up Device Initializer
This section demonstrates how to install and configure the Virgil Device Initializer for your platform of choice.

### Install Device Initializer
This section provides instructions for how to install the Virgil Device Initializer.

#### Linux OS
Virgil Device Initializer is distributed as a package.

In order to download and install the Virgil Device Initializer on Linux, use the YUM package manager and run the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```
#### Ubuntu OS, Debian OS
Virgil Device Initializer is distributed as a package.

In order to download and install the Virgil Device Initializer on Ubuntu, Debian, use the YUM package manager and run the following command:
```bash
$ sudo apt-get install virgil-iot-sdk-tools
```

#### CentOS, Fedora OS
Virgil Device Initializer is distributed as a package.

In order to download and install the Virgil Device Initializer on CentOS, Fedora, use the YUM package manager and run the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```

#### Mac OS
At this moment we don't provide a built package for Mac OS, so you'll need to build and run it yourself using [cmake](https://cmake.org).

```bash
$ git clone --recursive https://github.com/VirgilSecurity/virgil-iot-sdk.git
$ cd virgil-iot-sdk
$ mkdir build && cd build
$ cmake ..
$ make vs-tool-virgil-device-initializer
```

#### Windows OS
Virgil Device Initializer package for Windows OS is currently in development. To join our mailing list to receive updates, please contact our support team at support@VirgilSecurity.com.

## Command Reference
Here is the list of the commands for Virgil Device Initializer:

### Syntax
The CLI has the following syntax:

```bash
virgil-device-initializer
--output "/root/current-credentials/card_requests_gateways.txt"
--device_info_output "/root/current-credentials/device_info.txt"
--auth_pub_key_1 "/root/current-credentials/key_storage/pubkeys/auth_15918_auth2.pub"
--auth_pub_key_2 "/root/current-credentials/key_storage/pubkeys/auth_54929_auth1.pub"
--rec_pub_key_1 "/root/current-credentials/key_storage/pubkeys/recovery_10514_recovery1.pub"
--rec_pub_key_2 "/root/current-credentials/key_storage/pubkeys/recovery_8644_recovery2.pub"
--tl_pub_key_1 "/root/current-credentials/key_storage/pubkeys/tl_23138_tl2.pub"
--tl_pub_key_2 "/root/current-credentials/key_storage/pubkeys/tl_41287_tl1.pub"
--fw_pub_key_1 "/root/current-credentials/key_storage/pubkeys/firmware_57637_firmware1.pub"
--fw_pub_key_2 "/root/current-credentials/key_storage/pubkeys/firmware_62881_firmware2.pub"
--trust_list "/root/current-credentials/key_storage/trust_lists/release/TrustList_16568.tl"
--factory_key "/root/current-credentials/key_storage/private/factory_24251_factory.key"
```
Use  ```virgil-device-initializer -h```   to see the list of available arguments.

### Device Initialization
In order to initialize the IoT device, Virgil Device Initializer uses the following command:

| Command                                                                                   | Description                                                         |
|-------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| ```virgil-device-initializer [global options] command [command options] [arguments...]``` | CLI forms a Device card request and store it in ```transfer file``` |

The result of the command execution is the following:

- A generated IoT device card request for further registration via device registrar.
- A generated IoT device key pair. The private key is stored in the IoT device memory and the public key is stored in the device's digital card.

**Example**

Here is an example of a device being initialized:

```bash
Run:virgil-device-initializer --output "/root/current-credentials/card_requests_gateways.txt" --device_info_output "/root/current-credentials/device_info.txt" --auth_pub_key_1 "/root/current-credentials/key_storage/pubkeys/auth_15918_auth2.pub" --auth_pub_key_2 "/root/current-credentials/key_storage/pubkeys/auth_54929_auth1.pub" --rec_pub_key_1 "/root/current-credentials/key_storage/pubkeys/recovery_10514_recovery1.pub" --rec_pub_key_2 "/root/current-credentials/key_storage/pubkeys/recovery_8644_recovery2.pub" --tl_pub_key_1 "/root/current-credentials/key_storage/pubkeys/tl_23138_tl2.pub" --tl_pub_key_2 "/root/current-credentials/key_storage/pubkeys/tl_41287_tl1.pub" --fw_pub_key_1 "/root/current-credentials/key_storage/pubkeys/firmware_57637_firmware1.pub" --fw_pub_key_2 "/root/current-credentials/key_storage/pubkeys/firmware_62881_firmware2.pub" --trust_list "/root/current-credentials/key_storage/trust_lists/release/TrustList_16568.tl" --factory_key "/root/current-credentials/key_storage/private/factory_24251_factory.key"
Got 1 device
Device roles: [GATEWAY]
Device MAC: 25:f4:69:0c:99:5a
Upload Recovery key 1
Success: upload Recovery key 1
Upload Recovery key 2
Success: upload Recovery key 2
Upload Auth key 1
Success: upload Auth key 1
Upload Auth key 2
Success: upload Auth key 2
Upload Firmware key 1
Success: upload Firmware key 1
Upload Firmware key 2
Success: upload Firmware key 2
Upload TrustList key 1
Success: upload TrustList key 1
Upload TrustList key 2
Success: upload TrustList key 2
Sign device by Factory key
Device key type 5
Device public key (raw): BCMBfTZGL1wlVUv3EvN3dq25rjFAou/1q428ycEUswE3Rd8YM7JUfrXJd8g9bBKALMWxzGbmQOf5+d4kmftVi8w=
Signature (raw): Nbzx4vmyH8CAkZ4PRB9+4y/uhuUm/O891UvR0ttpexMn65jvb86Ce7+i2u5GvZQR8NjyOGTQ0Qv94wYetFHW+A==
Device public key (virgil): MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELj0gdSdRZWzwnVYwMUmC6s693yYaZ6Ahw2bc6MK9riy+vQGYt3rKBicEIyyPUZZAR0OR+ROfYaQIZBClyVPBDQ==
Upload Device signature
Success: upload Device signature
Upload TrustList Header
Upload TrustList chunk 0
Success: upload TrustList chunk 0
Upload TrustList chunk 1
Success: upload TrustList chunk 1
Upload TrustList Footer
OK: TrustList set successfully.
OK: Device initialization done successfully.
Device info: {"manufacturer":"0x5652474c000000000000000000000000","model":"0x43663031","roles":["GATEWAY"],"mac":"25:f4:69:0c:99:5a","serial":"JfRpDJlaAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","publicKeyTiny":"BCMBfTZGL1wlVUv3EvN3dq25rjFAou/1q428ycEUswE3Rd8YM7JUfrXJd8g9bBKALMWxzGbmQOf5+d4kmftVi8w=","signature":"Nbzx4vmyH8CAkZ4PRB9+4y/uhuUm/O891UvR0ttpexMn65jvb86Ce7+i2u5GvZQR8NjyOGTQ0Qv94wYetFHW+A==","key_type":5}
Card request: eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNklqSTFaalEyT1RCak9UazFZVEF6TURNd016QXpNRE13TXpBek1E
```
