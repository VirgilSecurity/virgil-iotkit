# Virgil Device Initializer
The Virgil Device Initializer is a CLI utility used to make IoT devices provisioning and create their digital cards

## Content
- [Overview](#Overview)
- [Setting up Virgil Device Initializer](#setting-up-virgil-device-initializer)
- [Command Reference](#command-reference)

## Overview
In order to make each IoT device identifiable, verifiable and trusted by each party of IoT solution you have to provide it with specific provision files, generate private keys and create the digital cards for further device registration in Cloud.

Virgil Device Initializer allows you to make IoT device provoisioning and prepare your IoT device (create digital cards) for its further registration in Virgil Cloud.

## How It Works
The IoT device provisioning process consists of 2 steps: Preparation and Initialization.

The **preparation** step requires to grab all necessary information (e.g. provisioning files) and prepare your IoT device for further initialization.

The **initialization** step includes uploading provisioning files, generating device key pair and creating device digital card request.

### Prerequisites
In order to perform provisioning of IoT device you have to prepare the following:
- Trust List
- Factory Private Key
- Upper Level public keys (Auth, Recovery, Trust List Service, Firmware)

### Initialization
In order to perform device initialization you have to go through the following steps:
- After IoT device MAC is selected you need to cpecify Upper Level public keys.
- Device Initializer generates IoT device key pair.
- The IoT device is signed with a Factory Key.
- Then Device Initializer returns the IoT device's public key and signature.
- Signature is uploaded to the IoT device.
- Then Device Initializer uploads a Trust List to IoT device.
- Thereafter Device Initializer obtains device info: manufacturer, model, MAC, serial number, factory signature and public key.
- And finally, Device Initializer creates device's digital card request and stores it in the Transfer File.

Initialization of each device is performed one by one.

## Setting up Virgil Device Initializer
This section demonstrates on how to install and configure Virgil Device Initializer for preferred platform.

### Installing Virgil Device Initializer
This section provides instructions for installing Virgil Device Initializer.

#### Linux OS
Virgil Device Initializer is distributed as a package.

In order to download and install the Virgil Device Initializer on Linux, use the YUM package manager and the following command:

```bash
yum -y install virgil-iot-sdk-tools
```
## Command Reference
Here is the list of possible commands for Virgil Device Initializer.

### Syntax
The CLI has the following syntax.

```bash
virgil-device-initializer
--output "/root/current-credentials/card_requests_gateways.txt"
--device_info_output "/root/current-credentials/device_info.txt"
--auth_pub_key_1 "/root/current-credentials/key_storage/pubkeys/auth_15918_auth2.pub"
--auth_pub_key_2 "/root/current-credentials/key_storage/pubkeys/auth_54929_auth1.pub"
--rec_pub_key_1 "/root/current-credentials/key_storage/pubkeys/recovery_10514_recovery1.pub"
--rec_pub_key_2 "/root/current-credentials/key_storage/pubkeys/recovery_8644_recovery2.pub"
--tl_pub_key_1 "/root/current-credentials/key_storage/pubkeys/tl_service_23138_tl2.pub"
--tl_pub_key_2 "/root/current-credentials/key_storage/pubkeys/tl_service_41287_tl1.pub"
--fw_pub_key_1 "/root/current-credentials/key_storage/pubkeys/firmware_57637_firmware1.pub"
--fw_pub_key_2 "/root/current-credentials/key_storage/pubkeys/firmware_62881_firmware2.pub"
--trust_list "/root/current-credentials/key_storage/trust_lists/release/TrustList_16568.tl"
--factory_key "/root/current-credentials/key_storage/private/factory_24251_factory.key"
--factory_key_ec_type 3
```
Use  ```virgil-device-initializer -h```   to see the list of available arguments.

### Device Initialization
In order to Initialize IoT device, Virgil Device Initializer uses the following command:

| Command                                                                                   | Description                                                         |
|-------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| ```virgil-device-initializer [global options] command [command options] [arguments...]``` | CLI forms a Device card request and store it in ```transfer file``` |

The result of the command executing is the following:

- Generated IoT device card request for further registration via Device registrar.
- Generated IoT device key pair. Private key is stored in IoT device memory, public key is stored in device digital card.

**Example**

Here is an example of initializing of one device.

```bash
Run:virgil-device-initializer --output "/root/current-credentials/card_requests_gateways.txt" --device_info_output "/root/current-credentials/device_info.txt" --file_transfer_key "/root/current-credentials/factory-file-transfer/factory-sender-key/private.key" --file_transfer_key_pass "qweASD123" --file_recipient_key "/root/current-credentials/factory-file-transfer/registrar-key/public.key" --auth_pub_key_1 "/root/current-credentials/key_storage/pubkeys/auth_15918_auth2.pub" --auth_pub_key_2 "/root/current-credentials/key_storage/pubkeys/auth_54929_auth1.pub" --rec_pub_key_1 "/root/current-credentials/key_storage/pubkeys/recovery_10514_recovery1.pub" --rec_pub_key_2 "/root/current-credentials/key_storage/pubkeys/recovery_8644_recovery2.pub" --tl_pub_key_1 "/root/current-credentials/key_storage/pubkeys/tl_service_23138_tl2.pub" --tl_pub_key_2 "/root/current-credentials/key_storage/pubkeys/tl_service_41287_tl1.pub" --fw_pub_key_1 "/root/current-credentials/key_storage/pubkeys/firmware_57637_firmware1.pub" --fw_pub_key_2 "/root/current-credentials/key_storage/pubkeys/firmware_62881_firmware2.pub" --trust_list "/root/current-credentials/key_storage/trust_lists/release/TrustList_16568.tl" --factory_key "/root/current-credentials/key_storage/private/factory_24251_factory.key" --factory_key_ec_type 3
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
Device key EC type 3
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
OK: Trust List set successfully.
OK: Device initialization done successfully.
Device info: {"manufacturer":"0x5652474c000000000000000000000000","model":"0x43663031","roles":["GATEWAY"],"mac":"25:f4:69:0c:99:5a","serial":"JfRpDJlaAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=","publicKeyTiny":"BCMBfTZGL1wlVUv3EvN3dq25rjFAou/1q428ycEUswE3Rd8YM7JUfrXJd8g9bBKALMWxzGbmQOf5+d4kmftVi8w=","signature":"Nbzx4vmyH8CAkZ4PRB9+4y/uhuUm/O891UvR0ttpexMn65jvb86Ce7+i2u5GvZQR8NjyOGTQ0Qv94wYetFHW+A==","key_type":5,"ec_type":3}
Card request: eyJjb250ZW50X3NuYXBzaG90IjoiZXlKcFpHVnVkR2wwZVNJNklqSTFaalEyT1RCak9UazFZVEF6TURNd016QXpNRE13TXpBek1E
```
