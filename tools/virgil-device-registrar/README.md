# Virgil Device Registrar
The Virgil IoT Device Registrar is a CLI utility used to registrar IoT devices and their digital cards in the Virgil Security Cloud.

## Content
- [Overview](#overview)
- [Setting Up Device Registrar](#set-up-device-registrar)
- [Command Reference](#command-reference)


## Overview
In order to make your IoT device identifiable, verifiable and manageable, you have to assign the IoT device (its identification information) to the Cloud and as a result, get its cloud credentials, and the Virgil Device Registrar helps you to do this in the one request.

### How it works
- After IoT device goes through the provisioning process at manufacturing stage at Factory, it gets signed digital card request (SCR).
- All SCRs are collected in a file and encrypted with public key of the Virgil Device Registrar.
- The encrypted file is transferred to the Virgil Device Registrar.
- Virgil IoT Device Registrar uses own private key which is called File Transfer Key and decrypts the encrypted file.
- Virgil IoT Device Registrar gets the SCR of the IoT device with its identification information and registries it in the Virgil Cloud.
- All requests to Virgil Cloud have to be authenticated, therefore Virgil IoT Device Registrar uses Application Token during the device registration. An Application Token is generated in Virgil Cloud and provided by you.
- If the request is successful, the IoT identification information is registered at the Virgil Thing Service and the SCR is registered at Virgil Cards Service.

Now, IoT device is ready for application development.



## Setting Up Device Registrar
This section demonstrates on how to install and configure Virgil IoT Device Registrar for preferred platform.

### Install Device Registrar
This section provides instructions for installing Virgil IoT Device Registrar.

#### Linux OS
Virgil Device Registrar is distributed as a package.
In order to download and install the Virgil Device Registrar on Linux, use the YUM package manager and the following command:

```bash
yum -y install virgil-iot-sdk-tools
```

## Command Reference
Here is the list of possible commands for Virgil IoT Device Regis

### Syntax
The CLI has the following syntax:

```bash
virgil-device-registrar [global options] command [command options] [arguments...]
```
Use ```virgil-device-registrar -h``` to see the list of available arguments.

### Registering Device
In order to registrar IoT device, Virgil Device Registrar uses the following command:

| Command                                                                           | Description               |
|-----------------------------------------------------------------------------------|---------------------------|
| ```virgil-device-registrar [global options] command [command options] [arguments...]``` | IoT device is registrated |

``` bash
virgil-device-registrar --data "/root/current-credentials/card_requests_gateways.txt" --file_key "/root/current-credentials/factory-file-transfer/registrar-key/private.key" --file_key_pass qweASD123 --file_sender_key "/root/current-credentials/factory-file-transfer/factory-sender-key/public.key" --app_token "AT.K6E4PEeOdLfacsq0I9C1I34CSgitDKRB" --registration_url https://api-iot.virgilsecurity.com/things/card
```
| Option                             | Description                                                                                                                                                                                                                                               |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --data value, -d value             | Encrypted File with signed digital card requests (SCR)                                                                                                                                                                                                    |
| --file_key value, -k value         | File with a private transfer key to decrypt the encrypted file. If this is your first time using Virgil Device Registrar, you need to generate a pair of transfer key using the Virgil CLI and share the Public Key for Virgil Device Initializer utility |
| --file_key_pass value, -p value    | Transfer Private Key password                                                                                                                                                                                                                             |
| --file_sender_key value, -s value  | Public Key of sender of the file. Public Key of the Virgil Device Initializer CLI                                                                                                                                                                         |
| --app_token value, -t value        | Virgil application token. The Token is generated by you in Virgil Cloud                                                                                                                                                                                   |
| --registration_url value, -b value | URL of Virgil IoT services                                                                                                                                                                                                                                |
| --help, -h                         | Show help (default: false)                                                                                                                                                                                                                                |
| --version, -v                      | Print the version (default: false)                                                                                                                                                                                                                        |
