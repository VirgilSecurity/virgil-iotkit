# Virgil Device Registrar

<img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) The Virgil IoT Device Registrar is a CLI utility used to registrar IoT devices and their digital cards in the Virgil Security Cloud.

## Content
- [Overview](#overview)
- [Set Up Device Registrar](#set-up-device-registrar)
- [Command Reference](#command-reference)


## Overview
In order to make your IoT device identifiable, verifiable and manageable, you have to assign the IoT device (its identification information) to the Cloud and as a result, get its cloud credentials, and the Virgil Device Registrar helps you to do this in the one request.

### How it works
- After IoT device goes through the provisioning process at manufacturing stage at Factory, it gets signed digital card request (SCR)
- All SCRs are collected in a file and encrypted with public key of the Virgil Device Registrar
- The encrypted file is transferred to the Virgil Device Registrar
- Virgil IoT Device Registrar uses own private key which is called File Transfer Key and decrypts the encrypted file.
- Virgil IoT Device Registrar gets the SCR of the IoT device with its identification information and registries it in the Virgil Cloud
- All requests to Virgil Cloud have to be authenticated, therefore Virgil IoT Device Registrar uses Application Token during the device registration. An Application Token is generated in Virgil Cloud and provided by you
- If the request is successful, the IoT identification information is registered at the Virgil Thing Service and the SCR is registered at Virgil Cards Service

Now, IoT device is ready for application development.

```bash
virgil-device-registrar [global options] command [command options] [arguments...]
```


....


## Overview
....

## Set Up Device Registrar

## Command Reference

....
