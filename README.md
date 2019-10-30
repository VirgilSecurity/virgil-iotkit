# Virgil IoTKit C

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-iot-sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iot-sdk/release/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [SDK Modules](#sdk-modules) | [Installation](#installation) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application and devices. 

Virgil IoTKit is a framework that connects IoT devices to Virgil IoT Security PaaS to integrate fully security for your IoT solution. IoTKit helps you easily and quickly add security to your IoT devices at any lifecycle stage and securely authenticate, exchange messages, and update the firmware or trust list chain while using devices.


## IoTKit Features
- **Crypto Module. API for connecting any crypto library and hard secure module (HSM)**. Virgil IoTKit provides flexible and simple API for any provides of crypto library and HSM. At the same time, the framework provides default software HSM implementation based on Virgil Crypto. (Support for ATECC608A and ATECC508A in the next version).
- **Provision Module. API for secure IoT device provision**. In order to securely update firmware, securely register, authenticate or exchange messages between IoT devices, each IoT device must have its own tools, which allow the device to perform cryptographic operations, and these tools must contain the necessary information to identify the device or other participants (e.g. trust list provider). These tools are the device keys, trust list chain, device card, etc. The process of providing your IoT devices with these tools is called device provision, and Virgil IoTKit gives you all the necessary functionality to make your IoT devices identifiable and verifiable, as a result, protect them from counterfeit and fabrication.
- **Firmware Module. API for secure firmware and trust chain verification**. IoTKit provides set of API for secure verification of firmware in a bootloader. Also, IoTKit provides an example of bootloader implementation in the form of emulator.
- **Secbox Module. Secure software storage for any sensetive data**. IoTKit provides secure software storage that is called **Secbox** for storing any sensetive data, like private keys. The Secbox works in the two modes; the first mode - when data is only signed and the second one - when data is encrypted and then signed.
- **Protocols Module** IoTKit provides a flexible, programmable and simple device management protocol (SDMP) for device-to-device, device-to-cloud, and cloud-to-device communication. SDMP can be used for secure firmware distribution, secure notification about device state, secure device provision. Also, SDMP contains a set of functions and interfaces that allows you to work with any transport protocol (BLE, Wi-Fi, PLC, NoiseSocket, etc.).  
- **Works with Virgil IoT Security PaaS**. IoTKit interactes with the Virgil IoT Security Platform as a Service (PaaS) to provide you with the services for security, management, and monitoring IoT devices.



which allow him to perform cryptographic operations, and these tools must contain the necessary information to identify users. In Virgil Security, these tools are the Virgil Key and the Virgil Card.

- Provides secure storage for key data
- Works with any hardware modules and HSM
- IoT Device Provision
- IoT Device Enrollment
- Possibility to change Network Security Protocols

- Works with Virgil IoT Security PaaS
- Provides strong authentication for devices


- Secure Messaging: cloud-to-device, device-to-device
- Works with any Message Brokers
- Secure Firmware Updating
- Secure Trust List Updating
- Provides Logger Manager
- Contains sets of tests for IoT projects


## SDK Modules
Virgil IoT SDK is divided into the following modules:
	
- **Cloud**. Contains...
- **Crypto**. Contains....	
- **Firmware**. Contains...
- **Logger**. Contains..
- **Protocols**. Contains...
- **Provision**. Contains...
- **Secbox**. Contains..

## Installation

Linux
Mac OS 


### Requirements

- Install `clang-format`
- Setup git hooks for automatic code formatting

```
cd <virgil-iot-sdk>
git config core.hooksPath git-hooks
```

### Docs
- [API Reference of IoTKit](http://VirgilSecurity.github.io/virgil-iot-sdk)


## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
