# Virgil IoTKit C

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-iot-sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iot-sdk/release/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [SDK Modules](#sdk-modules) | [Installation](#installation) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application and devices.

Virgil IoTKit is a C library for connecting IoT devices to Virgil IoT Security PaaS. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for secure provisioning and authenticating devices, secure updating firmware and trust chain, and for secure exchanging messages using any transport protocols.

## Features
Virgil IoTKit provides set of features for IoT device security and management:
- **Crypto Module. Connect any crypto library and hard secure module (HSM)**. Virgil IoTKit provides flexible and simple API for any provides of crypto library and HSM. At the same time, the framework provides default software HSM implementation based on Virgil Crypto. (Support for ATECC608A and ATECC508A in the next version).
- **Provision Module. Secure IoT device provision**. In order to securely update firmware, securely register, authenticate or exchange messages between IoT devices, each IoT device must have its own tools, which allow the device to perform cryptographic operations, and these tools must contain the necessary information to identify the device or other participants (e.g. trust list provider). These tools are the device keys, trust chain, device card, etc. The process of providing your IoT devices with these tools is called device provision, and Virgil IoTKit gives you all the necessary functionality to make your IoT devices identifiable and verifiable, as a result, protect them from counterfeit and fabrication.
- **Firmware Module. Secure firmware and trust chain verification and distribution**. IoTKit provides set of API for secure verification of firmware in a bootloader. Also, IoTKit provides an example of bootloader implementation in the form of emulator.
- **Secbox Module. Secure software storage for any sensetive data**. IoTKit provides secure software storage that is called **Secbox** for storing any sensetive data, like private keys. The Secbox works in the two modes; the first mode - when data is only signed and the second one - when data is encrypted and then signed.
- **Protocols Module**. IoTKit provides a flexible, programmable and simple device management protocol (SDMP) for device-to-device, device-to-cloud, and cloud-to-device communication. SDMP can be used for secure firmware distribution, secure notification about device state, secure device provision. Also, SDMP contains a set of functions and interfaces that allows you to work with any transport protocol (BLE, Wi-Fi, PLC, NoiseSocket, etc.).  
- **Cloud Module. API for working with Virgil IoT Security PaaS**. IoTKit interactes with the Virgil IoT Security Platform as a Service (PaaS) to provide you with the services for security, management, and monitoring IoT devices.
- **Logger Module**. IoTKit contains a set of functions and interfaces for logging device events.

## Requirements

Product has been tested on Linux platforms (Ubuntu, Fedora, CentOS) and MacOS.
- Install make, CMake version 3.11 or higher for project building 
- Install gcc or another toolchain for C/C++ compile
- Install [Go](https://golang.org/) for utilities support
- Install [git](https://git-scm.com/) for Virgil Crypto installation and update
- Install [curl](https://curl.haxx.se/) for gateway target

// TODO : TO REMOVE
~~- Install [doxygen](http://www.doxygen.nl/), [swig](http://www.swig.org/) for Virgil Crypto support~~

## Installation

- Install required components.

For Ubuntu : 
```
apt install make gcc cmake golang git libcurl4-openssl-dev doxygen swig
```

For Fedora, CentOS :
```
yum install make cmake golang git gcc gcc-c++ libcurl-devel doxygen swig
```

For Mac OS :
```
brew install make cmake golang git gcc curl doxygen swig
```

- Check CMake version. It must be 3.11 or higher :

```
$ cmake --version
cmake version 3.14.5
```

- Clone repository :

```
git clone --recurse-submodules -b develop git@github.com:VirgilSecurity/virgil-iot-sdk.git
```

- Install Virgil Crypto library :

```
virgil-iot-sdk/scripts/install-virgil-crypto.sh
```

- Initialize CMake :

```
mkdir -p build
cd build
cmake ..
```

## Docs
- [API Reference of IoTKit](http://VirgilSecurity.github.io/virgil-iot-sdk)


## License

This library is released under the [3-clause BSD License](LICENSE).

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
