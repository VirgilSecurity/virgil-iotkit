# Virgil IoT C SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-iot-sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iot-sdk/release/LICENSE)

[Introduction](#introduction) | [SDK Features](#sdk-features) | [SDK Modules](#sdk-modules) | [Installation](#installation) | [Docs](#docs) | [Support](#support)

## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application and devices. In a few simple steps you can encrypt communication, securely store data, and ensure data integrity.

IoT SDK connects IoT devices to Virgil IoT Security PaaS. The IoT Device SDK helps you easily and quickly add end-to-end encryption to your IoT devices at any lifecycle and enables devices securely to connect, authenticate, update firmware or trust chain, and exchange messages using the MQTT, HTTP, or WebSockets protocols.

## SDK Features
- Includes Crypto Library
- Provides Secure Boot Manager
- Provides secure storage for key data
- Works with any hardware modules and HSM
- IoT Device Provision
- Works with Virgil IoT Security PaaS
- Provides strong authentication for devices
- IoT Device Enrollment
- Possibility to change Network Security Protocols
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

### Requirements

- Install `clang-format`
- Setup git hooks for automatic code formatting

```
cd <virgil-iot-sdk>
git config core.hooksPath git-hooks
```

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
