# Virgil IoTKit C

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk.svg?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-iot-sdk)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-iot-sdk)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iot-sdk/release/LICENSE)


## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application and devices.

Virgil IoTKit is a C library for connecting IoT devices to Virgil IoT Security PaaS. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for secure provisioning and authenticating devices, secure updating firmware and trust chain, and for secure exchanging messages using any transport protocols.

## Content
- [Features](#features)
- [Run Demo](#run-demo)
- [IoT Dev Tools](#iot-dev-tools)
- [IoTKit Installation](#iotkit-installation)
  - [Requirements](#requirements)
  - [Installation](#installation)
- [Modules](#modules)
- [Tests](#tests)
- [SDK usage](#SDK-usage)
- [API Reference](#api-reference)
- [License](#license)
- [Support](#support)

<div id='features'/>

## Features
Virgil IoTKit provides a set of features for IoT device security and management:
- **Crypto Module. Connect any crypto library and Security Module**. Virgil IoTKit provides flexible and simple API for any types of crypto library and SECMODULE. At the same time, the framework provides default Software Security Module implementation based on Virgil Crypto. (Support for ATECC608A and ATECC508A in the next version).
- **Provision Module. Secure IoT device provision**. In order to securely update firmware, securely register, authenticate or exchange messages between IoT devices, each IoT device must have its own tools, which allow the device to perform cryptographic operations. These tools must contain the necessary information to identify the device or other participants (e.g., trust list provider). These tools are the device keys, trust chain, device card, etc. The process of providing your IoT devices with these tools is called device provision, and Virgil IoTKit gives you all the necessary functionality to make your IoT devices identifiable and verifiable, as a result, protect them from counterfeit and fabrication.
- **Firmware Module. Secure firmware and trust chain verification and distribution**. IoTKit provides a set of API for secure verification of firmware in a bootloader. Also, IoTKit provides an example of bootloader implementation in the form of emulator.
- **Secbox Module. Secure software storage for any sensitive data**. IoTKit provides secure software storage that is called **Secbox** for storing any sensitive data, like private keys. The Secbox works in two modes; the first mode - when data is only signed, and the second one - when data is encrypted and then signed.
- **Protocols Module**. IoTKit provides a flexible, programmable and security network adaptive protocol (SNAP) for device-to-device, device-to-cloud, and cloud-to-device communication. SNAP can be used for secure firmware distribution, secure notification about device state, secure device provision. Also, SNAP contains a set of functions and interfaces that allows you to work with any transport protocol (BLE, Wi-Fi, PLC, NoiseSocket, etc.).  
- **Cloud Module. API for working with Virgil IoT Security PaaS**. IoTKit interacts with the Virgil IoT Security Platform as a Service (PaaS) to provide you with the services for security, management, and monitoring IoT devices.
- **Logger Module**. IoTKit contains a set of functions and interfaces for logging device events.

<div id='run-demo'/>

## Requirements

The product has been tested on Linux platforms (Ubuntu, Fedora, CentOS) and macOS.
- Install make, CMake version 3.11 or higher for project building 
- Install gcc or another toolchain for C/C++ compile
- Install [Go](https://golang.org/) for utilities support
- Install [git](https://git-scm.com/) for Virgil Crypto installation and update
- Install [curl](https://curl.haxx.se/) for gateway target

// TODO : TO REMOVE
~~- Install [doxygen](http://www.doxygen.nl/), [swig](http://www.swig.org/) for Virgil Crypto support~~

<div id='iotkit-installation'/>

## Installation

- Install the required components.

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
cmake version 3.11.0
```

- Install Virgil Crypto library :

```
$ scripts/install-virgil-crypto.sh
```

<div id='iot-dev-tools'/>

## IoT Dev Tools
- KeyManager
- Factory Initializer
- IoT Device Registrar
- Firmware Signer

<div id='modules'/>

## Modules
- [Cloud](https://virgilsecurity.github.io/virgil-iot-sdk/cloud_8h.html) : Cloud library for obtaining credentials from
thing service and downloading firmware images and trust list files from cloud storage.
- Crypto : cryptographic operations callbacks for [Hardware Security Modules supports](https://virgilsecurity.github.io/virgil-iot-sdk/cloud_8h.html) and [cryptographic converters](https://virgilsecurity.github.io/virgil-iot-sdk/crypto__format__converters_8h.html).
- [Firmware](https://virgilsecurity.github.io/virgil-iot-sdk/firmware_8h.html) : Firmware download/upload by Gateway and Firmware download/processing by Thing.
- [Logger](https://virgilsecurity.github.io/virgil-iot-sdk/logger_8h.html) : tool to output logging messages to screen, file etc. See [HAL functions declarations](https://virgilsecurity.github.io/virgil-iot-sdk/logger-hal_8h.html) for its implementation.
- [Provision](https://virgilsecurity.github.io/virgil-iot-sdk/provision_8h.html) : Trust List keys reading and verifying.
- Secbox.
- Protocols.

<div id='tests'/>

## Tests
- Crypto : Crypto algorithms and primitives tests (aes, hash ecdh, hmac, kdf, etc.)
- Firmware : Firmware related functionality. Create device/firmware. Save firmware
- Helpers : Create and save trust list
- Secbox : Test storage module. Read write signed or/and encrypted data
- SNAP : Secure Network Adjustable Protocol test

<div id='SDK-usage'/>

## SDK usage
After Virgil IoT SDK installation or building it is necessary to do some steps for its successful usage listed below :

- specify configuration headers path.
- provide user implementations. You can select default implementations for some of them.

### Configuration headers
There are configuration headers that customize Virigl IoT SDK. You can provide yours or use
standard ones. They are stored in config directory.

It is necessary to add VIRGIL_IOT_CONFIG_DIRECTORY variable that points to directory with configuration files.

For example, if you want to use PC configuration provided by library and library is stored in `virgil-iot-sdk` directory,
you have to set compiler option:

`-DVIRGIL_IOT_CONFIG_DIRECTORY virgil-iot-sdk/config/pc`.

Or you can initialize CMake variable :

`set(VIRGIL_IOT_CONFIG_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/virgil-iot-sdk/config/pc CACHE STRING "Path to the Virgil IoT SDK configuration")`

### Obligatory user implementations 
Some modules use external implementations. It is necessary to implement HAL functions by user :

- [Storage context](https://virgilsecurity.github.io/virgil-iot-sdk/storage__hal_8h.html) : structure **vs_storage_op_ctx_t**
contains external data operations like open/read/write/close (see [Storage HAL Usage](https://virgilsecurity.github.io/virgil-iot-sdk/storage__hal_8h.html#storage_hal)
for details). In case of OS with files standard file I/O calls like fopen/fread/fwrite/fclose can be used. See [Storeage HAL Usage](https://virgilsecurity.github.io/virgil-iot-sdk/storage__hal_8h.html)
for details.

- [Firmware](https://virgilsecurity.github.io/virgil-iot-sdk/firmware_8h.html) : **vs_firmware_install_prepare_space_hal**,
**vs_firmware_install_append_data_hal** and **vs_firmware_get_own_firmware_footer_hal** functions need to be implemented for firmware processing. If filesystem
is present, those functions implement read/write operations with firmware file. See [Firmware HAL signatures](https://virgilsecurity.github.io/virgil-iot-sdk/firmware__hal_8h.html)
for details.

- [Logger](https://virgilsecurity.github.io/virgil-iot-sdk/logger_8h.html) : depending on [logger-config.h](https://virgilsecurity.github.io/virgil-iot-sdk/logger-config_8h.html)
configurations **vs_logger_output_hal** for string output and/or **vs_logger_current_time_hal** for current time output would be
necessary to be implemented. See [Logger HAL Implementation](https://virgilsecurity.github.io/virgil-iot-sdk/logger-hal_8h.html) for details.

- [SNAP protocol](https://virgilsecurity.github.io/virgil-iot-sdk/snap_8h.html) : **vs_netif_t** network interface as
transport level for SNAP protocol has to be implemented. As UDP broadcast example user can use c-implementation tool.
See [SNAP Structures](https://virgilsecurity.github.io/virgil-iot-sdk/snap-structs_8h.html) for details.

- [FLDT Client service](https://virgilsecurity.github.io/virgil-iot-sdk/fldt-client_8h.html), for Client only : **vs_fldt_got_file**
function has to be implemented by user. This is FLDT Client notification about new file retrieval and installation. In case of successful
installation application must be restarted. See [documentation](https://virgilsecurity.github.io/virgil-iot-sdk/fldt-client_8h.html)
for details.

- [FLDT Server service](https://virgilsecurity.github.io/virgil-iot-sdk/fldt-server_8h.html), for Server only : **vs_fldt_server_add_filetype_cb**
function has to be implemented by user. This is FLDT Server notification about new file request by Client. It is necessary to
return update context for new file. See [documentation](https://virgilsecurity.github.io/virgil-iot-sdk/fldt-server_8h.html)
for details.

- [PRVS Client service](https://virgilsecurity.github.io/virgil-iot-sdk/prvs-client_8h.html), for Client only : **vs_snap_prvs_client_impl_t**
structure has to be implemented by user. This is wait functions used for SNAP interface. You can see example of implementation
is c-implementation tool. See [documentation](https://virgilsecurity.github.io/virgil-iot-sdk/prvs-client_8h.html) for details.

### Obligatory user implementations with default ones 
There are other modules that need user implementation, but Virgil IoT SDK provides default implementations for them :

- [Cloud](https://virgilsecurity.github.io/virgil-iot-sdk/cloud_8h.html) : **vs_cloud_impl_t** and **vs_cloud_message_bin_impl_t**
are required by vs_cloud_init call. Function vs_curl_http_impl returns cURL HTTP implementation, vs_cloud_message_bin_impl_t
returns MQTT implementation.

- [Crypto](https://virgilsecurity.github.io/virgil-iot-sdk/secmodule_8h.html) introduces security module implementation structure
**vs_secmodule_impl_t** that is used by many functions. Function vs_soft_secmodule_impl returns software implementation.

<div id='api-reference'/>

## API Reference
- [API Reference of IoTKit](http://VirgilSecurity.github.io/virgil-iot-sdk)

<div id='license'/>

## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
