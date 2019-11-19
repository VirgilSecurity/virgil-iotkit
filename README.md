# Virgil IoTKit C

[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-iotkit)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iotkit/release/LICENSE)


## Introduction

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a>[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application and devices.

Virgil IoTKit is a C library for connecting IoT devices to Virgil IoT Security PaaS. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for secure provisioning and authenticating devices, secure updating firmware and trust chain, and for secure exchanging messages using any transport protocols.

## Content
- [Features](#features)
- [IoT Dev Tools](#iot-dev-tools)
- [Run IoTKit Demo](#run-iotkit-demo)
- [IoTKit Modules](#modules)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Ubuntu, Debian OS](#ubuntu-debian-os)
  - [CentOS, Fedora OS](#centos-fedora-os)
  - [MacOS](#macos)
  - [Windows OS](#windows-os)
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

<div id='iot-dev-tools'/>

## IoT Dev Tools
Virgil Security also provides set of tools for secure device lifecycle.
- **Virgil Trust Provisioner**. The Virgil Trust Provisioner is a CLI used to manage your distributed trust between all parties, including IoT devices, in your IoT solutions. The CLI is aimed at key pairs and TrustLists generation and management, which together make each IoT device identifiable, verifiable and trusted by each party of IoT solution. To start working with the tool read more [here](/tools/virgil-trust-provisioner).
- **Virgil Device Initializer**. In order to make each IoT device identifiable, verifiable and trusted by each party of IoT solution you have to provide it with specific provision files, generate private keys and create the digital cards for further device registration in Cloud. Virgil Device Initializer allows you to make IoT device provisioning and prepare your IoT device (create digital cards) for its further registration in Virgil Cloud. To start working with the tool read more [here](/tools/virgil-device-initializer).
- **Virgil Device Registrar**. Virgil IoT Device Registrar is used to registrar IoT devices and their digital cards in the Virgil Security Cloud. To start working with the tool read more [here](/tools/virgil-device-registrar).
- **Virgil Firmware Signer**. Virgil Firmware Signer is a CLI that allows you to sign a firmware using Auth and Firmware Private Keys to provide firmware integrity before distributing it. To start working with the tool read more [here](/tools/virgil-firmware-signer).
- **Virgil SnapD**. Virgil SnapD is a local web utility which allows you to obtain information and statistics of your IoT devices. In order to get such device information SnapD interacts with Virgil SNAP protocol, which operates directly with your IoT devices. As far as Virgil SnapD is a local service, the obtained information can be displayed in browser under http://localhost:8080/ (by default). In case you work with Virgil IoT Simulator, you can run SnapD under http://localhost:8081/. To start working with the tool read more [here](/tools/virgil-snapd).

<div id='run-iotkit-demo'/>

## Run IoTKit Demo
To demonstrate our IoTKit in action we developed [Demo for UNIX-like OS based on IoTKit toolkits](https://github.com/VirgilSecurity/demo-iotkit-nix).

The IoTKit Demo is conditionally divided into 3 actors (Vendor, Factory and End-user) and shows secure lifecycle of IoT devices. The IoTKit Demo allows you to:
- **Generate trusted provisioning package**. To start working with emulated IoT infrastructure the Demo uses Virgil Trust Provisioner utility for generating provisioning files, such as private keys (e.g. for factory, firmware) and a distributed trust list that contains public keys and signatures of trusted services providers (e.g. factory, cloud).
- **Emulate IoT devices**. Then, you can emulate two IoT device types: IoT Gateway - an internet-capable smart device that communicates with other IoT devices and Clouds; and IoT Device - end-device, like smart bulb, that can be controlled remotely through the IoT Gateway.
- **Securely perform IoT device provisioning**. Demo uses the Virgil Device Initializer for IoT devices provisioning to make them identifiable, verifiable and trusted. Securely integrate trust list and crypto library on IoT devices, then generate key pairs and create digital cards, and sign digital cards with the Factory Key.
- **Register IoT devices on the security platform**. At this step the Virgil Device Registrar is used to register digital cards of IoT devices at Virgil Cloud for further device authentication and management.
- **Sign and publish new Firmware and TrustList**. Also, you can emulate process of creating and publishing new Firmware or TrustList to Virgil Cloud. Demo uses Virgil Firmware Signer to sign a firmware before its distributing.
- **Manage IoT devices**. Demo allows to manage IoT devices and get information about their state. Demo uses Virgil services to notify IoT devices about new updates and then securely verify incoming firmware or trust lists before updating them.

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/virgil_demo_iotkit_nix.png" align="left" hspace="0" vspace="6"> &nbsp;

To start working with the Demo head over to [Demo IoTKit Nix GitHub](https://github.com/VirgilSecurity/demo-iotkit-nix) repository and follow the instructions in the README.

<div id='iotkit-modules'/>

## IoTKit Modules
As we mentioned above, Virgil IoTKit provides a set of features that implemented to modules:
- **Crypto Module** is used for cryptographic operations with callbacks for [Hardware Security Modules supports](https://virgilsecurity.github.io/virgil-iotkit/cloud_8h.html) and [cryptographic converters](https://virgilsecurity.github.io/virgil-iotkit/crypto__format__converters_8h.html).
- **[Cloud Module](https://virgilsecurity.github.io/virgil-iotkit/cloud_8h.html)** is used for for obtaining credentials from Virgil Thing service and downloading firmware images and trustlist files from cloud storage.
- **[Firmware Module](https://virgilsecurity.github.io/virgil-iotkit/firmware_8h.html)** is used for firmware downloading, uploading and processing by IoT Gateway or by Thing (IoT Device).
- **[Logger](https://virgilsecurity.github.io/virgil-iotkit/logger_8h.html)** is a tool is used to output logging messages to screen, file etc.
- **[Provision](https://virgilsecurity.github.io/virgil-iotkit/provision_8h.html)**. Trust List keys reading and verifying.
- **[Secbox](https://virgilsecurity.github.io/virgil-iotkit/secbox_8h.html)** is a secure data storage wth signing and authenticating abilities.
- **Protocols Module** provides the set of services for [SNAP](https://virgilsecurity.github.io/virgil-iotkit/snap_8h.html) protocol:
  - INFO : service for collecting statistics from devices. See [INFO Server](https://virgilsecurity.github.io/virgil-iotkit/info-server_8h.html) and [INFO Client](https://virgilsecurity.github.io/virgil-iotkit/info-client_8h.html)
  - FLDT : service for files download from Gateway to Thing. See [FLDT Server](https://virgilsecurity.github.io/virgil-iotkit/fldt-server_8h.html) and [FLDT Client](https://virgilsecurity.github.io/virgil-iotkit/fldt-client_8h.html)
  - PRVS : service for make provision for device by factory initializer. See [PRVS Server](https://virgilsecurity.github.io/virgil-iotkit/prvs-server_8h.html) and [PRVS Client](https://virgilsecurity.github.io/virgil-iotkit/prvs-client_8h.html)
<div id='installation'/>

## Installation
Virgil IoTKit is distributed as a package. This section demonstrates on how to install Virgil IoTKit for preferred platform.

### Prerequisites
To start working with Virgil IoTKit the following components are required:
- CMake v3.11 or higher, for project building
- GCC or another toolchain for C/C++ compile
- [Golang](https://golang.org/) to compile Virgil IoT dev tools
- [git](https://git-scm.com/) for Virgil Crypto installation and update
- [curl](https://curl.haxx.se/)


### Ubuntu, Debian OS
To download and install the Virgil IoTKit on Ubuntu, use the following command:

```shell
$ apt install make gcc cmake golang git libcurl4-openssl-dev doxygen swig
```

### Fedora, CentOS
To download and install the Virgil IoTKit on Fedora or CentOS, use the following command:

```shell
$ yum install make cmake golang git gcc gcc-c++ libcurl-devel doxygen swig
```

### MacOS
To download and install the Virgil IoTKit on MacOS, use the following command:
```shell
$ brew install make cmake golang git gcc curl doxygen swig
```

### Windows OS
Virgil IoTKit for Windows OS is currently in development. To be included to information update list please contact our support team: support@VirgilSecurity.com.

- Check CMake version. It must be 3.11 or higher:

```shell
$ cmake --version
cmake version 3.11.0
```

- Install Virgil Crypto library :

```
$ scripts/install-virgil-crypto.sh
```


<div id='tests'/>

## Tests
To make sure that everything goes in the right way, we also provide a set of ready code-snippets for testing the necessary features. Pursue the [tests folder](/tests) of this repository to find preferred tests.
- Crypto : Crypto algorithms and primitives tests. (AES, Hash, ECDH, ECDSA, HMAC, KDF, ChaCha20-Poly1305, etc.)
- Firmware : Firmware related functionality. Create device/firmware. Save firmware.
- Helpers : Create and save trust list.
- Secbox : Test storage module. Read write signed or/and encrypted data.
- SNAP : Secure Network Adjustable Protocol tests.

<div id='SDK-usage'/>

## SDK usage
After Virgil IoT SDK installation or building it is necessary to do some steps for its successful usage listed below :

- specify configuration headers path.
- provide user implementations. You can select default implementations for some of them.

### Configuration headers
There are configuration headers that customize Virigl IoT SDK. You can provide yours or use
standard ones. They are stored in config directory.

It is necessary to add VIRGIL_IOT_CONFIG_DIRECTORY variable that points to directory with configuration files.

For example, if you want to use PC configuration provided by library and library is stored in `virgil-iotkit` directory,
you have to set compiler option:

`-DVIRGIL_IOT_CONFIG_DIRECTORY virgil-iotkit/config/pc`.

### Mandatory implementations
Some modules use external implementations. It is necessary to implement HAL functions by user :

- [Storage context](https://virgilsecurity.github.io/virgil-iotkit/storage__hal_8h.html) : structure **vs_storage_op_ctx_t**
contains external data operations like open/read/write/close (see [Storage HAL Usage](https://virgilsecurity.github.io/virgil-iotkit/storage__hal_8h.html#storage_hal)
for details). In case of OS with files standard file I/O calls like fopen/fread/fwrite/fclose can be used. See [Storeage HAL Usage](https://virgilsecurity.github.io/virgil-iotkit/storage__hal_8h.html)
for details.
- [Firmware](https://virgilsecurity.github.io/virgil-iotkit/firmware_8h.html) : **vs_firmware_install_prepare_space_hal**,
**vs_firmware_install_append_data_hal** and **vs_firmware_get_own_firmware_footer_hal** functions need to be implemented for firmware processing. If filesystem is present, those functions implement read/write operations with firmware file. See [Firmware HAL signatures](https://virgilsecurity.github.io/virgil-iotkit/firmware__hal_8h.html)
for details.
- [Logger](https://virgilsecurity.github.io/virgil-iotkit/logger_8h.html) : depending on [logger-config.h](https://virgilsecurity.github.io/virgil-iotkit/logger-config_8h.html)
configurations **vs_logger_output_hal** for string output and/or **vs_logger_current_time_hal** for current time output would be
necessary to be implemented. See [Logger HAL Implementation](https://virgilsecurity.github.io/virgil-iotkit/logger-hal_8h.html) for details.
- [SNAP protocol](https://virgilsecurity.github.io/virgil-iotkit/snap_8h.html) : **vs_netif_t** network interface as
transport level for SNAP protocol has to be implemented. As UDP broadcast example user can use c-implementation tool.
See [SNAP Structures](https://virgilsecurity.github.io/virgil-iotkit/snap-structs_8h.html) for details.
- [FLDT Client service](https://virgilsecurity.github.io/virgil-iotkit/fldt-client_8h.html), for Client only : **vs_fldt_got_file**
function has to be implemented by user. This is FLDT Client notification about new file retrieval and installation. In case of successful
installation application must be restarted. See [documentation](https://virgilsecurity.github.io/virgil-iotkit/fldt-client_8h.html)
for details.
- [FLDT Server service](https://virgilsecurity.github.io/virgil-iotkit/fldt-server_8h.html), for Server only : **vs_fldt_server_add_filetype_cb**
function has to be implemented by user. This is FLDT Server notification about new file request by Client. It is necessary to
return update context for new file. See [documentation](https://virgilsecurity.github.io/virgil-iotkit/fldt-server_8h.html)
for details.
- [PRVS Client service](https://virgilsecurity.github.io/virgil-iotkit/prvs-client_8h.html), for Client only : **vs_snap_prvs_client_impl_t**
structure has to be implemented by user. This is wait functions used for SNAP interface. You can see example of implementation
is c-implementation tool. See [documentation](https://virgilsecurity.github.io/virgil-iotkit/prvs-client_8h.html) for details.

### Mandatory implementations with default ones
There are other modules that need user implementation, but Virgil IoT SDK provides default implementations for them :
- [Cloud](https://virgilsecurity.github.io/virgil-iotkit/cloud_8h.html) : **vs_cloud_impl_t** and **vs_cloud_message_bin_impl_t**
are required by vs_cloud_init call. Function vs_curl_http_impl returns cURL HTTP implementation, vs_cloud_message_bin_impl_t
returns MQTT implementation.
- [Crypto](https://virgilsecurity.github.io/virgil-iotkit/secmodule_8h.html) introduces security module implementation structure
**vs_secmodule_impl_t** that is used by many functions. Function vs_soft_secmodule_impl returns software implementation.

<div id='api-reference'/>

## API Reference
- [API Reference of IoTKit](http://VirgilSecurity.github.io/virgil-iotkit)

<div id='license'/>

## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
