# Virgil IoTKit
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](https://virgilsecurity.github.io/virgil-iotkit/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iotkit/release/LICENSE)



<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/iotkit/IoTKit.png" align="left" hspace="1" vspace="3"></a>

## Introduction
[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application or IoT device.

Virgil IoTKit is a C library for connecting IoT devices to the Virgil IoT Security Platform. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for securely provisioning and authenticating devices, updating firmware and TrustLists, and exchanging messages using any transport protocols.

## Content
- [Features](#features)
- [IoT Dev Tools](#iot-dev-tools)
- [Run IoTKit Sandbox](#run-iotkit-sandbox)
- [IoTKit Modules](#modules)
- [Scripts](#scripts)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Ubuntu, Debian, Raspbian OS](#ubuntu-debian-raspbian-os)
  - [Fedora OS](#fedora-os)
  - [MacOS](#macos)
  - [Windows OS](#windows-os)
  - [Ready Linux packets](#ready-linux-packets)
  - [Qt integration](#qt-integration)
- [Tests](#tests)
- [IoTKit Usage](#iotkit-usage)
  - [Configuration parameters](#config-params)
  - [Mandatory implementations](#mandatory-implementations)
  - [Default mandatory implementations](#default-mandatory-implementations)
- [API Reference](#api-reference)
- [License](#license)
- [Support](#support)

<div id='features'/>

## Features
Virgil IoTKit provides a set of features for IoT device security and management:
- **Crypto Module. Connect any crypto library and Security Module**. Virgil IoTKit provides a flexible and simple API for any types of crypto library and SECMODULE. The framework also provides default Software Security Module implementation based on the Virgil Crypto Library. (Support for ATECC608A and ATECC508A in the next version).
- **Provision Module. Secure IoT device provision**. In order to securely update firmware and securely register, authenticate or exchange messages between IoT devices, each IoT device must have its own tools that allow the device to perform cryptographic operations. These tools must contain information needed to identify the device or other participants (e.g. the TrustList provider). These tools are the device keys, TrustLists, device card, etc. The process of providing your IoT devices with these tools is called device provisioning, and Virgil IoTKit gives you all the functionality needed to make your IoT devices identifiable and verifiable, as a result, protected from counterfeiting and fabrication.
- **Firmware Module. Secure firmware and TrustList verification and distribution**. IoTKit provides a set of APIs for secure verification of firmware in a bootloader. Also, IoTKit provides an example of bootloader implementation in the form of emulator.
- **Secbox Module. Secure storage software for any sensitive data**. IoTKit provides secure storage software that is called **Secbox** for storing any sensitive data, like private keys. The Secbox works in two modes; the first mode - when data is only signed, and the second one - when data is encrypted and then signed.
- **Protocols Module**. IoTKit provides a flexible, programmable security network adaptive protocol (SNAP) for device-to-device, device-to-cloud, and cloud-to-device communication. SNAP can be used for secure firmware distribution, secure notification about device state, and secure device provision. Also, SNAP contains a set of functions and interfaces that allows you to work with any transport protocol (BLE, Wi-Fi, PLC, NoiseSocket, etc.).  
- **Cloud Module. API for working with the Virgil IoT Security Platform**. IoTKit interacts with the Virgil IoT Security Platform to provide you with the services for the security, management, and monitoring of IoT devices.
- **Logger Module**. IoTKit contains a set of functions and interfaces for logging device events.
- **C/C++ support**. Library is implemented on C99. There is C++ integration based on Qt crossplatform library. Also there are tools implemented on Golang.

<div id='iot-dev-tools'/>

## IoT Dev Tools
Virgil Security also provides a set of tools for secure device lifecycle:
- **Virgil Trust Provisioner**. The Virgil Trust Provisioner is a CLI used to manage your distributed trust between all parties, including IoT devices, in your IoT solutions. The CLI is aimed at key pairs and TrustList generation and management, which together make each IoT device identifiable, verifiable and trusted by each party of IoT solution. To start working with the tool, read more [here](/tools/virgil-trust-provisioner).
- **Virgil Device Initializer**. In order to make each IoT device identifiable, verifiable and trusted by each party of IoT solution, you have to provide it with specific provision files, generate private keys and create the digital cards for further device registration on the Virgil Cloud. Virgil Device Initializer allows you to make IoT device provisioning and prepare your IoT device (create digital cards) for its further registration on the Virgil Cloud. To start working with the tool, read more [here](/tools/virgil-device-initializer).
- **Virgil Device Registrar**. Virgil IoT Device Registrar is used to register IoT devices and their digital cards with the Virgil Security Cloud. To start working with the tool, read more [here](/tools/virgil-device-registrar).
- **Virgil Firmware Signer**. Virgil Firmware Signer is a CLI that allows you to sign firmware in order to provide integrity before distributing it. To start working with the tool, read more [here](/tools/virgil-firmware-signer).
- **Virgil SnapD**. Virgil SnapD is a local web utility which allows you to obtain information and statistics about your IoT devices. In order to get such device information, SnapD interacts with Virgil SNAP protocol, which operates directly with your IoT devices. As far as Virgil SnapD is a local service, the obtained information can be displayed in browser under http://localhost:8080/ (by default). If you're working with the Virgil IoT Simulator, you can run SnapD under http://localhost:8081/. To start working with the tool, read more [here](/tools/virgil-snapd).

<div id='run-iotkit-sandbox'/>

## Run IoTKit Sandbox
To demonstrate our IoTKit in action we developed [Sandbox based on IoTKit](/scripts).

The Sandbox is conditionally divided into 3 actors (Vendor, Factory and End-user) and shows the secure lifecycle of IoT devices. The Sandbox allows you to:
- **Generate trusted provisioning package**. To start working with emulated IoT infrastructure, the Sandbox uses Virgil Trust Provisioner utility for generating provisioning files, such as private keys (e.g. for factory, firmware) and a distributed TrustList that contains public keys and signatures of trusted service providers (e.g. factory, cloud).
- **Emulate IoT devices**. Then, you can emulate two IoT device types: IoT Gateway - an internet-capable smart device that communicates with other IoT devices and the Virgil Cloud; and IoT Device - edge device, like smart bulb, that can be controlled remotely through the IoT Gateway.
- **Securely perform IoT device provisioning**. Sandbox uses the Virgil Device Initializer for IoT devices provisioning to make them identifiable, verifiable and trusted. Securely integrate TrusList into IoT device, then generate key pair and create digital card, and sign digital card with the device key.
- **Register IoT devices on the security platform**. On this step, the Virgil Device Registrar is used to register digital cards of IoT devices with the Virgil Cloud for further device authentication and management.
- **Sign and publish new Firmware and TrustList**. Also, you can emulate the process of creating and publishing new Firmware or TrustList to Virgil Cloud. Sandbox uses Virgil Firmware Signer to sign a firmware before its distributing.
- **Manage IoT devices**. Sandbox allows you to manage IoT devices and get information about their state. Sandbox uses Virgil services to notify IoT devices about new updates and then securely verify incoming firmware or TrustLists before updating them.

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_sandbox_demo.png?demo" align="left" hspace="0" vspace="6">


To start working with the Sandbox follow [Sandbox README](/scripts).

You can try to use [Demo IoTKit Qt](https://github.com/VirgilSecurity/demo-iotkit-qt/) open project on your platform to test Qt integration usage. This software grants you modern GUI application able to be started on many desktop and mobile platforms like Linux, Windows, Android, iOS etc.

<div id='modules'/>

## IoTKit Modules
As we mentioned above, Virgil IoTKit provides a set of features that implemented to modules:
- **[Cloud Module](https://virgilsecurity.github.io/virgil-iotkit/cloud_8h.html)** is used for for obtaining credentials from Virgil Thing service and downloading firmware images and TrustList files from cloud storage.
- **Crypto Module** is used for cryptographic operations with callbacks for [Software Security Module](https://virgilsecurity.github.io/virgil-iotkit/secmodule_8h.html) and [cryptographic converters](https://virgilsecurity.github.io/virgil-iotkit/crypto__format__converters_8h.html).
- **[Firmware Module](https://virgilsecurity.github.io/virgil-iotkit/firmware_8h.html)** is used for firmware downloading, uploading and processing by IoT Gateway or by Thing (IoT Device).
- **[Logger](https://virgilsecurity.github.io/virgil-iotkit/logger_8h.html)** is a tool is used to output logging messages to screen, file etc.
- **[Provision](https://virgilsecurity.github.io/virgil-iotkit/provision_8h.html)**. TrustList keys reading and verifying.
- **[Secbox](https://virgilsecurity.github.io/virgil-iotkit/secbox_8h.html)** is a secure data storage wth signing and authenticating abilities.
- **Protocols Module** provides the set of services for [SNAP](https://virgilsecurity.github.io/virgil-iotkit/snap_8h.html) protocol:
  - INFO: service for collecting statistics from devices. See [INFO Server](https://virgilsecurity.github.io/virgil-iotkit/info-server_8h.html) and [INFO Client](https://virgilsecurity.github.io/virgil-iotkit/info-client_8h.html)
  - FLDT: service for files download from Gateway to Thing. See [FLDT Server](https://virgilsecurity.github.io/virgil-iotkit/fldt-server_8h.html) and [FLDT Client](https://virgilsecurity.github.io/virgil-iotkit/fldt-client_8h.html)
  - PRVS: service for make provision for device by factory initializer. See [PRVS Server](https://virgilsecurity.github.io/virgil-iotkit/prvs-server_8h.html) and [PRVS Client](https://virgilsecurity.github.io/virgil-iotkit/prvs-client_8h.html)

<div id='scripts'/>

## Scripts
Virgil IoTKit also contains a set of scripts that can be run from the [scripts folder](/scripts).
- `run-sandbox` is used to run IoTKit sandbox. Read more about the sandbox and its functionality [here](/scripts).
- `publish-firmware.sh` is used to publish a signed firmware on the Virgil Cloud for its distribution to IoT devices. Read more about firmware distribution [here](/tools/virgil-firmware-signer#firmware-distribution).
- `publish-trustlist.sh` is used to publish a generated TrustList on the Virgil Cloud for its distribution to IoT devices. Read more about TrustLists distribution [here](/tools/virgil-trust-provisioner#trustlist-distribution).
- `build-for-qt.sh` is used to generate Virgil IoTKit libraries for different platform. If you run this script without parameters, it will output all supported platforms. Usage examples :
  - To get a library for Android : `ext/virgil-iotkit/scripts/build-for-qt.sh android armeabi-v7a`
  - To get a library for iOS : `ext/virgil-iotkit/scripts/build-for-qt.sh ios`
  - To get a library for iOS-simulator: `ext/virgil-iotkit/scripts/build-for-qt.sh ios-sim`
  - To get a library for Linux : `ext/virgil-iotkit/scripts/build-for-qt.sh linux`
  - To get a library for MacOS : `ext/virgil-iotkit/scripts/build-for-qt.sh macos`
  - To get a library for Windows by using mingw32 on another host platform : `ext/virgil-iotkit/scripts/build-for-qt.sh mingw32`
  - To get a library for Windows : `ext/virgil-iotkit/scripts/build-for-qt.sh windows`. See [Windows installation](/windows-installation) for running script details.

<div id='installation'/>

## Installation
Virgil IoTKit is distributed as a package. This section demonstrates on how to install Virgil IoTKit for preferred platform.

<div id='prerequisites'/>

### Prerequisites
To start working with Virgil IoTKit the following components are required:
- C99 for C.
- CMake v3.11 or higher, for project building
- GCC or another toolchain for C/C++ compile
- [Golang](https://golang.org/) to compile Virgil IoT dev tools
- [git](https://git-scm.com/) for Virgil Crypto installation and update
- [curl](https://curl.haxx.se/) for default NIX implementation

Also Virgil IoTKit has C++/Qt integration based on Qt crossplatform library. Following components are required to use Qt integration:
- C++14.
- Qt 5.12.6 or higher.
- Qt built for your target platform: Android, iOS, Linux, MacOS, Windows etc.

<div id='ubuntu-debian-raspbian-os'/>

### Ubuntu, Debian, Raspbian OS
To download and install the Virgil IoTKit on Ubuntu, use the following command:

```shell
$ sudo apt-get install make gcc cmake golang git libcurl4-openssl-dev doxygen swig
```

To add repository to preferred OS, use the following command:

#### Ubuntu 19.10 Suite (eoan)
```shell
echo "deb http://virgilsecurity.bintray.com/iot-deb/ Ubuntu_19  iot" >> /etc/apt/sources.list
```

#### Ubuntu 18.04 (bionic)
```shell
echo "deb http://virgilsecurity.bintray.com/iot-deb/ Ubuntu_18 iot" >> /etc/apt/sources.list
```

#### Raspbian 9 (stretch)
```shell
echo "deb http://virgilsecurity.bintray.com/iot-deb/ Raspbian_9 iot" >> /etc/apt/sources.list
```

#### Raspbian 10 (buster)
```shell
echo "deb http://virgilsecurity.bintray.com/iot-deb/ Raspbian_10 iot" >> /etc/apt/sources.list
```

**Note!** All DEB repositories are not signed, therefore to update lists for them use the following command: `apt-get update --allow-insecure-repositories --allow-unauthenticated`

<div id='fedora-os'/>

### Fedora OS
To download and install the Virgil IoTKit on Fedora or CentOS, use the following command:

```shell
$ sudo yum install make cmake golang git gcc gcc-c++ libcurl-devel doxygen swig
```
To add repository to preferred OS use the following command:

#### Fedora 29
```shell
$ sudo yum install https://virgilsecurity.bintray.com/iot-rpm/Fedora/29/x86_64/virgil-bintray-release-0.1.0-1.1.noarch.rpm
```

#### Fedora 30
```shell
$ sudo yum install https://virgilsecurity.bintray.com/iot-rpm/Fedora/30/x86_64/virgil-bintray-release-0.1.0-1.1.noarch.rpm
```

#### Fedora 31
```shell
$ sudo yum install https://virgilsecurity.bintray.com/iot-rpm/Fedora/31/x86_64/virgil-bintray-release-0.1.0-1.1.noarch.rpm
```

<div id='macos'/>

### MacOS
To download and install the Virgil IoTKit on MacOS, use the following command:
```shell
$ brew install make cmake golang git gcc curl doxygen swig
```

<div id='windows-os'/>

### Windows OS
It is necessary to install software listed below :
- [Git](https://git-scm.com/) for Virgil IoTKit components installation and upgrade.
- [CMake](https://cmake.org/) as Virgil IoTKit framework build system.
- make. It can be installed separately from [GNUWin32 project](http://gnuwin32.sourceforge.net/packages/make.htm). Also
it contains in mingw compiler.
- [MSYS2](https://www.msys2.org/) as shell commands interpreter
- [mingw-w64](http://mingw-w64.org/) as C/C++ compiler. It is suggested to use mingw to use GCC bytes alignment in
packet structures.
- Also you can install [Qt](https://www.qt.io/) that will be used for Qt integration. Qt Maintenance Tool installs mingw,
CMake and make.

Start MSYS2 and try to see all those software versions :

```shell
git --version
cmake --version
make --version
gcc --version
```

If some software has not been found, check PATH system variable.

After these steps you can clone Git repository and use `build-for-qt.sh` script.

<div id='qt-integration'/>

### Ready Linux packets
IoTKit also contains ready-made (pre-compiled) packets for Linux OS, that can be installed using an OS package manager.
- `virgil-iot-sdk-tools` - a set of tools [mentioned above](#iot-dev-tools) for secure device lifecycle management
- `virgil-iot-sdk-snapd` - a local web utility which allows you to obtain information and statistics from your IoT devices. Virgil SnapD interacts with Virgil SNAP protocol, which operates directly with your IoT devices. Read more [here](/tools/virgil-snapd)
- `virgil-iot-sdk-libs` - a set of libraries necessary for interacting Virgil IoTKit modules with your IoT devices


### Qt integration
- Setup Qt with your target platforms support. Each platform has its own requirement. See Qt documentation for details.
- Compile Virgil IoTKit library for target platform. See [Scripts](#scripts) section, `build-for-qt.sh` script description for details.
- Build and deploy application.

<div id='tests'/>

## Tests
To make sure that everything goes in the right way, we also provide a set of ready code-snippets for testing all the required features:
- Crypto: crypto algorithms (e. g. hash, RNG, AES) and crypto operations (key pair, sign/verify etc.).
- Firmware related functionality: create firmware, save/load/install.
- Security Box (test storage module): read write for signed or/and encrypted data.
- SNAP (Secure Network Adjustable Protocol tests): send, receive etc.

Navigate to the [tests folder](https://github.com/VirgilSecurity/demo-iotkit-nix/tree/release/v0.1.0-alpha/tests) of our IoTKit Demo repository to find preferred tests and start working with them.

You can try to use [Demo IoTKit Qt](https://github.com/VirgilSecurity/demo-iotkit-qt/) open project to test Qt integration usage. To have full testing start any IoT devices in your network and observe its states by using demo-iotkit-qt software. You can use Sandbox as such devices set.

<div id='iotkit-usage'/>

## IoTKit Usage
To start working with Virgil IoTKit you have to:
- specify configuration parameters.
- provide implementations (you can also use default implementations).

<div id='config-params'/>

### Configuration parameters

#### Configuration headers directory
There are configuration headers that customize Virgil IoTKit, they are stored in **config directory**. You can provide your headers or use standard ones.
It's necessary to add `VIRGIL_IOT_CONFIG_DIRECTORY` variable that points to the directory with configuration files.

> For example, if you want to use PC configuration provided by library and library is stored in `virgil-iotkit` directory, you have to set compiler option: `-DVIRGIL_IOT_CONFIG_DIRECTORY virgil-iotkit/config/pc`.

#### MCU Build
The `VIRGIL_IOT_MCU_BUILD` variable enables or disables microcontroller features. If some microcontroller features are not compatible with your PC configuration or you don't need to use MCU features, you can disable them through the  `VIRGIL_IOT_MCU_BUILD` variable during compilation: `-DVIRGIL_IOT_MCU_BUILD=OFF`.

#### Mobile platforms Build
Use integration/qt/iotkit.pri qmake script to include Virgil IoTKit Qt framework.

<div id='mandatory-implementations'/>

### Mandatory implementations
Some IoTKit modules use external implementations, therefore it's necessary to implement HAL (hardware abstraction layer) functions:
- [Storage context](https://virgilsecurity.github.io/virgil-iotkit/storage__hal_8h.html): structure **vs_storage_op_ctx_t**
contains external data operations like open/read/write/close. See [Storage HAL](https://virgilsecurity.github.io/virgil-iotkit/storage__hal_8h.html) for details.
- [Firmware](https://virgilsecurity.github.io/virgil-iotkit/firmware_8h.html): **vs_firmware_install_prepare_space_hal**,
**vs_firmware_install_append_data_hal** and **vs_firmware_get_own_firmware_footer_hal** functions have to be implemented for firmware processing. See [Firmware HAL](https://virgilsecurity.github.io/virgil-iotkit/firmware__hal_8h.html#details) for details.
- [Logger](https://virgilsecurity.github.io/virgil-iotkit/logger_8h.html): depends on [logger-config.h](https://virgilsecurity.github.io/virgil-iotkit/logger-config_8h.html) configurations **vs_logger_output_hal** for string output and/or **vs_logger_current_time_hal** for current time output. See [Logger HAL](https://virgilsecurity.github.io/virgil-iotkit/logger-hal_8h.html) for details.
- [SNAP protocol](https://virgilsecurity.github.io/virgil-iotkit/snap_8h.html): **vs_netif_t** network interface as
transport level for SNAP protocol. As [UDP broadcast example](https://github.com/VirgilSecurity/demo-iotkit-nix/blob/release/v0.1.0-alpha/common/src/sdk-impl/netif/netif-udp-broadcast.c) user can use c-implementation tool.
See [SNAP Reference](https://virgilsecurity.github.io/virgil-iotkit/snap-structs_8h.html) for details.
- [FLDT Server](https://virgilsecurity.github.io/virgil-iotkit/fldt-server_8h.html) is a service that is used by a IoT Gateway for files (e.g. firmware, TrustLists) distribution for IoT devices. Server sends new files in the network to IoT Devices and processes Client requests for new files.
- [FLDT Client](https://virgilsecurity.github.io/virgil-iotkit/fldt-client_8h.html) is client for FLDT service that used by IoT Devices to receive new files (e.g. Firmware, TrustLists) from IoT Gateway. FLDT Client also can request files versions.
- [PRVS Client](https://virgilsecurity.github.io/virgil-iotkit/prvs-client_8h.html): there is a need to implement **vs_snap_prvs_client_impl_t** structure. This structure contains wait functions for SNAP interface. You can see example of implementation in the [c-implementation](https://github.com/VirgilSecurity/virgil-iotkit/blob/release/v0.1.0-alpha/tools/c-implementation/src/helpers/ti_wait_functionality.c).

<div id='default-mandatory-implementations'/>

### Default Mandatory implementations
Virgil IoTKit also provides default mandatory implementations:
- [Cloud](https://virgilsecurity.github.io/virgil-iotkit/cloud_8h.html) : **vs_cloud_impl_t** and **vs_cloud_message_bin_impl_t** are required `by vs_cloud_init`. Function `vs_curl_http_impl` returns cURL HTTP implementation, `vs_cloud_message_bin_impl_t` returns MQTT implementation.
- [Crypto](https://virgilsecurity.github.io/virgil-iotkit/secmodule_8h.html) introduces security module implementation structure **vs_secmodule_impl_t**. Function `vs_soft_secmodule_impl` returns software implementation.

<div id='api-reference'/>

## API Reference
- [API Reference of IoTKit](https://virgilsecurity.github.io/virgil-iotkit/)

<div id='license'/>

## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email at support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
