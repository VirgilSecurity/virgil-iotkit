# IoTKit Demo

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/iotkit/IoTKit.png" align="left" hspace="1" vspace="3"></a>

## Introduction
To demonstrate Virgil IoTKit in action we developed a demo based on [Virgil IoTKit](https://github.com/VirgilSecurity/virgil-iotkit) and its dev tools. The Demo contains samples for UNIX-like OS.

&nbsp;

## Demo Content
The Demo provides you with samples of key elements that are necessary to build a secure IoT lifecycle:
- **common**. Contains samples of HAL implementations (hardware abstraction layer). Find all implementations [here](/common/src/sdk-impl).
- **initializer**. Implementation of initializer of IoT Device and Gateway. Find all implementations [here](/initializer/src/main.c).
- **bootloader**. Application that simulates a bootloader for the controller. The application performs firmware verification.
- **thing**. Samples of IoT Device (end-device) implementation based on IoTKit. Find examples on how to work with IoT device [here](/thing/src/main.c).
- **gateway**. Samples of IoT Gateway implementation based on IoTKit. Find examples on how to work with the Cloud, Getaway or its threads [here](/gateway/src).
- **dummy-keys**. Testing keys for signing a testing firmware.
- **tests**. A set of ready code-snippets for testing the needed features.


## Prerequisites
To start working with the IoTKit Demo you have to:
- Clone IoTKit repository
```shell
$ git clone --recursive https://github.com/VirgilSecurity/virgil-iotkit
```
## Run Tests
To make sure that everything goes in the right way, we also provide a set of ready code-snippets for testing the necessary features:
- Crypto: crypto algorithms (e. g. hash, RNG, AES) and crypto operations (key pair, sign/verify etc.).
- Firmware related functionality: create firmware, save/load/install.
- Security Box (test storage module): read write for signed or/and encrypted data.
- SNAP (Secure Network Adjustable Protocol tests): send, receive, etc.
Navigate to the [tests folder](/tests) of the repository to find preferred tests and start working with them.

To run the preferred test go through the following steps:
- Clone the demo repository (if you haven't done that already)
```shell
$ git clone --recursive https://github.com/VirgilSecurity/demo-iotkit-nix
```
- Build test project
```shell
$ mkdir build
$ cd build
$ cmake ..
$ make rpi-tests
```
- Run tests

## Reference
- [Virgil IoTKit repository](https://github.com/VirgilSecurity/virgil-iotkit)


## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or via email at support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
