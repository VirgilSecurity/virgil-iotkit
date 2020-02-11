# Virgil Device Registrar
Virgil Device Registrar is a CLI utility used to register IoT devices and their digital cards on the Virgil Security Cloud.

## Content
- [Virgil Device Registrar](#virgil-device-registrar)
  - [Content](#content)
  - [Overview](#overview)
    - [How it works](#how-it-works)
  - [Setting Up Device Registrar](#setting-up-device-registrar)
    - [Install Device Registrar](#install-device-registrar)
      - [Linux OS](#linux-os)
      - [Ubuntu OS, Debian OS](#ubuntu-os-debian-os)
      - [CentOS, Fedora OS](#centos-fedora-os)
      - [Mac OS](#mac-os)
      - [Windows OS](#windows-os)
  - [Command Reference](#command-reference)
    - [Syntax](#syntax)
    - [Registering Device](#registering-device)


## Overview
In order to make your IoT device identifiable, verifiable and manageable, you have to assign the IoT device and its identifying information to the Cloud and then receive its Cloud credentials. Virgil Device Registrar helps you to do this in the one request.

### How it works
- After the IoT device goes through the provisioning process at the manufacturing stage at the factory, it gets a signed digital card request (SCR).
- All SCRs are collected in a file.
- The file is transferred to the Virgil Device Registrar.
- Virgil Device Registrar gets the SCR of the IoT device with its identification information and registers it with the Virgil Cloud.
- All requests to the Virgil Cloud have to be authenticated, so the Virgil Device Registrar uses an Application Token during the device registration. An Application Token is generated on the Virgil Cloud and provided by you.
- If the request is successful, the IoT identification information is registered with the Virgil Thing Service and the SCR is registered with Virgil Cards Service.

Now, the IoT device is ready for application development.


## Setting Up Device Registrar
This section demonstrates how to install and configure Virgil Device Registrar for the preferred platform.

### Install Device Registrar
This section provides instructions for installing Virgil Device Registrar.

#### Linux OS
Virgil Device Registrar is distributed as a package.

In order to download and install Virgil Device Registrar on Linux, use the YUM package manager and run the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```

#### Ubuntu OS, Debian OS
Virgil Device Registrar is distributed as a package.

In order to download and install the Virgil Device Registrar on Ubuntu, Debian, use the YUM package manager and run the following command:
```bash
$ sudo apt-get install virgil-iot-sdk-tools
```

#### CentOS, Fedora OS
Virgil Device Registrar is distributed as a package.

In order to download and install the Virgil Device Registrar on CentOS, Fedora, use the YUM package manager and run the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```

#### Mac OS
At this moment we don't provide a built package for Mac OS, so you'll have to build and run it by yourself using [cmake](https://cmake.org).

```bash
$ git clone --recursive https://github.com/VirgilSecurity/virgil-iot-sdk.git
$ cd virgil-iot-sdk
$ mkdir build && cd build
$ cmake ..
$ make vs-tool-virgil-device-registrar
```

#### Windows OS
Virgil Device Registrar package for Windows OS is currently in development. To join our mailing list to receive information on updates, please contact our support team support@VirgilSecurity.com.

## Command Reference
Here is the list of the commands for Virgil Device Registrar.

### Syntax
The CLI has the following syntax:

```bash
virgil-device-registrar [global options] command [command options] [arguments...]
```
Use ```virgil-device-registrar -h``` to see the list of available arguments.

### Registering Device
In order to register IoT device, Virgil Device Registrar uses the following command:

| Command                                                                           | Description               |
|-----------------------------------------------------------------------------------|---------------------------|
| ```virgil-device-registrar [global options] command [command options] [arguments...]``` | IoT device is registered |

``` bash
virgil-device-registrar --data "/root/current-credentials/card_requests_gateways.txt" --app_token "AT.K6E8PEeOd...CSgiоDKМB" --api_url https://api-iot.virgilsecurity.com
```
| Option                             | Description                                                                                                                                                                                                                                               |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --data value, -d value             | File with signed digital card requests (SCR) |
| --app_token value, -t value        | Virgil Application Token. The Token is generated by you on the Virgil Cloud |
| --api_url value, -b value | URL of Virgil IoT services |
| --help, -h                         | Show help (default: false) |
| --version, -v                      | Print the version (default: false)  |
