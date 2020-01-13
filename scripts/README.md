# Virgil IoTKit Sandbox
The IoT Sandbox is based on Virgil IoTKit and its dev tools to demonstrate secure IoT devices development in action. The Sandbox is conditionally divided into 3 actors (Vendor, Factory, and End-User) to easily understand the whole development process.

## Content
- [Functions](#functions)
- [Download Sandbox](#download-sandbox)
- [Configure and Run Sandbox](#configure-and-run-sandbox)
  - [Prerequisites](#prerequisites)
  - [Generate App Token](#generate-app-token)
  - [Run Sandbox](#run-sandbox)
- [Explore Sandbox](#explore-sandbox)
- [Reference](#reference)
- [Support](#support)

## Functions
The IoTKit Sandbox allows you to:
- Generate trusted provisioning package
- Emulate IoT devices
- Securely perform IoT device provisioning
- Register IoT devices on the security platform
- Sign and publish new Firmware and TrustList
- Manage a user's IoT devices

Also, while working with Sandbox you can:
- View logs of all operations using integrated logs viewer
- View devices information using integrated device manager (Virgil SnapD)

## Download Sandbox
The Sandbox is a part of the IoTKit package, therefore you need to clone the IoTKit repository.

Clone the IoTKit package with the following link:
```shell
$ git clone https://github.com/VirgilSecurity/virgil-iotkit.git
```

## Configure and Run Sandbox
To launch the Sandbox you will need to run the Docker and generate Virgil application token (`App Token`).

### Prerequisites
Before you start, you need to install the following:
- **Virgil CLI** is a unified tool to manage your Virgil Cloud services and perform all required commands to configure the Sandbox. Follow this guide to [install the Virgil CLI](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/install) on your platform.
- **Docker** is a tool designed to make it easier to create, deploy, and run applications by using containers. Follow this guide to [install the Docker](https://docs.docker.com/install/) for your platform.

### Generate App Token
To start working with the Sandbox, you need to specify your `App Token`. In case you don't have App Token you need to generate it using Virgil CLI.

To generate an `App Token` go through the following steps:
- Launch the Virgil CLI
```shell
$ virgil
# or virgil.exe for Windows OS
```
- Register Virgil Account (omit this step, in case you have it). Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-account).
```shell
$ virgil register <email>
```
- Log into your Virgil Account:
```shell
$ virgil login
```
- Create Virgil Application. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-applications).
```shell
$ virgil app create <App Name>
```
As a result, you'll get `App_ID`.
- Generate App Token specifying `App_ID` and `App Name`. Find examples [here](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/manage-apptokens).
```shell
$ virgil app token create --app-id <App ID> --name <Name>
```
As a result, you'll get `Token`.

> Store the App Token in a secure place and use it to initialize the Sandbox.

### Run Sandbox
Now, you can run the Sandbox.

- First of all, check whether the Docker is launched.
- Navigate to your CLI terminal and run the Sandbox script (Unix-like OS: `run-sandbox.sh` and Windows:`run-sandbox.bat`) from the scripts folder of the downloaded IoTKit package.
```shell
# for MacOS
$ ./run-sandbox.sh
```
- Specify your `App_Token` in the appeared window to run the Sandbox

If you did everything correctly, you would see the following Sandbox window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/virgil_demo_iotkit_nix.png?demo" align="left" hspace="0" vspace="6"> &nbsp;

&nbsp;

### Run Logs Viewer
While working with the Sandbox you can:
- View logs of all operations using integrated logs viewer that can be run in browser under http://localhost:8080/:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/logs-viewer.png?demo" align="left" hspace="0" vspace="6">
&nbsp;

- View devices information using integrated device manager (Virgil SnapD) that can be run in browser under http://localhost:8081/:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/devices_manager.png?demo" align="left" hspace="0" vspace="6">
&nbsp;

## Explore Sandbox
The Sandbox is conditionally divided into 3 actors (Vendor, Factory and End-user) and shows secure lifecycle of IoT devices. The Sandbox allows you to:
- **Step #1. Generate trusted provisioning package**.

To start working with emulated IoT infrastructure you have to generate a trusted provisioning package that includes private keys (e.g. for factory, firmware) and a distributed TrustList that contains public keys and signatures of trusted services providers (e.g. factory, cloud).

<img width="320" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/generate_files.png?demo" align="left" hspace="0" vspace="6">  

&nbsp;

&nbsp;

&nbsp;

&nbsp;

&nbsp;

Sandbox uses [Virgil Trust Provisioner](/tools/virgil-trust-provisioner) utility under the hood for this purpose.

- **Step #2. Emulate IoT devices**.

Now, you have to emulate IoT devices. There are two types of devices:
  - IoT Gateway - an internet-capable smart device that communicates with other IoT devices and Clouds; NOTE! At this moment Sandbox supports only one active IoT-Gateway in network.
  - and IoT Device - end-device, like smart bulb, that can be controlled remotely through the IoT Gateway.

Generate both of them. The information about generated devices can be found in the Sandbox window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/emulated_device.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Step #3. Securely perform IoT device provisioning**.

To make each IoT device identifiable, verifiable and trusted by each party of IoT solution you have to make device provisioning.

Sandbox uses the [Virgil Device Initializer](/tools/virgil-device-initializer) for IoT devices provisioning to securely integrate TrustList and crypto library on IoT devices, then generate key pairs and create digital cards, and sign digital cards with the Factory Key.

The information about initialized (provisioned) devices can be found in the Sandbox window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/initialized_device.png?demo" align="left" hspace="0" vspace="6"> &nbsp;

or in browser under http://localhost:8080 in the Device Initializer section.

- **Step #4. Register IoT devices on the security platform**.

At this step the [Virgil Device Registrar](/tools/virgil-device-registrar) is used to register digital cards of IoT devices at Virgil Cloud for further device authentication and management.

After the IoT devices were registered at Virgil they are conditionally shipped to end-user for further operations:

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/shipped_devices.png?demo" align="left" hspace="0" vspace="6">
&nbsp;

The information about registered IoT devices can be also found in Logs Viewer (http://localhost:8080/) in the Device Registrar section and in Virgil SnapD (http://localhost:8081/):
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/shipped_devices_manager.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Step 5. Sign and publish new Firmware**.

Now, you can emulate the process of creating and publishing new Firmware to Virgil Cloud. Sandbox uses [Virgil Firmware Signer](/tools/virgil-firmware-signer) to sign a firmware before its distributing. Sandbox uses Virgil services to notify IoT devices about new updates and then securely verify incoming firmware or trustlists before updating them.

<img width="320" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/update_firmware.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

&nbsp;

&nbsp;

After the Firmware is successfully uploaded to the Virgil Cloud, IoT device gets information about new firmware. Then Firmware is downloaded, verified using integrated crypto library and updated on devices for which the Firmware was created (in our case for IoT Gateway).

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/updated_devices.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

The information about signed Firmware can be also found in Logs Viewer (http://localhost:8080/) in the Firmware Signer section and in Virgil SnapD (http://localhost:8081/):

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/updated_devices_manager.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Step 6. Sign and publish new TrustList**.

Now, you can emulate the process of creating and publishing new TrustList to Virgil Cloud. Sandbox uses [Virgil Trust Provisioner](/tools/virgil-trust-provisioner) utility under the hood for this purpose.
After you generate a new TrustList it will be distributed to all IoT devices.

After the new TrustList is successfully uploaded to the Virgil Cloud, IoT device gets information about new TrustList. Then TrustList is downloaded, verified using integrated crypto library and updated on all devices.

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/updated_devices_tl.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

The information about generated TrustList can be also found in Logs Viewer (http://localhost:8080/) and in Virgil SnapD (http://localhost:8081/):

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_demo/updated_devices_manager_tl.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Manage IoT devices**.

Sandbox also allows you to manage IoT devices and get information about their state in the in Virgil SnapD (http://localhost:8081/).


## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
