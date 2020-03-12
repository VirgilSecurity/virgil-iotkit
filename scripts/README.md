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
- [Web services](#web-services)
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
This section contains information on how to perform installation and running processes.

### Prerequisites
Before you start, you need to install the **Virgil CLI** - a unified tool to manage your Virgil Cloud services and perform all required commands to configure the Sandbox. Follow this guide to [install the Virgil CLI](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/install) on your platform.

#### Windows:

- Install [Vagrant](https://www.vagrantup.com/docs/installation/)

- Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

- Install VirtualBox Guest Additions plugin: `vagrant plugin install vagrant-vbguest`

- Enable VT-X (Intel Virtualization Technology) in your computer bios settings.

- Disable Hyper-V on "program and features page" in the control panel.

#### MacOS:

- Install [Vagrant](https://www.vagrantup.com/docs/installation/)

- Install [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

- Install VirtualBox Guest Additions plugin: vagrant plugin install vagrant-vbguest

#### Linux
- Install [Docker](https://docs.docker.com/install/).

### Generate App Token
To start working with the Sandbox, you need to specify your `Virgil App Token`. In case you don't have an App Token you can generate it using the [Virgil Dashboard](https://dashboard.virgilsecurity.com/) or the [Virgil CLI](https://developer.virgilsecurity.com/docs/platform/cli/).

If you don't have a Virgil Account yet  you can create it using [Virgil Dashboard](https://dashboard.virgilsecurity.com/) as well as using [Virgil CLI](https://developer.virgilsecurity.com/docs/platform/cli/).

> Store the App Token in a secure place and use it to initialize the Sandbox.

### Run Sandbox
Now, you can run the Sandbox.

- First of all, check whether the Docker is launched (if you are using Linux).
- Navigate to your CLI terminal and run the Sandbox starting script from the scripts folder of the downloaded IoTKit package:
  - Unix-like OS: `run.sh`  
  - Windows: `run.bat`
  - MacOS: `./run-in-vm.sh`
- Specify your `App_Token` in the appeared window to run the Sandbox

Now you have to navigate to [localhost](http://localhost:8000/) to start exploring the demo.

If you did everything correctly, you would see the following Sandbox window:

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_sandbox_demo.png?demo" align="left" hspace="0" vspace="6">
&nbsp;

&nbsp;
### Sandbox Cautions

- You can run only one Sandbox in a subnetwork
- You can have only one active gateway inside of Sandbox
- Above mentioned scripts are not allowed yet to be used in virtual machines


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

To start working with emulated IoT infrastructure you have to generate a trusted provisioning package that includes private keys (e.g. for factory, firmware) and a distributed trust list that contains public keys and signatures of trusted services providers (e.g. factory, cloud).

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_provisioning.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

Sandbox uses [Virgil Trust Provisioner](/tools/virgil-trust-provisioner) utility under the hood for this purpose.

- **Step #2. Emulate IoT devices**.

Now, you have to emulate IoT devices. There are two types of devices:
  - IoT Gateway - an internet-capable smart device that communicates with other IoT devices and Clouds; 
  > **NOTE! At this moment Sandbox supports only one active IoT-Gateway in network.**
  
  - IoT Device - end-device, like smart bulb, that can be controlled remotely through the IoT Gateway.

Generate both of them. The information about generated devices can be found in the Sandbox window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_emulate.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Step #3. Securely perform IoT device provisioning**.

To make each IoT device identifiable, verifiable and trusted by each party of IoT solution you have to make device provisioning.

Sandbox uses the [Virgil Device Initializer](/tools/virgil-device-initializer) for IoT devices provisioning to securely integrate trust list and crypto library on IoT devices, then generate key pairs and create digital cards, and sign digital cards with the Factory Key.

The information about initialized (provisioned) devices can be found in the Sandbox window:
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_initialize.png?demo" align="left" hspace="0" vspace="6"> &nbsp;

or in browser under http://localhost:8080 in the Device Initializer section.

- **Step #4. Register IoT devices on the security platform**.

At this step the [Virgil Device Registrar](/tools/virgil-device-registrar) is used to register digital cards of IoT devices at Virgil Cloud for further device authentication and management.

After the IoT devices were registered at Virgil they are conditionally shipped to end-user for further operations:

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_register.png?demo" align="left" hspace="0" vspace="6">
&nbsp;

The information about registered IoT devices can be also found in Logs Viewer (http://localhost:8080/) in the Device Registrar section and in Virgil SnapD (http://localhost:8081/):
<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_register_dmanager.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Step 5. Sign and publish new Firmware**.

Now, you can emulate the process of creating and publishing new Firmware to Virgil Cloud. Sandbox uses [Virgil Firmware Signer](/tools/virgil-firmware-signer) to sign a firmware before its distributing. Sandbox uses Virgil services to notify IoT devices about new updates and then securely verify incoming firmware or trustlists before updating them.

&nbsp;

After the Firmware is successfully uploaded to the Virgil Cloud, IoT device gets information about new firmware. Then Firmware is downloaded, verified using integrated crypto library and updated on devices for which the Firmware was created (in our case for IoT Gateway).

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_firmware.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

The information about signed Firmware can be also found in Logs Viewer (http://localhost:8080/) in the Firmware Signer section and in Virgil SnapD (http://localhost:8081/):

<img width="65%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_firmware_dmanager.png?demo" align="" hspace="0" vspace="6">


&nbsp;

- **Step 6. Sign and publish new TrustList**.

Now, you can emulate the process of creating and publishing new TrustList to Virgil Cloud. Sandbox uses [Virgil Trust Provisioner](/tools/virgil-trust-provisioner) utility under the hood for this purpose.
After you generate a new TrustList it will be distributed to all IoT devices.

After the new TrustList is successfully uploaded to the Virgil Cloud, IoT device gets information about new TrustList. Then TrustList is downloaded, verified using integrated crypto library and updated on all devices.

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_trustlist.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

The information about generated TrustList can be also found in Logs Viewer (http://localhost:8080/) and in Virgil SnapD (http://localhost:8081/):

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/web_demo/web_demo_trustlist_dmanager.png?demo" align="left" hspace="0" vspace="6">

&nbsp;

- **Manage IoT devices**.

Sandbox also allows you to manage IoT devices and get information about their state in the in Virgil SnapD (http://localhost:8081/).

- **Reset Sandbox**

User can use `Reset Sandbox` button to reset Sandbox to default state.

### Web services
- http://localhost:8000/ - Sandbox UI
- http://localhost:8080/ - Logs viewer for Web Sandbox demo
- http://localhost:8081/ - Virgil SnapD for Web Sandbox demo


## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
