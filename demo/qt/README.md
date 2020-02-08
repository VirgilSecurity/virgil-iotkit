# Qt/QML Demo for Virgil IoTKIT Usage

<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/iotkit/IoTKit.png" align="left" hspace="1" vspace="3"></a>
&nbsp;

&nbsp;

&nbsp;

&nbsp;
&nbsp;

&nbsp;
# Content
- [Introduction](#introduction)
- [Features](#features)
- [Setting Up Demo-iotkit-qt](#setting-up-demo-iotkit-qt)
  - [Prerequisites](#prerequisites)
  - [Install Qt](#install-qt)
  - [Getting started with Qt on Android](#getting-started-with-qt-on-android)
  - [Getting started with Qt on iOS](#getting-started-with-qt-on-ios)
  - [Demo-iotkit-qt package installation](#demo-iotkit-qt-package-installation)
- [Run Demo-iotkit-qt](#run-demo-iotkit-qt)



## Introduction
[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application or IoT device.

[Virgil IoTKit](https://github.com/virgilsecurity/virgil-iotkit/) is a C library for connecting IoT devices to the Virgil IoT Security Platform. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for securely provisioning and authenticating devices, updating firmware and TrustLists, and exchanging messages using any transport protocols.

Demo for Virgil IoTKIT is the Virgil IoTKIT usage example based on C++ and Qt/QML library.

Qt is a crossplatform framework for creating modern console and GUI applications. It supports wide range of desktop and mobile platforms like Windows, Linux, MacOS, Android, iOS etc.

## Features
Demo-iotkit-qt package is a sample application that uses the virgil-iotkit library.

- Demo-iotkit-qt is a cross-platform application, based on the Qt library. It is tested for Android, iOS, iOS simulator, Linux, MacOS, and Windows.
- In “Devices” mode, demo-iotkit-qt shows information on available IoT devices. Active devices are able to transmit their status information using the INFO Server of SNAP protocol service. Demo-iotkit-qt uses INFO Client.
- In "Sniffer" mode, demo-iokit-qt shows the device's packet exchange.

## Setting Up Demo-iotkit-qt
The following section contains information on how to set up the demo-iotkit-qt.

The most simple way to try IoTKit and Qt interaction:
- Select prefered platfrom and download ready-to-use package ([Android_arm64](https://bintray.com/virgilsecurity/iotl-demo-cdn/download_file?file_path=android_arm64_v8a-0.1.3.59.zip), [Android_armv7](https://bintray.com/virgilsecurity/iotl-demo-cdn/download_file?file_path=android_armv7-0.1.3.59.zip), [Android_x86](https://bintray.com/virgilsecurity/iotl-demo-cdn/download_file?file_path=android_x86-0.1.3.59.zip), [Linux](https://bintray.com/virgilsecurity/iotl-demo-cdn/download_file?file_path=linux-0.1.3.59.zip), [MacOS](https://bintray.com/virgilsecurity/iotl-demo-cdn/download_file?file_path=MacOS-0.1.3.59.zip), [Windows](https://bintray.com/virgilsecurity/iotl-demo-cdn/download_file?file_path=windows-0.1.3.59.zip))
- Run the downloaded Qt application
- Run Sandbox (Sandbox must be running in the same subnetwork with qt application)
- Create device and gateway in Sandbox and perform their provisioning and registration

Otherwise you can create your own application following the instructions below

### Prerequisites
Elements required for successful compilation:
- Qt v5.12.6 or higher for demo-iotkit-qt building.
- CMake v3.11 or higher for Virgil IoTKit framework building.
- С99 or higher for Virgil IoTKit framework building.
- С++14 or higher for demo-iotkit-qt building.

Demo-iotkit-qt package was tested on the gcc, clang, mingw compilers. For Windows mingw is suggested due to binary packets received from other Virgil IoT devices compatibility.

Before running the Demo-iotkit-qt you have to:
- Install QtCreator and Qt library for the preferred platforms.
- Clone demo-iotkit-qt application from GitHub, which will download virgil-iotkit by default.
- Compile the Virgil IoTKit library for a given platform.
- After that, build the demo-iotkit-qt using QtCreator tools.


### Install Qt
The fastest way is to install the Qt Maintenance Tool, which will install the required components. To perform such Qt installation you need to:

- Navigate to the QT site (https://www.qt.io/download), select an option you need. For testing, select “Go open source” in the “Downloads for open source users” section.
- Then, on the next page, find the “Download the Qt Online Installer” section. Select “Download” if you are comfortable with the default options and follow the further instructions.
- Next, skipping the choice of license (this is enough for testing), select the necessary  elements to install. For example, to install the minimal package on macOS with the ability to test the application on different Android and iOS platforms you must select the following items:

<img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_qt/Qt_components.png" >

Next, run the Qt installation.

### Getting started with Qt on Android
In order to use Qt for Android please go through the following steps:

- Follow the steps in the section “Getting Started with Qt for Android” at https://doc.qt.io/qt-5/android-getting-started.html. You will be prompted to install the Android SDK, Android NDK and a suitable JDK version.
- Run the QtCreator. Choose a sample project for the platform you are interested in. In the next step, you will configure the settings for these platforms.
- Add ${ANDROID_SDK} = path to  SDK, ${ANDROID_NDK} = path to NDK to system variables.
- Compile and run this example on the platform you need.

### Getting started with Qt on iOS
In order to use Qt for iOS please go through the following steps:
- Follow the steps in the “Connecting iOS Devices” at https://doc.qt.io/qtcreator/creator-developing-ios.html.
- Compile and run this example on the platform you need.

### Demo-iotkit-qt package installation
- Clone the github project:
`git clone --recurse-submodules https://github.com/VirgilSecurity/demo-iotkit-qt`
- Get libraries for specific platforms. To do this, run the script `ext/virgil-iotkit/scripts/build-for-qt.sh` and indicate the preferred platform.
&nbsp;

&nbsp;
**Example**:
  - To get a library for Android: `ext/virgil-iotkit/scripts/build-for-qt.sh android armeabi-v7a`
  - To get a library for iOS library: `ext/virgil-iotkit/scripts/build-for-qt.sh ios`
  - To get a library for Linux library: `ext/virgil-iotkit/scripts/build-for-qt.sh linux`
  - To get a library for MacOS library: `ext/virgil-iotkit/scripts/build-for-qt.sh mac`
  - To get a library for Windows by using mingw32 on another host platform : `ext/virgil-iotkit/scripts/build-for-qt.sh mingw32`
  - To get a library for Windows library: `ext/virgil-iotkit/scripts/build-for-qt.sh windows`. See details in [Virgil IoTKit documentation](https://virgilsecurity.github.io/virgil-iotkit/#windows-installation).
- Run the QtCreator. Open the downloaded project by selecting the demo-iotkit-qt.pro file in it.
- In the project settings (button on the left) select the platforms you are interested in. E.g.:

<img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_qt/Qt_platforms.png" >


- After that, select the platform and compiling mode. For example, for Android, the debug version:

<img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/iotkit_qt/Qt_mode:version.png" >

- Next, connect your device and start execution or debugging.

## Run Demo-iotkit-qt
This application will provide you with the list of Gateways and Thing devices that demo-iotkit-qt can detect. It
searches for the IoT of the device in the local network, to which the mobile device or the stationary platform on which
the application is running has access. IoT devices should use the Virgil IoTKIT library for interoperability. You can
find examples of Gateway-, Thing- and other devices for UNIX / Linux platforms in the open github repository [demo-iotkit-nix](https://github.com/VirgilSecurity/demo-iotkit-nix/).

## License

This demo and Virgil IoTKIT are released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email at support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
