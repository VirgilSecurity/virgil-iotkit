# Virgil IoTKit Qt Integration
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](https://virgilsecurity.github.io/virgil-iotkit/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iotkit/release/LICENSE)



<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/iotkit/IoTKit.png" align="left" hspace="1" vspace="3"></a>

## Introduction
Virgil IoTKit Qt integration is a C library wrapper for C++ based on Virgil IoTKit security framework and [Qt crossplatform framework](https://www.qt.io/). Such combination allows developers to run Sandbox on desktop or mobile devices to communicate with IoT devices.

- **Virgil IoTKit** is a C library for connecting IoT devices to the Virgil IoT Security Platform. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for securely provisioning and authenticating devices, updating firmware and TrustLists, and exchanging messages using any transport protocols.
- **Qt** is a crossplatform framework for creating modern console and GUI applications. It supports wide range of desktop and mobile platforms like Windows, Linux, MacOS, Android, iOS etc.

## Content
- [Features](#features)
- [Installation](#installation)
- [Usage example](#example)
- [API Reference](#api-reference)
- [License](#license)
- [Support](#support)

<div id='features'/>

## Features
Virgil IoTKit Qt framework provides you with the following possibilities:
- **Snap Protocol**. The basis of interaction between Virgil IoT devices is the SNAP protocol. IoTKit Qt framework provides you with the VSQNetifBase basic class for personal implementations creation and UDP Broadcast implementation.
- **INFO Client**. SNAP protocol gives you the basis for different services building. INFO Service allows for active devices to broadcast their versions, statistical information etc. INFO Server is the end device, which transmits its state. INFO Client is a device that collects information over a network. IoTKit Qt framework provides you with the VSQSnapInfoClient class for INFO Client service operation and the VSQSnapInfoClientQml class for use it directly in QML files.
- **Sniffer**. IoTKit Qt framework provides you with a sniffer for all Virgil IoTKit packets scanning inside of the network.
- **Simple configuration and initialization of IoTKit Qt framework**. IoTKit Qt framework uses the "facade" pattern. VSQIoTKitFacade class is an object which consists of all framework entities. During the startup it gets full information about the library - which interfaces should be used, which solutions will be used, separate modules settings etc. There is also an unifying umbrella header VSQIoTKit.h with all framework modules except default implementations.
- **QML Support**. All IoTKit Qt framework classes are created to be used in QML project. You can build lists with a data model based on INFO Client and Sniffer. All future implementations will also support this technology.
- **Cross-platform**. Library is implemented on C++ classes based on Qt cross-platform library. Different desktop and mobile platforms like Linux, MacOS, Windows, Android, iOS are supported.

<div id='installation'/>

## Installation
- Virgil IoTKit Qt framework is a part of Virgil IoTKit library. Therefore, this library has to be installed first.
- Next you need to install Qt Framework version 5.12.6 or higher.
- After that you should compile Virgil IoTKit for the necessary platform. To do this, use the script `scripts/build-for-qt.sh` and indicate the preferred platform. Example:
  - To get a library for Android: `ext/virgil-iotkit/scripts/build-for-qt.sh android armeabi-v7a`
  - To get a library for iOS library: `ext/virgil-iotkit/scripts/build-for-qt.sh ios`
  - To get a library for iOS-simulator: `ext/virgil-iotkit/scripts/build-for-qt.sh ios-sim`
  - To get a library for Linux library: `ext/virgil-iotkit/scripts/build-for-qt.sh linux`
  - To get a library for MacOS library: `ext/virgil-iotkit/scripts/build-for-qt.sh macos`
  - To get a library for Windows library: `ext/virgil-iotkit/scripts/build-for-qt.sh windows`
  - To get a library for Windows by using mingw32 on another host platform : `ext/virgil-iotkit/scripts/build-for-qt.sh mingw32`

<div id='example'/>

## Usage example

Virgil IoTKit Qt framework is tapped by integration/qt/iotkit.pri file.

Virgil IoTKit Qt framework initialization in C++ code can be performed as listed below:
```cpp
int
VirgilIoTKitQtInit() {
    QQmlApplicationEngine engine;

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT << VSQFeatures::SNAP_SNIFFER;    
    // Use INFO Client and Sniffer features
    auto impl = VSQImplementations() << QSharedPointer<VSQUdpBroadcast>::create();                  
    // Use UDP Broadcast
    auto roles = VSQDeviceRoles() << VirgilIoTKit::VS_SNAP_DEV_CONTROL;                             
    // Device has CONTROL role
    auto appConfig = VSQAppConfig() << VSQManufactureId() << VSQDeviceType() << VSQDeviceSerial()
                                    << VirgilIoTKit::VS_LOGLEV_DEBUG << roles << VSQSnapSnifferQmlConfig();
                                    // Device is configured with default options, logger level is DEBUG

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {                             
      // Try to initialize Virgil IoTKit Qt Framework
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
        return -1;
    }

    QQmlContext *context = engine.rootContext();
    context->setContextProperty("SnapInfoClient", &VSQSnapInfoClientQml::instance());               
    // Register INFO Client and "SnapInfoClient" data model for QML's ListView
    context->setContextProperty("SnapSniffer", VSQIoTKitFacade::instance().snapSniffer());          
    // Register SNAP Sniffer and "SnapSniffer" data model for QML's ListView

    const QUrl url(QStringLiteral("qrc:/qml/Main.qml"));                                            
    // Use qml/main.qml for main QML object
    engine.load(url);

    return QGuiApplication::instance()->exec();                                                     
    // Start QML application
}
```

In this example you connect necessary modules and launch the QML application. This code is a part of open Virgil IoTKit Qt framework use-case: [Demo IoTKit Qt](https://github.com/VirgilSecurity/demo-iotkit-qt/).

<div id='api-reference'/>

## API Reference
Virgil IoTKit Qt framework is a part of Virgil IoTKit. C++ classes have VSQ prefix. E.g. "facade" pattern is implemented as VSQIoTKitFacade class. See [API Reference of IoTKit](https://virgilsecurity.github.io/virgil-iotkit/)

<div id='license'/>

## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email at support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
