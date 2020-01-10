# Virgil IoTKit Qt Integration
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](https://virgilsecurity.github.io/virgil-iotkit/)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-iotkit/release/LICENSE)



<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/iotkit/IoTKit.png" align="left" hspace="1" vspace="3"></a>

## Introduction
[Virgil Security](https://virgilsecurity.com) provides a set of APIs for adding security to any application or IoT device.

Virgil IoTKit is a C library for connecting IoT devices to the Virgil IoT Security Platform. IoTKit helps you easily add security to your IoT devices at any lifecycle stage for securely provisioning and authenticating devices, updating firmware and TrustLists, and exchanging messages using any transport protocols.

This is Virgil IoTKit C library wrapper for C++ b`sed on Qt crossplatform framework.

## Content
- [Features](#features)
- [Installation](#installation)
- [Usage example](#example)
- [API Reference](#api-reference)
- [License](#license)
- [Support](#support)

<div id='features'/>

## Features
Virgil IoTKit Qt framework предоставляет следующие возможности:
- **Snap Protocol**. Основой взаимодействия между Virgil IoT устройствами является SNAP protocol. IoTKit Qt framework предоставляет базовый класс для создания собственных имплементаций и предоставляет UDP Broadcast implementation.
- **INFO Client**. SNAP protocol предоставляет основу для создания различных сервисов. INFO - сервис для сбора информации об активнхы устройствах в сети - их версии, статистическая информация и т. д. INFO Server - это конечное устройства, которое передает свое состояние. INFO CLient - это устройство, собирающее информацию по сети. IoTKit Qt framework предоставляет класс для работы INFO Client сервиса.
- **Sniffer**. IoTKit Qt framework предоставляет sniffer для чтения всех Virgil IoTKit пакетов, передающихся в данной сети.
- **Простая конфигурация и инициализация IoTKit Qt framework**. IoTKit Qt framework построен на базе паттерна "фасад". Класс VSQIoTKitFacade является объектом, который скрывает в себе все объекты библиотеки. При старте он получает полную информацию о библиотеке - какие интерфейсы использовать, какие будут использованы возможности, настройки отдельных модулей и т. д. Также есть единый umbrella header VSQIoTKit.h со всеми модулями библиотеки.
- **Поддержка QML**. Все элементы IoTKit Qt framework созданы для использования в QML-проекте. Вы можете строить списки с моделью данных на основе INFO Client и Sniffer. Все последующие имплементации также будут поддерживать эту технологию.
- **Кроссплатформенность**. Library is implemented on C++14 classes based on Qt crossplatform library. Поддерживаются платформы desktop, Android, iOS, Windows Mobile и пр.

<div id='installation'/>

## Installation
- Virgil IoTKit Qt framework является частью библиотеки Virgil IoTKit. Поэтому вначале устанавливается эта библиотека.
- Далее необходимо установить Qt Framework версии 5.12.6 or higher.
- Следующим шагом является компиляция Virgil IoTKit для целевой платформы. Для этого используется скрипт scripts/build-for-qt.sh and indicate the preferred platform. Example:
  - To get a library for Android: ext/virgil-iotkit/scripts/build-for-qt.sh android armeabi-v7a
  - To get a library for iOS library: ext/virgil-iotkit/scripts/build-for-qt.sh ios
  - To get a library for Linux library: ext/virgil-iotkit/scripts/build-for-qt.sh linux
  - To get a library for MacOS library: ext/virgil-iotkit/scripts/build-for-qt.sh mac
  - To get a library for Windows library: ext/virgil-iotkit/scripts/build-for-qt.sh windows

<div id='example'/>

## Usage example

Virgil IoTKit Qt framework подключается файлом integration/qt/iotkit.pri.

Инициализация Virgil IoTKit Qt framework в C++-коде может быть реализована следуюищм образом:
```cpp
int
VirgilIoTKitQtInit() {
    QQmlApplicationEngine engine;

    auto features = VSQFeatures() << VSQFeatures::SNAP_INFO_CLIENT << VSQFeatures::SNAP_SNIFFER;    // Use INFO Client and Sniffer features
    auto impl = VSQImplementations() << QSharedPointer<VSQUdpBroadcast>::create();                  // Use UDP Broadcast
    auto roles = VSQDeviceRoles() << VirgilIoTKit::VS_SNAP_DEV_CONTROL;                             // Device has CONTROL role
    auto appConfig = VSQAppConfig() << VSQManufactureId() << VSQDeviceType() << VSQDeviceSerial()
                                    << VirgilIoTKit::VS_LOGLEV_DEBUG << roles << VSQSnapSnifferQmlConfig(); // Device is configured with default options, logger level is DEBUG

    if (!VSQIoTKitFacade::instance().init(features, impl, appConfig)) {                             // Try to initialize Virgil IoTKit Qt Framework
        VS_LOG_CRITICAL("Unable to initialize Virgil IoT KIT");
        return -1;
    }

    QQmlContext *context = engine.rootContext();
    context->setContextProperty("SnapInfoClient", &VSQSnapInfoClientQml::instance());               // Register INFO Client and "SnapInfoClient" data model for QML's ListView
    context->setContextProperty("SnapSniffer", VSQIoTKitFacade::instance().snapSniffer());          // Register SNAP Sniffer and "SnapSniffer" data model for QML's ListView

    const QUrl url(QStringLiteral("qrc:/qml/Main.qml"));                                            // Use qml/main.qml for main QML object
    engine.load(url);

    return QGuiApplication::instance()->exec();                                                     // Start QML application
}
```

В данном примере подключатся необходимые модули и запускается QML-приложение. Этот код является частью открытого примера использования Virgil IoTKit Qt framework : [Demo IoTKit Qt](https://github.com/VirgilSecurity/demo-iotkit-qt/)


<div id='api-reference'/>

## API Reference
Virgil IoTKit Qt framework является частью Virgil IoTKit. C++-классы имеют префикс VSQ. Например, паттерн "фасад" реализуется классом VSQIoTKitFacade.h. См. [API Reference of IoTKit](https://virgilsecurity.github.io/virgil-iotkit/)

<div id='license'/>

## License

This library is released under the [3-clause BSD License](LICENSE).

<div id='support'/>

## Support
Our developer support team is here to help you. Find more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us an email at support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
