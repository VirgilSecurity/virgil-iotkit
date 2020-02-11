# Virgil Trust Provisioner
The Virgil Trust Provisioner is a command-line interface (CLI) utility used to manage your distributed trust between all parties, including IoT devices, in your IoT solutions.

## Features
- Generating and managing upper level key pairs for IoT parties
- Generating and managing TrustLists
- Provides databases for storing keys and TrustLists
- Creating and registering upper level Virgil Cards for IoT parties with the Virgil Security Platform

## Content
- [Virgil Trust Provisioner](#virgil-trust-provisioner)
    - [Features](#features)
    - [Content](#content)
    - [Trust Provisioner Overview](#trust-provisioner-overview)
    - [Setting up Trust Provisioner](#setting-up-trust-provisioner)
        - [Install Trust Provisioner](#install-trust-provisioner)
            - [Linux OS](#linux-os)
            - [Ubuntu OS, Debian OS](#ubuntu-os-debian-os)
            - [CentOS, Fedora OS](#centos-fedora-os)
            - [Mac OS](#mac-os)
            - [Windows OS](#windows-os)
        - [Configure Trust Provisioner](#configure-trust-provisioner)
            - [Config File Structure](#config-file-structure)
            - [Configurable Variables](#configurable-variables)
    - [Launch Trust Provisioner](#launch-trust-provisioner)
    - [Command Reference](#command-reference)
        - [Syntax](#syntax)
        - [Application Commands](#application-commands)
        - [Private Keys](#private-keys)
        - [TrustList](#trustlist)
        - [Trust Provisioner Database](#trust-provisioner-database)
    - [Private Keys Commands](#private-keys-commands)
        - [Initial Generation (get everything at once)](#initial-generation-get-everything-at-once)
        - [Recovery Key](#recovery-key)
            - [Generating Recovery Key](#generating-recovery-key)
        - [Auth Key](#auth-key)
            - [Generating Auth Key](#generating-auth-key)
        - [TrustList Key](#trustlist-key)
            - [Generating TrustList Key](#generating-trustlist-key)
        - [Factory Key](#factory-key)
            - [Generating Factory Key](#generating-factory-key)
            - [Deleting Factory Key](#deleting-factory-key)
        - [Firmware Key](#firmware-key)
            - [Generating Firmware Key](#generating-firmware-key)
    - [TrustList Commands](#trustlist-commands)
        - [TrustList Overview](#trustlist-overview)
        - [TrustList Content](#trustlist-content)
        - [TrustList structure](#trustlist-structure)
        - [TrustList Management](#trustlist-management)
        - [TrustList Generation](#trustlist-generation)
        - [TrustList Uploading](#trustlist-uploading)
        - [TrustList Distribution](#trustlist-distribution)
    - [Trust Provisioner Database](#trust-provisioner-database-1)
        - [Database Types](#database-types)
        - [Database Security](#database-security)
        - [Database Commands](#database-commands)
            - [Print public keys from database](#print-public-keys-from-database)
            - [Add Public Keys to Database](#add-public-keys-to-database)
            - [Export data as provision package for Factory](#export-data-as-provision-package-for-factory)
            - [Export upper level public keys](#export-upper-level-public-keys)
            - [Export Private Keys](#export-private-keys)

## Trust Provisioner Overview
Virgil Trust Provisioner deals with key pair and TrustList generation and management, which together make each IoT device identifiable, verifiable and trusted by each party within the IoT solution.

In this connected world, IoT devices interact with many services and applications in order to provide valuable features for end-users. At the same time, it's important that each IoT device is protected from unauthorized access at any given lifecycle stage. In order to achieve this, each party and process within the IoT system needs to be identifiable, verifiable and trusted.

The diagram below demonstrates a standard IoT infrastructure and all its participants, or parties, that need to be identifiable and verifiable as a part of distributed trust system.

<img width="100%" src="https://cdn.virgilsecurity.com/assets/images/github/provisioner.jpg" align="left" hspace="3" vspace="6"> &nbsp;



| Participant            | Role                                                                                                                                                                 |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Auth and Recovery Keys | Upper Level keys that are responsible for managing secure TrustLists and the participants' key pairs                                                                 |
| Firmware service       | Service is responsible for creating, storing and distributing firmware                                                                                               |
| TrustList             | TrustList is a distributed list of trust contained in a file that consists of public keys and signatures of all trusted parties in the IoT system |
| TrustList service     | Service is responsible for creating, storing and distributing TrustList                                                                                            |
| Factory                | Place where all IoT devices are manufactured and go through the provisioning step                                                                                    |
| Cloud                  | Cloud service that is responsible for authorizing and authenticating users and applications.                                                                       |

Virgil Trust Provisioner helps you to build up a trusted IoT solution ecosystem by creating and managing the key pairs and a distributed TrustList for all participants. Then the keys and TrustList are distributed to all participants (e.g. IoT devices, user application, etc.). As a result, each participant uses the TrustList while interacting with each other to verify whether the participant is authorized to perform a given operation.

## Setting up Trust Provisioner
This section demonstrates how to install and configure the Virgil Trust Provisioner for your platform of choice.

### Install Trust Provisioner
This section provides instructions for installing the Virgil Trust Provisioner.

#### Linux OS
Virgil Trust Provisioner is distributed as a package.

In order to download and install the Virgil Trust Provisioner on Linux, use the YUM package manager and the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```

#### Ubuntu OS, Debian OS
Virgil Trust Provisioner is distributed as a package.

In order to download and install the Virgil Trust Provisioner on Ubuntu, Debian, use the YUM package manager and the following command:

```bash
$ sudo apt-get install virgil-iot-sdk-tools
```

#### CentOS, Fedora OS
Virgil Trust Provisioner is distributed as a package.

In order to download and install the Virgil Trust Provisioner on CentOS, Fedora, use the YUM package manager and the following command:

```bash
$ sudo yum install virgil-iot-sdk-tools
```
#### Mac OS
In order to download and install the Virgil Trust Provisioner on Mac OS, use [pip](https://pip.pypa.io/en/stable/) and run the following commands:

```bash
$ git clone https://github.com/VirgilSecurity/virgil-iotkit.git
$ cd virgil-iotkit/tools/virgil-trust-provisioner
$ pip3 install .
```

#### Windows OS
Virgil Trust Provisioner package for Windows OS is currently in development. To join our mailing list to receive updates, please contact our support team at support@VirgilSecurity.com.


### Configure Trust Provisioner
After the Trust Provisioner is installed, you need to set up the **provisioner.conf** file. By default, **provisioner.conf** file is placed in **/etc/virgil-trust-provisioner/provisioner.conf**. While it is there, you don't have to specify the path to the config file every time you launch the Trust Provisioner:

```bash
virgil-trust-provisioner -c samples/provisioner.conf
```
To avoid having to specify the Virgil Trust Provisioner's configuration file every time you launch it, place the **provisioner.conf** file into the following repository on your device:

- /etc/virgil-trust-provisioner/provisioner.conf

#### Config File Structure
By default, the Virgil Trust Provisioner configuration file has the following format:

```bash
[MAIN]
# path to main storage folder
storage_path = ~/virgil-trust-provisioner

# path to folder for logs
log_path = ~/virgil-trust-provisioner/logs

# path to provision package folder
provision_pack_path = ~/virgil-trust-provisioner/provision-package

[VIRGIL]
# URL of Virgil IoT API. Used for Cloud key retrieving and cards registration.
iot_api_url = https://api-iot.virgilsecurity.com
```
#### Configurable Variables
The configuration file (default name: **provisioner.conf**) contains the following variables:

| Name                       | Description                                                                                                                  |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------|
| storage_path               | The path to the main Virgil Trust Provisioner directory. Storage for Virgil Trust Provisioner databases and TrustList files. |
| log_path                   | The path to the folder for logs  |
| provision_pack_path | Path to provision package folder.          |
| iot_api_url             | URL of Virgil IoT API. URL https://api-iot.virgilsecurity.com is by default.                                       |

**Factory JSON file example**
```bash
{
    "name": "Sample Factory Name",
    "address": "sample address",
    "contacts": "sample_factory@some_mail.com"
}
```
## Launch Trust Provisioner
To launch the Virgil Trust Provisioner use the following syntax:

```bash
virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>
```
If you need to specify a path to the custom config file, use following syntax:

```bash
virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO> -c ./provisioner.conf
```
| Option                              | Description                                                                                                                                                                  |
|-------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --app-token , -t                    | Application token (App token) is used for authentication on the Virgil Cloud to register Virgil Cards for Upper Level keys. To generate an application token use the Virgil CLI. |
| -c CONFIG_PATH,--config CONFIG_PATH | The path to the custom configuration file of the Virgil Trust Provisioner                                                                                                        |
| -i FACTORY_INFO, --factory-info FACTORY_INFO | Path to JSON with factory info (Information about factory will be added to factory's digital Virgil Card)                                                                                                        |
| -y, --skip-confirm | Skip all confirmation requests                                                                                                 |


## Command Reference
Here is the list of possible commands for Virgil Trust Provisioner:

### Syntax
```bash
virgil-trust-provisioner
```
Use  virgil-trust-provisioner --help to get information about a specific command.

### Application Commands
Application commands are used to perform operations such as key generating, database (db) operations and printing options.

### Private Keys
| Command | Result                                                                                                                       |
|---------|------------------------------------------------------------------------------------------------------------------------------|
| ```1```       | Initial Generation. One by one generation of 2 Recovery Keys, 2 Auth Keys, 2 TL Keys, 2 Firmware Keys, 1 Factory Key |
| ```2```       | Generate 2 Recovery Keys                                                                                                     |
| ```3```       | Generate 2 Auth Keys                                                                                                         |
| ```4```       | Generate 2 keys of TrustList (TL) Service                                                                                   |
| ```5```       | Generate a Factory Key                                                                                                       |
| ```6```       | Delete a Factory Key                                                                                                         |
| ```7```       | Generate 2 Firmware Keys                                                                                                     |

### TrustList
| Command | Result                                                           |
|---------|------------------------------------------------------------------|
| ```8```      | Generate a TrustList and store it in Virgil Trust Provisioner db |

### Trust Provisioner Database
| Command | Result                         |
|---------|--------------------------------|
| ```9```      | Print all public keys from db  |
| ```10```      | Add public key to db           |
| ```11```      | Export data as provision package for factory |
| ```12```      | Export upper level public keys |
| ```13```      | Export private keys            |


## Private Keys Commands
This deals with the generation, exchange, storage, use and replacement of keys.

Each private key has its own card that contains a public part of the key. The card is registered in the Virgil Card Service.

### Initial Generation (get everything at once)
This command allows you to generate all keys for the entire key management infrastructure.

| Command | Result                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------|
| ```1```       | Virgil Trust Provisioner generates 2 Recovery Keys, 2 Auth Keys, 2 TL Keys, 2 Firmware Keys, 1 Factory Key one by one |

User is able to make decisions and leave comments about all CLI actions within Initial Generation process.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command

$ Please enter option number: 1
$ Are you sure you want to choose [Initial Generation (2 Recovery, 2 Auth, 2 TL Service, 2 Firmware, 1 Factory)] [y/n]: y
# Infrastructure already exists. Do you want to DROP and re-create it?
$ Drop infrastructure? [y/n]: y

# Cleaning all data...
# Data cleaned

# Recovery Key 1:

# Generating Recovery Key...
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Recovery Key: My 1 recovery key
# Virgil Card for key successfully registered
# Generation finished

# Recovery Key 2:

# Generating Recovery Key...
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Recovery Key: My 2 recovery
# Virgil Card for key successfully registered
# Generation finished

# Auth Key 1:

# Generating Auth Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My 2 recovery, key_id: 12842
	2. db: RecoveryPrivateKeys, type: recovery, comment: My 1 recovery key, key_id: 59294
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Auth Key: My 1 Auth key
# Virgil Card for key successfully registered
# Generation finished

# Auth Key 2:

# Generating Auth Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My 2 recovery, key_id: 12842
	2. db: RecoveryPrivateKeys, type: recovery, comment: My 1 recovery key, key_id: 59294
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Auth Key: My 2 Auth key
# Virgil Card for key successfully registered
# Generation finished

# TrustList Key 1:

# Generating TrustList Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My 2 recovery, key_id: 12842
	2. db: RecoveryPrivateKeys, type: recovery, comment: My 1 recovery key, key_id: 59294
# Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
#  Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for TrustList Key: My 1 TL key
# Virgil Card for key successfully registered
# Generation finished

# TrustList Key 2:

#Generating TrustList Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My 2 recovery, key_id: 12842
	2. db: RecoveryPrivateKeys, type: recovery, comment: My 1 recovery key, key_id: 59294
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for TrustList Key: My 2 TL key
# Virgil Card for key successfully registered
# Generation finished

# Firmware Key 1:

# Generating Firmware Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My 2 recovery, key_id: 12842
	2. db: RecoveryPrivateKeys, type: recovery, comment: My 1 recovery key, key_id: 59294
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Firmware Key: My 1 Firmware key
# Virgil Card for key successfully registered
# Generation finished

# Firmware Key 2:

# Generating Firmware Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My 2 recovery, key_id: 12842
	2. db: RecoveryPrivateKeys, type: recovery, comment: My 1 recovery key, key_id: 59294
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Firmware Key: My 2 Firmware key
# Virgil Card for key successfully registered
# Generation finished

# Factory Key:

# Generating Factory Key...

$ Enter the signature limit number from 1 to 4294967295 [4294967295]: 12313
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 30
$ Year: 2019, Month: 10, Day: 30. Confirm? [y/n] y
$ Enter expiration date? [y/n]: n
$ Enter comment for Factory Key: My Factory key
# Virgil Card for key successfully registered
# Generation finished
```

### Recovery Key
The upper level key for recovery operations and for some keys creation. Recovery Key allows devices to identify Keys authorised by User. Recovery Key signs Auth Keys, TL Keys, Firmware Keys.

| Command | Result                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------|
| ```2```      | Virgil Trust Provisioner generates 2 Recovery keys |

#### Generating Recovery Key
Recovery Keys are used to sign other types of keys, and are known by every device. The public key is stored in TrustList and the private key is stored in db.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command

# Please enter option number:
$ 2

$ Are you sure you want to choose [Generate Recovery Key (2)] [y/n]: y

# Generate Recovery Key 1:
# Generating Recovery Key...
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
$ Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for Recovery Key: My recovery key
# Virgil Card for key successfully registered
# Generation finished
```
### Auth Key
The Auth Key is trusted as the second signer of the firmware and TrustLists.

| Command | Result                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------|
| ```3```      | Virgil Trust Provisioner generates 2 Auth Keys  |

#### Generating Auth Key
After Auth Keys are generated they have to be signed with one of the Recovery keys. You also can add a comment about the Key purpose. Auth Key guards against the unauthorized use of firmware and TrustList. Auth Keys sign firmwares and the TrustLists. Public key is stored in the TrustList and the private key is stored in db.

**Example**

```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command

$ Please enter option number: 3
$ Are you sure you want to choose [Generate Auth Key (2)] [y/n]: y

# Generate Auth Key 1:

# Generating Auth Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My recovery key, key_id: 2591
	2. db: RecoveryPrivateKeys, type: recovery, comment: My second recovery key, key_id: 59802
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for Auth Key: My Auth key
# Virgil Card for key successfully registered
# Generation finished

# Generate Auth Key 2:

# Generating Auth Key...
# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My recovery key, key_id: 2591
	2. db: RecoveryPrivateKeys, type: recovery, comment: My second recovery key, key_id: 59802
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for Auth Key: My second Auth key
# Virgil Card for key successfully registered
# Generation finished
```

### TrustList Key
The TL key is the primary signer of the TrustLists. The TL Key is trusted because it is signed by a Recovery key.

| Command | Result                                       |
|---------|----------------------------------------------|
| ```4```       | Virgil Trust Provisioner generates 2 TL keys |

#### Generating TrustList Key
The TL key is trusted because it is signed by a Recovery key. Key Infrastructure needs two key pairs of the TL key.  Public key is stored in TrustList and private key is stored in db.

**Example**
```bash
$ Please enter option number: 4
$ Are you sure you want to choose [Generate TrustList Key (2)] [y/n]: y

# Generate TrustList Key 1:

# Generating TrustList Key...

# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My recovery key, key_id: 2591
	2. db: RecoveryPrivateKeys, type: recovery, comment: My second recovery key, key_id: 59802
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for TrustList Key: My TL key    
# Virgil Card for key successfully registered   
# Generation finished

# Generate TrustList Key 2:

# Generating TrustList Key...

# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My recovery key, key_id: 2591
	2. db: RecoveryPrivateKeys, type: recovery, comment: My second recovery key, key_id: 59802
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for TrustList Key: My second TL key
# Virgil Card for key successfully registered
# Generation finished
```
### Factory Key
Factory key signs devices and guarantees official device distribution from the factory. Signature indicates that the manufacture of a device was authorized.

| Command | Result                                                                 |
|---------|------------------------------------------------------------------------|
| ```5```       | Virgil Trust Provisioner generates factory key and stores it in own db |
| ```6```       | Virgil Trust Provisioner deletes factory key from own db               |

#### Generating Factory Key
After factory key is generated, private key is stored in private keys db and public key is stored in TrustList. Also, factory key has a signature number limit that allows you to prevent uncountable device release at the factory  (```4294967295```) and is stored in ```FactoryPrivateKeys.db.```

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command
$ Please enter option number: 5

$ Are you sure you want to choose [Generate Factory Key] [y/n]: y

# Generating Factory Key...

$ Enter the signature limit number from 1 to 4294967295 [4294967295]: 32323232        
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for Factory Key: My Factory key
# Virgil Card for key successfully registered
# Generation finished
```

#### Deleting Factory Key
This command allows you to remove the factory key from the Virgil Trust Provisioner factory keys db FactoryPrivateKeys.db. Remember to release the new TrustList after deleting factory key and update it on IoT devices.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command
$ Please enter option number: 6
$ Are you sure you want to choose [Delete Factory Key] [y/n]: y
# Deleting Factory Key...
# Factory Keys:
	1. factory_name: My Factory key
$ Please choose Factory Key to delete: 1
# Factory Key deleted
```
### Firmware Key
The firmware key is trusted as the primary signer of firmware and has no other capabilities.

| Command | Result                                                                 |
|---------|------------------------------------------------------------------------|
| ```7```       | Virgil Trust Provisioner generates 2 firmware keys |

#### Generating Firmware Key
Firmware keys are stored on selected devices. They are signed by a recovery key.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command

$ Please enter option number: 7
$ Are you sure you want to choose [Generate Firmware Key (2)] [y/n]: y

# Generate Firmware Key 1:

# Generating Firmware Key...

# Please choose Recovery Key for signing:
# Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My recovery key, key_id: 2591
	2. db: RecoveryPrivateKeys, type: recovery, comment: My second recovery key, key_id: 59802
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for Firmware Key: My Firmware key
# Virgil Card for key successfully registered
# Generation finished

# Generate Firmware Key 2:

# Generating Firmware Key...

$ Please choose Recovery Key for signing:
$ Keys list:
	1. db: RecoveryPrivateKeys, type: recovery, comment: My recovery key, key_id: 2591
	2. db: RecoveryPrivateKeys, type: recovery, comment: My second recovery key, key_id: 59802
$ Please enter option number: 1
$ Add start and expiration date for key? [y/n]: y
# Please choose start date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 10
$ Enter day (1-31): 29
$ Year: 2019, Month: 10, Day: 29. Confirm? [y/n] y
$ Enter expiration date? [y/n]: y
# Please choose expiration date for key
$ Enter year (yyyy): 2019
$ Enter month (1-12): 12
$ Enter day (1-31): 31
$ Year: 2019, Month: 12, Day: 31. Confirm? [y/n] y
$ Enter comment for Firmware Key: My second Firmware key
# Virgil Card for key successfully registered
# Generation finished
```
## TrustList Commands
Distributed list of trust that is used by IoT devices and applications to check Information about trusted parties.

### TrustList Overview
TrustList is a distributed list of trust that introduced in way of a file that consists of public keys and signatures of all trusted parties in the your IoT system.

TrustList has basic content structure that was created based on general best security practices, but the final number of trusted participants in the TrustList is determined by you.

After the TrustList is created and signed, it's distributed to all participants (e.g. IoT devices, User Application, etc),  as a result each participant uses the TrustList while interacting with each other to verify wether the participant is authorized to do some operation.

### TrustList Content
Each TrustList contains the following information:

| Information type | Value                                                |
|------------------|------------------------------------------------------|
| Public Keys      | - Cloud Public Key(s) - Factory Public Key(s)        |
| Signatures       | - Signature of TrustList Key - Signature of Auth Key |

### TrustList structure
TrustList has the following structure:

```bash
type TrustListContainer struct {
    Header           Header
    PubKeysStructure []PubKeyStructure
    Footer           Footer
}

type Header struct {
    WholeTLSize      uint32
    Version          FileVersion
    PubKeysCount     uint16
    SignaturesCount  uint8
}

type PubKeyStructure struct {
    StartDate           uint32
    ExpirationDate      uint32
    KeyType             uint8
    ECType              uint8
    MetadataSize        uint16
    MetadataAndPubKey   [MetadataSize+PublicKeySize]byte
}

type Footer struct {
    TLType        uint8
    Signatures    [SignaturesCount]Signature
}

type Signature struct {
    SignerType               uint8
    ECType                   uint8
    Hash_type                uint8
    SignAndSignerPublicKey   [SignSize+PublicKeySize]byte
}

type FileVersion struct {
    Major           uint8
    Minor           uint8
    Patch           uint8
    Build           uint32
    Timestamp       uint32
}
```

### TrustList Management
Distributed list of trust which contains keys information and is used by IoT devices and applications to check trust information about IoT parties.

| Code | Result                                             |
|------|----------------------------------------------------|
| ```8```   | Virgil Trust Provisioner generates TrustList file |

### TrustList Generation
TrustList that contains public keys (factory and Cloud) and signatures (Auth Key and TL Key) of all critical system elements.  All public keys in TrustList are stored in TrustListPubKeys.db.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command

$ Please enter option number: 8
$ Are you sure you want to choose [Generate TrustList] [y/n]: y

# Generating TrustList...

# Current TrustList version is 0.0.0.0
$ Enter the TrustList version [1]: 1.0.0.0
# Please choose Auth Key for TrustList signing:
# Keys list:
	1. db: AuthPrivateKeys, type: auth, comment: My Auth key, key_id: 17326
	2. db: AuthPrivateKeys, type: auth, comment: My second Auth key, key_id: 56318
$ Please enter option number: 1
$ Please choose TrustList Key for TrustList signing:
# Keys list:
	1. db: TLServicePrivateKeys, type: tl_service, comment: My second TL key, key_id: 3847
	2. db: TLServicePrivateKeys, type: tl_service, comment: My TL key, key_id: 64076
$ Please enter option number: 1
# Generation finished
# Storing to file...
# File stored
# TrustList generated and stored in the file storage cpecified in a config file
```

### TrustList Uploading
TrustList updating is a release of the new TrustList. This function is used in case you need to change information about any key, re-generate key or add any new key. You need to create and release the new TrustList and distribute it to your IoT devices. In this case you need to use command ```10``` and distribute the new TrustList to your IoT device.

### TrustList Distribution
This section describes how to distribute a TrustList to IoT devices.

Once you generated your TrustList, you are able to distribute it to all your IoT devices via the Virgil Cloud. IoT devices will get notification as soon as they get online. In order to upload TrustList to the Virgil Cloud you have to run the `publish-trustlist.sh` script from the [scripts folder](https://github.com/VirgilSecurity/virgil-iotkit/tree/master/scripts) of Virgil IoTKit.

Here is how it works:
- First of all you have to install [jq](https://stedolan.github.io/jq/download/) library.
- Then navigate to your terminal (cli) and run the `publish-trustlist.sh` from scripts folder.

```bash
$ ./scripts/publish-firmware.sh --tl-file  [path to TrustList file] --app-token [Virgil AppToken]
```

- Once the TrustList uploaded to Virgil Cloud, an IoT gateway gets notification about new TrustList.
- Then IoT gateway gets new TrustList, verifies its signatures (signatures of Firmware and Auth Keys) and installs it.
- At the same time, IoT gateway distributes TrustList to all IoT devices.
- Every IoT device also verifies TrustList signatures and installs it.  


## Trust Provisioner Database
This page contains information about Virgil Trust Provisioner database.

### Database Types
Virgil Trust Provisioner contains following types of databases.

| Database type            | Description                                                                                                                           |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| ```UpperLevelKeys.db```       | contains public keys of high-level keys (Recovery public keys, Auth public Keys, TrustList public keys, Firmware public keys) |
| ```TrustListPubKeys.db```     | contains public keys of Factory,  and cloud                                                           |
| ```TrustListVerions.db```    | contains versions of created TrustLists                                                                                              |
| ```FactoryPrivateKeys.db```   | contains private key of Factory key                                                                                                   |
| ```FirmwarePrivateKeys.db```  | contains private key of Firmware key                                                                                                  |
| ```AuthPrivateKeys.db```      | contains private key of Auth key                                                                                                      |
| ```RecoveryPrivateKeys.db```  | contains private key of Recovery key                                                                                                  |
| ```TLServicePrivateKeys.db``` | contains private key of TrustList key                                                                                          |
### Database Security
Virgil Trust Provisioner doesn't provide any security mechanism for protecting databases, therefore it is very important to restrict access to Virgil Trust Provisioner for non authorized users.


###  Database Commands

#### Print public keys from database
This function helps to print all public keys from db.

| Code | Result                                             |
|------|----------------------------------------------------|
| ```9```   | Virgil Trust Provisioner provides all public keys from db to the user |

You can print all public keys from Virgil Trust Provisioner database on the screen or on the paper.

**Example**

```bash
$ Please enter option number: 9
$ Are you sure you want to choose [Print all Public Keys from db's] [y/n]: y
# Printing Public Keys from db's...

# Upper level Keys:
+--------+------------+--------------------------+-----------+-----------+-----------+------------------------------------------------------------------------------------------+
| Key Id |    Type    |         Comment          | Signed by |   Start   |   Expire  |                                           Key                                            |
+--------+------------+--------------------------+-----------+-----------+-----------+------------------------------------------------------------------------------------------+
| 59802  |  recovery  |  My second recovery key  |           |     0     |     0     | BDHLav5qUoU2I0vkR5hxcKlGv8MFF8CqzmkCCr7UOroVaqNK0mRncZ0dSebW4xM9GmWpUPEaGdqfewaLPeszL8E= |
|  3847  | tl_service | My second TL key |    2591   | 152236800 | 157680000 | BLVkY5A6k4hgAw/auNgJUOR07eDoVn+4aeAdqgn3XlapJr1E6R6+1ALw9my9EjaILFYq/2oMAPeNdwqSOfLvx2o= |
|  8079  |  firmware  |     My Firmware key      |    2591   | 152236800 | 157680000 | BOBzJhYo9H4Zt8jpYBXOHU90UdDyRJ4EC0Jeaqn7tgXzzMa6PkvUSrS5Rpc9PR4Ljeot/a+6BE+A0rEVJ1LcUjY= |
|  2591  |  recovery  |     My recovery key      |           | 152236800 | 157680000 | BCDE6GWvuQdRw8oXPqLBKG18VW8y4neenhpEcjKu51PxgnYW6fKd9OLdGWp7HmXz9/RVuk45f7/lFm5do8VIZSk= |
| 17326  |    auth    |       My Auth key        |    2591   | 152236800 | 157680000 | BIutaAbco7P6ycw3p8mUXzlybkWPMG/pppvpkCOVpf0HbducgwYbOWrkaKtoTJrQNDNHLjPDgDqYUphtdPYpq1U= |
| 56318  |    auth    |    My second Auth key    |    2591   | 152236800 | 157680000 | BO8dALo4qJWqACTgiPg+iT/H+5lWaoBzI43vygUUC4D+g1YNThjOjsqtBcx44p9QRFuQnAgNafOVaMmFCj2EsAM= |
| 64076  | tl_service |    My TL key     |    2591   | 152236800 | 157680000 | BDzVCcbLFzyzEG5HjSPxdwDKY5jnTkwluQFTGQmmtFZPKHmbnLkMVXorSXhvYFV+25uyG+RRM0QZAtpoBSF5lOo= |
| 32842  |  firmware  |  My second Firmware key  |    2591   | 152236800 | 157680000 | BNI+ES2Gyps499Ur1oOTVwUkW5prCU8hylgxaYbL3o6/6htXM5iAkGc1OClyjq3T9Sd6ZkFTVy39TmUasdUtic0= |
+--------+------------+--------------------------+-----------+-----------+-----------+------------------------------------------------------------------------------------------+
```

#### Add Public Keys to Database

| Code | Result                                             |
|------|----------------------------------------------------|
| ```10```   | Virgil Trust Provisioner allows user to input Public Key to db in base64 format |

This command allows you to add additional public key of some participants like the cloud to Virgil Trust Provisioner database
You can also leave a comment about added key.

**Example**

```#!/usr/bin/env bash
$ Please enter option number: 10
$ Are you sure you want to choose [Add Public Key to db (Factory)] [y/n]: y
# Manual adding Public Key to db...
# Key types:
	1. factory
$ Please choose Key type: 1
$ Enter Public Key (tiny base64): BNNhOY9ia3npXWdtGrkRv++FKYIfkf+RoysKzPP+fHnymQWY7I7+1/K7O3lVSstNESGEVN7MHx87zwpHJzRoQw4=
$ Enter comment for [factory] Key: My Added public key
# Key added
```

#### Export data as provision package for Factory
This command allows you to put together private keys, public keys and TrustList necessary for IoT device provisioning in the directory mentioned in ``config file``. Private and public keys are stored in their personal directories and Trust List is stored in the general directory.

| Code | Result                                             |
|------|----------------------------------------------------|
| ```11```   | Private and public keys and TrustList are put together and are ready to be exported |

**Example**
```bash
$ Please enter option number: 11
$ Are you sure you want to choose [Export data as provision package for Factory] [y/n]: y
# Exporting Private Keys...
# Export finished
# Exporting upper level Public Keys...
# Export finished
# Provision package for Factory saved as '/Users/<User>/virgil-trust-provisioner/provision-package' folder
```
**Directory Structure Example**
``` bash
├── TrustList_22875.tl
├── private
│   └── factory_30152_factory.key
└── pubkeys
    ├── auth_3047_auth1.pub
    ├── auth_32586_auth2.pub
    ├── firmware_10264_fw1.pub
    ├── firmware_27292_fw2.pub
    ├── recovery_22976_recovery1.pub
    ├── recovery_58398_recovery2.pub
    ├── tl_43163_tl2.pub
    └── tl_46577_tl1.pub

```



#### Export upper level public keys

UpperLevelKeys Export – the process of uploading of all UpperLevelKeys from ```UpperLevelKeys.db```

Public keys are uploaded to the storage which is specified in the config file.

| Code | Result                                             |
|------|----------------------------------------------------|
| ```12```   | Upper Level Keys are dumped from ```UpperLevelKeys.db``` |

**Example**

```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner --app-token <token> --factory-info <FACTORY_INFO>

# Specify the cli command

$ Please enter option number: 12
$ Are you sure you want to choose [Dump upper level Public Keys] [y/n]: y
# Dumping upper level Public Keys
# Keys dump finished
```

#### Export Private Keys
This command allows exporting private keys from Virgil Trust Provisioner databases.

| Code | Result                                             |
|------|----------------------------------------------------|
| ```13```   | Private keys are exported from database to Virgil Trust Provisioner storage, specified in the config file |

After executing the export private key command, private key bytes are stored in the file in DER format (SECP256R1). The file with private key can be found in the storage specified in the Virgil Trust Provisioner configuration file.
