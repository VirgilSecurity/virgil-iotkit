# Virgil Trust Provisioner
The Virgil Trust Provisioner is a command-line interface (CLI) used to manage your distributed trust between all parties, including IoT devices, in your IoT solutions.

#### Virgil Trust Provisioner Features
- Generating and managing Key Pairs for upper level IoT parties
- Generating and managing Trust Lists
- Provides databases for storing keys and Trust Lists
- Creating and registering Virgil Cards of upper level IoT parties on Virgil Security Platform

## Virgil Trust Provisioner Overview
Virgil Trust Provisioner is aimed at key pairs and TrustLists generation and management, which together make each IoT device identifiable, verifiable and trusted by each party of IoT solution.

Nowadays, each IoT device interacts with lots of services and application to provide the necessary features for end-users. At the same time, it's important to be sure that each IoT device is protected from unauthorized access at any its lifecycle stage, therefore each party and process have to be identifiable, verifiable and trusted.

The diagram below demonstrates a standard IoT infrastructure and its parties that have to be identifiable and verifiable as a part of distributed trust.

| Participant            | Role                                                                                                                                                                 |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Auth and Recovery Keys | Upper Level Keys that are responsible for secure Trust Lists and participants's key pairs management                                                                 |
| Firmware service       | Service is responsible for creating, storing and distributing Firmware                                                                                               |
| Trust List             | Trust List is a distributed list of trust that introduced in way of a file that consists of public keys and signatures of all trusted parties in the your IoT system |
| Trust List service     | Service is responsible for creating, storing and distributing Trust Lists                                                                                            |
| Factory                | Place where all IoT devices are manufactured and go through the provisioning step                                                                                    |
| Cloud                  | Cloud service that is responsible for users and applications authorization and authentication.                                                                       |

Virgil Trust Provisioner helps you to build up a trusted IoT solution ecosystem by creating and managing necessary key pairs and distibuted trust list for all participants. Then the keys and Trust Lists are distributed to all participants (e.g. IoT devices, user application, etc),  as a result each participant uses the TrustList while interacting with each other to verify wether the participant is authorized to do some operation.

## Setting up Virgil Trust Provisioner
This section demonstrates on how to install and configure Virgil Trust Provisioner for preferred platform.

### Install Virgil Trust Provisioner
This section provides instructions for installing Virgil Trust Provisioner.

#### LinuxOS
In order to download and install the Virgil Trust Provisioner on Linux, use the YUM package manager and the following command:

```bash
yum -y install virgil-iot-sdk-tools
```

### Configure Virgil Trust Provisioner
After the KeyManer installed, you need to set up the **provisioner.conf** file. By default, **provisioner.conf** file is placed in **./test_fs/** folder of the KeyManager repository.  While it is here, every time you launch the KeyManager you have to specify the path to the config file:

```bash
virgil-trust-provisioner -c ./test_fs/provisioner.conf
```
In order to not specify every time Virgil Trust Provisioner's configuration file when you launch it, place the **provisioner.conf** file into one of the next repositories on your device:

- /etc/VirgilTrustProvisioner/provisioner.conf
- ~/.VirgilTrustProvisioner/provisioner.conf

### Config File Structure
By default, the Virgil Trust Provisioner configuration file has the following format:

```bash
[MAIN]
# path to main storage folder
storage_path = ./test_fs

# path to folder for logs
log_path = ./test_fs/logs

[CARDS]
# URL of Virgil API. Used for cloud key retrieving and cards registration.
virgil_api_url = https://api.virgilsecurity.com
card_registration_endpoint = /things/card/key

# json with factory info (will be add to Factory key card)
factory_info_json = ./test_fs/factory_info_sample.json
```
### Configurable Variables
The configuration file (default name: **provisioner.conf**) contains the following variables:

| Name                       | Description                                                                                                                  |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------|
| storage_path               | The path to the main Virgil Trust Provisioner directory. Storage for Virgil Trust Provisioner databases and TrustList files. |
| log_path                   | The path to the folder for logs                                                                                              |
| virgil_api_url             | URL of Virgil Security Platform API. URL https://api.virgilsecurity.com is by default.                                       |
| card_registration_endpoint | URL of Virgil Cards Service endpoint for Cards registration. The /things/card/key is used by default.                        |
| factory_ingo_json          | The path to the JSON file with factory information. The example can be found below.                                          |

**Factory JSON example**
```bash
{
  "factory_info": {
    "name": "Sample Factory Name",
    "address": "sample address",
    "contacts": "sample_factory@some_mail.com"
  }
}
```
### Launch Virgil Trust Provisioner
To launch the Virgil Trust Provisioner use the following syntax:

```bash
virgil-trust-provisioner --app-token <token>
```
In case you need to specify path to the custom config file, you use following syntax:

```bash
virgil-trust-provisioner --app-token <token> -c ./test_fs/keymanager.conf
```
| Option                              | Description                                                                                                                                                                  |
|-------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| --app-token , -t                    | Application token (App Token) is used for authentication at Virgil Cloud to register Virgil Cards for Upper Level Keys. To generate an application token use the Virgil CLI. |
| -c CONFIG_PATH,--config CONFIG_PATH | The path to custom configuration file of the Virgil Trust Provisioner                                                                                                        |

## Command Reference
Here is the list of possible commands for Virgil Trust Provisioner.

### Syntax
```bash
virgil-trust-provisioner
```
Use  virgil-trust-provisioner --help to get information on a specific command.

### Application Commands
Application commands are used to perform operations such as key generating, database (db) operations and printing options.

### Private keys
| Command | Result                                                                                                                       |
|---------|------------------------------------------------------------------------------------------------------------------------------|
| 1       | Initial Generation. One by one generation of 2 Recovery Keys, 2 Auth Keys, 2 TL Service Keys, 2 Firmware Keys, 1 Factory Key |
| 2       | Generate 2 Recovery Keys                                                                                                     |
| 3       | Generate 2 Auth Keys                                                                                                         |
| 5       | Generate 2 keys of Trust List (TL) Service                                                                                   |
| 6       | Generate a Factory Key                                                                                                       |
| 7       | Delete a Factory Key                                                                                                         |
| 8       | Generate 2 Firmware Keys                                                                                                     |

### Trust List
| Command | Result                                                           |
|---------|------------------------------------------------------------------|
| 10      | Generate a TrustList and store it in Virgil Trust Provisioner db |

### KeyManager Database
| Command | Result                         |
|---------|--------------------------------|
| 11      | Print all public keys from db  |
| 12      | Add public key to db           |
| 13      | Export upper level public keys |
| 15      | Export private keys            |

## Private Keys
This includes dealing with the generation, exchange, storage, use and replacement of keys

Each private key has its own card that contains a public part of the key. The card is registered in the Virgil Card Service.

### Initial Generation (Get everything at once)
This command allows generating all keys for the entire key management infrastructure.

| Command | Result                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------|
| 1       | Virgil Trust Provisioner generates 2 Recovery Keys, 2 Auth Keys, 2 TL Keys, 2 Firmware Keys, 1 Factory Key one by one |

User is able to make decisions and leave comments about all CLI actions within Initial Generation process.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner

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
# Generation finished

# TrustList Service Key 1:

# Generating TrustList Service Key...
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
$ Enter comment for TrustList Service Key: My 1 TL key
# Generation finished

# TrustList Service Key 2:

#Generating TrustList Service Key...
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
$ Enter comment for TrustList Service Key: My 2 TL key
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
# Generation finished
```

### Recovery Key
The upper level key for recovery operations and for some keys creation. Recovery Key allows devices to identify Keys authorised by User. Recovery Key signs Auth Keys, TL Service Keys, Firmware Keys.

| Command | Result                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------|
| 2      | Virgil Trust Provisioner generates 2 Recovery keys |

#### Generating Recovery Key
Recovery Keys are used to sign other types of keys, and is known by every device. Public key is stored in Tust list and private key is stored in db.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner

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
# Generation finished
```
### Auth Key
The Auth Key is trusted as the second signer of the Firmware and Trust Lists.

| Command | Result                                                                                                                |
|---------|-----------------------------------------------------------------------------------------------------------------------|
| 3      | Virgil Trust Provisioner generates 2 Auth Keys  |

#### Generating Auth Key
After Auth Keys are generated they have to be signed with one of the Recovery keys. You also can add a coment about the Key purpose. Auth Key guards against the unauthorized use of Firmware and Trust List. Auth Keys sign Firmwares and the Trust Lists. Public key is stored in Tust list and private key is stored in db.

**Example**

```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner

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
# Generation finished
```

### TrustList Key
The TL Key is the primary signer of the Trust Lists. The TL Key is trusted because it is signed by a Recovery Key.

| Command | Result                                       |
|---------|----------------------------------------------|
| 5       | Virgil Trust Provisioner generates 2 TL Keys |

#### Generating TrustList Key
The TL Key is trusted because it is signed by a Recovery Key. Key Infrastructure needs two Key Pairs of the TL Key.  Public key is stored in Tust list and private key is stored in db.

**Example**
```bash
$ Please enter option number: 5
$ Are you sure you want to choose [Generate TrustList Service Key (2)] [y/n]: y

# Generate TrustList Service Key 1:

# Generating TrustList Service Key...

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
$ Enter comment for TrustList Service Key: My TL Service key       
# Generation finished

# Generate TrustList Service Key 2:

# Generating TrustList Service Key...

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
$ Enter comment for TrustList Service Key: My second TL Service key
# Generation finished
```
### Factory Key
Factory Key signs devices and guarantees official device distribution from the factory. Signature indicates that the manufacture of a device was authorized.

| Command | Result                                                                 |
|---------|------------------------------------------------------------------------|
| 6       | Virgil Trust Provisioner generates Factory Key and stores it in own db |
| 7       | Virgil Trust Provisioner deletes Factory Key from own db               |

#### Generating Factory Key
After Factory Key is generated, private key is stored in private keys db and public key is stored in Trust List. Also, Factory Key has a signature number limit that allows you to prevent uncountable device release at a factory  (```4294967295```) and is stored in ```FactoryPrivateKeys.db.```

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner

# Specify the cli command
$ Please enter option number: 6

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
# Generation finished
```

#### Deleting Factory Key
This commmand allows to remove Factory Key from the Virgil Trust Provisioner Factory Keys db FactoryPrivateKeys.db. Remember to release the new Trust List after deleting Factory Key and update it on IoT devices.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner

# Specify the cli command
$ Please enter option number: 7
$ Are you sure you want to choose [Delete Factory Key] [y/n]: y
# Deleting Factory Key...
# Factory Keys:
	1. factory_name: My Factory key
$ Please choose Factory Key to delete: 1
# Factory Key deleted
```
### Firmware Key
The Firmware Key is trusted as the primary signer of firmware and has no other capabilities.

| Command | Result                                                                 |
|---------|------------------------------------------------------------------------|
| 8       | Virgil Trust Provisioner generates 2 Firmware Keys |

#### Generating Firmware Key
Firmware Keys are stored on selected devices. They are signed by a Recovery Key.

**Example**
```bash
# Launch virgil-trust-provisioner
$ virgil-trust-provisioner

# Specify the cli command

$ Please enter option number: 8
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
# Generation finished
```
## Trust List
Distributed list of trust that is used by IoT devices and applications to check Information about trusted parties.

### TrustList Overview
TrustList is a distributed list of trust that introduced in way of a file that consists of public keys and signatures of all trusted parties in the your IoT system.

TrustList has basic content structure that was created based on general best secuirty practices, but the final number of trusted participants in the TrustList is determined by you.

After the TrustList created and signed it's distributed to all participants (e.g. IoT devices, User Application, etc),  as a result each participant uses the TrustList while interacting with each other to verify wether the participant is authorized to do some operation.

### TrustList Content
Each Trust List contains the following information:

| Information type | Value                                                |
|------------------|------------------------------------------------------|
| Public Keys      | - Cloud Public Key(s) - Factory Public Key(s)        |
| Signatures       | - Signature of TrustList Key - Signature of Auth Key |

### TrustList structure
Trust List has the following structure:

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
Distributed list of trust which contains keys information and is used by IoT devices and applications to check trust Information about IoT parties.

| Code | Result                                             |
|------|----------------------------------------------------|
| 10   | Virgil Trust Provisioner generates Trust List file |

### TrustList Generating
Trust List that contains Public Keys and signatures (signatures of Auth Key and TL Key) of all critical system elements.  All public keys in trust list are stored in TrustListPubKeys.db. TL contains signatures of Recovery Keys and Auth Keys.

**Example**
```bash
# Launch virgil-trust-provisioner
$ keymanager

# Specify the cli command

$ Please enter option number: 10
$ Are you sure you want to choose [Generate TrustList] [y/n]: y
# TrustList types:
	1. Dev
	2. Release
$ Please choose TrustList type: 1

# Generating Dev TrustList...

# Current TrustList version is 0
$ Enter the TrustList version [1]: 1
# Please choose Auth Key for TrustList signing:
# Keys list:
	1. db: AuthPrivateKeys, type: auth, comment: My Auth key, key_id: 17326
	2. db: AuthPrivateKeys, type: auth, comment: My second Auth key, key_id: 56318
$ Please enter option number: 1
$ Please choose TrustList Service Key for TrustList signing:
# Keys list:
	1. db: TLServicePrivateKeys, type: tl_service, comment: My second TL Service key, key_id: 3847
	2. db: TLServicePrivateKeys, type: tl_service, comment: My TL Service key, key_id: 64076
$ Please enter option number: 1
# Generation finished
# Storing to file...
# File stored
# TrustList generated and stored in the file storage cpecified in a config file
```

### TrustList Uploading
Trust List updating is a release of the new Trust List. This function is used in case if you need to change information about any key, re-generate key or add any new key. You need to create and release the new Trust List and distribute it to your IoT devices. In this case you need to use command ```10``` and distribute the new Trust List to your IoT device.
