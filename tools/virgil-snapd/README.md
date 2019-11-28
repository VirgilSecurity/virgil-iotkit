# Virgil SnapD
Virgil SnapD is a local web utility which allows you to obtain information and statistics from your IoT devices.

In order to get this device information, SnapD interacts with Virgil SNAP protocol, which operates directly with your IoT devices. Since Virgil SnapD is a local service, the device information can be displayed in a browser window at http://localhost:8080/ (by default).

If you're using the [Virgil IoT Simulator](https://github.com/VirgilSecurity/iot-rpi-gateway), you can run SnapD under http://localhost:8081/.

## Content
- [Setting Up SnapD](#setting-up-snapd)
  - [Install](#install-snapd)
    - [Linux OS](#linux-os)
    - [Ubuntu OS, Debian OS](#ubuntu-os-debian-os)
    - [CentOS, Fedora OS](#centos-fedora-os)
    - [Mac OS](#mac-os)
    - [Windows OS](#windows-os)
  - [Configure and run](#configure-and-run-snapd)
- [API Reference](#api-reference)
  - [Display all devices](#display-all-devices)
  - [Display device by MAC](#display-device-by-mac)
- [Samples](#samples)

## Setting Up SnapD
This section demonstrates on how to install and configure Virgil SnapD.

### Install SnapD
This section provides instructions for installing Virgil SnapD.

#### Linux OS
Virgil SnapD is distributed as a package.

To download and install Virgil SnapD on Linux, use the YUM package manager and the following command:

```bash
$ sudo yum install virgil-iot-sdk-snapd
```

#### Ubuntu OS, Debian OS
Virgil SnapD is distributed as a package.

To download and install the Virgil SnapD on Ubuntu, Debian, use the YUM package manager and the following command:
```bash
$ sudo apt-get install virgil-iot-sdk-snapd
```

#### CentOS, Fedora OS
Virgil SnapD is distributed as a package.

To download and install the Virgil SnapD on CentOS, Fedora, use the YUM package manager and the following command:

```bash
$ sudo yum install virgil-iot-sdk-snapd
```
#### Mac OS
At this moment, we don't provide a built package for Mac OS, so you'll need to build and run it yourself using [cmake](https://cmake.org).

```bash
$ git clone --recursive https://github.com/VirgilSecurity/virgil-iot-sdk.git
$ cd virgil-iot-sdk
$ mkdir build && cd build
$ cmake ..
$ make vs-tool-virgil-snapd
```

#### Windows OS
Virgil SnapD package for Windows OS is currently in development. To receive product updates, please contact our support team at support@VirgilSecurity.com.

### Configure and run SnapD
By default SnapD works under http://localhost:8080/ if nothing else is specified for the `SNAPD_SERVICE_PORT` variable.

In order to run Virgil SnapD under the default port, use the following command:
```shell
virgil-snapd
```

To run Virgil SnapD under a customized port, use the following command:
```shell
virgil-snapd 8081
```

## API Reference
Virgil SnapD also provides an API for obtaining the IoT device information.

### Display all devices
In order to display information about all available IoT devices use the following API:

**Request info**

```shell
Request URL: curl -i localhost:8081/devices

```
This endpoint returns HTTP 200 if successful or a corresponding error if it wasn't successful.

**Request body**

Request body should be empty.

**Response info**

```shell
HTTP/1.1 200 OK
Date: Fri, 15 Nov 2019 09:04:36 GMT
Content-Length: 526
Content-Type: text/plain; charset=utf-8
```

**Response body**

```json
{
"2d:90:93:79:c6:35":
  {
      "id":"",
      "manufacture_id":"VIRGIL",
      "device_type":"MCU1",
      "roles":["THING"],
      "fw_version":"ver 0.0.0.0, 2019-11-15 08:29:59 +0000 UTC",
      "tl_version":"ver 0.6.1.1, 2019-11-15 08:30:20 +0000 UTC",
      "mac":"2d:90:93:79:c6:35",
      "sent":2092,
      "received":4},
      "eb:da:c4:b5:f5:20":
        {
          "id":"",
          "manufacture_id":"VRGL",
          "device_type":"Cf01",
          "roles":["GATEWAY"],
          "fw_version":"ver 0.0.0.0, 2019-11-15 08:29:59 +0000 UTC",
          "tl_version":"ver 0.6.1.1, 2019-11-15 08:30:20 +0000 UTC",
          "mac":"eb:da:c4:b5:f5:20",
          "sent":2079,
          "received":15
        }
    }
}
```


### Display device by MAC
In order to display information about a specific IoT device by its MAC, use the following API:

**Request info**

```shell
Request URL: curl -i localhost:8081/devices?key=eb:da:c4:b5:f5:20

```
This endpoint returns HTTP 200 if successful or a corresponding error if it wasn't successful.

**Request body**

Request body should be empty.

**Response info**

```shell
HTTP/1.1 200 OK
Date: Fri, 15 Nov 2019 09:08:33 GMT
Content-Length: 242
Content-Type: text/plain; charset=utf-8
```

**Response body**

```json
{
    "id":"",
    "manufacture_id":"VRGL",
    "device_type":"Cf01",
    "roles":["GATEWAY"],
    "fw_version":"ver 0.0.0.0, 2019-11-15 08:29:59 +0000 UTC",
    "tl_version":"ver 0.6.1.1, 2019-11-15 08:30:20 +0000 UTC",
    "mac":"eb:da:c4:b5:f5:20",
    "sent":2315,
    "received":15
}
```

## Samples
- To see SnapD in action, take a look at our [Virgil IoT Simulator](https://github.com/VirgilSecurity/iot-rpi-gateway).
