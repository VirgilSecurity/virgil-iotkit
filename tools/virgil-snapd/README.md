# Virgil SnapD
Virgil SnapD is a local web utility which allows you to obtain information and statistics of your IoT devices.

In order to get such device information SnapD interacts with Virgil SNAP protocol, which operates directly with your IoT devices. As far as Virgil SnapD is a local service, the obtained information can be displayed in browser under http://localhost:8080/ (by default).

In case you work with [Virgil IoT Simulator](https://github.com/VirgilSecurity/iot-rpi-gateway), you can run SnapD under http://localhost:8081/.

## Content
- [Setting Up SnapD](#setting-up-snapd)
- [Command Reference](#command-reference)
- [API Reference](#api-reference)
- [Samples](#samples)

## Setting Up SnapD
By default, utility operates on the port 8080 if other value is not indicated for variable Snap Service Core. And if you work with Demo, utility operates at port 8081.

## Command Reference




## API Reference
Virgil SnapD also provides api for obtaining IoT device information

### Display all devices
In order to display information about all available IoT devices use the following API:

**Request info**
```shell
Request URL: curl -i localhost:8081/devices

```
This endpoint returns HTTP 200 if successful or a corresponding error if it wasn't successful.

**Request body** Request body should be empty.

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
In order to display information about specific IoT device by its MAC use the following API:

**Request info**
```shell
Request URL: curl -i localhost:8081/devices?key=eb:da:c4:b5:f5:20

```
This endpoint returns HTTP 200 if successful or a corresponding error if it wasn't successful.

**Request body** Request body should be empty.

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
