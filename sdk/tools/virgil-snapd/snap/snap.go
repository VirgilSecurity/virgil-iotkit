//   Copyright (C) 2015-2020 Virgil Security Inc.
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//       (1) Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//       (2) Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//
//       (3) Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//   DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGE.
//
//   Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

package snap

/*
#cgo LDFLAGS: -lvs-module-snap-factory -ltools-hal -lvs-module-logger
#include <virgil/iot/protocols/snap.h>
#include <virgil/iot/protocols/snap/info/info-client.h>
#include <virgil/iot/protocols/snap/cfg/cfg-client.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/tools/hal/ti_netif_udp_bcast.h>
extern int goDeviceStartNotifCb(vs_snap_info_device_t *device);
extern int goGeneralInfoCb(vs_info_general_t *general_info);
extern int goDeviceStatCb(vs_info_statistics_t *stat);

static int go_snap_init(void) {
    vs_device_manufacture_id_t manufacture_id = {0};
    vs_device_type_t device_type = {0};
    vs_device_serial_t serial = {0};
    uint32_t roles = VS_SNAP_DEV_SNIFFER;

    return vs_snap_init(vs_hal_netif_udp_bcast(), NULL, manufacture_id, device_type, serial, roles);
}

static int _set_polling(void) {
    return vs_snap_info_set_polling(vs_snap_netif_routing(),
                                    vs_snap_broadcast_mac(),
                                    VS_SNAP_INFO_GENERAL | VS_SNAP_INFO_STATISTICS,
                                    true,
                                    2);
}

static int _set_test_config(void) {

    vs_cfg_wifi_configuration_t config;

    strcpy((char *)config.ssid, "test_ssid");
    strcpy((char *)config.pass, "test_pass");
    strcpy((char *)config.account, "test_account");

    return vs_snap_cfg_wifi_configure_device(vs_snap_netif_routing(),
                                        vs_snap_broadcast_mac(),
                                        &config);
}

static int _register_info_client(void) {
    vs_snap_info_client_service_t _impl;

    _impl.device_start = goDeviceStartNotifCb;
    _impl.general_info = goGeneralInfoCb;
    _impl.statistics = goDeviceStatCb;

    return vs_snap_register_service(vs_snap_info_client(_impl));
}

static int _register_cfg_client(void) {
    return vs_snap_register_service(vs_snap_cfg_client());
}
*/
import "C"

import (
    "fmt"
    "time"
    "unsafe"

    "../devices"
    "../utils"
)

const (
    DEFAULT_TIMEOUT_MS = 7000
)

var (
    generalInfoCb func(generalInfo devices.DeviceInfo) error
    statisticsCb func(statistics devices.DeviceInfo) error
)

func ConnectToDeviceNetwork() error {
    // Prepare C logger
    C.vs_logger_init(C.VS_LOGLEV_DEBUG)

    // Use UDP Broadcast as transport
    if 0 != C.go_snap_init() {
        return fmt.Errorf("can't start SNAP communication")
    }

    if 0 != C._register_info_client() {
        return fmt.Errorf("can't register SNAP:INFO client service")
    }

    if 0 != C._register_cfg_client() {
        return fmt.Errorf("can't register SNAP:_CFG client service")
    }

    return nil
}

func DisconnectDeviceNetwork() {
    utils.Log.Println("DisconnectDeviceNetwork")
    C.vs_snap_deinit()
}

func carray2string(array *C.uint8_t, sz C.int) string {
        b := C.GoBytes(unsafe.Pointer(array), sz)
        var i int
        for i = 0; i < len(b); i++ {
            if b[i] == 0 {
                break
            }
        }

        return string(b[:i])
}

func mac2string(mac *C.uint8_t) string {
        b := C.GoBytes(unsafe.Pointer(mac), 6)
        return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func fileVer2string(major C.uint8_t, minor C.uint8_t,
                    patch C.uint8_t, build C.uint32_t,
                    timestamp C.uint32_t) string {
        // Create time string
        unixTime := int64(timestamp)
        unixTime += 1420070400
        tm := time.Unix(unixTime, 0)

        return fmt.Sprintf("ver %d.%d.%d.%d, %s", major, minor, patch, build, tm.String())
}

func roles2strings(roles C.uint32_t) []string {
        res := []string{}

        if (roles & C.VS_SNAP_DEV_GATEWAY) == C.VS_SNAP_DEV_GATEWAY {
            res = append(res, "GATEWAY")
        }

        if (roles & C.VS_SNAP_DEV_THING) == C.VS_SNAP_DEV_THING {
            res = append(res, "THING")
        }

        if (roles & C.VS_SNAP_DEV_INITIALIZER) == C.VS_SNAP_DEV_INITIALIZER {
            res = append(res, "INITIALIZER")
        }

        if (roles & C.VS_SNAP_DEV_CONTROL) == C.VS_SNAP_DEV_CONTROL {
            res = append(res, "CONTROL")
        }

        if (roles & C.VS_SNAP_DEV_LOGGER) == C.VS_SNAP_DEV_LOGGER {
            res = append(res, "LOGGER")
        }

        if (roles & C.VS_SNAP_DEV_SNIFFER) == C.VS_SNAP_DEV_SNIFFER {
            res = append(res, "SNIFFER")
        }

        if (roles & C.VS_SNAP_DEV_DEBUGGER) == C.VS_SNAP_DEV_DEBUGGER {
            res = append(res, "DEBUGGER")
        }

        return res
}

//export goDeviceStartNotifCb
func goDeviceStartNotifCb(device *C.vs_snap_info_device_t) C.int {
     if 0 != C._set_polling() {
        utils.Log.Println("can't set devices polling. SNAP:INFO:POLL error")
        return -1
     }

     return C.VS_CODE_OK
}

//export goGeneralInfoCb
func goGeneralInfoCb(general_info *C.vs_info_general_t) C.int {
    if nil != generalInfoCb {
        var goInfo devices.DeviceInfo
        goInfo.ID = ""
        goInfo.ManufactureID = carray2string(&general_info.manufacture_id[0], C.VS_DEVICE_MANUFACTURE_ID_SIZE)
        goInfo.DeviceType = carray2string(&general_info.device_type[0], C.VS_DEVICE_TYPE_SIZE)
        goInfo.FWVersion = fileVer2string(general_info.fw_ver.major,
                                        general_info.fw_ver.minor,
                                        general_info.fw_ver.patch,
                                        general_info.fw_ver.build,
                                        general_info.fw_ver.timestamp)
        goInfo.TLVersion = fileVer2string(general_info.tl_ver.major,
                                          general_info.tl_ver.minor,
                                          general_info.tl_ver.patch,
                                          general_info.tl_ver.build,
                                          general_info.tl_ver.timestamp)
        goInfo.MAC = mac2string(&general_info.default_netif_mac[0])
        goInfo.Roles = roles2strings(general_info.device_roles);

        generalInfoCb(goInfo)
    }
    return 0;
}

//export goDeviceStatCb
func goDeviceStatCb(stat *C.vs_info_statistics_t) C.int {
    if nil != statisticsCb {
        var goStat devices.DeviceInfo
        goStat.MAC = mac2string(&stat.default_netif_mac[0])
        goStat.Sent = uint32(stat.sent)
        goStat.Received = uint32(stat.received)
        statisticsCb(goStat)
    }

    return C.VS_CODE_OK
}

func SetupPolling(_generalInfoCb func(generalInfo devices.DeviceInfo) error,
                  _statisticsCb func(statistics devices.DeviceInfo) error) error {

    if 0 != C._set_polling() {
        return fmt.Errorf("can't set devices polling. SNAP:INFO:POLL error")
    }

    generalInfoCb = _generalInfoCb
    statisticsCb = _statisticsCb

    return nil
}

func UploadTestConfig() error {

    if 0 != C._set_test_config() {
        return fmt.Errorf("can't set devices polling. SNAP:_CFG:CONF error")
    }

    return nil
}
