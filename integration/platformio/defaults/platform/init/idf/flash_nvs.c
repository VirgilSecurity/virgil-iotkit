//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

#include "esp_system.h"
#include <platform/init/idf/flash_nvs.h>

#include <virgil/iot/protocols/snap/snap-structs.h>

#define VS_NVS_SERIAL_NAMESPACE "NVS_SERIAL"
#define VS_NVS_SERIAL_KEY_NAME "SERIAL"

esp_err_t
_create_serial(nvs_handle handle, vs_device_serial_t serial);

esp_err_t
_read_serial(nvs_handle handle, vs_device_serial_t serial);

//******************************************************************************
esp_err_t
flash_nvs_init(void) {
    esp_err_t err = ESP_OK;
    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        INIT_STATUS_CHECK(err = nvs_flash_erase(), "Error erase NVS flash");
        INIT_STATUS_CHECK(err = nvs_flash_init(), "Error NVS flash init");
    }

terminate:
    return err;
}

//******************************************************************************
esp_err_t
flash_nvs_get_serial(vs_device_serial_t serial) {
    nvs_handle handle;
    esp_err_t err = ESP_FAIL;

    err = nvs_open(VS_NVS_SERIAL_NAMESPACE, NVS_READONLY, &handle);

    switch (err) {
    case ESP_OK:
        err = _read_serial(handle, serial);
        break;
    case ESP_ERR_NVS_NOT_FOUND:
        err = nvs_open(VS_NVS_SERIAL_NAMESPACE, NVS_READWRITE, &handle);
        CHECK_RET(ESP_OK == err, err, "Can't create namespace");
        err = _create_serial(handle, serial);
        break;
    default:
        VS_LOG_ERROR("Can't open namespace");
        return err;
    }

    nvs_close(handle);
    return err;
}

//******************************************************************************
esp_err_t
_create_serial(nvs_handle handle, vs_device_serial_t serial) {
    esp_err_t err;

    err = esp_efuse_mac_get_default(serial);
    CHECK_RET(ESP_OK == err, err, "Can't get default mac address");

    esp_fill_random(&serial[sizeof(vs_mac_addr_t)], sizeof(vs_device_serial_t) - sizeof(vs_mac_addr_t));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Create serial number ", serial, sizeof(vs_device_serial_t));

    err = nvs_set_blob(handle, (char *)VS_NVS_SERIAL_KEY_NAME, serial, sizeof(vs_device_serial_t));
    CHECK_RET(ESP_OK == err,
              err,
              "Unable to write %d bytes to the file [%s]. err = %d",
              (char *)VS_NVS_SERIAL_KEY_NAME,
              err);

    return ESP_OK;
}

//******************************************************************************
esp_err_t
_read_serial(nvs_handle handle, vs_device_serial_t serial) {
    esp_err_t err;
    size_t f_sz = sizeof(vs_device_serial_t);
    err = nvs_get_blob(handle, (char *)VS_NVS_SERIAL_KEY_NAME, serial, &f_sz);

    if (ESP_ERR_NVS_NOT_FOUND == err) {
        VS_LOG_DEBUG("Serial number has not found. Try to create it");
        err = _create_serial(handle, serial);
    } else {
        VS_LOG_HEX(VS_LOGLEV_DEBUG, "Read serial number ", serial, sizeof(vs_device_serial_t));
    }

    return err;
}