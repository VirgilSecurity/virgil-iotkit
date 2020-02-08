//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <defaults/netif/netif-ble.h>

#include <virgil/iot/logger/logger.h>

#include "esp_bt.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static vs_netif_t _netif_ble = {.user_data = NULL, .packet_buf_filled = 0};

static vs_netif_rx_cb_t _netif_ble_rx_cb = NULL;
static vs_netif_process_cb_t _netif_ble_process_cb = NULL;

static char *_adv_data = NULL;
static size_t _adv_data_sz = 0;
static char *_dev_name = NULL;

#define SPP_PROFILE_NUM 1
#define SPP_PROFILE_APP_IDX 0
#define ESP_SPP_APP_ID 0x56

// Service
static const uint16_t spp_service_uuid = 0xABF0;
// Characteristic UUID
#define ESP_GATT_UUID_SPP_DATA_RECEIVE 0xABF1
#define ESP_GATT_UUID_SPP_DATA_NOTIFY 0xABF2

#define BLE_MAX_SZ (20)

// Attributes State Machine
enum {
    SPP_IDX_SVC,

    SPP_IDX_SPP_DATA_RECV_CHAR,
    SPP_IDX_SPP_DATA_RECV_VAL,

    SPP_IDX_SPP_DATA_NOTIFY_CHAR,
    SPP_IDX_SPP_DATA_NTY_VAL,
    SPP_IDX_SPP_DATA_NTF_CFG,

    SPP_IDX_NB,
};

static uint16_t spp_conn_id = 0xffff;
static esp_gatt_if_t spp_gatts_if = 0xff;

static bool is_connected = false;

static uint16_t spp_handle_table[SPP_IDX_NB];

static esp_ble_adv_params_t spp_adv_params = {
        .adv_int_min = 0x20,
        .adv_int_max = 0x40,
        .adv_type = ADV_TYPE_IND,
        .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
        .channel_map = ADV_CHNL_ALL,
        .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

struct gatts_profile_inst {
    esp_gatts_cb_t gatts_cb;
    uint16_t gatts_if;
    uint16_t app_id;
    uint16_t conn_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    esp_gatt_char_prop_t property;
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
};

static void
gatts_profile_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

/* One gatt-based profile one app_id and one gatts_if, this array will store the
 * gatts_if returned by ESP_GATTS_REG_EVT */
static struct gatts_profile_inst spp_profile_tab[SPP_PROFILE_NUM] = {
        [SPP_PROFILE_APP_IDX] =
                {
                        .gatts_cb = gatts_profile_event_handler,
                        .gatts_if = ESP_GATT_IF_NONE, /* Not get the gatt_if, so initial is
                                                         ESP_GATT_IF_NONE */
                },
};

/*
 *  SPP PROFILE ATTRIBUTES
 ****************************************************************************************
 */

#define CHAR_DECLARATION_SIZE (sizeof(uint8_t))
static const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t character_declaration_uuid = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t character_client_config_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;

static const uint8_t char_prop_read_notify = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY;
static const uint8_t char_prop_read_write = ESP_GATT_CHAR_PROP_BIT_WRITE_NR | ESP_GATT_CHAR_PROP_BIT_READ;

/// SPP Service - data receive characteristic, read&write without response
static const uint16_t spp_data_receive_uuid = ESP_GATT_UUID_SPP_DATA_RECEIVE;
static const uint8_t spp_data_receive_val[20] = {0x00};

/// SPP Service - data notify characteristic, notify&read
static const uint16_t spp_data_notify_uuid = ESP_GATT_UUID_SPP_DATA_NOTIFY;
static const uint8_t spp_data_notify_val[20] = {0x00};
static const uint8_t spp_data_notify_ccc[2] = {0x00, 0x00};

/// Full HRS Database Description - Used to add attributes into the database
static const esp_gatts_attr_db_t spp_gatt_db[SPP_IDX_NB] = {
        // SPP -  Service Declaration
        [SPP_IDX_SVC] = {{ESP_GATT_AUTO_RSP},
                         {ESP_UUID_LEN_16,
                          (uint8_t *)&primary_service_uuid,
                          ESP_GATT_PERM_READ,
                          sizeof(spp_service_uuid),
                          sizeof(spp_service_uuid),
                          (uint8_t *)&spp_service_uuid}},

        // SPP -  data receive characteristic Declaration
        [SPP_IDX_SPP_DATA_RECV_CHAR] = {{ESP_GATT_AUTO_RSP},
                                        {ESP_UUID_LEN_16,
                                         (uint8_t *)&character_declaration_uuid,
                                         ESP_GATT_PERM_READ,
                                         CHAR_DECLARATION_SIZE,
                                         CHAR_DECLARATION_SIZE,
                                         (uint8_t *)&char_prop_read_write}},

        // SPP -  data receive characteristic Value
        [SPP_IDX_SPP_DATA_RECV_VAL] = {{ESP_GATT_AUTO_RSP},
                                       {ESP_UUID_LEN_16,
                                        (uint8_t *)&spp_data_receive_uuid,
                                        ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                        BLE_MAX_SZ,
                                        sizeof(spp_data_receive_val),
                                        (uint8_t *)spp_data_receive_val}},

        // SPP -  data notify characteristic Declaration
        [SPP_IDX_SPP_DATA_NOTIFY_CHAR] = {{ESP_GATT_AUTO_RSP},
                                          {ESP_UUID_LEN_16,
                                           (uint8_t *)&character_declaration_uuid,
                                           ESP_GATT_PERM_READ,
                                           CHAR_DECLARATION_SIZE,
                                           CHAR_DECLARATION_SIZE,
                                           (uint8_t *)&char_prop_read_notify}},

        // SPP -  data notify characteristic Value
        [SPP_IDX_SPP_DATA_NTY_VAL] = {{ESP_GATT_AUTO_RSP},
                                      {ESP_UUID_LEN_16,
                                       (uint8_t *)&spp_data_notify_uuid,
                                       ESP_GATT_PERM_READ,
                                       BLE_MAX_SZ,
                                       sizeof(spp_data_notify_val),
                                       (uint8_t *)spp_data_notify_val}},

        // SPP -  data notify characteristic - Client Characteristic Configuration
        // Descriptor
        [SPP_IDX_SPP_DATA_NTF_CFG] = {{ESP_GATT_AUTO_RSP},
                                      {ESP_UUID_LEN_16,
                                       (uint8_t *)&character_client_config_uuid,
                                       ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
                                       sizeof(uint16_t),
                                       sizeof(spp_data_notify_ccc),
                                       (uint8_t *)spp_data_notify_ccc}},
};

//******************************************************************************
static uint8_t
_handle_to_index(uint16_t handle) {
    uint8_t error = 0xff;

    for (int i = 0; i < SPP_IDX_NB; i++) {
        if (handle == spp_handle_table[i]) {
            return i;
        }
    }

    return error;
}

//******************************************************************************
static void
_rcv_data(const uint8_t *data, size_t data_sz) {
    const uint8_t *packet_data = NULL;
    uint16_t packet_data_sz = 0;

    if (_netif_ble_rx_cb) {
        if (0 == _netif_ble_rx_cb(&_netif_ble, data, data_sz, &packet_data, &packet_data_sz)) {
            // Ready to process packet
            if (_netif_ble_process_cb) {
                VS_LOG_HEX(VS_LOGLEV_DEBUG, "RECV DUMP:", packet_data, packet_data_sz);
                _netif_ble_process_cb(&_netif_ble, packet_data, packet_data_sz);
            }
        }
    }
}

//******************************************************************************
static void
_gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
    if (ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT == event) {
        esp_ble_gap_start_advertising(&spp_adv_params);
    }
}

//******************************************************************************
static void
gatts_profile_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    esp_ble_gatts_cb_param_t *p_data = (esp_ble_gatts_cb_param_t *)param;

    switch (event) {
    case ESP_GATTS_REG_EVT:
        esp_ble_gap_set_device_name(_dev_name);
        esp_ble_gap_config_adv_data_raw((uint8_t *)_adv_data, _adv_data_sz);
        esp_ble_gatts_create_attr_tab(spp_gatt_db, gatts_if, SPP_IDX_NB, 0);
        break;

    case ESP_GATTS_CREAT_ATTR_TAB_EVT:
        if (ESP_GATT_OK == param->add_attr_tab.status && SPP_IDX_NB == param->add_attr_tab.num_handle) {
            memcpy(spp_handle_table, param->add_attr_tab.handles, sizeof(spp_handle_table));
            esp_ble_gatts_start_service(spp_handle_table[SPP_IDX_SVC]);
        }
        break;

    case ESP_GATTS_CONNECT_EVT:
        spp_conn_id = p_data->connect.conn_id;
        spp_gatts_if = gatts_if;
        is_connected = true;
        break;

    case ESP_GATTS_DISCONNECT_EVT:
        is_connected = false;
        esp_ble_gap_start_advertising(&spp_adv_params);
        break;

    case ESP_GATTS_READ_EVT:
        break;

    case ESP_GATTS_WRITE_EVT:
        if (!p_data->write.is_prep) {
            if (SPP_IDX_SPP_DATA_RECV_VAL == _handle_to_index(p_data->write.handle)) {
                _rcv_data(p_data->write.value, p_data->write.len);
            }
        }
        break;

    default:
        break;
    }
}

//******************************************************************************
static void
gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param) {
    /* If event is register event, store the gatts_if for each profile */
    if (event == ESP_GATTS_REG_EVT) {
        if (param->reg.status == ESP_GATT_OK) {
            spp_profile_tab[SPP_PROFILE_APP_IDX].gatts_if = gatts_if;
        } else {
            VS_LOG_DEBUG("Reg app failed, app_id %04x, status %d\n", param->reg.app_id, param->reg.status);
            return;
        }
    }

    do {
        int idx;
        for (idx = 0; idx < SPP_PROFILE_NUM; idx++) {
            if (gatts_if == ESP_GATT_IF_NONE || /* ESP_GATT_IF_NONE, not specify a
                                                   certain gatt_if, need to call every
                                                   profile cb function */
                gatts_if == spp_profile_tab[idx].gatts_if) {
                if (spp_profile_tab[idx].gatts_cb) {
                    spp_profile_tab[idx].gatts_cb(event, gatts_if, param);
                }
            }
        }
    } while (0);
}

/******************************************************************************/
static vs_status_e
_ble_tx(const vs_netif_t *netif, const uint8_t *data, const uint16_t data_sz) {
    const uint8_t *p;
    size_t to_send, part_sz;

    if (!is_connected) {
        return VS_CODE_ERR_SOCKET;
    }

    VS_LOG_DEBUG("sending: [%d]", (int)data_sz);

    to_send = data_sz;
    p = data;

    while (to_send) {
        part_sz = to_send >= BLE_MAX_SZ ? BLE_MAX_SZ : to_send;
        esp_ble_gatts_send_indicate(
                spp_gatts_if, spp_conn_id, spp_handle_table[SPP_IDX_SPP_DATA_NTY_VAL], part_sz, p, false);

        to_send -= part_sz;
        p += part_sz;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_ble_init(vs_netif_t *netif, const vs_netif_rx_cb_t rx_cb, const vs_netif_process_cb_t process_cb) {
    assert(rx_cb);
    _netif_ble_rx_cb = rx_cb;
    _netif_ble_process_cb = process_cb;
    _netif_ble.packet_buf_filled = 0;

    vs_status_e ret = VS_CODE_OK;
    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();

    uint8_t base_mac_addr[6] = {0};

    CHECK_RET(ESP_OK == esp_efuse_mac_get_default(base_mac_addr),
              VS_CODE_ERR_INIT_SNAP,
              "BLE MAC load error: %s",
              esp_err_to_name(ret));
    esp_base_mac_addr_set(base_mac_addr);

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    CHECK_RET(ESP_OK == esp_bt_controller_init(&bt_cfg),
              VS_CODE_ERR_INIT_SNAP,
              "BLE init error: %s",
              esp_err_to_name(ret));
    CHECK_RET(ESP_OK == esp_bt_controller_enable(ESP_BT_MODE_BLE),
              VS_CODE_ERR_INIT_SNAP,
              "BLE enable error: %s",
              esp_err_to_name(ret));
    CHECK_RET(ESP_OK == esp_bluedroid_init(), VS_CODE_ERR_INIT_SNAP, "Bluedroid init error: %s", esp_err_to_name(ret));
    CHECK_RET(ESP_OK == esp_bluedroid_enable(),
              VS_CODE_ERR_INIT_SNAP,
              "Bluedroid enable error: %s",
              esp_err_to_name(ret));

    esp_ble_gatts_register_callback(gatts_event_handler);
    esp_ble_gap_register_callback(_gap_event_handler);
    esp_ble_gatts_app_register(ESP_SPP_APP_ID);

    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_ble_deinit(const vs_netif_t *netif) {
    //...
    return VS_CODE_OK;
}

/******************************************************************************/
static vs_status_e
_ble_mac(const vs_netif_t *netif, struct vs_mac_addr_t *mac_addr) {
    if (mac_addr) {
        VS_IOT_ASSERT(ESP_OK == esp_efuse_mac_get_default(mac_addr->bytes));
        return VS_CODE_OK;
    }

    return VS_CODE_ERR_NULLPTR_ARGUMENT;
}

/******************************************************************************/
static void
_save_adv_data(const char *device_name) {
    const char *base_name = device_name ? device_name : "VS";
    uint8_t base_mac_addr[6] = {0};
    static const size_t _name_field_descr = 2;
    static const size_t _name_suffix_sz = 13; // "-aabbccddeeff"
    static const uint8_t spp_adv_data[] = {0x02, 0x01, 0x06};

    // Prepare memory
    vPortFree(_adv_data);
    _adv_data_sz = sizeof(spp_adv_data) + _name_field_descr + strlen(base_name) + _name_suffix_sz;
    _adv_data = pvPortMalloc(_adv_data_sz + 1); // 1 is for zero byte for ASCIIZ
    VS_IOT_ASSERT(_adv_data);

    // Get MAC address
    VS_IOT_ASSERT(ESP_OK == esp_efuse_mac_get_default(base_mac_addr));

    // Fill device name
    memcpy(_adv_data, spp_adv_data, sizeof(spp_adv_data));
    _adv_data[sizeof(spp_adv_data)] = strlen(base_name) + _name_suffix_sz;
    _adv_data[sizeof(spp_adv_data) + 1] = 0x09; // Adv name field
    _dev_name = _adv_data + sizeof(spp_adv_data) + _name_field_descr;

    strcpy(_dev_name, base_name);
    sprintf(&_dev_name[strlen(base_name)],
            "-%02X%02X%02X%02X%02X%02X",
            base_mac_addr[0],
            base_mac_addr[1],
            base_mac_addr[2],
            base_mac_addr[3],
            base_mac_addr[4],
            base_mac_addr[5]);

    VS_LOG_INFO("BLE device name %s", _dev_name);
}

/******************************************************************************/
vs_netif_t *
vs_hal_netif_ble(const char *device_name) {
    _save_adv_data(device_name);

    _netif_ble.init = _ble_init;
    _netif_ble.deinit = _ble_deinit;
    _netif_ble.tx = _ble_tx;
    _netif_ble.mac_addr = _ble_mac;

    return &_netif_ble;
}

/******************************************************************************/