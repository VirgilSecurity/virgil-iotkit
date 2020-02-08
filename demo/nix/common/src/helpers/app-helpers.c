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

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/protocols/snap/snap-structs.h>

static pthread_mutex_t _sleep_lock;
static bool _need_restart = false;

/******************************************************************************/
char *
vs_app_get_commandline_arg(int argc, char *argv[], const char *shortname, const char *longname) {
    size_t pos;

    if (!(argv && shortname && *shortname && longname && *longname)) {
        return NULL;
    }

    for (pos = 0; pos < argc; ++pos) {
        if (!strcmp(argv[pos], shortname) && (pos + 1) < argc)
            return argv[pos + 1];
        if (!strcmp(argv[pos], longname) && (pos + 1) < argc)
            return argv[pos + 1];
    }

    return NULL;
}

/******************************************************************************/
static bool
_read_mac_address(const char *arg, vs_mac_addr_t *mac) {
    unsigned int values[6];
    int i;

    if (6 ==
        sscanf(arg, "%x:%x:%x:%x:%x:%x%*c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])) {
        /* convert to uint8_t */
        for (i = 0; i < 6; ++i) {
            mac->bytes[i] = (uint8_t)values[i];
        }
        return true;
    }

    return false;
}

/******************************************************************************/
vs_status_e
vs_app_get_mac_from_commandline_params(int argc, char *argv[], vs_mac_addr_t *forced_mac_addr) {
    static const char *MAC_SHORT = "-m";
    static const char *MAC_FULL = "--mac";
    char *mac_str;

    if (!argv || !argc || !forced_mac_addr) {
        VS_LOG_ERROR("Wrong input parameters.");
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    mac_str = vs_app_get_commandline_arg(argc, argv, MAC_SHORT, MAC_FULL);

    // Check input parameters
    if (!mac_str) {
        VS_LOG_ERROR("usage: %s/%s <forces MAC address>", MAC_SHORT, MAC_FULL);
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    if (!_read_mac_address(mac_str, forced_mac_addr)) {
        VS_LOG_ERROR("Incorrect forced MAC address \"%s\" was specified", mac_str);
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_app_get_image_path_from_commandline_params(int argc, char *argv[], char **path) {
    static const char *PATH_TO_IMAGE_SHORT = "-i";
    static const char *PATH_TO_IMAGE_FULL = "--image";
    char *path_to_str;

    if (!argv || !argc || !path) {
        VS_LOG_ERROR("Wrong input parameters.");
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    path_to_str = vs_app_get_commandline_arg(argc, argv, PATH_TO_IMAGE_SHORT, PATH_TO_IMAGE_FULL);

    // Check input parameters
    if (!path_to_str) {
        VS_LOG_ERROR("usage: %s/%s <path to image which need to start>", PATH_TO_IMAGE_SHORT, PATH_TO_IMAGE_FULL);
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    *path = path_to_str;


    return VS_CODE_OK;
}

/******************************************************************************/
void
vs_app_print_title(const char *devices_dir,
                   const char *app_file,
                   const char *manufacture_id_str,
                   const char *device_type_str) {
    VS_LOG_INFO("\n\n");
    VS_LOG_INFO("--------------------------------------------");
    VS_LOG_INFO("%s app at %s", devices_dir, app_file);
    VS_LOG_INFO("Manufacture ID = \"%s\" , Device type = \"%s\"", manufacture_id_str, device_type_str);
    VS_LOG_INFO("--------------------------------------------\n");
}

/******************************************************************************/
static void
_wait_signal_process(int sig, siginfo_t *si, void *context) {
    pthread_mutex_unlock(&_sleep_lock);
}

/******************************************************************************/
void
vs_app_sleep_until_stop(void) {
    struct sigaction sigaction_ctx;

    memset(&sigaction_ctx, 0, sizeof(sigaction_ctx));

    // Catch Signals to terminate application correctly
    sigaction_ctx.sa_flags = SA_SIGINFO;
    sigaction_ctx.sa_sigaction = _wait_signal_process;
    sigaction(SIGINT, &sigaction_ctx, NULL);
    sigaction(SIGTERM, &sigaction_ctx, NULL);

    if (0 != pthread_mutex_init(&_sleep_lock, NULL)) {
        VS_LOG_ERROR("Mutex init failed");
        return;
    }

    pthread_mutex_lock(&_sleep_lock);
    pthread_mutex_lock(&_sleep_lock);

    pthread_mutex_destroy(&_sleep_lock);
}

/******************************************************************************/
void
vs_app_restart(void) {
    _need_restart = true;
    pthread_mutex_unlock(&_sleep_lock);
}

/******************************************************************************/
void
vs_app_str_to_bytes(uint8_t *dst, const char *src, size_t elem_buf_size) {
    size_t pos;
    size_t len;

    assert(src && *src);
    assert(elem_buf_size);

    memset(dst, 0, elem_buf_size);

    len = strlen(src);
    for (pos = 0; pos < len && pos < elem_buf_size; ++pos, ++src, ++dst) {
        *dst = *src;
    }
}

/******************************************************************************/
void
vs_app_get_serial(vs_device_serial_t serial, vs_mac_addr_t mac) {
    VS_IOT_MEMSET(serial, 0x03, VS_DEVICE_SERIAL_SIZE);
    VS_IOT_MEMCPY(serial, mac.bytes, ETH_ADDR_LEN);
}

/******************************************************************************/
bool
vs_app_is_need_restart(void) {
    return _need_restart;
}

/******************************************************************************/
