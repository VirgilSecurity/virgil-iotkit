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

#ifndef VIRGIL_IOT_SDK_PROTOCOL_FLDT_CONFIG_H
#define VIRGIL_IOT_SDK_PROTOCOL_FLDT_CONFIG_H

/*
 * vs_fldt_file_type_id_t
 * File type identification. Used to separate different file type to be loaded
 * by gateway for each device and to be upgrade by each client.
 * In most cases used as value, not as pointer.
 * Each file type has it own callbacks.
 */

typedef enum { VS_FLDT_FIRMWARE = 0, VS_FLDT_TRUSTLIST, VS_FLDT_OTHER } vs_fldt_file_type_id_t;

/*
 * const char *vs_fldt_file_type_descr(const vs_fldt_file_type_id_t *file_type)
 * File type description.
 * Provides file type description returned as a pointer to the static ASCIIZ string.
 */

#include <stdlib-config.h>
#include <virgil/iot/logger/logger.h>

static inline const char *
vs_fldt_file_type_descr(vs_fldt_file_type_id_t file_type){
    switch(file_type){
        case VS_FLDT_FIRMWARE : return "firmware";
        case VS_FLDT_TRUSTLIST : return "trust list";
        case VS_FLDT_OTHER : return "other type";
        default:
            VS_IOT_ASSERT(0 && "Unsupported file type");
            VS_LOG_ERROR("[FLDT] Unsupported file type %d", (int) file_type);
            return "";
    }
}

#endif //VIRGIL_IOT_SDK_PROTOCOL_FLDT_CONFIG_H
