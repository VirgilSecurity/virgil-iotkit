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

#ifndef VS_UPDATE_INTERFACE_H
#define VS_UPDATE_INTERFACE_H

typedef enum {
    VS_UPDATE_ERR_OK,
    VS_UPDATE_ERR_FAIL,
    VS_UPDATE_ERR_INVAL,
    VS_UPDATE_ERR_NOMEM,
    VS_UPDATE_ERR_NOT_FOUND,
} vs_update_err_code_e;

int
vs_update_save_firmware_chunk(vs_firmware_descriptor_t *descriptor, uint8_t *chunk, uint16_t chunk_sz, uint32_t offset);

int
vs_update_save_firmware_footer(vs_firmware_descriptor_t *descriptor, uint8_t *footer);

int
vs_update_load_firmware_chunk(vs_firmware_descriptor_t *descriptor,
                              uint32_t offset,
                              uint8_t *data,
                              uint16_t buff_sz,
                              uint16_t *data_sz);

int
vs_update_load_firmware_footer(vs_firmware_descriptor_t *descriptor,
                               uint8_t *data,
                               uint16_t buff_sz,
                               uint16_t *data_sz);

int
vs_update_save_firmware_descriptor(vs_firmware_descriptor_t *descriptor);


int
vs_update_load_firmware_descriptor(uint8_t manufacture_id[MANUFACTURE_ID_SIZE],
                                   uint8_t device_type[DEVICE_TYPE_SIZE],
                                   vs_firmware_descriptor_t *descriptor);

int
vs_update_delete_firmware(vs_firmware_descriptor_t *descriptor);

#endif // VS_UPDATE_INTERFACE_H
