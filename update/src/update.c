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

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/update/update.h>

/*************************************************************************/
char *
vs_update_type_descr(vs_update_file_type_t *file_type, const struct vs_update_interface_t *update_context, char *buf, size_t buf_size){
    if(update_context){
        return update_context->describe_type(update_context->file_context, file_type, buf, buf_size);
    } else {
        VS_IOT_SNPRINTF(buf, buf_size, "id = %d", file_type->file_type_id);
        return buf;
    }
}

/*************************************************************************/
bool
vs_update_equal_file_type(struct vs_update_interface_t *update_context, vs_update_file_type_t *file_type, const vs_update_file_type_t *unknown_file_type){

    if(update_context){
        return update_context->equal_file_type(update_context, file_type, unknown_file_type);
    } else if (file_type->file_type_id != unknown_file_type->file_type_id){
        return false;
    } else {
        return !VS_IOT_MEMCMP(file_type->add_info, unknown_file_type->add_info, sizeof(file_type->add_info));
    }
}
