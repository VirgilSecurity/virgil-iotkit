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

#include <sdmp_cvt.h>



/******************************************************************************/
// Converting encode function for (vs_sdmp_header_t)
void  vs_sdmp_header_t_encode(vs_sdmp_header_t *src_data) {
  src_data->content_size = htons(src_data->content_size);
  src_data->flags = htons(src_data->flags);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_header_t)
void vs_sdmp_header_t_decode(vs_sdmp_header_t *src_data) {
  src_data->content_size = htohs(src_data->content_size);
  src_data->flags = htohs(src_data->flags);
}

/******************************************************************************/
// Converting encode function for (vs_sdmp_packet_t)
void  vs_sdmp_packet_t_encode(vs_sdmp_packet_t *src_data) {
  src_data->eth_header.type = htons(src_data->eth_header.type);
  src_data->header.flags = htons(src_data->header.flags);
  src_data->header.content_size = htons(src_data->header.content_size);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_packet_t)
void vs_sdmp_packet_t_decode(vs_sdmp_packet_t *src_data) {
  src_data->eth_header.type = htohs(src_data->eth_header.type);
  src_data->header.flags = htohs(src_data->header.flags);
  src_data->header.content_size = htohs(src_data->header.content_size);
}

/******************************************************************************/
// Converting encode function for (vs_sdmp_prvs_signature_t)
void  vs_sdmp_prvs_signature_t_encode(vs_sdmp_prvs_signature_t *src_data) {
  src_data->id = htons(src_data->id);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_prvs_signature_t)
void vs_sdmp_prvs_signature_t_decode(vs_sdmp_prvs_signature_t *src_data) {
  src_data->id = htohs(src_data->id);
}

/******************************************************************************/
// Converting encode function for (vs_sdmp_prvs_devi_t)
void  vs_sdmp_prvs_devi_t_encode(vs_sdmp_prvs_devi_t *src_data) {
  src_data->model = htons(src_data->model);
  src_data->signature.id = htons(src_data->signature.id);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_prvs_devi_t)
void vs_sdmp_prvs_devi_t_decode(vs_sdmp_prvs_devi_t *src_data) {
  src_data->model = htohs(src_data->model);
  src_data->signature.id = htohs(src_data->signature.id);
}

/******************************************************************************/
// Converting encode function for (vs_ethernet_header_t)
void  vs_ethernet_header_t_encode(vs_ethernet_header_t *src_data) {
  src_data->type = htons(src_data->type);
}

/******************************************************************************/
// Converting decode function for (vs_ethernet_header_t)
void vs_ethernet_header_t_decode(vs_ethernet_header_t *src_data) {
  src_data->type = htohs(src_data->type);
}