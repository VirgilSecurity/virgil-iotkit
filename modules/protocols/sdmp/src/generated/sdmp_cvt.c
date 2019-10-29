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

#include <virgil/iot/protocols/sdmp/generated/sdmp_cvt.h>


/******************************************************************************/
// Converting encode function for (vs_info_ginf_response_t)
void
vs_info_ginf_response_t_encode(vs_info_ginf_response_t *src_data) {
    src_data->device_roles = VS_IOT_HTONL(src_data->device_roles);
}

/******************************************************************************/
// Converting decode function for (vs_info_ginf_response_t)
void
vs_info_ginf_response_t_decode(vs_info_ginf_response_t *src_data) {
    src_data->device_roles = VS_IOT_NTOHL(src_data->device_roles);
}

/******************************************************************************/
// Converting encode function for (vs_info_enum_response_t)
void
vs_info_enum_response_t_encode(vs_info_enum_response_t *src_data) {
    src_data->device_roles = VS_IOT_HTONL(src_data->device_roles);
}

/******************************************************************************/
// Converting decode function for (vs_info_enum_response_t)
void
vs_info_enum_response_t_decode(vs_info_enum_response_t *src_data) {
    src_data->device_roles = VS_IOT_NTOHL(src_data->device_roles);
}

/******************************************************************************/
// Converting encode function for (vs_sdmp_prvs_devi_t)
void
vs_sdmp_prvs_devi_t_encode(vs_sdmp_prvs_devi_t *src_data) {
    src_data->data_sz = VS_IOT_HTONS(src_data->data_sz);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_prvs_devi_t)
void
vs_sdmp_prvs_devi_t_decode(vs_sdmp_prvs_devi_t *src_data) {
    src_data->data_sz = VS_IOT_NTOHS(src_data->data_sz);
}

/******************************************************************************/
// Converting encode function for (vs_info_poll_request_t)
void
vs_info_poll_request_t_encode(vs_info_poll_request_t *src_data) {
    src_data->elements = VS_IOT_HTONL(src_data->elements);
    src_data->period_seconds = VS_IOT_HTONS(src_data->period_seconds);
}

/******************************************************************************/
// Converting decode function for (vs_info_poll_request_t)
void
vs_info_poll_request_t_decode(vs_info_poll_request_t *src_data) {
    src_data->elements = VS_IOT_NTOHL(src_data->elements);
    src_data->period_seconds = VS_IOT_NTOHS(src_data->period_seconds);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfd_data_response_t)
void
vs_fldt_gnfd_data_response_t_encode(vs_fldt_gnfd_data_response_t *src_data) {
    src_data->data_size = VS_IOT_HTONS(src_data->data_size);
    src_data->offset = VS_IOT_HTONL(src_data->offset);
    src_data->next_offset = VS_IOT_HTONL(src_data->next_offset);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfd_data_response_t)
void
vs_fldt_gnfd_data_response_t_decode(vs_fldt_gnfd_data_response_t *src_data) {
    src_data->data_size = VS_IOT_NTOHS(src_data->data_size);
    src_data->offset = VS_IOT_NTOHL(src_data->offset);
    src_data->next_offset = VS_IOT_NTOHL(src_data->next_offset);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnff_footer_response_t)
void
vs_fldt_gnff_footer_response_t_encode(vs_fldt_gnff_footer_response_t *src_data) {
    src_data->footer_size = VS_IOT_HTONS(src_data->footer_size);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnff_footer_response_t)
void
vs_fldt_gnff_footer_response_t_decode(vs_fldt_gnff_footer_response_t *src_data) {
    src_data->footer_size = VS_IOT_NTOHS(src_data->footer_size);
}

/******************************************************************************/
// Converting encode function for (vs_sdmp_packet_t)
void
vs_sdmp_packet_t_encode(vs_sdmp_packet_t *src_data) {
    vs_ethernet_header_t_encode(&src_data->eth_header);
    vs_sdmp_header_t_encode(&src_data->header);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_packet_t)
void
vs_sdmp_packet_t_decode(vs_sdmp_packet_t *src_data) {
    vs_ethernet_header_t_decode(&src_data->eth_header);
    vs_sdmp_header_t_decode(&src_data->header);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfh_header_response_t)
void
vs_fldt_gnfh_header_response_t_encode(vs_fldt_gnfh_header_response_t *src_data) {
    src_data->file_size = VS_IOT_HTONL(src_data->file_size);
    src_data->header_size = VS_IOT_HTONS(src_data->header_size);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfh_header_response_t)
void
vs_fldt_gnfh_header_response_t_decode(vs_fldt_gnfh_header_response_t *src_data) {
    src_data->file_size = VS_IOT_NTOHL(src_data->file_size);
    src_data->header_size = VS_IOT_NTOHS(src_data->header_size);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfd_data_request_t)
void
vs_fldt_gnfd_data_request_t_encode(vs_fldt_gnfd_data_request_t *src_data) {
    src_data->offset = VS_IOT_HTONL(src_data->offset);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfd_data_request_t)
void
vs_fldt_gnfd_data_request_t_decode(vs_fldt_gnfd_data_request_t *src_data) {
    src_data->offset = VS_IOT_NTOHL(src_data->offset);
}

/******************************************************************************/
// Converting encode function for (vs_ethernet_header_t)
void
vs_ethernet_header_t_encode(vs_ethernet_header_t *src_data) {
    src_data->type = VS_IOT_HTONS(src_data->type);
}

/******************************************************************************/
// Converting decode function for (vs_ethernet_header_t)
void
vs_ethernet_header_t_decode(vs_ethernet_header_t *src_data) {
    src_data->type = VS_IOT_NTOHS(src_data->type);
}

/******************************************************************************/
// Converting encode function for (vs_sdmp_header_t)
void
vs_sdmp_header_t_encode(vs_sdmp_header_t *src_data) {
    src_data->padding = VS_IOT_HTONS(src_data->padding);
    src_data->content_size = VS_IOT_HTONS(src_data->content_size);
    src_data->transaction_id = VS_IOT_HTONS(src_data->transaction_id);
}

/******************************************************************************/
// Converting decode function for (vs_sdmp_header_t)
void
vs_sdmp_header_t_decode(vs_sdmp_header_t *src_data) {
    src_data->padding = VS_IOT_NTOHS(src_data->padding);
    src_data->content_size = VS_IOT_NTOHS(src_data->content_size);
    src_data->transaction_id = VS_IOT_NTOHS(src_data->transaction_id);
}

/******************************************************************************/
// Converting encode function for (vs_info_stat_response_t)
void
vs_info_stat_response_t_encode(vs_info_stat_response_t *src_data) {
    src_data->sent = VS_IOT_HTONL(src_data->sent);
    src_data->received = VS_IOT_HTONL(src_data->received);
}

/******************************************************************************/
// Converting decode function for (vs_info_stat_response_t)
void
vs_info_stat_response_t_decode(vs_info_stat_response_t *src_data) {
    src_data->sent = VS_IOT_NTOHL(src_data->sent);
    src_data->received = VS_IOT_NTOHL(src_data->received);
}