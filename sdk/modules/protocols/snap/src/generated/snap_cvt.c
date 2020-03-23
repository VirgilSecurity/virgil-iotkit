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

#include <virgil/iot/protocols/snap/generated/snap_cvt.h>


/******************************************************************************/
// Converting encode function for (vs_snap_packet_t)
void
vs_snap_packet_t_encode(vs_snap_packet_t *src_data) {
    vs_snap_header_t_encode(&src_data->header);
    vs_ethernet_header_t_encode(&src_data->eth_header);
}

/******************************************************************************/
// Converting decode function for (vs_snap_packet_t)
void
vs_snap_packet_t_decode(vs_snap_packet_t *src_data) {
    vs_snap_header_t_decode(&src_data->header);
    vs_ethernet_header_t_decode(&src_data->eth_header);
}

/******************************************************************************/
// Converting encode function for (vs_snap_prvs_set_data_t)
void
vs_snap_prvs_set_data_t_encode(vs_snap_prvs_set_data_t *src_data) {
    src_data->request_id = VS_IOT_HTONS(src_data->request_id);
}

/******************************************************************************/
// Converting decode function for (vs_snap_prvs_set_data_t)
void
vs_snap_prvs_set_data_t_decode(vs_snap_prvs_set_data_t *src_data) {
    src_data->request_id = VS_IOT_NTOHS(src_data->request_id);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_file_info_t)
void
vs_fldt_file_info_t_encode(vs_fldt_file_info_t *src_data) {
    vs_update_file_type_t_encode(&src_data->type);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_file_info_t)
void
vs_fldt_file_info_t_decode(vs_fldt_file_info_t *src_data) {
    vs_update_file_type_t_decode(&src_data->type);
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

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfh_header_request_t)
void
vs_fldt_gnfh_header_request_t_encode(vs_fldt_gnfh_header_request_t *src_data) {
    vs_update_file_type_t_encode(&src_data->type);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfh_header_request_t)
void
vs_fldt_gnfh_header_request_t_decode(vs_fldt_gnfh_header_request_t *src_data) {
    vs_update_file_type_t_decode(&src_data->type);
}

/******************************************************************************/
// Converting encode function for (vs_cfg_messenger_config_request_t)
void
vs_cfg_messenger_config_request_t_encode(vs_cfg_messenger_config_request_t *src_data) {
    src_data->enjabberd_port = VS_IOT_HTONS(src_data->enjabberd_port);
}

/******************************************************************************/
// Converting decode function for (vs_cfg_messenger_config_request_t)
void
vs_cfg_messenger_config_request_t_decode(vs_cfg_messenger_config_request_t *src_data) {
    src_data->enjabberd_port = VS_IOT_NTOHS(src_data->enjabberd_port);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfh_header_response_t)
void
vs_fldt_gnfh_header_response_t_encode(vs_fldt_gnfh_header_response_t *src_data) {
    vs_fldt_file_info_t_encode(&src_data->fldt_info);
    src_data->file_size = VS_IOT_HTONL(src_data->file_size);
    src_data->header_size = VS_IOT_HTONS(src_data->header_size);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfh_header_response_t)
void
vs_fldt_gnfh_header_response_t_decode(vs_fldt_gnfh_header_response_t *src_data) {
    vs_fldt_file_info_t_decode(&src_data->fldt_info);
    src_data->file_size = VS_IOT_NTOHL(src_data->file_size);
    src_data->header_size = VS_IOT_NTOHS(src_data->header_size);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfd_data_request_t)
void
vs_fldt_gnfd_data_request_t_encode(vs_fldt_gnfd_data_request_t *src_data) {
    vs_update_file_type_t_encode(&src_data->type);
    src_data->offset = VS_IOT_HTONL(src_data->offset);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfd_data_request_t)
void
vs_fldt_gnfd_data_request_t_decode(vs_fldt_gnfd_data_request_t *src_data) {
    vs_update_file_type_t_decode(&src_data->type);
    src_data->offset = VS_IOT_NTOHL(src_data->offset);
}

/******************************************************************************/
// Converting encode function for (vs_msgr_getd_response_t)
void
vs_msgr_getd_response_t_encode(vs_msgr_getd_response_t *src_data) {
    src_data->data_sz = VS_IOT_HTONL(src_data->data_sz);
}

/******************************************************************************/
// Converting decode function for (vs_msgr_getd_response_t)
void
vs_msgr_getd_response_t_decode(vs_msgr_getd_response_t *src_data) {
    src_data->data_sz = VS_IOT_NTOHL(src_data->data_sz);
}

/******************************************************************************/
// Converting encode function for (vs_file_version_t)
void
vs_file_version_t_encode(vs_file_version_t *src_data) {
    src_data->build = VS_IOT_HTONL(src_data->build);
    src_data->timestamp = VS_IOT_HTONL(src_data->timestamp);
}

/******************************************************************************/
// Converting decode function for (vs_file_version_t)
void
vs_file_version_t_decode(vs_file_version_t *src_data) {
    src_data->build = VS_IOT_NTOHL(src_data->build);
    src_data->timestamp = VS_IOT_NTOHL(src_data->timestamp);
}

/******************************************************************************/
// Converting encode function for (vs_info_poll_request_t)
void
vs_info_poll_request_t_encode(vs_info_poll_request_t *src_data) {
    src_data->period_seconds = VS_IOT_HTONS(src_data->period_seconds);
}

/******************************************************************************/
// Converting decode function for (vs_info_poll_request_t)
void
vs_info_poll_request_t_decode(vs_info_poll_request_t *src_data) {
    src_data->period_seconds = VS_IOT_NTOHS(src_data->period_seconds);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnfd_data_response_t)
void
vs_fldt_gnfd_data_response_t_encode(vs_fldt_gnfd_data_response_t *src_data) {
    vs_update_file_type_t_encode(&src_data->type);
    src_data->offset = VS_IOT_HTONL(src_data->offset);
    src_data->next_offset = VS_IOT_HTONL(src_data->next_offset);
    src_data->data_size = VS_IOT_HTONS(src_data->data_size);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnfd_data_response_t)
void
vs_fldt_gnfd_data_response_t_decode(vs_fldt_gnfd_data_response_t *src_data) {
    vs_update_file_type_t_decode(&src_data->type);
    src_data->offset = VS_IOT_NTOHL(src_data->offset);
    src_data->next_offset = VS_IOT_NTOHL(src_data->next_offset);
    src_data->data_size = VS_IOT_NTOHS(src_data->data_size);
}

/******************************************************************************/
// Converting encode function for (vs_pubkey_t)
void
vs_pubkey_t_encode(vs_pubkey_t *src_data) {
    src_data->meta_data_sz = VS_IOT_HTONS(src_data->meta_data_sz);
}

/******************************************************************************/
// Converting decode function for (vs_pubkey_t)
void
vs_pubkey_t_decode(vs_pubkey_t *src_data) {
    src_data->meta_data_sz = VS_IOT_NTOHS(src_data->meta_data_sz);
}

/******************************************************************************/
// Converting encode function for (vs_file_info_t)
void
vs_file_info_t_encode(vs_file_info_t *src_data) {
    vs_file_version_t_encode(&src_data->version);
}

/******************************************************************************/
// Converting decode function for (vs_file_info_t)
void
vs_file_info_t_decode(vs_file_info_t *src_data) {
    vs_file_version_t_decode(&src_data->version);
}

/******************************************************************************/
// Converting encode function for (vs_snap_header_t)
void
vs_snap_header_t_encode(vs_snap_header_t *src_data) {
    src_data->transaction_id = VS_IOT_HTONS(src_data->transaction_id);
    src_data->padding = VS_IOT_HTONS(src_data->padding);
    src_data->content_size = VS_IOT_HTONS(src_data->content_size);
}

/******************************************************************************/
// Converting decode function for (vs_snap_header_t)
void
vs_snap_header_t_decode(vs_snap_header_t *src_data) {
    src_data->transaction_id = VS_IOT_NTOHS(src_data->transaction_id);
    src_data->padding = VS_IOT_NTOHS(src_data->padding);
    src_data->content_size = VS_IOT_NTOHS(src_data->content_size);
}

/******************************************************************************/
// Converting encode function for (vs_snap_prvs_devi_t)
void
vs_snap_prvs_devi_t_encode(vs_snap_prvs_devi_t *src_data) {
    src_data->data_sz = VS_IOT_HTONS(src_data->data_sz);
}

/******************************************************************************/
// Converting decode function for (vs_snap_prvs_devi_t)
void
vs_snap_prvs_devi_t_decode(vs_snap_prvs_devi_t *src_data) {
    src_data->data_sz = VS_IOT_NTOHS(src_data->data_sz);
}

/******************************************************************************/
// Converting encode function for (vs_info_ginf_response_t)
void
vs_info_ginf_response_t_encode(vs_info_ginf_response_t *src_data) {
    vs_file_version_t_encode(&src_data->fw_version);
    vs_file_version_t_encode(&src_data->tl_version);
    src_data->device_roles = VS_IOT_HTONL(src_data->device_roles);
}

/******************************************************************************/
// Converting decode function for (vs_info_ginf_response_t)
void
vs_info_ginf_response_t_decode(vs_info_ginf_response_t *src_data) {
    vs_file_version_t_decode(&src_data->fw_version);
    vs_file_version_t_decode(&src_data->tl_version);
    src_data->device_roles = VS_IOT_NTOHL(src_data->device_roles);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnff_footer_request_t)
void
vs_fldt_gnff_footer_request_t_encode(vs_fldt_gnff_footer_request_t *src_data) {
    vs_update_file_type_t_encode(&src_data->type);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnff_footer_request_t)
void
vs_fldt_gnff_footer_request_t_decode(vs_fldt_gnff_footer_request_t *src_data) {
    vs_update_file_type_t_decode(&src_data->type);
}

/******************************************************************************/
// Converting encode function for (vs_fldt_gnff_footer_response_t)
void
vs_fldt_gnff_footer_response_t_encode(vs_fldt_gnff_footer_response_t *src_data) {
    src_data->footer_size = VS_IOT_HTONS(src_data->footer_size);
    vs_update_file_type_t_encode(&src_data->type);
}

/******************************************************************************/
// Converting decode function for (vs_fldt_gnff_footer_response_t)
void
vs_fldt_gnff_footer_response_t_decode(vs_fldt_gnff_footer_response_t *src_data) {
    src_data->footer_size = VS_IOT_NTOHS(src_data->footer_size);
    vs_update_file_type_t_decode(&src_data->type);
}

/******************************************************************************/
// Converting encode function for (vs_msgr_poll_request_t)
void
vs_msgr_poll_request_t_encode(vs_msgr_poll_request_t *src_data) {
    src_data->period_seconds = VS_IOT_HTONS(src_data->period_seconds);
}

/******************************************************************************/
// Converting decode function for (vs_msgr_poll_request_t)
void
vs_msgr_poll_request_t_decode(vs_msgr_poll_request_t *src_data) {
    src_data->period_seconds = VS_IOT_NTOHS(src_data->period_seconds);
}

/******************************************************************************/
// Converting encode function for (vs_update_file_type_t)
void
vs_update_file_type_t_encode(vs_update_file_type_t *src_data) {
    src_data->type = VS_IOT_HTONS(src_data->type);
    vs_file_info_t_encode(&src_data->info);
}

/******************************************************************************/
// Converting decode function for (vs_update_file_type_t)
void
vs_update_file_type_t_decode(vs_update_file_type_t *src_data) {
    src_data->type = VS_IOT_NTOHS(src_data->type);
    vs_file_info_t_decode(&src_data->info);
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
// Converting encode function for (vs_msgr_setd_request_t)
void
vs_msgr_setd_request_t_encode(vs_msgr_setd_request_t *src_data) {
    src_data->data_sz = VS_IOT_HTONL(src_data->data_sz);
}

/******************************************************************************/
// Converting decode function for (vs_msgr_setd_request_t)
void
vs_msgr_setd_request_t_decode(vs_msgr_setd_request_t *src_data) {
    src_data->data_sz = VS_IOT_NTOHL(src_data->data_sz);
}

/******************************************************************************/
// Converting encode function for (vs_pubkey_dated_t)
void
vs_pubkey_dated_t_encode(vs_pubkey_dated_t *src_data) {
    src_data->start_date = VS_IOT_HTONL(src_data->start_date);
    src_data->expire_date = VS_IOT_HTONL(src_data->expire_date);
    vs_pubkey_t_encode(&src_data->pubkey);
}

/******************************************************************************/
// Converting decode function for (vs_pubkey_dated_t)
void
vs_pubkey_dated_t_decode(vs_pubkey_dated_t *src_data) {
    src_data->start_date = VS_IOT_NTOHL(src_data->start_date);
    src_data->expire_date = VS_IOT_NTOHL(src_data->expire_date);
    vs_pubkey_t_decode(&src_data->pubkey);
}