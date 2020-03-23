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

#ifndef SNAP_CVT_H
#define SNAP_CVT_H

#include <endian-config.h>
#include <virgil/iot/protocols/snap/prvs/prvs-structs.h>
#include <virgil/iot/protocols/snap/info/info-structs.h>
#include <virgil/iot/protocols/snap/msgr/msgr-structs.h>
#include <virgil/iot/protocols/snap/cfg/cfg-structs.h>
#include <virgil/iot/protocols/snap/info/info-private.h>
#include <virgil/iot/protocols/snap/fldt/fldt-private.h>
#include <virgil/iot/protocols/snap/msgr/msgr-private.h>
#include <virgil/iot/protocols/snap/cfg/cfg-private.h>
#include <virgil/iot/protocols/snap/snap-structs.h>


/******************************************************************************/
// Converting functions for (vs_snap_packet_t)
void
vs_snap_packet_t_encode(vs_snap_packet_t *src_data);
void
vs_snap_packet_t_decode(vs_snap_packet_t *src_data);

/******************************************************************************/
// Converting functions for (vs_snap_prvs_set_data_t)
void
vs_snap_prvs_set_data_t_encode(vs_snap_prvs_set_data_t *src_data);
void
vs_snap_prvs_set_data_t_decode(vs_snap_prvs_set_data_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_file_info_t)
void
vs_fldt_file_info_t_encode(vs_fldt_file_info_t *src_data);
void
vs_fldt_file_info_t_decode(vs_fldt_file_info_t *src_data);

/******************************************************************************/
// Converting functions for (vs_info_stat_response_t)
void
vs_info_stat_response_t_encode(vs_info_stat_response_t *src_data);
void
vs_info_stat_response_t_decode(vs_info_stat_response_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_gnfh_header_request_t)
void
vs_fldt_gnfh_header_request_t_encode(vs_fldt_gnfh_header_request_t *src_data);
void
vs_fldt_gnfh_header_request_t_decode(vs_fldt_gnfh_header_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_cfg_messenger_config_request_t)
void
vs_cfg_messenger_config_request_t_encode(vs_cfg_messenger_config_request_t *src_data);
void
vs_cfg_messenger_config_request_t_decode(vs_cfg_messenger_config_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_gnfh_header_response_t)
void
vs_fldt_gnfh_header_response_t_encode(vs_fldt_gnfh_header_response_t *src_data);
void
vs_fldt_gnfh_header_response_t_decode(vs_fldt_gnfh_header_response_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_gnfd_data_request_t)
void
vs_fldt_gnfd_data_request_t_encode(vs_fldt_gnfd_data_request_t *src_data);
void
vs_fldt_gnfd_data_request_t_decode(vs_fldt_gnfd_data_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_msgr_getd_response_t)
void
vs_msgr_getd_response_t_encode(vs_msgr_getd_response_t *src_data);
void
vs_msgr_getd_response_t_decode(vs_msgr_getd_response_t *src_data);

/******************************************************************************/
// Converting functions for (vs_file_version_t)
void
vs_file_version_t_encode(vs_file_version_t *src_data);
void
vs_file_version_t_decode(vs_file_version_t *src_data);

/******************************************************************************/
// Converting functions for (vs_info_poll_request_t)
void
vs_info_poll_request_t_encode(vs_info_poll_request_t *src_data);
void
vs_info_poll_request_t_decode(vs_info_poll_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_gnfd_data_response_t)
void
vs_fldt_gnfd_data_response_t_encode(vs_fldt_gnfd_data_response_t *src_data);
void
vs_fldt_gnfd_data_response_t_decode(vs_fldt_gnfd_data_response_t *src_data);

/******************************************************************************/
// Converting functions for (vs_pubkey_t)
void
vs_pubkey_t_encode(vs_pubkey_t *src_data);
void
vs_pubkey_t_decode(vs_pubkey_t *src_data);

/******************************************************************************/
// Converting functions for (vs_file_info_t)
void
vs_file_info_t_encode(vs_file_info_t *src_data);
void
vs_file_info_t_decode(vs_file_info_t *src_data);

/******************************************************************************/
// Converting functions for (vs_snap_header_t)
void
vs_snap_header_t_encode(vs_snap_header_t *src_data);
void
vs_snap_header_t_decode(vs_snap_header_t *src_data);

/******************************************************************************/
// Converting functions for (vs_snap_prvs_devi_t)
void
vs_snap_prvs_devi_t_encode(vs_snap_prvs_devi_t *src_data);
void
vs_snap_prvs_devi_t_decode(vs_snap_prvs_devi_t *src_data);

/******************************************************************************/
// Converting functions for (vs_info_ginf_response_t)
void
vs_info_ginf_response_t_encode(vs_info_ginf_response_t *src_data);
void
vs_info_ginf_response_t_decode(vs_info_ginf_response_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_gnff_footer_request_t)
void
vs_fldt_gnff_footer_request_t_encode(vs_fldt_gnff_footer_request_t *src_data);
void
vs_fldt_gnff_footer_request_t_decode(vs_fldt_gnff_footer_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_fldt_gnff_footer_response_t)
void
vs_fldt_gnff_footer_response_t_encode(vs_fldt_gnff_footer_response_t *src_data);
void
vs_fldt_gnff_footer_response_t_decode(vs_fldt_gnff_footer_response_t *src_data);

/******************************************************************************/
// Converting functions for (vs_msgr_poll_request_t)
void
vs_msgr_poll_request_t_encode(vs_msgr_poll_request_t *src_data);
void
vs_msgr_poll_request_t_decode(vs_msgr_poll_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_update_file_type_t)
void
vs_update_file_type_t_encode(vs_update_file_type_t *src_data);
void
vs_update_file_type_t_decode(vs_update_file_type_t *src_data);

/******************************************************************************/
// Converting functions for (vs_ethernet_header_t)
void
vs_ethernet_header_t_encode(vs_ethernet_header_t *src_data);
void
vs_ethernet_header_t_decode(vs_ethernet_header_t *src_data);

/******************************************************************************/
// Converting functions for (vs_msgr_setd_request_t)
void
vs_msgr_setd_request_t_encode(vs_msgr_setd_request_t *src_data);
void
vs_msgr_setd_request_t_decode(vs_msgr_setd_request_t *src_data);

/******************************************************************************/
// Converting functions for (vs_pubkey_dated_t)
void
vs_pubkey_dated_t_encode(vs_pubkey_dated_t *src_data);
void
vs_pubkey_dated_t_decode(vs_pubkey_dated_t *src_data);

#endif // SNAP_CVT_H
