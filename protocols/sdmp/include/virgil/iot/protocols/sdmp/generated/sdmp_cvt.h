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

#ifndef SDMP_CVT_H
#define SDMP_CVT_H

#include <endian-config.h>
#include <virgil/iot/protocols/sdmp/prvs.h>
#include <virgil/iot/protocols/sdmp/sdmp_structs.h>


/******************************************************************************/
// Converting functions for (vs_ethernet_header_t)
void
vs_ethernet_header_t_encode(vs_ethernet_header_t *src_data);
void
vs_ethernet_header_t_decode(vs_ethernet_header_t *src_data);

/******************************************************************************/
// Converting functions for (vs_sdmp_header_t)
void
vs_sdmp_header_t_encode(vs_sdmp_header_t *src_data);
void
vs_sdmp_header_t_decode(vs_sdmp_header_t *src_data);

/******************************************************************************/
// Converting functions for (vs_sdmp_packet_t)
void
vs_sdmp_packet_t_encode(vs_sdmp_packet_t *src_data);
void
vs_sdmp_packet_t_decode(vs_sdmp_packet_t *src_data);

/******************************************************************************/
// Converting functions for (vs_sdmp_prvs_devi_t)
void
vs_sdmp_prvs_devi_t_encode(vs_sdmp_prvs_devi_t *src_data);
void
vs_sdmp_prvs_devi_t_decode(vs_sdmp_prvs_devi_t *src_data);

#endif // SDMP_CVT_H
