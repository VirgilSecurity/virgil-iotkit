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

#ifndef VS_IOT_PROVISION_PRIVATE_H
#define VS_IOT_PROVISION_PRIVATE_H

#include <virgil/iot/status_code/status_code.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
typedef enum { VS_PRVS_SERVICE_ID = HTONL_IN_COMPILE_TIME('PRVS') } vs_prvs_t;

typedef enum {
    VS_PRVS_DNID = HTONL_IN_COMPILE_TIME('DNID'), /**< Discover Not Initialized Devices */
    VS_PRVS_SGNP = HTONL_IN_COMPILE_TIME('SGNP'), /**< Signature of own public key (by private key VS_PRVS_PBDM)  */
    VS_PRVS_PBR1 = HTONL_IN_COMPILE_TIME('PBR1'), /**< Set Recovery Key 1 */
    VS_PRVS_PBR2 = HTONL_IN_COMPILE_TIME('PBR2'), /**< Set Recovery Key 2 */
    VS_PRVS_PBA1 = HTONL_IN_COMPILE_TIME('PBA1'), /**< Set Auth Key 1 */
    VS_PRVS_PBA2 = HTONL_IN_COMPILE_TIME('PBA2'), /**< Set Auth Key 2 */
    VS_PRVS_PBT1 = HTONL_IN_COMPILE_TIME('PBT1'), /**< Set Trust List Key 1 */
    VS_PRVS_PBT2 = HTONL_IN_COMPILE_TIME('PBT2'), /**< Set Trust List 2 */
    VS_PRVS_PBF1 = HTONL_IN_COMPILE_TIME('PBF1'), /**< Set Firmware Key 1 */
    VS_PRVS_PBF2 = HTONL_IN_COMPILE_TIME('PBF2'), /**< Set Firmware Key 2 */
    VS_PRVS_TLH = HTONL_IN_COMPILE_TIME('_TLH'),  /**< Set Trust List Header */
    VS_PRVS_TLC = HTONL_IN_COMPILE_TIME('_TLC'),  /**< Set Trust List Chunk */
    VS_PRVS_TLF = HTONL_IN_COMPILE_TIME('_TLF'),  /**< Set Trust List Footer */
    VS_PRVS_DEVI = HTONL_IN_COMPILE_TIME('DEVI'), /**< Get DEVice Info */
    VS_PRVS_ASAV = HTONL_IN_COMPILE_TIME('ASAV'), /**< Action SAVe provision */
    VS_PRVS_ASGN = HTONL_IN_COMPILE_TIME('ASGN'), /**< Action SiGN data */
} vs_sdmp_prvs_element_e;
#pragma GCC diagnostic pop

typedef enum {
    VS_PROVISION_SGNP = VS_PRVS_SGNP,
    VS_PROVISION_PBR1 = VS_PRVS_PBR1,
    VS_PROVISION_PBR2 = VS_PRVS_PBR2,
    VS_PROVISION_PBA1 = VS_PRVS_PBA1,
    VS_PROVISION_PBA2 = VS_PRVS_PBA2,
    VS_PROVISION_PBT1 = VS_PRVS_PBT1,
    VS_PROVISION_PBT2 = VS_PRVS_PBT2,
    VS_PROVISION_PBF1 = VS_PRVS_PBF1,
    VS_PROVISION_PBF2 = VS_PRVS_PBF2
} vs_provision_element_id_e;

vs_status_e
vs_provision_get_slot_num(vs_provision_element_id_e id, uint16_t *slot);

#endif // VS_IOT_PROVISION_PRIVATE_H