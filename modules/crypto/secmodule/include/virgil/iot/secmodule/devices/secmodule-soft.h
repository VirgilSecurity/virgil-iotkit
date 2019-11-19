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

#ifndef VS_SECMODULE_SOFT_DEVICE_H
#define VS_SECMODULE_SOFT_DEVICE_H

#define KEY_SLOT_STD_DATA_SIZE (380)  // Max data size of standard slot
#define KEY_SLOT_EXT_DATA_SIZE (1532) // Max data size of extended slot

typedef enum {
    VS_KEY_SLOT_STD_OTP_0,
    VS_KEY_SLOT_STD_OTP_1,
    VS_KEY_SLOT_STD_OTP_2,
    VS_KEY_SLOT_STD_OTP_3,
    VS_KEY_SLOT_STD_OTP_4,
    VS_KEY_SLOT_STD_OTP_5,
    VS_KEY_SLOT_STD_OTP_6,
    VS_KEY_SLOT_STD_OTP_7,
    VS_KEY_SLOT_STD_OTP_8,
    VS_KEY_SLOT_STD_OTP_9,
    VS_KEY_SLOT_STD_OTP_10,
    VS_KEY_SLOT_STD_OTP_11,
    VS_KEY_SLOT_STD_OTP_12,
    VS_KEY_SLOT_STD_OTP_13,
    VS_KEY_SLOT_STD_OTP_14,
    VS_KEY_SLOT_STD_OTP_MAX,
    VS_KEY_SLOT_EXT_OTP_0,
    VS_KEY_SLOT_OTP_MAX,
    VS_KEY_SLOT_STD_MTP_0,
    VS_KEY_SLOT_STD_MTP_1,
    VS_KEY_SLOT_STD_MTP_2,
    VS_KEY_SLOT_STD_MTP_3,
    VS_KEY_SLOT_STD_MTP_4,
    VS_KEY_SLOT_STD_MTP_5,
    VS_KEY_SLOT_STD_MTP_6,
    VS_KEY_SLOT_STD_MTP_7,
    VS_KEY_SLOT_STD_MTP_8,
    VS_KEY_SLOT_STD_MTP_9,
    VS_KEY_SLOT_STD_MTP_10,
    VS_KEY_SLOT_STD_MTP_11,
    VS_KEY_SLOT_STD_MTP_12,
    VS_KEY_SLOT_STD_MTP_13,
    VS_KEY_SLOT_STD_MTP_14,
    VS_KEY_SLOT_STD_MTP_MAX,
    VS_KEY_SLOT_EXT_MTP_0,
    VS_KEY_SLOT_MTP_MAX,
    VS_KEY_SLOT_STD_TMP_0,
    VS_KEY_SLOT_STD_TMP_1,
    VS_KEY_SLOT_STD_TMP_2,
    VS_KEY_SLOT_STD_TMP_3,
    VS_KEY_SLOT_STD_TMP_4,
    VS_KEY_SLOT_STD_TMP_5,
    VS_KEY_SLOT_STD_TMP_6,
    VS_KEY_SLOT_STD_TMP_MAX,
    VS_KEY_SLOT_EXT_TMP_0,
    VS_KEY_SLOT_TMP_MAX
} vs_iot_secmodule_slot_e;

#define PROVISION_KEYS_QTY 2

#define PRIVATE_KEY_SLOT VS_KEY_SLOT_STD_OTP_1

#define REC1_KEY_SLOT VS_KEY_SLOT_STD_OTP_2
#define REC2_KEY_SLOT VS_KEY_SLOT_STD_OTP_3

#define SIGNATURE_SLOT VS_KEY_SLOT_STD_OTP_4

#define AUTH1_KEY_SLOT VS_KEY_SLOT_STD_MTP_2
#define AUTH2_KEY_SLOT VS_KEY_SLOT_STD_MTP_3

#define TL1_KEY_SLOT VS_KEY_SLOT_STD_MTP_4
#define TL2_KEY_SLOT VS_KEY_SLOT_STD_MTP_5

#define FW1_KEY_SLOT VS_KEY_SLOT_STD_MTP_6
#define FW2_KEY_SLOT VS_KEY_SLOT_STD_MTP_7

#endif // VS_SECMODULE_SOFT_DEVICE_H
