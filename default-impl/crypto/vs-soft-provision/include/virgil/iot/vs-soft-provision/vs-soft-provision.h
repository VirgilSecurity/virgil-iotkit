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

#ifndef VS_SOFT_PROVISION_H
#define VS_SOFT_PROVISION_H

#include <virgil/iot/provision/provision.h>
#include <virgil/iot/vs-soft-secmodule/vs-soft-slots-config.h>

/** Returns soft secmodule based implementation of provision.
 *
 * \return #vs_soft_provision_impl_t
 */
const vs_provision_impl_t *
vs_soft_provision_impl(void);

/** Recovery key 1 slot */
#define REC1_KEY_SLOT VS_KEY_SLOT_STD_OTP_2
/** Recovery key 2 slot */
#define REC2_KEY_SLOT VS_KEY_SLOT_STD_OTP_3

/** Signature slot */
#define SIGNATURE_SLOT VS_KEY_SLOT_STD_OTP_4

/** Authentification key 1 slot */
#define AUTH1_KEY_SLOT VS_KEY_SLOT_STD_MTP_2
/** Authentification key 2 slot */
#define AUTH2_KEY_SLOT VS_KEY_SLOT_STD_MTP_3

/** Trust List key 1 slot */
#define TL1_KEY_SLOT VS_KEY_SLOT_STD_MTP_4
/** Trust List key 2 slot */
#define TL2_KEY_SLOT VS_KEY_SLOT_STD_MTP_5

/** Firmware key 1 slot */
#define FW1_KEY_SLOT VS_KEY_SLOT_STD_MTP_6
/** Firmware key 2 slot */
#define FW2_KEY_SLOT VS_KEY_SLOT_STD_MTP_7

#endif // VS_SOFT_PROVISION_H
