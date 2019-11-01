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

/*! \file trust_list-config.h
 * \brief Trust List settings
 *
 * This file provides defines that set up Trust List behavior.
 *
 */

#ifndef VS_IOT_SDK_TL_CONFIG_H
#define VS_IOT_SDK_TL_CONFIG_H

/** Maximum size of trust list used.
 *
 * Please note that library uses three type of storage,
 * so you need have at least \a VS_TL_STORAGE_SIZE * 3 memory size
 * (excluding filesystem)
 */
#define VS_TL_STORAGE_SIZE (10 * 4096)

/** Maximum size of each part of trust list.
 *
 * It should be not less than max size of tl header, tl footer and tl public key
 */

#define VS_TL_STORAGE_MAX_PART_SIZE (512)

/*Trust list signature rules*/

/** Minimum quantity of required signatures, which must be in TL footer */

#define VS_TL_SIGNATURES_QTY (2)

/** List of signer types, which must be among signatures in TL footer
 *
 * Quantity MUST be equal to #VS_TL_SIGNATURES_QTY
 * It's values of vs_key_type_e from provision library
 */

#define VS_TL_SIGNER_TYPE_LIST {                                                                                       \
    VS_KEY_AUTH,                                                                                                    \
    VS_KEY_TRUSTLIST                                                                                                \
}

#endif // VS_IOT_SDK_TL_CONFIG_H
