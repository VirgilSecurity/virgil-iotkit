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

#include <assert.h>
#include <stdint.h>

#include "private/vs-soft-secmodule-internal.h"

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>

#include <virgil/crypto/foundation/vscf_secp256r1_private_key.h>
#include <virgil/crypto/foundation/vscf_secp256r1_public_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_private_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_public_key.h>
#include <virgil/crypto/foundation/vscf_ed25519_private_key.h>
#include <virgil/crypto/foundation/vscf_ed25519_public_key.h>
#include <virgil/crypto/foundation/vscf_rsa_private_key.h>
#include <virgil/crypto/foundation/vscf_rsa_public_key.h>
#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_sha384.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_signer.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/common/vsc_data.h>

// memory layout for keypair save/load buffer:
// . uint8_t key_type
// . uint8_t prvkey_sz
// . uint8_t prvkey[]
// . uint8_t pubkey_sz
// . uint8_t pubkey[]

#define KEYPAIR_BUF_KEYSZ_SIZEOF 1

#define KEYPAIR_BUF_KEYTYPE_OFF 0
#define KEYPAIR_BUF_KEYTYPE_SIZEOF 1

#define KEYPAIR_BUF_PRVKEYSZ_OFF (KEYPAIR_BUF_KEYTYPE_OFF + KEYPAIR_BUF_KEYTYPE_SIZEOF)
#define KEYPAIR_BUF_PRVKEYSZ_SIZEOF KEYPAIR_BUF_KEYSZ_SIZEOF

#define KEYPAIR_BUF_PRVKEY_OFF (KEYPAIR_BUF_PRVKEYSZ_OFF + KEYPAIR_BUF_PRVKEYSZ_SIZEOF)
#define KEYPAIR_BUF_PRVKEY_SIZEOF(BUF) ((BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF])

#define KEYPAIR_BUF_PUBKEYSZ_OFF(BUF) (KEYPAIR_BUF_PRVKEY_OFF + KEYPAIR_BUF_PRVKEY_SIZEOF(BUF))
#define KEYPAIR_BUF_PUBKEYSZ_SIZEOF KEYPAIR_BUF_KEYSZ_SIZEOF

#define KEYPAIR_BUF_PUBKEY_OFF(BUF) (KEYPAIR_BUF_PUBKEYSZ_OFF(BUF) + KEYPAIR_BUF_PUBKEYSZ_SIZEOF)
#define KEYPAIR_BUF_PUBKEY_SIZEOF(BUF) ((BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)])

#define KEYPAIR_BUF_SZ ((KEYPAIR_BUF_KEYTYPE_SIZEOF) + ((MAX_KEY_SZ + KEYPAIR_BUF_KEYSZ_SIZEOF) * 2))

#define ADD_KEYTYPE(BUF, KEYRPAIR_BUF, KEYPAIR_TYPE)                                                                   \
    do {                                                                                                               \
        (BUF)[KEYPAIR_BUF_KEYTYPE_OFF] = (KEYPAIR_TYPE);                                                               \
        vsc_buffer_inc_used(&(KEYRPAIR_BUF), KEYPAIR_BUF_KEYTYPE_SIZEOF);                                              \
    } while (0)

#define ADD_PRVKEYSZ(BUF, KEYPAIR_BUF, KEYSZ)                                                                          \
    do {                                                                                                               \
        if ((KEYSZ) > MAX_KEY_SZ) {                                                                                    \
            VS_LOG_ERROR("Too big private key : %d bytes. Maximum allowed size : %d", (KEYSZ), MAX_KEY_SZ);            \
            goto terminate;                                                                                            \
        }                                                                                                              \
        (BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF] = (KEYSZ);                                                                     \
        vsc_buffer_inc_used(&(KEYPAIR_BUF), KEYPAIR_BUF_PRVKEYSZ_SIZEOF);                                              \
    } while (0)

#define LOG_PRVKEY(BUF)                                                                                                \
    do {                                                                                                               \
        VS_LOG_DEBUG("Private key size : %d", (BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF]);                                        \
        VS_LOG_HEX(                                                                                                    \
                VS_LOGLEV_DEBUG, "Private key : ", (BUF) + KEYPAIR_BUF_PRVKEY_OFF, (BUF)[KEYPAIR_BUF_PRVKEYSZ_OFF]);   \
    } while (0)

#define ADD_PUBKEYSZ(BUF, KEYPAIR_BUF, KEYSZ)                                                                          \
    do {                                                                                                               \
        if ((KEYSZ) > MAX_KEY_SZ) {                                                                                    \
            VS_LOG_ERROR("Too big public key : %d bytes. Maximum allowed size : %d", (KEYSZ), MAX_KEY_SZ);             \
            goto terminate;                                                                                            \
        }                                                                                                              \
        (BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)] = (KEYSZ);                                                                \
        vsc_buffer_inc_used(&(KEYPAIR_BUF), KEYPAIR_BUF_PUBKEYSZ_SIZEOF);                                              \
    } while (0)

#define LOG_PUBKEY(BUF)                                                                                                \
    do {                                                                                                               \
        VS_LOG_DEBUG("Public key size : %d", (BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)]);                                    \
        VS_LOG_HEX(VS_LOGLEV_DEBUG,                                                                                    \
                   "Public key : ",                                                                                    \
                   (BUF) + KEYPAIR_BUF_PUBKEY_OFF(BUF),                                                                \
                   (BUF)[KEYPAIR_BUF_PUBKEYSZ_OFF(BUF)]);                                                              \
    } while (0)

/********************************************************************************/
static vs_status_e
vs_hsm_secp256r1_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_secp256r1_private_key_t *prvkey_ctx = NULL;
    vscf_secp256r1_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    const vs_hsm_impl_t *_secmodule = _soft_secmodule_intern();
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(prvkey_ctx = vscf_secp256r1_private_key_new(),
                    "Unable to allocate memory for slot %s",
                    get_slot_name(slot));

    CHECK_VSCF(vscf_secp256r1_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_secp256r1_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_secp256r1_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_secp256r1_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx =
                            (vscf_secp256r1_public_key_t *)vscf_secp256r1_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_secp256r1_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_secp256r1_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK(_secmodule->slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                 "Unable to save keypair buffer to the slot %s",
                 get_slot_name(slot));

    ret_code = VS_CODE_OK;

terminate:

    if (prvkey_ctx) {
        vscf_secp256r1_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_secp256r1_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_curve25519_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_curve25519_private_key_t *prvkey_ctx = NULL;
    vscf_curve25519_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    const vs_hsm_impl_t *_secmodule = _soft_secmodule_intern();
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(prvkey_ctx = vscf_curve25519_private_key_new(),
                    "Unable to allocate memory for slot %s",
                    get_slot_name(slot));

    CHECK_VSCF(vscf_curve25519_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_curve25519_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_curve25519_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_curve25519_private_key_export_private_key(prvkey_ctx, &keypair_buf),
               "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx =
                            (vscf_curve25519_public_key_t *)vscf_curve25519_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_curve25519_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_curve25519_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK(_secmodule->slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                 "Unable to save keypair buffer to the slot %s",
                 get_slot_name(slot));

    ret_code = VS_CODE_OK;

terminate:

    if (prvkey_ctx) {
        vscf_curve25519_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_curve25519_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_ed25519_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_ed25519_private_key_t *prvkey_ctx = NULL;
    vscf_ed25519_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    const vs_hsm_impl_t *_secmodule = _soft_secmodule_intern();
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(
            prvkey_ctx = vscf_ed25519_private_key_new(), "Unable to allocate memory for slot %s", get_slot_name(slot));

    CHECK_VSCF(vscf_ed25519_private_key_setup_defaults(prvkey_ctx),
               "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_ed25519_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_ed25519_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_ed25519_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx = (vscf_ed25519_public_key_t *)vscf_ed25519_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_ed25519_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_ed25519_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK(_secmodule->slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                 "Unable to save keypair buffer to the slot %s",
                 get_slot_name(slot));

    ret_code = VS_CODE_OK;

terminate:

    if (prvkey_ctx) {
        vscf_ed25519_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_ed25519_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
static vs_status_e
vs_hsm_rsa_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    vscf_rsa_private_key_t *prvkey_ctx = NULL;
    vscf_rsa_public_key_t *pubkey_ctx = NULL;
    vsc_buffer_t keypair_buf;
    uint8_t buf[KEYPAIR_BUF_SZ] = {0};
    uint8_t key_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    const vs_hsm_impl_t *_secmodule = _soft_secmodule_intern();
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    VS_LOG_DEBUG(
            "Generate keypair %s and save it to slot %s", vs_hsm_keypair_type_descr(keypair_type), get_slot_name(slot));

    CHECK_MEM_ALLOC(
            prvkey_ctx = vscf_rsa_private_key_new(), "Unable to allocate memory for slot %s", get_slot_name(slot));

    CHECK_VSCF(vscf_rsa_private_key_setup_defaults(prvkey_ctx), "Unable to initialize defaults for private key class");

    CHECK_VSCF(vscf_rsa_private_key_generate_key(prvkey_ctx), "Unable to generate private key");

    vsc_buffer_init(&keypair_buf);
    vsc_buffer_use(&keypair_buf, buf, sizeof(buf));

    ADD_KEYTYPE(buf, keypair_buf, keypair_type);

    key_sz = vscf_rsa_private_key_exported_private_key_len(prvkey_ctx);
    ADD_PRVKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_rsa_private_key_export_private_key(prvkey_ctx, &keypair_buf), "Unable to export private key");

    LOG_PRVKEY(buf);

    CHECK_MEM_ALLOC(pubkey_ctx = (vscf_rsa_public_key_t *)vscf_rsa_private_key_extract_public_key(prvkey_ctx),
                    "Unable to generate public key memory");

    key_sz = vscf_rsa_public_key_exported_public_key_len(pubkey_ctx);
    ADD_PUBKEYSZ(buf, keypair_buf, key_sz);

    CHECK_VSCF(vscf_rsa_public_key_export_public_key(pubkey_ctx, &keypair_buf), "Unable to save public key");

    assert(KEYPAIR_BUF_PUBKEY_OFF(buf) + KEYPAIR_BUF_PUBKEY_SIZEOF(buf) == vsc_buffer_len(&keypair_buf));

    LOG_PUBKEY(buf);

    STATUS_CHECK_RET(_secmodule->slot_save(slot, buf, vsc_buffer_len(&keypair_buf)),
                     "Unable to save keypair buffer to the slot %s",
                     get_slot_name(slot));

    ret_code = VS_CODE_OK;

terminate:

    if (prvkey_ctx) {
        vscf_rsa_private_key_delete(prvkey_ctx);
    }
    if (pubkey_ctx) {
        vscf_rsa_public_key_delete(pubkey_ctx);
    }

    return ret_code;
}

/********************************************************************************/
vs_status_e
vs_hsm_keypair_create(vs_iot_hsm_slot_e slot, vs_hsm_keypair_type_e keypair_type) {
    switch (keypair_type) {
    case VS_KEYPAIR_EC_SECP256R1:
        return vs_hsm_secp256r1_keypair_create(slot, keypair_type);

    case VS_KEYPAIR_EC_CURVE25519:
        return vs_hsm_curve25519_keypair_create(slot, keypair_type);

    case VS_KEYPAIR_EC_ED25519:
        return vs_hsm_ed25519_keypair_create(slot, keypair_type);

    case VS_KEYPAIR_RSA_2048:
        return vs_hsm_rsa_keypair_create(slot, keypair_type);

    default:
        VS_LOG_WARNING("Unsupported keypair type %s", vs_hsm_keypair_type_descr(keypair_type));
        return VS_CODE_ERR_NOT_IMPLEMENTED;
    }
}

/********************************************************************************/
vs_status_e
vs_hsm_keypair_get_pubkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type) {
    uint8_t keypair_buf[KEYPAIR_BUF_SZ];
    uint16_t keypair_buf_sz = sizeof(keypair_buf);
    uint8_t pubkey_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    const vs_hsm_impl_t *_secmodule = _soft_secmodule_intern();
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_secmodule->slot_load(slot, keypair_buf, keypair_buf_sz, &keypair_buf_sz),
                     "Unable to load data from slot %d (%s)",
                     slot,
                     get_slot_name(slot));

    pubkey_sz = keypair_buf[KEYPAIR_BUF_PUBKEYSZ_OFF(keypair_buf)];
    if (pubkey_sz == 0) {
        VS_LOG_ERROR("Zero size public key");
        goto terminate;
    }
    if (pubkey_sz > buf_sz) {
        VS_LOG_ERROR("Too big public key size %d bytes for buffer %d bytes", pubkey_sz, buf_sz);
        goto terminate;
    }

    memcpy(buf, keypair_buf + KEYPAIR_BUF_PUBKEY_OFF(keypair_buf), pubkey_sz);
    *key_sz = pubkey_sz;

    *keypair_type = keypair_buf[KEYPAIR_BUF_KEYTYPE_OFF];

    VS_LOG_DEBUG("Public key %d bytes from slot %s with keypair type %s has been loaded",
                 pubkey_sz,
                 get_slot_name(slot),
                 vs_hsm_keypair_type_descr(*keypair_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Public key : ", buf, *key_sz);

    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/********************************************************************************/
vs_status_e
vs_hsm_keypair_get_prvkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type) {
    uint8_t keypair_buf[KEYPAIR_BUF_SZ];
    uint16_t keypair_buf_sz = sizeof(keypair_buf);
    uint8_t prvkey_sz;
    vs_status_e ret_code = VS_CODE_ERR_CRYPTO;

    const vs_hsm_impl_t *_secmodule = _soft_secmodule_intern();
    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(_secmodule->slot_load(slot, keypair_buf, keypair_buf_sz, &keypair_buf_sz),
                     "Unable to load data from slot %d (%s)",
                     slot,
                     get_slot_name(slot));

    prvkey_sz = keypair_buf[KEYPAIR_BUF_PRVKEYSZ_OFF];
    if (prvkey_sz == 0) {
        VS_LOG_ERROR("Zero size private key");
        goto terminate;
    }
    if (prvkey_sz > buf_sz) {
        VS_LOG_ERROR("Too big private key %d bytes for buffer %d bytes", prvkey_sz, buf_sz);
        goto terminate;
    }

    memcpy(buf, keypair_buf + KEYPAIR_BUF_PRVKEY_OFF, prvkey_sz);
    *key_sz = prvkey_sz;

    *keypair_type = keypair_buf[KEYPAIR_BUF_KEYTYPE_OFF];

    VS_LOG_DEBUG("Private key %d bytes from slot %s with keypair type %s has been loaded",
                 prvkey_sz,
                 get_slot_name(slot),
                 vs_hsm_keypair_type_descr(*keypair_type));
    VS_LOG_HEX(VS_LOGLEV_DEBUG, "Private key : ", buf, *key_sz);

    ret_code = VS_CODE_OK;

terminate:

    return ret_code;
}

/********************************************************************************/
vs_status_e
_fill_keypair_impl(vs_hsm_impl_t *secmodule_impl) {
    CHECK_NOT_ZERO_RET(secmodule_impl, VS_CODE_ERR_NULLPTR_ARGUMENT);

    secmodule_impl->create_keypair = vs_hsm_keypair_create;
    secmodule_impl->get_pubkey = vs_hsm_keypair_get_pubkey;

    return VS_CODE_OK;
}

/********************************************************************************/
