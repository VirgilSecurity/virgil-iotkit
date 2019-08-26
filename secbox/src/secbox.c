#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/hsm/hsm_sw_sha2_routines.h>
#include <virgil/iot/hsm/hsm_interface.h>
#include <virgil/iot/hsm/hsm_helpers.h>
#include <virgil/iot/hsm/hsm_virgil_ecies.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>

/******************************************************************************/
int
vs_secbox_init(const vs_storage_op_ctx_t *ctx) {
    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);

    return VS_STORAGE_OK;
}

/******************************************************************************/
int
vs_secbox_deinit(const vs_storage_op_ctx_t *ctx) {
    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.deinit, VS_STORAGE_ERROR_PARAMS);

    return ctx->impl.deinit(ctx->storage_ctx);
}

/******************************************************************************/
int
vs_secbox_file_size(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id) {
    vs_storage_file_t f = NULL;
    uint8_t *data_load = NULL;
    size_t data_load_sz;
    uint8_t type;

    uint16_t sign_sz = (uint16_t)vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.load, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);

    int res = ctx->impl.size(ctx->storage_ctx, id);

    CHECK_RET(0 < res, res, "Can't find file")

    f = ctx->impl.open(ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_STORAGE_ERROR_GENERAL, "Can't open file")

    //read data type
    res = ctx->impl.load(ctx->storage_ctx, f, 0, &type, 1);
    if (VS_STORAGE_OK != res) {
        res = -1;
        VS_LOG_ERROR("Can't load data type from file");
        goto terminate;
    }

    switch (type) {
    case VS_SECBOX_SIGNED_AND_ENCRYPTED:
        data_load = VS_IOT_MALLOC(res - sign_sz);
        if (NULL == data_load) {
            res = -1;
            goto terminate;
        }

        res = ctx->impl.load(ctx->storage_ctx, f, 1, data_load, res - sign_sz);
        if (VS_STORAGE_OK != res) {
            res = -1;
            VS_LOG_ERROR("Can't load data from file");
            VS_IOT_FREE(data_load);
            goto terminate;
        }

        if (VS_HSM_ERR_OK != vs_hsm_virgil_decrypt_sha384_aes256(id,
                                                                 sizeof(vs_storage_element_id_t),
                                                                 (uint8_t *)data_load,
                                                                 res - sign_sz,
                                                                 data_load,
                                                                 res - sign_sz,
                                                                 &data_load_sz)) {
            VS_IOT_FREE(data_load);
            res = -1;
            goto terminate;
        }

        VS_IOT_FREE(data_load);
        res = data_load_sz;

        break;
    case VS_SECBOX_SIGNED:
        res = res - sign_sz;
        break;
    default:
        return -1;
    }

terminate:
    if (f) {
        ctx->impl.close(ctx->storage_ctx, f);
    }
    return res;
}

/******************************************************************************/
int
vs_secbox_save(const vs_storage_op_ctx_t *ctx,
               vs_secbox_type_t type,
               vs_storage_element_id_t id,
               const uint8_t *data,
               size_t data_sz) {
    int res = VS_STORAGE_OK;
    int ret = VS_STORAGE_OK;
    vs_storage_file_t f = NULL;
    uint8_t *data_to_save = NULL;
    size_t data_to_save_sz;
    uint8_t u8_type = (uint8_t)type;

    uint16_t hash_len = (uint16_t)vs_hsm_get_hash_len(VS_HASH_SHA_256);
    uint8_t hash[hash_len];
    vs_hsm_sw_sha256_ctx hash_ctx;
    vs_hsm_sw_sha256_init(&hash_ctx);

    uint16_t sign_sz = (uint16_t)vs_hsm_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint8_t sign[sign_sz];

    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.del, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.save, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(data, VS_STORAGE_ERROR_PARAMS);
    CHECK_RET(data_sz <= ctx->file_sz_limit, VS_STORAGE_ERROR_PARAMS, "Requested size is too big")


    switch (type) {
    case VS_SECBOX_SIGNED_AND_ENCRYPTED:
        data_to_save = VS_IOT_MALLOC(data_sz + 512);
        if (NULL == data_to_save) {
            return VS_STORAGE_ERROR_GENERAL;
        }

        if (VS_HSM_ERR_OK != vs_hsm_virgil_encrypt_sha384_aes256(id,
                                                                 sizeof(vs_storage_element_id_t),
                                                                 (uint8_t *)data,
                                                                 data_sz,
                                                                 data_to_save,
                                                                 data_sz + 512,
                                                                 &data_to_save_sz)) {
            res = VS_STORAGE_ERROR_WRITE;
            goto terminate;
        }

        break;
    case VS_SECBOX_SIGNED:
        data_to_save = (uint8_t *)data;
        data_to_save_sz = data_sz;
        break;
    default:
        return VS_STORAGE_ERROR_PARAMS;
    }

    // sign data
    vs_hsm_sw_sha256_update(&hash_ctx, &u8_type, 1);
    vs_hsm_sw_sha256_update(&hash_ctx, data_to_save, data_to_save_sz);
    vs_hsm_sw_sha256_final(&hash_ctx, hash);

    if (VS_HSM_ERR_OK !=
                vs_hsm_ecdsa_sign(PRIVATE_KEY_SLOT, VS_HASH_SHA_256, hash, sign, sign_sz, &sign_sz)) {
        res = VS_STORAGE_ERROR_WRITE;
        goto terminate;
    }

    //delete the old file if exists
    if (0 < ctx->impl.size(ctx->storage_ctx, id)) {
        res = ctx->impl.del(ctx->storage_ctx, id);
        if (VS_STORAGE_OK != res) {
            VS_LOG_ERROR("Can't delete file");
            goto terminate;
        }
    }

    f = ctx->impl.open(ctx->storage_ctx, id);
    if (NULL == f) {
        VS_LOG_ERROR("Can't open file");
        goto terminate;
    }

    // Save data type to file
    res = ctx->impl.save(ctx->storage_ctx, f, 0, &u8_type, 1);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't save data to file");
        goto terminate;
    }

    res = ctx->impl.save(ctx->storage_ctx, f, 0, data_to_save, data_to_save_sz);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't save data to file");
        goto terminate;
    }

    res = ctx->impl.save(ctx->storage_ctx, f, data_to_save_sz, sign, sign_sz);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't save sign to file");
        goto terminate;
    }

terminate:
    if(VS_SECBOX_SIGNED_AND_ENCRYPTED == type) {
        VS_IOT_FREE(data_to_save);
    }

    if (f) {
        ret = ctx->impl.close(ctx->storage_ctx, f);
    }

    return (VS_STORAGE_OK == res) ? ret : res;
}

/******************************************************************************/
int
vs_secbox_load(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id, uint8_t *data, size_t data_sz) {
    int res;
    int ret = VS_STORAGE_OK;
    uint8_t type;
    vs_storage_file_t f = NULL;
    uint8_t *data_load = NULL;
    size_t data_load_sz;

    vs_hsm_keypair_type_e pubkey_type = VS_KEYPAIR_EC_SECP256R1;
    uint16_t hash_len = (uint16_t)vs_hsm_get_hash_len(VS_HASH_SHA_256);
    uint8_t hash[hash_len];
    vs_hsm_sw_sha256_ctx hash_ctx;
    vs_hsm_sw_sha256_init(&hash_ctx);

    uint16_t sign_sz = (uint16_t)vs_hsm_get_signature_len(pubkey_type);
    uint8_t sign[sign_sz];

    uint16_t pubkey_sz = (uint16_t)vs_hsm_get_pubkey_len(pubkey_type);
    uint8_t pubkey[pubkey_sz];

    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.load, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(data, VS_STORAGE_ERROR_PARAMS);

    int file_sz = ctx->impl.size(ctx->storage_ctx, id);

    CHECK_RET(0 < file_sz, VS_STORAGE_ERROR_GENERAL, "Can't find file")
    CHECK_RET(file_sz > sign_sz + 1, VS_STORAGE_ERROR_GENERAL, "File format error")

    f = ctx->impl.open(ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_STORAGE_ERROR_GENERAL, "Can't open file")

    //read data type
    res = ctx->impl.load(ctx->storage_ctx, f, 0, &type, 1);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't load data type from file");
        ctx->impl.close(ctx->storage_ctx, f);
        return res;
    }

    switch (type) {
    case VS_SECBOX_SIGNED_AND_ENCRYPTED:
        data_load = VS_IOT_MALLOC(file_sz - sign_sz);
        if (NULL == data_load) {
            res = VS_STORAGE_ERROR_GENERAL;
            goto terminate;
        }

        res = ctx->impl.load(ctx->storage_ctx, f, 1, data_load, file_sz - sign_sz);
        if (VS_STORAGE_OK != res) {
            VS_LOG_ERROR("Can't load data from file");
            VS_IOT_FREE(data_load);
            goto terminate;
        }

        if (VS_HSM_ERR_OK != vs_hsm_virgil_decrypt_sha384_aes256(id,
                                                                 sizeof(vs_storage_element_id_t),
                                                                 (uint8_t *)data_load,
                                                                 file_sz - sign_sz,
                                                                 data,
                                                                 data_sz,
                                                                 &data_load_sz)) {
            VS_IOT_FREE(data_load);
            res = VS_STORAGE_ERROR_WRITE;
            goto terminate;
        }

        if(data_sz != data_load_sz) {
            VS_LOG_ERROR("Can't read requested data quantity");
            VS_IOT_FREE(data_load);
            goto terminate;
        }

        VS_IOT_FREE(data_load);
        data_load = data;
        break;
    case VS_SECBOX_SIGNED:

        if(data_sz != file_sz - sign_sz) {
            VS_LOG_ERROR("Can't read requested data quantity");
            goto terminate;
        }

        data_load = (uint8_t *)data;
        data_load_sz = file_sz - sign_sz;
        res = ctx->impl.load(ctx->storage_ctx, f, 1, data_load, data_load_sz);
        if (VS_STORAGE_OK != res) {
            VS_LOG_ERROR("Can't load data from file");
            goto terminate;
        }

        break;
    default:
        return VS_STORAGE_ERROR_PARAMS;
    }

    //check signature

    vs_hsm_sw_sha256_update(&hash_ctx, &type, 1);
    vs_hsm_sw_sha256_update(&hash_ctx, data_load, data_load_sz);
    vs_hsm_sw_sha256_final(&hash_ctx, hash);

    res = ctx->impl.load(ctx->storage_ctx, f, data_load_sz, sign, sign_sz);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't load signature from file");
        ctx->impl.close(ctx->storage_ctx, f);
        return res;
    }

    if ( VS_HSM_ERR_OK != vs_hsm_keypair_get_pubkey(PRIVATE_KEY_SLOT, pubkey, sizeof(pubkey), &pubkey_sz, &pubkey_type) ||
            VS_HSM_ERR_OK != vs_hsm_ecdsa_verify(VS_KEYPAIR_EC_SECP256R1, pubkey, pubkey_sz, VS_HASH_SHA_256, hash, sign, sign_sz)) {
        res = VS_STORAGE_ERROR_READ;
        goto terminate;
    }

terminate:
    if (f) {
        ret = ctx->impl.close(ctx->storage_ctx, f);
    }

    return (VS_STORAGE_OK == res) ? ret : res;
}

/******************************************************************************/
int
vs_secbox_del(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id) {
    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.del, VS_STORAGE_ERROR_PARAMS);

    return ctx->impl.del(ctx->storage_ctx, id);
}
