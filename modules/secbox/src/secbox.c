#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/secbox/secbox.h>
#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/secmodule/secmodule-helpers.h>
#include <virgil/iot/logger/logger.h>
#include <virgil/iot/macros/macros.h>
#include <stdlib-config.h>
#include <global-hal.h>

static vs_storage_op_ctx_t *_storage_ctx = NULL;
static vs_secmodule_impl_t *_secmodule = NULL;

/******************************************************************************/
static vs_status_e
_secbox_verify_signature(vs_storage_file_t f, uint8_t data_type, uint8_t *data, size_t data_sz) {
    vs_status_e ret_code;
    uint16_t hash_len = (uint16_t)vs_secmodule_get_hash_len(VS_HASH_SHA_256);
    uint8_t hash[hash_len];

    VS_IOT_ASSERT(_secmodule);

    uint16_t sign_sz = (uint16_t)vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint8_t sign[sign_sz];

    vs_secmodule_keypair_type_e pubkey_type;
    uint16_t pubkey_sz = (uint16_t)vs_secmodule_get_pubkey_len(VS_KEYPAIR_EC_SECP256R1);
    uint8_t pubkey[pubkey_sz];

    vs_secmodule_sw_sha256_ctx hash_ctx;
    _secmodule->hash_init(&hash_ctx);

    _secmodule->hash_update(&hash_ctx, &data_type, 1);
    _secmodule->hash_update(&hash_ctx, data, data_sz);
    _secmodule->hash_finish(&hash_ctx, hash);

    ret_code = _storage_ctx->impl_func.load(_storage_ctx->impl_data, f, data_sz + 1, sign, sign_sz);
    if (VS_CODE_OK != ret_code) {
        VS_LOG_ERROR("Can't load signature from file");
        _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
        return ret_code;
    }

    STATUS_CHECK_RET(_secmodule->get_pubkey(PRIVATE_KEY_SLOT, pubkey, sizeof(pubkey), &pubkey_sz, &pubkey_type),
                     "Unable to get public key");
    STATUS_CHECK_RET(_secmodule->ecdsa_verify(pubkey_type, pubkey, pubkey_sz, VS_HASH_SHA_256, hash, sign, sign_sz),
                     "Unable to verify");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_secbox_init(vs_storage_op_ctx_t *ctx, vs_secmodule_impl_t *secmodule) {
    CHECK_NOT_ZERO_RET(secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(ctx->impl_data, VS_CODE_ERR_NULLPTR_ARGUMENT);

    _storage_ctx = ctx;
    _secmodule = secmodule;

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_secbox_deinit(void) {
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    return _storage_ctx->impl_func.deinit(_storage_ctx->impl_data);
}

/******************************************************************************/
ssize_t
vs_secbox_file_size(vs_storage_element_id_t id) {
    vs_storage_file_t f = NULL;
    uint8_t *data_load = NULL;
    size_t data_load_sz;
    uint8_t type;
    vs_status_e ret_code = VS_CODE_ERR_FILE_READ;

    uint16_t sign_sz = (uint16_t)vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    ssize_t file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, id);

    CHECK_RET(0 < file_sz, file_sz, "File not found");
    CHECK_RET(file_sz > sign_sz + 1, VS_CODE_ERR_FILE, "File format error");

    f = _storage_ctx->impl_func.open(_storage_ctx->impl_data, id);
    CHECK_RET(NULL != f, VS_CODE_ERR_FILE, "Can't open file");

    // read data type
    STATUS_CHECK(_storage_ctx->impl_func.load(_storage_ctx->impl_data, f, 0, &type, 1),
                 "Can't load data type from file");

    switch (type) {
    case VS_SECBOX_SIGNED_AND_ENCRYPTED:
        data_load_sz = file_sz - sign_sz - 1;
        data_load = VS_IOT_MALLOC(data_load_sz);
        if (NULL == data_load) {
            ret_code = VS_CODE_ERR_NO_MEMORY;
            goto terminate;
        }

        STATUS_CHECK(_storage_ctx->impl_func.load(_storage_ctx->impl_data, f, 1, data_load, data_load_sz),
                     "Can't load data from file");

        STATUS_CHECK(vs_secmodule_ecies_decrypt(_secmodule,
                                                id,
                                                sizeof(vs_storage_element_id_t),
                                                (uint8_t *)data_load,
                                                data_load_sz,
                                                data_load,
                                                data_load_sz,
                                                &data_load_sz),
                     "Cannot decrypt");

        file_sz = data_load_sz;
        ret_code = VS_CODE_OK;
        break;

    case VS_SECBOX_SIGNED:
        file_sz -= (sign_sz + 1);
        ret_code = VS_CODE_OK;
        break;

    default:
        return VS_CODE_ERR_FILE_READ;
    }

terminate:
    VS_IOT_FREE(data_load);

    _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
    return VS_CODE_OK == ret_code ? file_sz : ret_code;
}

/******************************************************************************/
vs_status_e
vs_secbox_save(vs_secbox_type_t type, vs_storage_element_id_t id, const uint8_t *data, size_t data_sz) {
    vs_status_e res = VS_CODE_ERR_FILE_WRITE;
    vs_status_e res_close = VS_CODE_OK;
    vs_storage_file_t f = NULL;
    uint8_t *data_to_save = NULL;
    size_t data_to_save_sz;
    uint8_t u8_type = (uint8_t)type;

    uint16_t hash_len = (uint16_t)vs_secmodule_get_hash_len(VS_HASH_SHA_256);
    uint8_t hash[hash_len];
    vs_secmodule_sw_sha256_ctx hash_ctx;

    VS_IOT_ASSERT(_secmodule);

    _secmodule->hash_init(&hash_ctx);

    uint16_t sign_sz = (uint16_t)vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);
    uint8_t sign[sign_sz];

    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(data, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_RET(data_sz <= _storage_ctx->file_sz_limit, VS_CODE_ERR_INCORRECT_ARGUMENT, "Requested size is too big");


    switch (type) {
    case VS_SECBOX_SIGNED_AND_ENCRYPTED:
        data_to_save = VS_IOT_MALLOC(data_sz + 512);
        if (NULL == data_to_save) {
            return VS_CODE_ERR_NO_MEMORY;
        }

        STATUS_CHECK(vs_secmodule_ecies_encrypt(_secmodule,
                                                id,
                                                sizeof(vs_storage_element_id_t),
                                                (uint8_t *)data,
                                                data_sz,
                                                data_to_save,
                                                data_sz + 512,
                                                &data_to_save_sz),
                     "Cannot encrypt SHA384 AES256");
        break;

    case VS_SECBOX_SIGNED:
        data_to_save = (uint8_t *)data;
        data_to_save_sz = data_sz;
        break;

    default:
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

    // sign data
    _secmodule->hash_update(&hash_ctx, &u8_type, 1);
    _secmodule->hash_update(&hash_ctx, data_to_save, data_to_save_sz);
    _secmodule->hash_finish(&hash_ctx, hash);

    STATUS_CHECK(_secmodule->ecdsa_sign(PRIVATE_KEY_SLOT, VS_HASH_SHA_256, hash, sign, sign_sz, &sign_sz),
                 "Cannot sign");

    // delete the old file if exists
    if (0 < _storage_ctx->impl_func.size(_storage_ctx->impl_data, id)) {
        STATUS_CHECK(res = _storage_ctx->impl_func.del(_storage_ctx->impl_data, id), "Cannot delete file");
    }

    CHECK(f = _storage_ctx->impl_func.open(_storage_ctx->impl_data, id), "Cannot open file");

    // Save data type to file
    STATUS_CHECK(res = _storage_ctx->impl_func.save(_storage_ctx->impl_data, f, 0, &u8_type, 1),
                 "Can't save type to file");
    STATUS_CHECK(res = _storage_ctx->impl_func.save(_storage_ctx->impl_data, f, 1, data_to_save, data_to_save_sz),
                 "Can't save data to file");
    STATUS_CHECK(res = _storage_ctx->impl_func.save(_storage_ctx->impl_data, f, data_to_save_sz + 1, sign, sign_sz),
                 "Can't save sign to file");

    STATUS_CHECK(res = _storage_ctx->impl_func.sync(_storage_ctx->impl_data, f), "Can't sync secbox file");

terminate:
    if (VS_SECBOX_SIGNED_AND_ENCRYPTED == type) {
        VS_IOT_FREE(data_to_save);
    }

    if (f) {
        res_close = _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
    }

    return (VS_CODE_OK == res) ? res_close : res;
}

/******************************************************************************/
vs_status_e
vs_secbox_load(vs_storage_element_id_t id, uint8_t *data, size_t data_sz) {
    vs_status_e res;
    uint8_t type;
    vs_storage_file_t f = NULL;
    uint8_t *data_load = NULL;
    size_t data_load_sz;

    uint16_t sign_sz = (uint16_t)vs_secmodule_get_signature_len(VS_KEYPAIR_EC_SECP256R1);

    CHECK_NOT_ZERO_RET(_secmodule, VS_CODE_ERR_NULLPTR_ARGUMENT);
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    ssize_t file_sz = _storage_ctx->impl_func.size(_storage_ctx->impl_data, id);

    CHECK_RET(0 < file_sz, VS_CODE_ERR_FILE, "Can't find file");
    CHECK_RET(file_sz > sign_sz + 1, VS_CODE_ERR_FILE, "File format error");

    CHECK_RET(f = _storage_ctx->impl_func.open(_storage_ctx->impl_data, id), VS_CODE_ERR_FILE, "Can't open file");

    // read data type
    res = _storage_ctx->impl_func.load(_storage_ctx->impl_data, f, 0, &type, 1);
    if (VS_CODE_OK != res) {
        VS_LOG_ERROR("Can't load data type from file");
        _storage_ctx->impl_func.close(_storage_ctx->impl_data, f);
        return res;
    }

    switch (type) {
    case VS_SECBOX_SIGNED_AND_ENCRYPTED:
        data_load_sz = file_sz - sign_sz - 1;
        data_load = VS_IOT_MALLOC(data_load_sz);
        if (NULL == data_load) {
            res = VS_CODE_ERR_NO_MEMORY;
            goto terminate;
        }

        res = VS_CODE_ERR_FILE_WRITE;
        STATUS_CHECK(_storage_ctx->impl_func.load(_storage_ctx->impl_data, f, 1, data_load, data_load_sz),
                     "Can't load data from file");
        STATUS_CHECK(_secbox_verify_signature(f, type, data_load, data_load_sz), "Can't verify signature");
        STATUS_CHECK(vs_secmodule_ecies_decrypt(_secmodule,
                                                id,
                                                sizeof(vs_storage_element_id_t),
                                                (uint8_t *)data_load,
                                                data_load_sz,
                                                data,
                                                data_sz,
                                                &data_load_sz),
                     "Can't descrypt DHA384 AES256");

        CHECK(data_sz == data_load_sz, "Can't read requested data quantity");
        break;

    case VS_SECBOX_SIGNED:
        data_load_sz = file_sz - sign_sz - 1;

        if (data_sz != data_load_sz) {
            VS_LOG_ERROR("Can't read requested data quantity");
            goto terminate;
        }

        res = _storage_ctx->impl_func.load(_storage_ctx->impl_data, f, 1, data, data_load_sz);
        if (VS_CODE_OK != res) {
            VS_LOG_ERROR("Can't load data from file");
            goto terminate;
        }

        res = _secbox_verify_signature(f, type, data, data_load_sz);

        break;
    default:
        return VS_CODE_ERR_INCORRECT_ARGUMENT;
    }

terminate:
    VS_IOT_FREE(data_load);
    return VS_CODE_OK == _storage_ctx->impl_func.close(_storage_ctx->impl_data, f) ? VS_CODE_OK : res;
}

/******************************************************************************/
vs_status_e
vs_secbox_del(vs_storage_element_id_t id) {
    CHECK_NOT_ZERO_RET(_storage_ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);
    return _storage_ctx->impl_func.del(_storage_ctx->impl_data, id);
}

/******************************************************************************/
