#include <stdint.h>
#include <stddef.h>

#include <virgil/iot/secbox/secbox.h>
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
    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);

    return ctx->impl.size(ctx->storage_ctx, id);
}

/******************************************************************************/
int
vs_secbox_save(const vs_storage_op_ctx_t *ctx,
               vs_secbox_type_t type,
               vs_storage_element_id_t id,
               const uint8_t *data,
               size_t data_sz) {
    int res;
    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.del, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.save, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(data, VS_STORAGE_ERROR_PARAMS);
    CHECK_RET(data_sz <= ctx->file_sz_limit, VS_STORAGE_ERROR_PARAMS, "Requested size is too big")

    if (0 < ctx->impl.size(ctx->storage_ctx, id)) {
        CHECK_RET(VS_STORAGE_OK == ctx->impl.del(ctx->storage_ctx, id), VS_STORAGE_ERROR_GENERAL, "Can't delete file")
    }

    vs_storage_file_t f = ctx->impl.open(ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_STORAGE_ERROR_GENERAL, "Can't open file")

    res = ctx->impl.save(ctx->storage_ctx, f, 0, data, data_sz);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't save file");
        ctx->impl.close(ctx->storage_ctx, f);
        return res;
    }

    return ctx->impl.close(ctx->storage_ctx, f);
}

/******************************************************************************/
int
vs_secbox_load(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id, uint8_t *data, size_t data_sz) {
    int res;

    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.size, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.open, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.load, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.close, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(data, VS_STORAGE_ERROR_PARAMS);

    int file_sz = ctx->impl.size(ctx->storage_ctx, id);

    CHECK_RET(0 < file_sz, VS_STORAGE_ERROR_GENERAL, "Can't find file")

    CHECK_RET(data_sz == file_sz, VS_STORAGE_ERROR_PARAMS, "Can't read requested data quantity")

    vs_storage_file_t f = ctx->impl.open(ctx->storage_ctx, id);
    CHECK_RET(NULL != f, VS_STORAGE_ERROR_GENERAL, "Can't open file")

    res = ctx->impl.load(ctx->storage_ctx, f, 0, data, data_sz);
    if (VS_STORAGE_OK != res) {
        VS_LOG_ERROR("Can't load file");
        ctx->impl.close(ctx->storage_ctx, f);
        return res;
    }

    return ctx->impl.close(ctx->storage_ctx, f);
}

/******************************************************************************/
int
vs_secbox_del(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id) {
    CHECK_NOT_ZERO(ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->storage_ctx, VS_STORAGE_ERROR_PARAMS);
    CHECK_NOT_ZERO(ctx->impl.del, VS_STORAGE_ERROR_PARAMS);

    return ctx->impl.del(ctx->storage_ctx, id);
}
