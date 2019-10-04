#ifndef SECBOX_H
#define SECBOX_H

#include <stdint.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>

typedef enum {
    VS_SECBOX_SIGNED,
    VS_SECBOX_SIGNED_AND_ENCRYPTED,
} vs_secbox_type_t;

vs_status_code_e
vs_secbox_init(const vs_storage_op_ctx_t *ctx);

vs_status_code_e
vs_secbox_deinit(const vs_storage_op_ctx_t *ctx);

ssize_t
vs_secbox_file_size(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id);

vs_status_code_e
vs_secbox_save(const vs_storage_op_ctx_t *ctx,
               vs_secbox_type_t type,
               vs_storage_element_id_t id,
               const uint8_t *data,
               size_t data_sz);

vs_status_code_e
vs_secbox_load(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id, uint8_t *data, size_t data_sz);

vs_status_code_e
vs_secbox_del(const vs_storage_op_ctx_t *ctx, vs_storage_element_id_t id);

#endif // SECBOX_H
