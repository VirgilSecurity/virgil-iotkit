#ifndef TL_OPERATIONS_H
#define TL_OPERATIONS_H

#include <virgil/iot/secmodule/secmodule.h>
#include <virgil/iot/macros/macros.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>

typedef struct {
    size_t storage_type;
} vs_tl_storage_ctx_t;

typedef struct {
    uint16_t keys_amount;
    uint16_t keys_count;
} tl_keys_qty_t;

typedef struct {
    bool ready;
    const vs_storage_op_ctx_t *storage_ctx;
    vs_tl_storage_ctx_t storage;
    vs_tl_header_t header;
    tl_keys_qty_t keys_qty;
} vs_tl_context_t;

vs_status_e
vs_tl_storage_init_internal(vs_storage_op_ctx_t *op_ctx, vs_secmodule_impl_t *secmodule);
vs_status_e
vs_tl_storage_deinit_internal();

vs_status_e
vs_tl_invalidate(size_t storage_type);
vs_status_e
vs_tl_header_save(size_t storage_type, const vs_tl_header_t *header);
vs_status_e
vs_tl_header_load(size_t storage_type, vs_tl_header_t *header);
vs_status_e
vs_tl_footer_save(size_t storage_type, const uint8_t *footer, uint16_t footer_sz);
vs_status_e
vs_tl_apply_tmp_to(size_t storage_type);
vs_status_e
vs_tl_footer_load(size_t storage_type, uint8_t *footer, uint16_t buf_sz, uint16_t *footer_sz);
vs_status_e
vs_tl_key_save(size_t storage_type, const uint8_t *key, uint16_t key_sz);
vs_status_e
vs_tl_key_load(size_t storage_type, vs_tl_key_handle handle, uint8_t *key, uint16_t buf_sz, uint16_t *key_sz);
vs_status_e
vs_tl_verify_storage(size_t storage_type);

vs_status_e
vs_update_trust_list_init(vs_storage_op_ctx_t *storage_ctx);

#endif // TL_OPERATIONS_H
