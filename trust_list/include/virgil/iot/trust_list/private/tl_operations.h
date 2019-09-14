#ifndef TL_OPERATIONS_H
#define TL_OPERATIONS_H

#include <virgil/iot/hsm/hsm_structs.h>
#include <virgil/iot/macros/macros.h>

#include <virgil/iot/trust_list/rpi-tl-hal.h>
typedef struct {
    size_t storage_type;
} vs_tl_storage_ctx_t;

typedef struct {
    uint16_t keys_amount;
    uint16_t keys_count;
} tl_keys_qty_t;

typedef struct {
    bool ready;
    vs_tl_storage_ctx_t storage;
    vs_tl_header_t header;
    tl_keys_qty_t keys_qty;
} vs_tl_context_t;

bool
vs_tl_storage_init_internal();
int
vs_tl_invalidate(size_t storage_type);
int
vs_tl_header_save(size_t storage_type, const vs_tl_header_t *header);
int
vs_tl_header_load(size_t storage_type, vs_tl_header_t *header);
int
vs_tl_footer_save(size_t storage_type, const uint8_t *footer, uint16_t footer_sz);
int
vs_tl_apply_tmp_to(size_t storage_type);
int
vs_tl_footer_load(size_t storage_type, uint8_t *footer, uint16_t buf_sz, uint16_t *footer_sz);
int
vs_tl_key_save(size_t storage_type, const uint8_t *key, uint16_t key_sz);
int
vs_tl_key_load(size_t storage_type, vs_tl_key_handle handle, uint8_t *key, uint16_t buf_sz, uint16_t *key_sz);
int
vs_tl_verify_storage(size_t storage_type);

void
vs_tl_header_to_host(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data);

#endif // TL_OPERATIONS_H
