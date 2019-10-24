
#ifndef TRUST_LIST_H
#define TRUST_LIST_H

#include <stdint.h>
#include <stdbool.h>
#include <virgil/iot/hsm/hsm.h>
#include <virgil/iot/storage_hal/storage_hal.h>
#include <virgil/iot/status_code/status_code.h>
#include <virgil/iot/update/update.h>
#include <virgil/iot/trust_list/tl_structs.h>

typedef enum {
    VS_TL_ELEMENT_MIN = 0,
    VS_TL_ELEMENT_TLH,
    VS_TL_ELEMENT_TLC,
    VS_TL_ELEMENT_TLF,
    VS_TL_ELEMENT_MAX,
} vs_tl_element_e;

typedef struct vs_tl_element_info_s {
    vs_tl_element_e id;
    size_t index;
} vs_tl_element_info_t;

vs_status_e
vs_tl_init(vs_storage_op_ctx_t *op_ctx, vs_hsm_impl_t *hsm);

vs_status_e
vs_tl_deinit();

vs_status_e
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, uint16_t data_sz);

vs_status_e
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, uint16_t buf_sz, uint16_t *out_sz);

vs_update_interface_t *
vs_tl_update_ctx(void);

const vs_update_file_type_t *
vs_tl_update_file_type(void);

void
vs_tl_header_to_host(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data);

void
vs_tl_header_to_net(const vs_tl_header_t *src_data, vs_tl_header_t *dst_data);
#endif // TRUST_LIST_H
