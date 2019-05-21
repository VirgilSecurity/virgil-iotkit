
#ifndef TRUST_LIST_H
#define TRUST_LIST_H


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

void
vs_tl_init_storage();

int
vs_tl_save_part(vs_tl_element_info_t *element_info, const uint8_t *in_data, size_t data_sz);

int
vs_tl_load_part(vs_tl_element_info_t *element_info, uint8_t *out_data, size_t buf_sz, size_t *out_sz);
#endif // TRUST_LIST_H
