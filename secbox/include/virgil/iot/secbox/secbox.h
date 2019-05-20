#ifndef SECBOX_H
#define SECBOX_H
#include <stdint.h>

typedef struct vs_secbox_element_info_s {
    size_t id;
    size_t index;
} vs_secbox_element_info_t;

typedef int (*vs_secbox_save_hal_t)(vs_secbox_element_info_t *element_info, const uint8_t *in_data, size_t data_sz);
typedef int (*vs_secbox_load_hal_t)(vs_secbox_element_info_t *element_info,
                                    uint8_t *out_data,
                                    size_t buf_sz,
                                    size_t *out_sz);
typedef int (*vs_secbox_del_hal_t)(vs_secbox_element_info_t *element_info);

typedef struct {
    vs_secbox_save_hal_t save;
    vs_secbox_load_hal_t load;
    vs_secbox_del_hal_t del;
} vs_secbox_hal_impl_t;

int
vs_secbox_configure_hal(const vs_secbox_hal_impl_t *impl);

int
vs_secbox_save(vs_secbox_element_info_t *element_info, const uint8_t *data, size_t data_sz);

int
vs_secbox_load(vs_secbox_element_info_t *element_info, uint8_t *out_data, size_t buf_sz, size_t *out_sz);

int
vs_secbox_del(vs_secbox_element_info_t *element_info);

#endif // SECBOX_H
