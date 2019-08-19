//
// Created by Maxim Grigoryev on 2019-08-16.
//

#ifndef VS_TL_HAL_H
#define VS_TL_HAL_H

/*Hal, which is temporary defined*/

typedef struct vs_tl_element_info_hal_s {
    uint16_t storage_type;
    uint16_t id;
    uint16_t index;
} vs_tl_element_info_hal_t;

int
vs_tl_save_hal(vs_tl_element_info_hal_t *element_info, const uint8_t *data, uint16_t data_sz);

int
vs_tl_load_hal(vs_tl_element_info_hal_t *element_info, uint8_t *out_data, uint16_t data_sz);

int
vs_tl_del_hal(vs_tl_element_info_hal_t *element_info);

#endif // VS_TL_HAL_H
