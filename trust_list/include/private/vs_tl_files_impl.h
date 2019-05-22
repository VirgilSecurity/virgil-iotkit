#ifndef TL_FILES_H
#define TL_FILES_H

#include <stdint.h>
#include <stdio.h>
#include "vs_tl_structs.h"
#include "vs_trust_list.h"

size_t
get_tl_default_base_addr_impl(size_t storage_type);
bool
write_tl_part_to_file_impl(tl_context_t *ctx, vs_tl_element_info_t element_info, const uint8_t *data, size_t size);
bool
read_tl_part_from_file_impl(tl_context_t *ctx,
                            vs_tl_element_info_t element_info,
                            uint8_t *data,
                            size_t buf_sz,
                            size_t *data_sz);
bool
remove_tl_part_file_impl(tl_context_t *ctx, vs_tl_element_info_t element_info);


#endif // TL_FILES_H
