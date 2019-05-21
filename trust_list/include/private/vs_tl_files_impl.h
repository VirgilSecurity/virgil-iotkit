#ifndef TL_FILES_H
#define TL_FILES_H

#include <stdint.h>
#include <stdio.h>
#include "vs_tl_structs.h"

size_t
get_tl_default_base_addr_impl(size_t storage_type);
bool
write_tl_header_file_impl(tl_context_t *ctx, const trust_list_header_t *tl_header);
bool
read_tl_header_file_impl(tl_context_t *ctx, trust_list_header_t *tl_header);
bool
remove_tl_header_file_impl(tl_context_t *ctx);
bool
write_tl_key_file_impl(tl_context_t *ctx, size_t key_id, const trust_list_pub_key_t *key);
bool
read_tl_key_file_impl(tl_context_t *ctx, size_t key_id, trust_list_pub_key_t *key);
bool
remove_tl_key_file_impl(tl_context_t *ctx, tl_key_handle handle);
bool
write_tl_footer_file_impl(tl_context_t *ctx, const trust_list_footer_t *footer);
bool
read_tl_footer_file_impl(tl_context_t *ctx, trust_list_footer_t *footer);
bool
remove_tl_footer_file_impl(tl_context_t *ctx);

#endif // TL_FILES_H
