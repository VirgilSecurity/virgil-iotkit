#ifndef TL_OPERATIONS_H
#define TL_OPERATIONS_H

void
init_tl_storage();
bool
verify_hl_key_sign(const uint8_t *key_to_check, size_t key_size);
int
invalidate_tl(size_t storage_type);
int
save_tl_header(size_t storage_type, const trust_list_header_t *header);
int
load_tl_header(size_t storage_type, trust_list_header_t *header);
int
save_tl_footer(size_t storage_type, const trust_list_footer_t *footer);
int
apply_tmp_tl_to(size_t storage_type);
int
load_tl_footer(size_t storage_type, trust_list_footer_t *footer);
int
save_tl_key(size_t storage_type, const trust_list_pub_key_t *key);
int
load_tl_key(size_t storage_type, tl_key_handle handle, trust_list_pub_key_t *key);


#endif // TL_OPERATIONS_H
