#ifndef TL_OPERATIONS_H
#define TL_OPERATIONS_H

void
vs_tl_storage_init();
bool
vs_tl_verify_hl_key(const uint8_t *key_to_check, size_t key_size);
int
vs_tl_invalidate(size_t storage_type);
int
vs_tl_header_save(size_t storage_type, const vs_tl_header_t *header);
int
vs_tl_header_load(size_t storage_type, vs_tl_header_t *header);
int
vs_tl_footer_save(size_t storage_type, const vs_tl_footer_t *footer);
int
vs_tl_apply_tmp_to(size_t storage_type);
int
vs_tl_footer_load(size_t storage_type, vs_tl_footer_t *footer);
int
vs_tl_key_save(size_t storage_type, const vs_tl_pubkey_t *key);
int
vs_tl_key_load(size_t storage_type, vs_tl_key_handle handle, vs_tl_pubkey_t *key);


#endif // TL_OPERATIONS_H
