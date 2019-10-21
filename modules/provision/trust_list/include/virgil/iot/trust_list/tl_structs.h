#ifndef TL_STRUCTS_H
#define TL_STRUCTS_H

#include <stdint.h>
#include <stdbool.h>
#include <virgil/iot/provision/provision.h>

#define TL_STORAGE_TYPE_STATIC 0
#define TL_STORAGE_TYPE_DYNAMIC 1
#define TL_STORAGE_TYPE_TMP 2

typedef size_t vs_tl_key_handle;

typedef struct __attribute__((__packed__)) {
    uint32_t tl_size; // header + public keys + footer
    vs_file_version_t version;
    uint16_t pub_keys_count;
    uint8_t signatures_count;
} vs_tl_header_t;

typedef struct __attribute__((__packed__)) {
    uint8_t tl_type;
    uint8_t signatures[];
} vs_tl_footer_t;

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

#endif // TL_STRUCTS_H
