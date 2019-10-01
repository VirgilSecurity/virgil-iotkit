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
    uint32_t tl_size;   // header + public keys + footer
    uint16_t version;
    uint16_t pub_keys_count;
    uint8_t signatures_count;
} vs_tl_header_t;

typedef struct __attribute__((__packed__)) {
    uint8_t tl_type;
    uint8_t signatures[];
} vs_tl_footer_t;


#endif // TL_STRUCTS_H
