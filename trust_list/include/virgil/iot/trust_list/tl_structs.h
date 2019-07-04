#ifndef TL_STRUCTS_H
#define TL_STRUCTS_H

#include <stdint.h>
#include <stdbool.h>
#include <virgil/iot/provision/provision.h>

#define TL_STORAGE_TYPE_STATIC 0
#define TL_STORAGE_TYPE_DYNAMIC 1
#define TL_STORAGE_TYPE_TMP 2

typedef enum {
    VS_TL_OK = 0,
    VS_TL_ERROR_GENERAL = -1,
    VS_TL_ERROR_PARAMS = -2,
    VS_TL_ERROR_SMALL_BUFFER = -3,
    VS_TL_ERROR_WRITE = -4,
    VS_TL_ERROR_READ = -5,
} vs_tl_result_e;

typedef size_t vs_tl_key_handle;

typedef struct __attribute__((__packed__)) {
    uint32_t tl_size;
    uint16_t version;
    uint16_t pub_keys_count;
    uint8_t signatures_count;
} vs_tl_header_t;

typedef struct __attribute__((__packed__)) {
    uint8_t tl_type;
    uint8_t signatures[];
} vs_tl_footer_t;


#endif // TL_STRUCTS_H
