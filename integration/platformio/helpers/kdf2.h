
#ifndef VS_KDF2_H
#define VS_KDF2_H

#include <stdint.h>
#include <stdio.h>

#include <virgil/iot/status_code/status_code.h>

vs_status_e
vs_mbedtls_kdf2(const mbedtls_md_info_t *md_info,
                const unsigned char *input,
                size_t ilen,
                unsigned char *output,
                size_t olen);

#endif // VS_KDF2_H
