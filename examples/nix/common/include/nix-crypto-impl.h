//
// Created by Oleksandr Nemchenko on 10/9/19.
//

#ifndef VIRGIL_IOT_SDK_EXAMPLES_NIX_CRYPTO_IMPL_H
#define VIRGIL_IOT_SDK_EXAMPLES_NIX_CRYPTO_IMPL_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

#include <virgil/iot/hsm/hsm_structs.h>
#include <virgil/iot/hsm/devices/hsm_iotelic.h>

#define MAX_KEY_SZ (128)

const char *
get_slot_name(vs_iot_hsm_slot_e slot);

int
vs_hsm_keypair_get_prvkey(vs_iot_hsm_slot_e slot,
                          uint8_t *buf,
                          uint16_t buf_sz,
                          uint16_t *key_sz,
                          vs_hsm_keypair_type_e *keypair_type);

const char *
vs_nix_get_slots_dir(void);

#endif //VIRGIL_IOT_SDK_EXAMPLES_NIX_CRYPTO_IMPL_H
