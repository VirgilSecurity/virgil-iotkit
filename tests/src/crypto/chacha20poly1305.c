#if 0

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "keypair.h"
#include "randombytes.h"
#include <virgil/iot/logger/logger.h>

#include "crypto_aead_chacha20poly1305.h"
#include "crypto_aead_xchacha20poly1305.h"

/******************************************************************************/
static bool
_test_chacha20poly1305()
{
#undef MLEN
#define MLEN 10U
#undef ADLEN
#define ADLEN 10U
#undef CLEN
#define CLEN (MLEN + crypto_aead_chacha20poly1305_ABYTES)
    static const uint8_t firstkey[crypto_aead_chacha20poly1305_KEYBYTES]
            = { 0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
                0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
                0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07 };
    static const uint8_t m[MLEN]
            = { 0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca };
    static const uint8_t nonce[crypto_aead_chacha20poly1305_NPUBBYTES]
            = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
    static const uint8_t ad[ADLEN]
            = { 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 };
    uint8_t c[CLEN];
    uint8_t detached_c[MLEN];
    uint8_t mac[crypto_aead_chacha20poly1305_ABYTES];
    uint8_t m2[MLEN];

    unsigned long long found_clen;
    unsigned long long found_maclen;
    unsigned long long m2len;
    size_t i;

    crypto_aead_chacha20poly1305_encrypt(c, &found_clen, m, MLEN,
                                         ad, ADLEN,
                                         NULL, nonce, firstkey);
    if (found_clen != CLEN) {
        VS_LOG_DEBUG("found_clen is not properly set");
    }
    crypto_aead_chacha20poly1305_encrypt_detached(detached_c,
                                                  mac, &found_maclen,
                                                  m, MLEN, ad, ADLEN,
                                                  NULL, nonce, firstkey);

    CHECK_GOTO (crypto_aead_chacha20poly1305_decrypt(m2, &m2len, NULL, c, CLEN,
                                             ad, ADLEN,
                                             nonce, firstkey) == 0,
                                                     "crypto_aead_chacha20poly1305_decrypt() failed");

    memset(m2, 0, m2len);
    CHECK_GOTO (crypto_aead_chacha20poly1305_decrypt_detached(m2, NULL,
                                                      c, MLEN, mac,
                                                      ad, ADLEN,
                                                      nonce, firstkey) == 0,
        "crypto_aead_chacha20poly1305_decrypt_detached() failed");

    for (i = 0U; i < CLEN; i++) {
        c[i] ^= (i + 1U);
        if (crypto_aead_chacha20poly1305_decrypt(m2, NULL, NULL, c, CLEN,
                                                 ad, ADLEN, nonce, firstkey)
            == 0 || memcmp(m, m2, MLEN) == 0) {
            VS_LOG_INFO("message can be forged");
        }
        c[i] ^= (i + 1U);
    }

    crypto_aead_chacha20poly1305_encrypt(c, &found_clen, m, MLEN,
                                         NULL, 0U, NULL, nonce, firstkey);
    CHECK_GOTO (found_clen == CLEN,
        "found_clen is not properly set (adlen=0)");

    CHECK_GOTO (crypto_aead_chacha20poly1305_decrypt(m2, &m2len, NULL, c, CLEN,
                                             NULL, 0U, nonce, firstkey) == 0,
        "crypto_aead_chacha20poly1305_decrypt() failed (adlen=0)");

    if (m2len != MLEN) {
        VS_LOG_DEBUG("m2len is not properly set (adlen=0)");
    }
    if (memcmp(m, m2, MLEN) != 0) return false;
    m2len = 1;
    if (crypto_aead_chacha20poly1305_decrypt(
            m2, &m2len, NULL, NULL,
            randombytes_uniform(crypto_aead_chacha20poly1305_ABYTES),
            NULL, 0U, nonce, firstkey) != -1) {
        VS_LOG_DEBUG("crypto_aead_chacha20poly1305_decrypt() worked with a short "
                       "ciphertext");
    }
    if (m2len != 0) return false;
    m2len = 1;
    if (crypto_aead_chacha20poly1305_decrypt(m2, &m2len, NULL, c, 0U, NULL, 0U,
                                             nonce, firstkey) != -1) {
        return false;
    }
    if (m2len != 0) return false;
    memcpy(c, m, MLEN);
    crypto_aead_chacha20poly1305_encrypt(c, &found_clen, c, MLEN,
                                         NULL, 0U, NULL, nonce, firstkey);
    if (found_clen != CLEN) return false;
    if (crypto_aead_chacha20poly1305_decrypt(c, &m2len, NULL, c, CLEN,
                                             NULL, 0U, nonce, firstkey) != 0) {
        return false;
    }

    if (0 != memcmp(m, c, MLEN)) return false;
    if (0 == crypto_aead_chacha20poly1305_keybytes()) return false;
    if (0 == crypto_aead_chacha20poly1305_npubbytes()) return false;
    if (0 != crypto_aead_chacha20poly1305_nsecbytes()) return false;

    return true;
}

/******************************************************************************/
static bool
_test_x_chacha20poly1305()
{
#undef MLEN
#define MLEN 114U
#undef ADLEN
#define ADLEN 12U
#undef CLEN
#define CLEN (MLEN + crypto_aead_xchacha20poly1305_ietf_ABYTES)
    static const uint8_t firstkey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]
            = {
                    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
            };
#undef MESSAGE
#define MESSAGE                                                                                                        \
    "Ladies and Gentlemen of the class of '99: If I could offer you "                                                  \
    "only one tip for the future, sunscreen would be it."
    uint8_t m[MLEN];
    static const uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
            = { 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x48, 0x49, 0x4a, 0x4b };
    static const uint8_t ad[ADLEN]
            = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    uint8_t c[CLEN];
    uint8_t detached_c[MLEN];
    uint8_t mac[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    uint8_t m2[MLEN];
    unsigned long long found_clen;
    unsigned long long found_maclen;
    unsigned long long m2len;
    size_t i;

    if (sizeof MESSAGE - 1U != MLEN) return false;
    memcpy(m, MESSAGE, MLEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(c, &found_clen, m, MLEN,
                                               ad, ADLEN,
                                               NULL, nonce, firstkey);
    if (found_clen != MLEN + crypto_aead_xchacha20poly1305_ietf_abytes()) {
        VS_LOG_DEBUG("found_clen is not properly set");
    }
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(detached_c,
                                                        mac, &found_maclen,
                                                        m, MLEN,
                                                        ad, ADLEN,
                                                        NULL, nonce, firstkey);
    CHECK_GOTO (found_maclen == crypto_aead_xchacha20poly1305_ietf_abytes(),
        "found_maclen is not properly set");

    CHECK_GOTO (crypto_aead_xchacha20poly1305_ietf_decrypt(m2, &m2len, NULL, c, CLEN, ad,
                                                   ADLEN, nonce, firstkey) == 0,
        "crypto_aead_xchacha20poly1305_ietf_decrypt() failed");

    memset(m2, 0, m2len);
    CHECK_GOTO (crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m2, NULL,
                                                            c, MLEN, mac,
                                                            ad, ADLEN,
                                                            nonce, firstkey) == 0,
                                                                    "crypto_aead_xchacha20poly1305_ietf_decrypt_detached() failed");

    if (memcmp(m, m2, MLEN) != 0)  return false;

    for (i = 0U; i < CLEN; i++) {
        c[i] ^= (i + 1U);
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(m2, NULL, NULL, c, CLEN,
                                                       ad, ADLEN, nonce, firstkey)
            == 0 || memcmp(m, m2, MLEN) == 0) {
            VS_LOG_DEBUG("message can be forged");
        }
        c[i] ^= (i + 1U);
    }
    crypto_aead_xchacha20poly1305_ietf_encrypt(c, &found_clen, m, MLEN,
                                               NULL, 0U, NULL, nonce, firstkey);
    if (found_clen != CLEN)  return false;
    CHECK_GOTO (crypto_aead_xchacha20poly1305_ietf_decrypt(m2, &m2len, NULL, c, CLEN,
                                                   NULL, 0U, nonce, firstkey) == 0,
                                                           "crypto_aead_xchacha20poly1305_ietf_decrypt() failed (adlen=0)");

    if (m2len != MLEN)  return false;
    if (memcmp(m, m2, MLEN) != 0)  return false;
    m2len = 1;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            m2, &m2len, NULL, NULL,
            randombytes_uniform(crypto_aead_xchacha20poly1305_ietf_ABYTES),
            NULL, 0U, nonce, firstkey) != -1) {
        VS_LOG_DEBUG("crypto_aead_xchacha20poly1305_ietf_decrypt() worked with a short "
                       "ciphertext");
    }
    if (m2len != 0)  return false;
    m2len = 1;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(m2, &m2len, NULL, c, 0U, NULL, 0U,
                                                   nonce, firstkey) != -1) {
        VS_LOG_DEBUG("crypto_aead_xchacha20poly1305_ietf_decrypt() worked with an empty "
                       "ciphertext");
    }
    if (m2len != 0)  return false;

    memcpy(c, m, MLEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(c, &found_clen, c, MLEN,
                                               NULL, 0U, NULL, nonce, firstkey);
    if (found_clen != CLEN)  return false;
    CHECK_GOTO (crypto_aead_xchacha20poly1305_ietf_decrypt(c, &m2len, NULL, c, CLEN,
                                                   NULL, 0U, nonce, firstkey) == 0,
                                                           "crypto_aead_xchacha20poly1305_ietf_decrypt() failed (adlen=0)");
    if (m2len != MLEN)  return false;
    if (memcmp(m, c, MLEN) != 0) return false;

    if (crypto_aead_xchacha20poly1305_ietf_keybytes() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) return false;
    if (crypto_aead_xchacha20poly1305_ietf_npubbytes() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;
    if (crypto_aead_xchacha20poly1305_ietf_nsecbytes() != 0) return false;
    if (crypto_aead_xchacha20poly1305_ietf_nsecbytes() != crypto_aead_xchacha20poly1305_ietf_NSECBYTES) return false;
    if (crypto_aead_xchacha20poly1305_IETF_KEYBYTES  != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) return false;
    if (crypto_aead_xchacha20poly1305_IETF_NSECBYTES != crypto_aead_xchacha20poly1305_ietf_NSECBYTES) return false;
    if (crypto_aead_xchacha20poly1305_IETF_NPUBBYTES != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) return false;
    if (crypto_aead_xchacha20poly1305_IETF_ABYTES    != crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;

    return true;
}

/******************************************************************************/
void
test_chacha20poly1305(void)
{
    START_TEST("test_chacha20poly1305");

    TEST_CASE_OK ("ChaCha20_Poly1305", _test_chacha20poly1305());
    TEST_CASE_OK ("X ChaCha20_Poly1305", _test_x_chacha20poly1305());
}

#endif