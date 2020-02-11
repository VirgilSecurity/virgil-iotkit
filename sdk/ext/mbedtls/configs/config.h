/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/**
 * \name SECTION: System support
 *
 * This section sets system specific settings.
 * \{
 */

//#define MBEDTLS_HAVE_ASM

#define MBEDTLS_KDF_C
#define MBEDTLS_KDF2_C
#define MBEDTLS_FAST_EC_C
#define MBEDTLS_ED25519_C
#define MBEDTLS_ECIES_C
#define MBEDTLS_PK_WRITE_PKCS8_C
#define MBEDTLS_GENPRIME

#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_PLATFORM_MEMORY

#define MBEDTLS_NET_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD

#define MBEDTLS_BASE64_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_PEM_PARSE_C

#define MBEDTLS_SSL_PROTO_TLS1
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_SSL3
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED
#define MBEDTLS_SSL_PROTO_DTLS
#define MBEDTLS_ECIES_CIPHER_TYPE MBEDTLS_CIPHER_AES_128_CBC
#define MBEDTLS_CCM_C
#define MBEDTLS_DES_C
#define MBEDTLS_DEBUG_C

#define MBEDTLS_CIPHER_MODE_CBC

#define MBEDTLS_CIPHER_MODE_CTR

#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES

#define MBEDTLS_ECP_DP_SECP192K1_ENABLED
#define MBEDTLS_ECP_DP_SECP224K1_ENABLED
#define MBEDTLS_ECP_DP_SECP256K1_ENABLED
#define MBEDTLS_ECP_DP_SECP192R1_ENABLED
#define MBEDTLS_ECP_DP_SECP224R1_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED

#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED

#define MBEDTLS_ERROR_STRERROR_DUMMY

#define MBEDTLS_PKCS12_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_VERSION_FEATURES

//#define MBEDTLS_AESNI_C

#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
// #define MBEDTLS_CERTS_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_DHM_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C

#define MBEDTLS_OID_C
//#define MBEDTLS_PADLOCK_C

#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_PARSE_EC_EXTENDED
#define MBEDTLS_PLATFORM_C
//
#define MBEDTLS_RSA_C

#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C

#define MBEDTLS_VERSION_C

//
// EC optimizations
//
#define MBEDTLS_ECP_NIST_OPTIM 1
#define MBEDTLS_ECP_FIXED_POINT_OPTIM 1

#include "check_config.h"

#endif /* MBEDTLS_CONFIG_H */
