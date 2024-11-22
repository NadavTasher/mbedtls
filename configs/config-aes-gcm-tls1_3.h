/**
 * \file config-aes-gcm-tls1_3.h
 *
 * \brief Minimal configuration for TLS 1.3 with AES-GCM ciphersuites
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_PSA_CRYPTO_CONFIG_FILE "../configs/crypto-config-aes-gcm-tls1_3.h"

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_USE_PSA_CRYPTO
#define MBEDTLS_PSA_CRYPTO_CLIENT

/* System support */
//#define MBEDTLS_HAVE_TIME /* Optionally used in Hello messages */
/* Other MBEDTLS_HAVE_XXX flags irrelevant for this configuration */

/* Mbed TLS modules */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NET_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C

/* TLS protocol feature support */
#define MBEDTLS_SSL_PROTO_TLS1_3

/*
 * Use only AES-GCM ciphersuites, and
 * save ROM and a few bytes of RAM by specifying our own ciphersuite list
 */
#define MBEDTLS_SSL_CIPHERSUITES TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384

/*
 * Save RAM at the expense of interoperability: do this only if you control
 * both ends of the connection!  (See comments in "mbedtls/ssl.h".)
 * The optimal size here depends on the typical size of records.
 */
#define MBEDTLS_SSL_IN_CONTENT_LEN              1024
#define MBEDTLS_SSL_OUT_CONTENT_LEN             1024

/* Save RAM at the expense of ROM */
#define MBEDTLS_AES_ROM_TABLES

/*
 * You should adjust this to the exact number of sources you're using: default
 * is the "platform_entropy_poll" source, but you may want to add other ones
 * Minimum is 2 for the entropy test suite.
 */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2

/* Error messages and TLS debugging traces
 * (huge code size increase, needed for tests/ssl-opt.sh) */
//#define MBEDTLS_DEBUG_C
//#define MBEDTLS_ERROR_C
