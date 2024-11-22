/**
 * \file crypto-config-ccm-psk-tls1_2.h
 *
 * \brief Minimal crypto configuration for TLS 1.2 with
 * PSK and AES-CCM ciphersuites
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/**
 * To be used in conjunction with configs/config-ccm-psk-tls1_2.h
 * or configs/config-ccm-psk-dtls1_2.h. */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_SHA_256                    1
#define PSA_WANT_ALG_SHA_384                    1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_HKDF_EXTRACT               1

#define PSA_WANT_KEY_TYPE_AES               1

#endif /* PSA_CRYPTO_CONFIG_H */
