/*
 * Helper functions for PK
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PK_HELPERS_H
#define PK_HELPERS_H

#if defined(MBEDTLS_PK_C)

#include <psa/crypto.h>
#include <mbedtls/pk.h>

typedef enum {
    TEST_PK_WRAP_PSA,
    TEST_PK_COPY_FROM_PSA,
    TEST_PK_COPY_PUBLIC_FROM_PSA,
} pk_context_populate_method_t;

int pk_helpers_get_predefined_key_data(int is_ec, int group_id_or_keybits,
                                       const unsigned char **key, size_t *key_len,
                                       const unsigned char **pub_key, size_t *pub_key_len);

mbedtls_svc_key_id_t pk_helpers_make_psa_key_from_predefined(psa_key_type_t key_type,
                                                             psa_key_bits_t key_bits,
                                                             psa_algorithm_t alg,
                                                             psa_algorithm_t alg2,
                                                             psa_key_usage_t usage_flags);

void pk_helpers_populate_context(mbedtls_pk_context *pk, mbedtls_svc_key_id_t key_id,
                                 pk_context_populate_method_t method);

#endif /* MBEDTLS_PK_C */

#endif /* PK_HELPERS_H */
