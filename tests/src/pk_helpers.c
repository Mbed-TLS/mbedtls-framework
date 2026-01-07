/*
 * Helper functions for PK.
 * This is only for TF-PSA-Crypto 1.0 and above.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <mbedtls/pk.h>
#include <test/macros.h>
#include <test/helpers.h>
#include <test/pk_helpers.h>
#include <test/psa_helpers.h>
#include <test/test_keys.h>
#include "psa_util_internal.h"

/* Functions like mbedtls_pk_wrap_psa() are only available in tf-psa-crypto and
 * not in 3.6 LTS branch, so we need a guard for this. */
#if !defined(MBEDTLS_VERSION_MAJOR) || MBEDTLS_VERSION_MAJOR >= 4

#if defined(MBEDTLS_PK_C)

int mbedtls_pk_helpers_get_predefined_key_data(int is_ec, int group_id_or_keybits,
                                               const unsigned char **key, size_t *key_len,
                                               const unsigned char **pub_key, size_t *pub_key_len)
{
    size_t i;
    struct predefined_key_element *predefined_key = NULL;

    for (i = 0; i < ARRAY_LENGTH(predefined_keys); i++) {
        if (is_ec) {
            if (group_id_or_keybits == predefined_keys[i].group_id) {
                predefined_key = &predefined_keys[i];
            }
        } else if (group_id_or_keybits == predefined_keys[i].keybits) {
            predefined_key = &predefined_keys[i];
        }
    }

    if (predefined_key != NULL) {
        *key = predefined_key->priv_key;
        *key_len = predefined_key->priv_key_len;
        if (pub_key != NULL) {
            *pub_key = predefined_key->pub_key;
            *pub_key_len = predefined_key->pub_key_len;
        }
        return 0;
    }

    TEST_FAIL("Unsupported key");
    /* "exit" label is to make the compiler happy. */
exit:
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
}

mbedtls_svc_key_id_t mbedtls_pk_helpers_make_psa_key_from_predefined(psa_key_type_t key_type,
                                                                     psa_key_bits_t key_bits,
                                                                     psa_algorithm_t alg,
                                                                     psa_algorithm_t alg2,
                                                                     psa_key_usage_t usage_flags)
{
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    const uint8_t *priv_key = NULL;
    size_t priv_key_len = 0;
    const uint8_t *pub_key = NULL;
    size_t pub_key_len = 0;
    int ret;

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY)
    if (PSA_KEY_TYPE_IS_RSA(key_type)) {
        ret = mbedtls_pk_helpers_get_predefined_key_data(0, key_bits, &priv_key, &priv_key_len,
                                                         &pub_key, &pub_key_len);
        TEST_EQUAL(ret, 0);
    } else
#endif /* PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY */
#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
    if (PSA_KEY_TYPE_IS_ECC(key_type)) {
        psa_ecc_family_t ec_family = PSA_KEY_TYPE_ECC_GET_FAMILY(key_type);
        mbedtls_ecp_group_id ecp_group = mbedtls_ecc_group_from_psa(ec_family, key_bits);
        ret = mbedtls_pk_helpers_get_predefined_key_data(1, ecp_group, &priv_key, &priv_key_len,
                                                         &pub_key, &pub_key_len);
        TEST_EQUAL(ret, 0);
    } else
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */
    {
        TEST_FAIL("Unsupported key");
    }

    psa_set_key_type(&attr, key_type);
    psa_set_key_usage_flags(&attr, usage_flags);
    psa_set_key_algorithm(&attr, alg);
    psa_set_key_enrollment_algorithm(&attr, alg2);
    PSA_ASSERT(psa_import_key(&attr, priv_key, priv_key_len, &key_id));

exit:
    return key_id;
}

void mbedtls_pk_helpers_populate_context(mbedtls_pk_context *pk, mbedtls_svc_key_id_t key_id,
                                         pk_context_populate_method_t method)
{
    switch (method) {
        case TEST_PK_WRAP_PSA:
            TEST_EQUAL(mbedtls_pk_wrap_psa(pk, key_id), 0);
            break;
        case TEST_PK_COPY_FROM_PSA:
            TEST_EQUAL(mbedtls_pk_copy_from_psa(key_id, pk), 0);
            break;
        case TEST_PK_COPY_PUBLIC_FROM_PSA:
            TEST_EQUAL(mbedtls_pk_copy_public_from_psa(key_id, pk), 0);
            break;
        default:
            TEST_FAIL("Unknown method");
    }

exit:; /* Needed to make compiler happy */
}

#endif /* MBEDTLS_PK_C */

#endif /* !MBEDTLS_VERSION_MAJOR || MBEDTLS_VERSION_MAJOR >= 4 */
