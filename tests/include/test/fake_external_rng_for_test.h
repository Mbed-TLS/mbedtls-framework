/*
 * Insecure but standalone implementation of mbedtls_psa_external_get_random().
 * Only for use in tests!
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef FAKE_EXTERNAL_RNG_FOR_TEST_H
#define FAKE_EXTERNAL_RNG_FOR_TEST_H

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
/** Enable the insecure implementation of mbedtls_psa_external_get_random().
 *
 * The insecure implementation of mbedtls_psa_external_get_random() is
 * disabled by default.
 *
 * When MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG is enabled and the test
 * helpers are linked into a program, you must enable this before running any
 * code that uses the PSA subsystem to generate random data (including internal
 * random generation for purposes such as blinding when the random generation
 * is routed through PSA).
 *
 * You can enable and disable it at any time, regardless of the state
 * of the PSA subsystem. You may disable it temporarily to simulate a
 * depleted entropy source.
 */
void mbedtls_test_enable_insecure_external_rng(void);

/** Disable the insecure implementation of mbedtls_psa_external_get_random().
 *
 * See mbedtls_test_enable_insecure_external_rng().
 */
void mbedtls_test_disable_insecure_external_rng(void);
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#if defined(MBEDTLS_PLATFORM_GET_ENTROPY_ALT)

#include <mbedtls/platform.h>

/* Force return value or entropy content in mbedtls_platform_get_entropy_alt()
 * as follows:
 * - if fail == 0 && forced_entropy_content == 0 then
 *   mbedtls_platform_get_entropy_alt() behaves properly.
 * - if fail != 0 then MBEDTLS_ERR_ENTROPY_SOURCE_FAILED is returned.
 * - if forced_entropy_content != 0 then
 *      - return value is success (0) but
 *      - returned entropy_content will be equal to forced_entropy_content.
 */
void mbedtls_test_get_entropy_alt_force(int fail, size_t forced_entropy_content);

#endif /* MBEDTLS_PLATFORM_GET_ENTROPY_ALT */

#endif /* FAKE_EXTERNAL_RNG_FOR_TEST_H */
