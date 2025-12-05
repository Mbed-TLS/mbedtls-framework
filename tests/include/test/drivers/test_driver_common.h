/* Common definitions used by test drivers. */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_TEST_DRIVERS_TEST_DRIVER_COMMON_H
#define PSA_CRYPTO_TEST_DRIVERS_TEST_DRIVER_COMMON_H

#include "mbedtls/build_info.h"

/* Use the same formatting for error code definitions as the standard
 * error values, which must have a specific sequence of tokens for
 * interoperability between implementations of different parts of PSA.
 * This means no space between the cast and the - operator.
 * This contradicts our code style, so we temporarily disable style checking.
 *
 * *INDENT-OFF*
 */

/** Error code that test drivers return when they detect that an input
 * parameter was not initialized properly. This normally indicates a
 * bug in the core.
 */
#define PSA_ERROR_TEST_DETECTED_BAD_INITIALIZATION ((psa_status_t)-0x0201)

/* *INDENT-ON* */

/*
 * In the libtestdriver1 library used in Mbed TLS 3.6 and 4.0 for driver
 * dispatch testing, the PSA core code is cloned and all identifiers starting
 * with MBEDTLS_, PSA_, mbedtls_, or psa_ are prefixed with `libtestdriver1_`.
 * As a result, libtestdriver1 drivers use, for example,
 * `libtestdriver1_psa_key_attributes_t` instead of `psa_key_attributes_t`.
 *
 * With the generated test drivers introduced in TF-PSA-Crypto between 1.0
 * and 1.1, only the modules under `drivers/builtin` are cloned, not the PSA
 * core. The generated test drivers therefore do not use prefixed PSA core
 * identifiers. For example, they use the `psa_key_attributes_t` type, just
 * like the built-in drivers.
 *
 * To make driver dispatch work in both cases, we define certain
 * `libtestdriver1_xyz` identifiers as aliases of the corresponding `xyz`
 * identifiers in the latter case.
 */
#if defined(TF_PSA_CRYPTO_TEST_LIBTESTDRIVER1)
typedef psa_key_attributes_t libtestdriver1_psa_key_attributes_t;
typedef psa_crypto_driver_pake_inputs_t libtestdriver1_psa_crypto_driver_pake_inputs_t;
typedef psa_crypto_driver_pake_step_t libtestdriver1_psa_crypto_driver_pake_step_t;
#endif

#endif /* test_driver_common.h */
