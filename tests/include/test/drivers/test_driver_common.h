/* Common definitions used by test drivers. */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef PSA_CRYPTO_TEST_DRIVERS_TEST_DRIVER_COMMON_H
#define PSA_CRYPTO_TEST_DRIVERS_TEST_DRIVER_COMMON_H

#include "mbedtls/build_info.h"

/** Error code that test drivers return when they detect that an input
 * parameter was not initialized properly. This normally indicates a
 * bug in the core.
 */
#define PSA_ERROR_TEST_DETECTED_BAD_INITIALIZATION ((psa_status_t)-0x0201)

#endif /* test_driver_common.h */
