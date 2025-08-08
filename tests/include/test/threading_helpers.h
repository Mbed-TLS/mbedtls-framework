/**
 * \file threading_helpers.h
 *
 * \brief This file contains the prototypes of helper functions for the purpose
 *        of testing threading.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef THREADING_HELPERS_H
#define THREADING_HELPERS_H

#if defined MBEDTLS_THREADING_C

#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"

/* Most fields of publicly available structs are private and are wrapped with
 * MBEDTLS_PRIVATE macro. This define allows tests to access the private fields
 * directly (without using the MBEDTLS_PRIVATE wrapper). */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#define MBEDTLS_ERR_THREADING_THREAD_ERROR                 -0x001F

#if defined(MBEDTLS_THREADING_C11)
#include <threads.h>
typedef int mbedtls_test_thread_return_t;
#define MBEDTLS_TEST_THREAD_RETURN_0 0
#endif /* MBEDTLS_THREADING_C11 */

#if defined(MBEDTLS_THREADING_PTHREAD)
#include <pthread.h>
/** Type returned by ::mbedtls_test_thread_function_t */
typedef void *mbedtls_test_thread_return_t;
/** A value of type ::mbedtls_test_thread_return_t, to return from
 * ::mbedtls_test_thread_function_t. */
#define MBEDTLS_TEST_THREAD_RETURN_0 NULL
#endif /* MBEDTLS_THREADING_PTHREAD */

#if defined(MBEDTLS_THREADING_ALT)
/* You should define the mbedtls_test_thread_t type in your header */
#include "threading_alt.h"

#else /* MBEDTLS_THREADING_ALT*/

typedef struct mbedtls_test_thread_t {

#if defined(MBEDTLS_THREADING_C11)
    thrd_t MBEDTLS_PRIVATE(thread);
#elif defined(MBEDTLS_THREADING_PTHREAD)
    pthread_t MBEDTLS_PRIVATE(thread);
#else /* MBEDTLS_THREADING_ALT */
    /* Make sure this struct is always non-empty */
    unsigned dummy;
#endif

} mbedtls_test_thread_t;

#endif /* MBEDTLS_THREADING_ALT*/

/** The type of thread functions.
 */
typedef mbedtls_test_thread_return_t (mbedtls_test_thread_function_t)(void *);

/**
 * \brief                   The function pointers for thread create and thread
 *                          join.
 *
 * \note                    These functions are part of the testing API only
 *                          and thus not considered part of the public API of
 *                          MbedTLS and thus may change without notice.
 *
 * \note                    All these functions are expected to work or
 *                          the result will be undefined.
 */
extern int (*mbedtls_test_thread_create)(mbedtls_test_thread_t *thread,
                                         mbedtls_test_thread_function_t thread_func,
                                         void *thread_data);
extern int (*mbedtls_test_thread_join)(mbedtls_test_thread_t *thread);

#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE) || \
    (defined(MBEDTLS_THREADING_PTHREAD) && defined(MBEDTLS_TEST_HOOKS))
#define MBEDTLS_TEST_MUTEX_USAGE
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
/**
 *  Activate the mutex usage verification framework. See threading_helpers.c for
 *  information.
 */
void mbedtls_test_mutex_usage_init(void);

/**
 *  Deactivate the mutex usage verification framework. See threading_helpers.c
 *  for information.
 */
void mbedtls_test_mutex_usage_end(void);

/**
 *  Call this function after executing a test case to check for mutex usage
 * errors.
 */
void mbedtls_test_mutex_usage_check(void);
#endif /* MBEDTLS_TEST_MUTEX_USAGE */

#endif /* MBEDTLS_THREADING_C */

#endif /* THREADING_HELPERS_H */
