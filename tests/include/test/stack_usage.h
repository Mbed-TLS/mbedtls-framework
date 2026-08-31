/** A framework to measure stack usage of a code snippet.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TEST_STACK_USAGE_H
#define TEST_STACK_USAGE_H

#include "test/helpers.h"

#undef MBEDTLS_TEST_STACK_USAGE

/* Don't break the build if <alloca.h> is not available. */
#if defined(__has_include)
#if __has_include(<alloca.h>)
#define MBEDTLS_TEST_STACK_USAGE_ALLOCA
#define MBEDTLS_TEST_STACK_USAGE
#endif
#endif

/* The stack usage measurement code works with MemorySanitizer (MSan).
 * However, MSan induces considerable overhead to the stack usage
 * (more than double), so doing measurements with MSan is generally not
 * useful. Hence we disable stack usage measurement when building with MSan. */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#undef MBEDTLS_TEST_STACK_USAGE_ALLOCA
#undef MBEDTLS_TEST_STACK_USAGE
#endif
#endif

#if defined(MBEDTLS_TEST_STACK_USAGE)

/** Prepare to measure the stack usage of subsequent code.
 *
 * This function may temporarily grow the actually allocated stack space
 * by approximately \p max bytes.
 *
 * After calling this function:
 * - You may call mbedtls_test_stack_usage_get() from the same function
 *   one or more times to get the maximum stack usage since the call to
 *   mbedtls_test_stack_usage_start().
 * - You must call mbedtls_test_stack_usage_stop() from the same function.
 *
 * \param max       The number of bytes that should be measurable.
 *                  If the subsequent code uses more than \p max bytes
 *                  of stack space, mbedtls_test_stack_usage_get()
 *                  may not be able to measure the stack usage accurately.
 *
 * \retval #PSA_SUCCESS
 *                  Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *                  The stack usage framework doesn't work in this
 *                  environment.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *                  This implementation of stack usage measurement needs
 *                  to actually allocate memory, and the memory allocation
 *                  failed.
 */
int mbedtls_test_stack_usage_start(size_t max);

/** .
 *
 * \return          The largest stack depth since the previous call to
 *                  mbedtls_test_stack_usage_start(), not including the
 *                  part of the stack above the call to
 *                  mbedtls_test_stack_usage_start().
 *
 *                  The value is approximate. It may be rounded to a multiple
 *                  of 16, and does not account for the (small but nonzero)
 *                  stack space used by mbedtls_test_stack_usage_start().
 *
 *                  This function may return \c SIZE_MAX if the used stack
 *                  space is larger than approximately the \c max value
 *                  passed to mbedtls_test_stack_usage_start(), or if
 *                  mbedtls_test_stack_usage_start() has not been called
 *                  in this thread since the last call to
 *                  mbedtls_test_stack_usage_stop().
 */
size_t mbedtls_test_stack_usage_get(void);

/** Assert a bound on stack usage since the last call to
 * mbedtls_test_stack_usage_start().
 *
 * If the largest stack depth is more than \p limit, mark the test case
 * as failed and jump to the \c exit label.
 *
 * See mbedtls_test_stack_usage_get() for caveats regarding precision.
 *
 * \param limit     The number of bytes of stack space that may have been used.
 */
#define MBEDTLS_TEST_STACK_USAGE_CHECK(limit) \
    TEST_LE_U(mbedtls_test_stack_usage_get(), limit)

/** Stop stack measurement.
 *
 * You must call this function after calling mbedtls_test_stack_usage_start(),
 * from the same stack frame.
 *
 * This function does nothing if there has not been a previous call to
 * mbedtls_test_stack_usage_start().
 */
void mbedtls_test_stack_usage_stop(void);

#else /* MBEDTLS_TEST_STACK_USAGE */

static inline int mbedtls_test_stack_usage_start(size_t max)
{
    (void) max;
    return PSA_ERROR_NOT_SUPPORTED;
}

#define MBEDTLS_TEST_STACK_USAGE_CHECK(limit) ((void) 0)

static inline void mbedtls_test_stack_usage_stop(void)
{
    /* nothing to do */
}

#endif /* MBEDTLS_TEST_STACK_USAGE */

/** Prepare to measure the stack usage of subsequent code.
 *
 * This function may temporarily grow the actually allocated stack space
 * by approximately \p max bytes.
 *
 * After calling this macro:
 * - You may call #MBEDTLS_TEST_STACK_USAGE_CHECK() from the same function
 *   one or more times to get the maximum stack usage since the call to
 *   MBEDTLS_TEST_STACK_USAGE_START().
 * - You must call MBEDTLS_TEST_STACK_USAGE_STOP() from the same function.
 *
 * If the stack usage framework doesn't work, mark the test case as failed
 * and jump to the \c exit label.
 *
 * \param max       The number of bytes that should be measurable.
 */
#define MBEDTLS_TEST_STACK_USAGE_START(max)             \
    PSA_ASSERT(mbedtls_test_stack_usage_start(max))

/** Prepare to measure the stack usage of subsequent code.
 *
 * This function may temporarily grow the actually allocated stack space
 * by approximately \p max bytes.
 *
 * After calling this macro:
 * - You may call #MBEDTLS_TEST_STACK_USAGE_CHECK() from the same function
 *   one or more times to get the maximum stack usage since the call to
 *   MBEDTLS_TEST_STACK_USAGE_START().
 * - You must call MBEDTLS_TEST_STACK_USAGE_STOP() from the same function.
 *
 * If the stack usage framework doesn't work, mark the test case as skipped
 * and jump to the \c exit label.
 *
 * \param max       The number of bytes that should be measurable.
 */
#define MBEDTLS_TEST_STACK_USAGE_TRY(max)               \
    TEST_ASSUME(mbedtls_test_stack_usage_start(max) == PSA_SUCCESS)

/** Stop stack measurement.
 *
 * You must call this macro after calling #MBEDTLS_TEST_STACK_USAGE_START()
 * or #MBEDTLS_TEST_STACK_USAGE_TRY(), from the same stack frame.
 *
 * This function does nothing if there has not been a previous call to
 * mbedtls_test_stack_usage_start().
 */
#define MBEDTLS_TEST_STACK_USAGE_STOP(max)      \
    mbedtls_test_stack_usage_stop()

#endif /* TEST_STACK_USAGE_H */
