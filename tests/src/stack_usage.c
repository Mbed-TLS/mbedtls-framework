/** \file stack_usage.c
 *
 * \brief A framework to measure stack usage of a code snippet.
 *
 * This framework is only implemented on specific platforms,
 * and only makes approximate measurements.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "test_common.h"
#include <test/helpers.h>
#include <test/macros.h>
#include <test/stack_usage.h>


#if defined(MBEDTLS_TEST_STACK_USAGE_ALLOCA)

#include <alloca.h>
#include <test/random.h>

/* The stack usage check involves reading memory which is uninitialized
 * by the rules of C. If necessary, tell sanitizers that it's ok. */
#undef MAKE_MEMORY_DEFINED

#if defined(__has_include)
#if __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define MAKE_MEMORY_DEFINED(start, len) VALGRIND_MAKE_MEM_DEFINED(start, len)
#endif
#endif

#if !defined(MAKE_MEMORY_DEFINED)
#define MAKE_MEMORY_DEFINED(start, len) ((void) 0)
#endif

/* Length of the pattern written repeatedly to the stack to detect the
 * unchanged region. This should be a power of 2, large enough so that
 * a random string of this length is statistically unique. The stack usage
 * figure is rounded to a multiple of this length, so it should be small
 * to get more precise measurements. */
#define PATTERN_LENGTH 16

/* A pattern written repeatedly to the stack to detect the unchanged region. */
static unsigned char pattern[PATTERN_LENGTH];

/* Starting (i.e. lowest) address of the stack region that has been filled
 * with the pattern. It will be aligned to PATTERN_LENGTH.
 *
 * 0 when no marking has been done.
 */
static uintptr_t marked_start;

/* Length of the stack region that has been filled with the pattern.
 * It will be a multiple of PATTERN_LENGTH.
 *
 * 0 when no marking has been done.
 */
static size_t marked_size;

/* Fill approximately max bytes on the stack with a random pattern.
 * The filled region is aligned and rounded to a multiple of PATTERN_LENGTH.
 *
 * Later, we can tell how much of the stack has remained unused by
 * checking where the pattern is still present.
 */
int mbedtls_test_stack_usage_start(size_t max)
{
    /* Generate a random pattern, which is statistically guaranteed
     * to be distinct from all other program data. */
    mbedtls_test_rnd_std_rand(NULL, pattern, PATTERN_LENGTH);

    /* Align the start and size of the marked region to multiples
     * of PATTERN_LENGTH. This simplifies filling with the pattern,
     * and later searching for the pattern. */
    if (max % PATTERN_LENGTH != 0) {
        max += PATTERN_LENGTH - max % PATTERN_LENGTH;
    }
    unsigned char *marking = alloca(max + PATTERN_LENGTH - 1);
    if (marking == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }
    marked_start = (uintptr_t) marking;
    if (marked_start % PATTERN_LENGTH != 0) {
        marked_start += PATTERN_LENGTH - marked_start % PATTERN_LENGTH;
        marking = (unsigned char *) marked_start;
    }
    marked_size = max;

    for (size_t i = 0; i < marked_size; i += PATTERN_LENGTH) {
        memcpy(marking + i, pattern, PATTERN_LENGTH);
    }
    return PSA_SUCCESS;
}

/* Detect how much of the region marked by mbedtls_test_stack_usage_start()
 * is still intact, i.e. how much of the stack has remained unused. */
size_t mbedtls_test_stack_usage_get(void)
{
    if (marked_start == 0 || marked_size == 0) {
        /* Misuse. */
        return SIZE_MAX;
    }

    /* We assume a downward-growing stack, so the unchanged part
     * is at low addresses. If this code runs on a platform with
     * an upward-growing stack, this function will in practice
     * always believe that the whole marked region was overwritten.
     */
    const unsigned char *p = (const unsigned char *) marked_start;
    MAKE_MEMORY_DEFINED(p, marked_size);

    if (memcmp(pattern, p, PATTERN_LENGTH)) {
        /* None of the marked region was preserved, so we have no
         * way to bound the amount of stack that was used. */
        return SIZE_MAX;
    }

    for (size_t i = PATTERN_LENGTH; i < marked_size; i += PATTERN_LENGTH) {
        if (memcmp(pattern, p + i, PATTERN_LENGTH)) {
            return marked_size - i;
        }
    }
    return 0;
}

void mbedtls_test_stack_usage_stop(void)
{
    memset(pattern, 0, PATTERN_LENGTH);
    marked_start = 0;
    marked_size = 0;
}

#endif /* MBEDTLS_TEST_STACK_USAGE_ALLOCA */
