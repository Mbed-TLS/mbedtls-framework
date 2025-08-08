/** Mutex usage verification framework. */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <test/helpers.h>
#include <test/threading_helpers.h>
#include <test/macros.h>

#if defined(MBEDTLS_THREADING_C)

#include "mbedtls/threading.h"

#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
#include "threading_internal.h"
#endif

#if defined(MBEDTLS_PLATFORM_THREADING_THREAD)
#define GET_THREAD(ptr) (ptr)
#else
#define GET_THREAD(ptr) (&(ptr)->thread)
#endif

#if defined(MBEDTLS_THREADING_C11)

static int threading_thread_create_c11(mbedtls_test_thread_t *thread,
                                       mbedtls_test_thread_function_t thread_func,
                                       void *thread_data)
{
#if !defined(MBEDTLS_PLATFORM_THREADING_THREAD)
    if (thread == NULL || thread_func == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }
#endif

    int ret = thrd_create(GET_THREAD(thread), thread_func, thread_data);

    switch (ret) {
        case thrd_success:
            return 0;
        case thrd_nomem:
            return PSA_ERROR_INSUFFICIENT_MEMORY;
        default:
            return MBEDTLS_ERR_THREADING_THREAD_ERROR;
    }
}

static int threading_thread_join_c11(mbedtls_test_thread_t *thread)
{
#if defined(MBEDTLS_PLATFORM_THREADING_THREAD)
    if (thread == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }
#endif

    if (thrd_join(*GET_THREAD(thread), NULL) != thrd_success) {
        return MBEDTLS_ERR_THREADING_THREAD_ERROR;
    }
    return 0;
}

int (*mbedtls_test_thread_create)(mbedtls_test_thread_t *thread,
                                  mbedtls_test_thread_function_t thread_func,
                                  void *thread_data) = threading_thread_create_c11;
int (*mbedtls_test_thread_join)(mbedtls_test_thread_t *thread) = threading_thread_join_c11;

#endif /* MBEDTLS_THREADING_C11 */

#if defined(MBEDTLS_THREADING_PTHREAD)

static int threading_thread_create_pthread(mbedtls_test_thread_t *thread,
                                           mbedtls_test_thread_function_t thread_func,
                                           void *thread_data)
{
#if !defined(MBEDTLS_PLATFORM_THREADING_THREAD)
    if (thread == NULL || thread_func == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }
#endif

    if (pthread_create(GET_THREAD(thread), NULL, thread_func, thread_data)) {
        return MBEDTLS_ERR_THREADING_THREAD_ERROR;
    }

    return 0;
}

static int threading_thread_join_pthread(mbedtls_test_thread_t *thread)
{
#if defined(MBEDTLS_PLATFORM_THREADING_THREAD)
    if (thread == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }
#endif

    if (pthread_join(*GET_THREAD(thread), NULL) != 0) {
        return MBEDTLS_ERR_THREADING_THREAD_ERROR;
    }

    return 0;
}

int (*mbedtls_test_thread_create)(mbedtls_test_thread_t *thread,
                                  mbedtls_test_thread_function_t thread_func,
                                  void *thread_data) = threading_thread_create_pthread;
int (*mbedtls_test_thread_join)(mbedtls_test_thread_t *thread) = threading_thread_join_pthread;

#endif /* MBEDTLS_THREADING_PTHREAD */

#if defined(MBEDTLS_THREADING_ALT)

static int threading_thread_create_fail(mbedtls_test_thread_t *thread,
                                        void *(*thread_func)(void *),
                                        void *thread_data)
{
    (void) thread;
    (void) thread_func;
    (void) thread_data;

    return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
}

static int threading_thread_join_fail(mbedtls_test_thread_t *thread)
{
    (void) thread;

    return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
}

int (*mbedtls_test_thread_create)(mbedtls_test_thread_t *thread,
                                  mbedtls_test_thread_function_t thread_func,
                                  void *thread_data) = threading_thread_create_fail;
int (*mbedtls_test_thread_join)(mbedtls_test_thread_t *thread) = threading_thread_join_fail;

#endif /* MBEDTLS_THREADING_ALT */

#if !defined(MBEDTLS_THREADING_ALT)
int mbedtls_platform_thread_create(mbedtls_platform_thread_object_t *thread,
                                   mbedtls_platform_thread_function_t *func,
                                   void *param)
{
    return mbedtls_test_thread_create(thread, func, param);
}

int mbedtls_platform_thread_join(mbedtls_platform_thread_object_t *thread)
{
    return mbedtls_test_thread_join(thread);
}
#endif

#if defined(MBEDTLS_TEST_MUTEX_USAGE)

#include "mbedtls/threading.h"

/** Mutex usage verification framework.
 *
 * The mutex usage verification code below aims to detect bad usage of
 * Mbed TLS's mutex abstraction layer at runtime. Note that this is solely
 * about the use of the mutex itself, not about checking whether the mutex
 * correctly protects whatever it is supposed to protect.
 *
 * The normal usage of a mutex is:
 * ```
 * digraph mutex_states {
 *   "UNINITIALIZED"; // the initial state
 *   "IDLE";
 *   "FREED";
 *   "LOCKED";
 *   "UNINITIALIZED" -> "IDLE" [label="init"];
 *   "FREED" -> "IDLE" [label="init"];
 *   "IDLE" -> "LOCKED" [label="lock"];
 *   "LOCKED" -> "IDLE" [label="unlock"];
 *   "IDLE" -> "FREED" [label="free"];
 * }
 * ```
 *
 * All bad transitions that can be unambiguously detected are reported.
 * An attempt to use an uninitialized mutex cannot be detected in general
 * since the memory content may happen to denote a valid state. For the same
 * reason, a double init cannot be detected.
 * All-bits-zero is the state of a freed mutex, which is distinct from an
 * initialized mutex, so attempting to use zero-initialized memory as a mutex
 * without calling the init function is detected.
 *
 * The framework attempts to detect missing calls to init and free by counting
 * calls to init and free. If there are more calls to init than free, this
 * means that a mutex is not being freed somewhere, which is a memory leak
 * on platforms where a mutex consumes resources other than the
 * mbedtls_threading_mutex_t object itself. If there are more calls to free
 * than init, this indicates a missing init, which is likely to be detected
 * by an attempt to lock the mutex as well. A limitation of this framework is
 * that it cannot detect scenarios where there is exactly the same number of
 * calls to init and free but the calls don't match. A bug like this is
 * unlikely to happen uniformly throughout the whole test suite though.
 *
 * If an error is detected, this framework will report what happened and the
 * test case will be marked as failed. Unfortunately, the error report cannot
 * indicate the exact location of the problematic call. To locate the error,
 * use a debugger and set a breakpoint on mbedtls_test_mutex_usage_error().
 */
enum value_of_mutex_state_field {
    /* Potential values for the state field of mbedtls_threading_mutex_t.
     * Note that MUTEX_FREED must be 0 and MUTEX_IDLE must be 1 for
     * compatibility with threading_mutex_init_pthread() and
     * threading_mutex_free_pthread(). MUTEX_LOCKED could be any nonzero
     * value. */
    MUTEX_FREED = 0, //! < Set by mbedtls_test_wrap_mutex_free
    MUTEX_IDLE = 1, //! < Set by mbedtls_test_wrap_mutex_init and by mbedtls_test_wrap_mutex_unlock
    MUTEX_LOCKED = 2, //! < Set by mbedtls_test_wrap_mutex_lock
};

typedef struct {
    void (*init)(mbedtls_threading_mutex_t *);
    void (*free)(mbedtls_threading_mutex_t *);
    int (*lock)(mbedtls_threading_mutex_t *);
    int (*unlock)(mbedtls_threading_mutex_t *);
} mutex_functions_t;
static mutex_functions_t mutex_functions;

/**
 *  The mutex used to guard live_mutexes below and access to the status variable
 *  in every mbedtls_threading_mutex_t.
 *  Note that we are not reporting any errors when locking and unlocking this
 *  mutex. This is for a couple of reasons:
 *
 *  1. We have no real way of reporting any errors with this mutex - we cannot
 *  report it back to the caller, as the failure was not that of the mutex
 *  passed in. We could fail the test, but again this would indicate a problem
 *  with the test code that did not exist.
 *
 *  2. Any failure to lock is unlikely to be intermittent, and will thus not
 *  give false test results - the overall result would be to turn off the
 *  testing. This is not a situation that is likely to happen with normal
 *  testing and we still have TSan to fall back on should this happen.
 */
#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
mbedtls_platform_mutex_t mbedtls_test_mutex_mutex;
#define LOCK_TEST_MUTEX() mbedtls_platform_mutex_lock(&mbedtls_test_mutex_mutex)
#define UNLOCK_TEST_MUTEX() mbedtls_platform_mutex_unlock(&mbedtls_test_mutex_mutex)
#else /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */
mbedtls_threading_mutex_t mbedtls_test_mutex_mutex;
#define LOCK_TEST_MUTEX() mutex_functions.lock(&mbedtls_test_mutex_mutex)
#define UNLOCK_TEST_MUTEX() mutex_functions.unlock(&mbedtls_test_mutex_mutex)
#endif /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */

/** The number of global mutexes, which remain live between test cases.
 *
 * \note This remains 0 in 3.6, where the global mutexes get special treatment
 *       (they are initialized to the live state without incrementing
 *       live_mutexes).
 */
static int permanent_mutex_count = 0;

/**
 *  The total number of calls to mbedtls_mutex_init(), minus the total number
 *  of calls to mbedtls_mutex_free().
 *
 *  Do not read or write without holding mbedtls_test_mutex_mutex (above). Reset
 *  to 0 after each test case.
 */
static int live_mutexes;

void mbedtls_test_mutex_usage_set_baseline(void)
{
    permanent_mutex_count = live_mutexes;
}

static void mbedtls_test_mutex_usage_error(mbedtls_threading_mutex_t *mutex,
                                           const char *msg)
{
    (void) mutex;

    mbedtls_test_set_mutex_usage_error(msg);
    mbedtls_fprintf(stdout, "[mutex: %s] ", msg);
    /* Don't mark the test as failed yet. This way, if the test fails later
     * for a functional reason, the test framework will report the message
     * and location for this functional reason. If the test passes,
     * mbedtls_test_mutex_usage_check() will mark it as failed. */
}

static int mbedtls_test_mutex_can_test(mbedtls_threading_mutex_t *mutex)
{
    /* If we attempt to run tests on this mutex then we are going to run into a
     * couple of problems:
     * 1. If any test on this mutex fails, we are going to deadlock when
     * reporting that failure, as we already hold the mutex at that point.
     * 2. Given the 'global' position of the initialization and free of this
     * mutex, it will be shown as leaked on the first test run. */
    if (mutex == mbedtls_test_get_info_mutex()) {
        return 0;
    }

    return 1;
}

static void mbedtls_test_post_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    if (mbedtls_test_mutex_can_test(mutex)) {
        if (LOCK_TEST_MUTEX() == 0) {
            mutex->state = MUTEX_IDLE;
            ++live_mutexes;

            UNLOCK_TEST_MUTEX();
        }
    }
}

static void mbedtls_test_pre_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    if (mbedtls_test_mutex_can_test(mutex)) {
        if (LOCK_TEST_MUTEX() == 0) {

            switch (mutex->state) {
                case MUTEX_FREED:
                    mbedtls_test_mutex_usage_error(mutex, "free without init or double free");
                    break;
                case MUTEX_IDLE:
                    mutex->state = MUTEX_FREED;
                    --live_mutexes;
                    break;
                case MUTEX_LOCKED:
                    mbedtls_test_mutex_usage_error(mutex, "free without unlock");
                    break;
                default:
                    mbedtls_test_mutex_usage_error(mutex, "corrupted state");
                    break;
            }

            UNLOCK_TEST_MUTEX();
        }
    }
}

static void mbedtls_test_post_mutex_lock(mbedtls_threading_mutex_t *mutex,
                                        int ret)
{
    if (mbedtls_test_mutex_can_test(mutex)) {
        if (LOCK_TEST_MUTEX() == 0) {
            switch (mutex->state) {
                case MUTEX_FREED:
                    mbedtls_test_mutex_usage_error(mutex, "lock without init");
                    break;
                case MUTEX_IDLE:
                    if (ret == 0) {
                        mutex->state = MUTEX_LOCKED;
                    }
                    break;
                case MUTEX_LOCKED:
                    mbedtls_test_mutex_usage_error(mutex, "double lock");
                    break;
                default:
                    mbedtls_test_mutex_usage_error(mutex, "corrupted state");
                    break;
            }

            UNLOCK_TEST_MUTEX();
        }
    }
}

static void mbedtls_test_pre_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    if (mbedtls_test_mutex_can_test(mutex)) {
        if (LOCK_TEST_MUTEX() == 0) {
            switch (mutex->state) {
                case MUTEX_FREED:
                    mbedtls_test_mutex_usage_error(mutex, "unlock without init");
                    break;
                case MUTEX_IDLE:
                    mbedtls_test_mutex_usage_error(mutex, "unlock without lock");
                    break;
                case MUTEX_LOCKED:
                    mutex->state = MUTEX_IDLE;
                    break;
                default:
                    mbedtls_test_mutex_usage_error(mutex, "corrupted state");
                    break;
            }
            UNLOCK_TEST_MUTEX();
        }
    }
}

#if !defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
static void mbedtls_test_wrap_mutex_init(mbedtls_threading_mutex_t *mutex)
{
    mutex_functions.init(mutex);
    mbedtls_test_post_mutex_init(mutex);
}

static void mbedtls_test_wrap_mutex_free(mbedtls_threading_mutex_t *mutex)
{
    mutex_functions.free(mutex);
    mbedtls_test_pre_mutex_free(mutex);
}

static int mbedtls_test_wrap_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
    /* Lock the passed in mutex first, so that the only way to change the state
     * is to hold the passed in and internal mutex - otherwise we create a race
     * condition. */
    int ret = mutex_functions.lock(mutex);
    mbedtls_test_post_mutex_lock(mutex, ret);
    return ret;
}

static int mbedtls_test_wrap_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
    /* Lock the internal mutex first and change state, so that the only way to
     * change the state is to hold the passed in and internal mutex - otherwise
     * we create a race condition. */
    mbedtls_test_pre_mutex_unlock(mutex);
    return mutex_functions.unlock(mutex);
}
#endif /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */

void mbedtls_test_mutex_usage_init(void)
{
    mutex_functions.init = mbedtls_mutex_init;
    mutex_functions.free = mbedtls_mutex_free;
    mutex_functions.lock = mbedtls_mutex_lock;
    mutex_functions.unlock = mbedtls_mutex_unlock;

#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
    mbedtls_test_hook_mutex_init_post = mbedtls_test_post_mutex_init;
    mbedtls_test_hook_mutex_free_pre = mbedtls_test_pre_mutex_free;
    mbedtls_test_hook_mutex_lock_post = mbedtls_test_post_mutex_lock;
    mbedtls_test_hook_mutex_unlock_pre = mbedtls_test_pre_mutex_unlock;
#else /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */
    mbedtls_mutex_init = &mbedtls_test_wrap_mutex_init;
    mbedtls_mutex_free = &mbedtls_test_wrap_mutex_free;
    mbedtls_mutex_lock = &mbedtls_test_wrap_mutex_lock;
    mbedtls_mutex_unlock = &mbedtls_test_wrap_mutex_unlock;
#endif /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */

#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
    mbedtls_platform_mutex_init(&mbedtls_test_mutex_mutex);
#else
    mutex_functions.init(&mbedtls_test_mutex_mutex);
#endif
}

void mbedtls_test_mutex_usage_check(void)
{
    if (LOCK_TEST_MUTEX() == 0) {
        if (live_mutexes != permanent_mutex_count) {
            /* A positive number (more init than free) means that a mutex resource
             * is leaking (on platforms where a mutex consumes more than the
             * mbedtls_threading_mutex_t object itself). The (hopefully) rare
             * case of a negative number means a missing init somewhere. */
            mbedtls_fprintf(stdout, "[mutex: %d leaked] ",
                            live_mutexes - permanent_mutex_count);
            live_mutexes = permanent_mutex_count;
            mbedtls_test_set_mutex_usage_error("missing free");
        }
        if (mbedtls_test_get_mutex_usage_error() != NULL &&
            mbedtls_test_get_result() != MBEDTLS_TEST_RESULT_FAILED) {
            /* Functionally, the test passed. But there was a mutex usage error,
             * so mark the test as failed after all. */
            mbedtls_test_fail("Mutex usage error", __LINE__, __FILE__);
        }
        mbedtls_test_set_mutex_usage_error(NULL);

        UNLOCK_TEST_MUTEX();
    }
}

void mbedtls_test_mutex_usage_end(void)
{
#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
    mbedtls_test_hook_mutex_init_post = NULL;
    mbedtls_test_hook_mutex_free_pre = NULL;
    mbedtls_test_hook_mutex_lock_post = NULL;
    mbedtls_test_hook_mutex_unlock_pre = NULL;
#else /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */
    mbedtls_mutex_init = mutex_functions.init;
    mbedtls_mutex_free = mutex_functions.free;
    mbedtls_mutex_lock = mutex_functions.lock;
    mbedtls_mutex_unlock = mutex_functions.unlock;
#endif /* MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE */

#if defined(MBEDTLS_TEST_HOOKS_FOR_MUTEX_USAGE)
    mbedtls_platform_mutex_free(&mbedtls_test_mutex_mutex);
#else
    mutex_functions.free(&mbedtls_test_mutex_mutex);
#endif
}

#endif /* MBEDTLS_TEST_MUTEX_USAGE */

#endif /* MBEDTLS_THREADING_C */
