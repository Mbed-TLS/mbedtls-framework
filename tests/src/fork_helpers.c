/** \file fork_helpers.c
 *
 * \brief Helper functions for testing with subprocesses.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "test_common.h"
#include <test/helpers.h>
#include <test/macros.h>

#if defined(MBEDTLS_PLATFORM_IS_UNIXLIKE)

#include <test/fork_helpers.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

/** Child exit code for mbedtls_test_fork_run_child().
 */
typedef enum {
    /** The child successfully reported its test result in the temporary
     * file, and its output if the test passed. Alternatively, the
     * child died before writing anything to the temporary file.
     *
     * The content of the file has the following format:
     * - mbedtls_test_info_t structure;
     * - on pass, the ouptut (up to the end of the file).
     */
    CHILD_EXIT_CODE_OK = 0,
    /** Something went wrong in a way that could not be recorded
     * in the temporary file. Pick a value that's nonzero (not a success),
     * less than 128 (conventionally the upper bound for exit statuses),
     * and unlikely to be the exit code of some other program if the
     * child calls execve(). */
    CHILD_EXIT_CODE_REPORTING_FAILED = 122,
} child_exit_code_t;

static int env_contains_substring(const char *name, const char *substring)
{
    const char *value = getenv(name);
    if (value == NULL) {
        return 0;
    } else {
        return strstr(value, substring) != NULL;
    }
}

static int probably_running_under_valgrind(void)
{
    if (env_contains_substring("LD_PRELOAD", "/vgpreload_")) {
        return 1;
    }
    if (env_contains_substring("DYLD_INSERT_LIBRARIES", "/vgpreload_")) {
        return 1;
    }
    return 0;
}

#if defined(__GNUC__)
__attribute__((__noreturn__))
#endif
static void run_child(
    FILE *file,
    mbedtls_test_fork_child_callback_t *child_callback,
    void *param,
    unsigned char *buf, size_t size)
{
    /* If something goes wrong while trying to report what happened
     * in the child, exit with a nonzero status. */
    int child_exit_code = CHILD_EXIT_CODE_REPORTING_FAILED;
    size_t length = 0;

    child_callback(param, buf, size, &length);

    if (mbedtls_test_get_result() == MBEDTLS_TEST_RESULT_SUCCESS && length != 0) {
        /* Write the output. This could fail on a full disk. Remember to
         * flush (otherwise the output would likely be truncated). */
        errno = 0;
        size_t n = fwrite(buf, 1, length, file);
        TEST_ASSERT_ERRNO(n == length);
        TEST_ASSERT_ERRNO(fflush(file) == 0);
    }

    /* Report our final status (covering the child callback and the output
     * reporting). The file is already large enough, so a failure at this
     * stage is very unlikely. */
exit:
    /* can't put a label on a declaration */;
    mbedtls_test_info_t test_info;
    mbedtls_test_info_save(&test_info);

    if (fseek(file, 0, SEEK_SET) != 0) {
        goto write_done;
    }
    if (fwrite(&test_info, sizeof(test_info), 1, file) != 1) {
        goto write_done;
    }
    if (fflush(file) != 0) {
        goto write_done;
    }
    child_exit_code = CHILD_EXIT_CODE_OK;

    /* Label for `_exit()` call: this is where we jump to if the failure
     * reporting fails. */
write_done:
    /* We must call _exit(), not exit(), because the child must not run the
     * things that normally run at exit.
     *
     * - Do not flush any stdio buffers! Any unflushed buffers are inherited
     *   from our parent, and if we flushed them, we'd get duplicate output
     *   since the parent would also write the same buffer content.
     * - Do not run atexit hooks, e.g. leak detection code from sanitizers
     *   such as ASan. The child leaks any number of resources which are
     *   inherited from the parent but not used in the child. It's the
     *   parent's job to check for resource leaks.
     *   (We deliberately do not clean up in the child. One reason is that
     *   we try to minimize what happens in the child, because it's difficult
     *   to debug. Another reason is that we must not cause external effects
     *   such as destroying a PSA persistent key.)
     */
    if (probably_running_under_valgrind()) {
        /* Valgrind overloads _exit(), and this makes it do weird things,
         * including an lseek() call to rewind the pointer on the file
         * description for the `.datax` file, causing the same test cases
         * to run again (or parse errors, depending on the exact amount
         * of rewinding).
         *
         * Valgrind doesn't overload execve() and friends. So instead of
         * _exit(), execute a shell command that returns the same status.
         */
        char cmd[20];
        snprintf(cmd, sizeof(cmd), "exit %d", child_exit_code);
        execlp("sh", "sh", "-c", cmd, NULL);
    }
    _exit(child_exit_code);
}

int mbedtls_test_fork_run_child(
    mbedtls_test_fork_child_callback_t *child_callback,
    void *param,
    unsigned char *child_output, size_t child_output_size,
    size_t *child_output_length)
{
    *child_output_length = 0;

    pid_t pid = -1;
    FILE *file = NULL;

    /* Create a temporary file where the child can write the test result
     * and its output. We unlink the file as soon as we've created it,
     * but we keep it open. This way, both the parent and the child process
     * can keep using the file until they close it, but the file will
     * be removed when both processes have closed it.
     */
    /* Make up a unique name using the current (parent) process ID and
     * a stack address inside that process. */
    char filename[sizeof("mbedtls_test_fork_run_child-%ld-%p.tmp") +
                  3 * sizeof(long) + 2 * sizeof(void *)];
    mbedtls_snprintf(filename, sizeof(filename),
                     "mbedtls_test_fork_run_child-%ld-%p.tmp",
                     (long) getpid(), (void *) filename);
    file = fopen(filename, "w+");
    TEST_ASSERT_ERRNO(file != NULL);
    unlink(filename);

    /* The temporary file will contain the test result from the child,
     * followed by the output from the child callback.
     *
     * Pre-fill a failure result.
     * The file position is at the beginning of the expected output.
     */
    mbedtls_test_info_t child_test_info;
    memset(&child_test_info, 0, sizeof(child_test_info));
    child_test_info.result = MBEDTLS_TEST_RESULT_FAILED;
    child_test_info.test = "Child died without reporting status";
    child_test_info.step = -1;
    child_test_info.filename = __FILE__;
    child_test_info.line_no = __LINE__;
    TEST_ASSERT_ERRNO(fwrite(&child_test_info, sizeof(child_test_info), 1, file) > 0);
    TEST_ASSERT_ERRNO(fflush(file) == 0);

    /* Fork the child */
    pid = fork();
    TEST_ASSERT_ERRNO(pid != -1);

    if (pid == 0) {
        run_child(file, child_callback, param,
                  child_output, child_output_size);
        /* Unreachable */
    }
    /* Beyond this point, we're in the parent (original) process. */

    /* Reap the child */
    int wstatus;
    TEST_ASSERT_ERRNO(waitpid(pid, &wstatus, 0) == pid);
    TEST_EQUAL(wstatus, CHILD_EXIT_CODE_OK);

    /* The child exited normally. Obtain the test result from the child. */
    TEST_ASSERT_ERRNO(fseek(file, 0, SEEK_SET) == 0);
    TEST_ASSERT_ERRNO(fread(&child_test_info, 1, sizeof(child_test_info), file) > 0);

    if (child_test_info.result != MBEDTLS_TEST_RESULT_SUCCESS) {
        /* Skip or failure in the child. Transfer the child's test
         * result into the parent. */
        mbedtls_test_info_overwrite(&child_test_info);
        goto exit;
    }

    /* The child succeeded. Read the output. */
    TEST_ASSERT_ERRNO(fseek(file, 0, SEEK_END) == 0);
    long pos = ftell(file);
    TEST_ASSERT_ERRNO(pos >= 0);
    TEST_LE_U(sizeof(child_test_info), pos);
    size_t len = pos - sizeof(child_test_info);
    TEST_LE_U(len, child_output_size);
    TEST_ASSERT_ERRNO(fseek(file, sizeof(child_test_info), SEEK_SET) == 0);
    TEST_EQUAL(fread(child_output, 1, len, file), len);
    *child_output_length = len;

    fclose(file);
    return 0;

exit:
    if (file != NULL) {
        fclose(file);
    }
    mbedtls_test_fork_child_fd = -1;
    return -1;
}

#endif /* MBEDTLS_PLATFORM_IS_UNIXLIKE */
