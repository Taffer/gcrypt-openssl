/*
 * Internal helpers of global.c, misc.c, memory.c and error.c that the
 * public API does not reach directly: context objects, OpenSSL error
 * translation, errno capture, debug and FIPS flags, the low level log and
 * progress hooks, and the fatal paths (run in forked children).
 */
#include "../src/gcrypt-int.h"

#include <errno.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

/* The upstream header marks the log handler setter deprecated; it is
 * still the only way to observe the logger. */
#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static char logbuf[1024];
static size_t loglen;
static int loglevel;

static void
capture_log(void *opaque, int level, const char *fmt, va_list ap)
{
    int n;

    (void)opaque;
    loglevel = level;

    if (loglen < sizeof logbuf - 1) {
        n = vsnprintf(logbuf + loglen, sizeof logbuf - loglen, fmt, ap);

        if (n > 0) {
            loglen += (size_t)n;

            if (loglen > sizeof logbuf - 1) {
                loglen = sizeof logbuf - 1;
            }
        }
    }
}

static void
log_reset(void)
{
    loglen = 0;
    logbuf[0] = 0;
    loglevel = -1;
}

static int
run_child(void (*fn)(void))
{
    pid_t pid = fork();
    int status = 0;

    if (pid == 0) {
        fclose(stderr);
        fn();
        _exit(0);
    }

    if (pid < 0) {
        return -1;
    }

    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        return 1000 + WTERMSIG(status);
    }

    return -1;
}

TEST(syserror)
{
    errno = 0;
    ASSERT_EQ(GPG_ERR_MISSING_ERRNO, _gcry_err_code_from_syserror());
    errno = ENOENT;
    ASSERT_EQ(GPG_ERR_ENOENT, _gcry_err_code_from_syserror());
    errno = 0;
}

TEST(openssl_errors)
{
    /* Nothing queued: the fallback is returned. */
    ERR_clear_error();
    ASSERT_EQ(GPG_ERR_INTERNAL, _gcry_err_from_openssl(GPG_ERR_INTERNAL));

    /* Memory failures are recognised whatever the fallback. */
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    ASSERT_EQ(GPG_ERR_ENOMEM, _gcry_err_from_openssl(GPG_ERR_INTERNAL));
    ASSERT_EQ(0, ERR_peek_error()); /* The queue was drained. */

    /* Other reasons map to the fallback and are logged when verbose. */
    gcry_set_log_handler(capture_log, NULL);
    log_reset();
    _gcry_set_log_verbosity(2);
    ASSERT_EQ(2, _gcry_log_verbosity());
    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    ASSERT_EQ(GPG_ERR_INV_ARG, _gcry_err_from_openssl(GPG_ERR_INV_ARG));
    ASSERT_EQ(GCRY_LOG_DEBUG, loglevel);
    ASSERT_NOT_NULL(strstr(logbuf, "openssl:"));
    _gcry_set_log_verbosity(0);
    gcry_set_log_handler(NULL, NULL);
}

static int deinit_calls;

static void
ctx_deinit(void *payload)
{
    deinit_calls++;
    *(int *)payload = 0;
}

TEST(context_objects)
{
    gcry_ctx_t ctx = _gcry_ctx_alloc(7, sizeof(int), ctx_deinit);
    int *payload;

    ASSERT_NOT_NULL(ctx);
    payload = _gcry_ctx_find_pointer(ctx, 7);
    ASSERT_NOT_NULL(payload);
    ASSERT_EQ(0, *payload); /* Zeroed on allocation. */
    *payload = 5;
    ASSERT_TRUE(_gcry_ctx_get_pointer(ctx, 7) == payload);
    ASSERT_NULL(_gcry_ctx_find_pointer(ctx, 8));
    ASSERT_NULL(_gcry_ctx_find_pointer(NULL, 7));
    ASSERT_NULL(_gcry_ctx_get_pointer(NULL, 7));
    gcry_ctx_release(ctx);
    ASSERT_EQ(1, deinit_calls);
    gcry_ctx_release(NULL);

    ctx = _gcry_ctx_alloc(9, 32, NULL);
    ASSERT_NOT_NULL(ctx);
    gcry_ctx_release(ctx); /* No deinit callback. */
    ASSERT_EQ(1, deinit_calls);
}

static void
child_wrong_context_type(void)
{
    gcry_ctx_t ctx = _gcry_ctx_alloc(7, 8, NULL);
    void *p = _gcry_ctx_get_pointer(ctx, 8); /* Must not return. */

    _exit(p ? 1 : 2);
}

TEST(wrong_context_type_is_a_bug)
{
    ASSERT_EQ(1000 + SIGABRT, run_child(child_wrong_context_type));
}

TEST(flags)
{
    unsigned int before = _gcry_get_debug_flags();

    ASSERT_OK(gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 4u));
    ASSERT_TRUE(_gcry_get_debug_flags() & 4u);
    ASSERT_OK(gcry_control(GCRYCTL_CLEAR_DEBUG_FLAGS, 4u));
    ASSERT_EQ(before, _gcry_get_debug_flags());

    ASSERT_EQ(GCRY_FIPS_FLAG_REJECT_DEFAULT, _gcry_fips_reject_flags());
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS, 0u));
    ASSERT_EQ(0, _gcry_fips_reject_flags());
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS,
                           (unsigned int)GCRY_FIPS_FLAG_REJECT_DEFAULT));
    ASSERT_EQ(GCRY_FIPS_FLAG_REJECT_DEFAULT, _gcry_fips_reject_flags());

    ASSERT_OK(gcry_control(GCRYCTL_SET_VERBOSITY, 3));
    ASSERT_EQ(3, _gcry_log_verbosity());
    ASSERT_OK(gcry_control(GCRYCTL_SET_VERBOSITY, 0));
    ASSERT_EQ(0, _gcry_log_verbosity());
    ASSERT_EQ(0, _gcry_fips_mode());
}

TEST(printhex)
{
    static const unsigned char b[2] = { 0x01, 0x02 };

    gcry_set_log_handler(capture_log, NULL);
    log_reset();
    _gcry_log_printhex("x", b, sizeof b);
    ASSERT_STR_EQ("x: 0102\n", logbuf);
    /* Without a text only the bare bytes appear, not even a newline. */
    log_reset();
    _gcry_log_printhex(NULL, b, sizeof b);
    ASSERT_STR_EQ("0102", logbuf);
    log_reset();
    _gcry_log_printhex("", b, sizeof b);
    ASSERT_STR_EQ("0102\n", logbuf);
    gcry_set_log_handler(NULL, NULL);
}

static int progress_hits;
static const char *progress_what;
static int progress_char;
static int progress_cur;
static int progress_tot;

static void
progress_cb(void *opaque, const char *what, int printchar, int current,
            int total)
{
    (void)opaque;
    progress_hits++;
    progress_what = what;
    progress_char = printchar;
    progress_cur = current;
    progress_tot = total;
}

TEST(progress)
{
    _gcry_progress("nothing", '.', 0, 0); /* No handler: ignored. */
    ASSERT_EQ(0, progress_hits);
    gcry_set_progress_handler(progress_cb, NULL);
    _gcry_progress("test", '!', 3, 7);
    ASSERT_EQ(1, progress_hits);
    ASSERT_STR_EQ("test", progress_what);
    ASSERT_EQ('!', progress_char);
    ASSERT_EQ(3, progress_cur);
    ASSERT_EQ(7, progress_tot);
    gcry_set_progress_handler(NULL, NULL);
}

static void
fatal_handler(void *opaque, int rc, const char *text)
{
    (void)opaque;

    if (rc == (int)GPG_ERR_INTERNAL && text
        && !strcmp(text, "Internal error")) {
        _exit(42);
    }

    _exit(43);
}

static void
child_fatal_with_handler(void)
{
    gcry_set_fatalerror_handler(fatal_handler, NULL);
    _gcry_fatal_error(GPG_ERR_INTERNAL, NULL); /* Text from the code. */
}

static void
child_fatal_without_handler(void)
{
    _gcry_fatal_error(GPG_ERR_INTERNAL, "custom text");
}

static void
child_bug(void)
{
    _gcry_bug("file.c", 42, "function");
}

static void
child_log_fatal(void)
{
    _gcry_log(GCRY_LOG_FATAL, "fatal %s\n", "message");
}

static void
child_log_unknown_level(void)
{
    _gcry_log(77, "odd level\n");
    _gcry_log(GCRY_LOG_INFO, "info\n");
    _gcry_log(GCRY_LOG_WARN, "warn\n");
    _gcry_log(GCRY_LOG_ERROR, "error\n");
    _gcry_log(GCRY_LOG_CONT, "cont\n");
    _exit(7);
}

TEST(fatal_paths)
{
    ASSERT_EQ(42, run_child(child_fatal_with_handler));
    ASSERT_EQ(1000 + SIGABRT, run_child(child_fatal_without_handler));
    ASSERT_EQ(1000 + SIGABRT, run_child(child_bug));
    ASSERT_EQ(1000 + SIGABRT, run_child(child_log_fatal));
    ASSERT_EQ(7, run_child(child_log_unknown_level));
}

static void
child_disable_secmem(void)
{
    if (_gcry_secmem_is_disabled()) {
        _exit(1);
    }

    _gcry_secmem_disable();

    if (!_gcry_secmem_is_disabled()) {
        _exit(2);
    }

    /* Allocations still work, they are just not secure. */
    {
        void *p = _gcry_malloc_secure(16);

        if (!p || _gcry_is_secure(p)) {
            _exit(3);
        }

        _gcry_free(p);
    }
    _gcry_secmem_init(4096);
    _gcry_secmem_term();
    _exit(0);
}

TEST(secmem_disable)
{
    ASSERT_EQ(0, run_child(child_disable_secmem));
}

int
main(void)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    RUN_TEST(syserror);
    RUN_TEST(openssl_errors);
    RUN_TEST(context_objects);
    RUN_TEST(wrong_context_type_is_a_bug);
    RUN_TEST(flags);
    RUN_TEST(printhex);
    RUN_TEST(progress);
    RUN_TEST(fatal_paths);
    RUN_TEST(secmem_disable);
    return TEST_RESULT();
}
