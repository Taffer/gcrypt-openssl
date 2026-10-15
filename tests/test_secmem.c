/*
 * Secure memory life cycle, the out-of-core and fatal error handlers, and
 * the allocator paths test_memory.c does not reach.  Scenarios that change
 * process-wide state irreversibly (disabling secure memory, swapping the
 * allocator, dying) run in forked children.
 */
#define _POSIX_C_SOURCE 200809L

#include <gcrypt.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

/* --- helpers ------------------------------------------------------------ */

/* Run FN in a child; return the exit status, or 1000 + signal number. */
static int
run_child(void (*fn)(void))
{
    pid_t pid = fork();
    int status = 0;

    if (pid == 0) {
        /* The children deliberately die noisily; keep the test log clean. */
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

/* An allocator that fails the next FAILS_LEFT requests. */
static int fails_left;

static void *
failing_alloc(size_t n)
{
    if (fails_left > 0) {
        fails_left--;
        errno = ENOMEM;
        return NULL;
    }

    return malloc(n);
}

static int
never_secure(const void *p)
{
    (void)p;
    return 0;
}

static void *
plain_realloc(void *p, size_t n)
{
    return realloc(p, n);
}

static void
plain_free(void *p)
{
    free(p);
}

static int oom_calls;
static size_t oom_last_size;
static unsigned int oom_last_flags;

static int
oom_retry(void *opaque, size_t n, unsigned int flags)
{
    *(int *)opaque += 1;
    oom_calls++;
    oom_last_size = n;
    oom_last_flags = flags;
    return 1; /* Please retry. */
}

static void
fatal_exit42(void *opaque, int rc, const char *text)
{
    (void)opaque;

    /* GPG_ERR_ENOMEM carries the system error bit. */
    if (rc == (int)GPG_ERR_ENOMEM && text && strlen(text) > 0) {
        _exit(42);
    }

    _exit(43);
}

/* --- in-process tests ----------------------------------------------------- */

TEST(secmem_lifecycle)
{
    void *p;
    int local = 0;

    /* The pool was created in main(); a second initialisation is
     * harmless. */
    ASSERT_OK(gcry_control(GCRYCTL_INIT_SECMEM, 32768u, 0));

    p = gcry_malloc_secure(32);
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(gcry_is_secure(p));
    gcry_free(p);

    /* With nothing outstanding the pool can be torn down and recreated. */
    ASSERT_OK(gcry_control(GCRYCTL_TERM_SECMEM));
    ASSERT_FALSE(gcry_is_secure(&local));
    ASSERT_OK(gcry_control(GCRYCTL_TERM_SECMEM));

    p = gcry_malloc_secure(32);
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(gcry_is_secure(p));
    gcry_free(p);

    ASSERT_OK(gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0));
    p = gcry_calloc_secure(1, 48);
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(gcry_is_secure(p));
    gcry_free(p);
}

TEST(realloc_paths)
{
    unsigned char *p = gcry_realloc(NULL, 16);
    unsigned char *q;

    ASSERT_NOT_NULL(p);
    memset(p, 0x5a, 16);
    q = gcry_realloc(p, 4096);
    ASSERT_NOT_NULL(q);
    ASSERT_EQ(0x5a, q[15]);
    ASSERT_FALSE(gcry_is_secure(q));
    gcry_free(q);

    p = gcry_malloc_secure(64);
    ASSERT_NOT_NULL(p);
    memset(p, 0xa5, 64);
    q = gcry_realloc(p, 16); /* Shrinking keeps the prefix. */
    ASSERT_NOT_NULL(q);
    ASSERT_TRUE(gcry_is_secure(q));
    ASSERT_EQ(0xa5, q[15]);
    gcry_free(q);

    /* Sizes that overflow are refused rather than wrapped. */
    ASSERT_NULL(gcry_calloc((size_t) - 1, 2));
    ASSERT_NULL(gcry_calloc_secure((size_t) - 1, 2));
}

TEST(free_keeps_errno)
{
    void *p = gcry_malloc(8);

    ASSERT_NOT_NULL(p);
    errno = EACCES;
    gcry_free(p);
    ASSERT_EQ(EACCES, errno);
    errno = 0;
}

TEST(outofcore_handler_retries)
{
    int hits = 0;
    void *p;
    char *s;
    unsigned char *r;

    gcry_set_outofcore_handler(oom_retry, &hits);
    gcry_set_allocation_handler(failing_alloc, failing_alloc, never_secure,
                                plain_realloc, plain_free);

    fails_left = 1;
    p = gcry_xmalloc(16);
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(1, oom_calls);
    ASSERT_EQ(16, oom_last_size);
    ASSERT_EQ(0, oom_last_flags);
    gcry_free(p);

    fails_left = 1;
    p = gcry_xcalloc(2, 8);
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(2, oom_calls);
    gcry_free(p);

    fails_left = 1;
    p = gcry_xmalloc_secure(24);
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(3, oom_calls);
    ASSERT_EQ(1, oom_last_flags); /* Secure allocation. */
    gcry_free(p);

    fails_left = 1;
    p = gcry_xcalloc_secure(3, 8);
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(4, oom_calls);
    gcry_free(p);

    fails_left = 1;
    s = gcry_xstrdup("retry");
    ASSERT_STR_EQ("retry", s);
    ASSERT_EQ(5, oom_calls);
    gcry_free(s);

    /* Growing through the custom realloc does not consult the handler. */
    fails_left = 0;
    r = gcry_xrealloc(NULL, 8);
    ASSERT_NOT_NULL(r);
    r = gcry_xrealloc(r, 64);
    ASSERT_NOT_NULL(r);
    gcry_free(r);
    ASSERT_EQ(5, oom_calls);
    ASSERT_EQ(5, hits);

    gcry_set_outofcore_handler(NULL, NULL);
}

/* --- children --------------------------------------------------------------- */

static void
child_disable_secmem(void)
{
    void *p;
    char *s;

    if (gcry_control(GCRYCTL_DISABLE_SECMEM)) {
        _exit(10);
    }

    p = gcry_malloc_secure(32);

    if (!p || gcry_is_secure(p)) {
        _exit(11);
    }

    memcpy(p, "plain", 6);
    s = gcry_strdup(p);

    if (!s || gcry_is_secure(s) || strcmp(s, "plain")) {
        _exit(12);
    }

    gcry_free(s);
    gcry_free(p);
    p = gcry_xmalloc_secure(8);

    if (!p || gcry_is_secure(p)) {
        _exit(13);
    }

    gcry_free(p);
    p = gcry_calloc_secure(4, 4);

    if (!p || gcry_is_secure(p)) {
        _exit(14);
    }

    gcry_free(p);

    if (gcry_control(GCRYCTL_TERM_SECMEM)) {
        _exit(15);
    }

    _exit(0);
}

TEST(disable_secmem_in_child)
{
    ASSERT_EQ(0, run_child(child_disable_secmem));
}

static void
child_fatal_handler(void)
{
    void *p;

    gcry_set_fatalerror_handler(fatal_exit42, NULL);
    gcry_set_allocation_handler(failing_alloc, failing_alloc, never_secure,
                                plain_realloc, plain_free);
    fails_left = 1000; /* Never succeeds: out of core is fatal. */
    p = gcry_xmalloc(16);
    free(p);
    _exit(1); /* Unreachable. */
}

TEST(fatal_handler_called)
{
    ASSERT_EQ(42, run_child(child_fatal_handler));
}

static void
child_fatal_abort(void)
{
    char *s;

    gcry_set_allocation_handler(failing_alloc, failing_alloc, never_secure,
                                plain_realloc, plain_free);
    fails_left = 1000;
    s = gcry_xstrdup("doomed");
    free(s);
    _exit(1); /* Unreachable. */
}

TEST(fatal_without_handler_aborts)
{
    ASSERT_EQ(1000 + SIGABRT, run_child(child_fatal_abort));
}

int
main(void)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    RUN_TEST(secmem_lifecycle);
    RUN_TEST(realloc_paths);
    RUN_TEST(free_keeps_errno);
    RUN_TEST(disable_secmem_in_child);
    RUN_TEST(fatal_handler_called);
    RUN_TEST(fatal_without_handler_aborts);
    RUN_TEST(outofcore_handler_retries); /* Last: it swaps the allocator. */
    return TEST_RESULT();
}
