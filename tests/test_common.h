/*
 * Minimal test helpers so the test suite has no external dependencies.
 */
#ifndef GCRYPT_OPENSSL_TEST_COMMON_H
#define GCRYPT_OPENSSL_TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_failures_ = 0;
static int test_count_ = 0;

#define TEST(name) static void test_##name(void)

#define RUN_TEST(name) \
    do {               \
        test_count_++; \
        test_##name(); \
    } while (0)

#define TEST_FAIL_(fmt, ...)                                          \
    do {                                                              \
        test_failures_++;                                             \
        fprintf(stderr, "%s:%d: FAIL: " fmt "\n", __FILE__, __LINE__, \
                __VA_ARGS__);                                         \
    } while (0)

#define ASSERT_TRUE(cond)                              \
    do {                                               \
        if (!(cond)) {                                 \
            TEST_FAIL_("%s", "expected true: " #cond); \
            return;                                    \
        }                                              \
    } while (0)

#define ASSERT_FALSE(cond)                              \
    do {                                                \
        if (cond) {                                     \
            TEST_FAIL_("%s", "expected false: " #cond); \
            return;                                     \
        }                                               \
    } while (0)

#define ASSERT_NOT_NULL(ptr)                              \
    do {                                                  \
        if ((ptr) == NULL) {                              \
            TEST_FAIL_("%s", "expected non-NULL: " #ptr); \
            return;                                       \
        }                                                 \
    } while (0)

#define ASSERT_NULL(ptr)                              \
    do {                                              \
        if ((ptr) != NULL) {                          \
            TEST_FAIL_("%s", "expected NULL: " #ptr); \
            return;                                   \
        }                                             \
    } while (0)

#define ASSERT_EQ(expected, actual)                                     \
    do {                                                                \
        long long e_ = (long long)(expected);                           \
        long long a_ = (long long)(actual);                             \
        if (e_ != a_) {                                                 \
            TEST_FAIL_("%s: expected %lld, got %lld", #actual, e_, a_); \
            return;                                                     \
        }                                                               \
    } while (0)

#define ASSERT_STR_EQ(expected, actual)                        \
    do {                                                       \
        const char *e_ = (expected);                           \
        const char *a_ = (actual);                             \
        if (e_ == NULL || a_ == NULL || strcmp(e_, a_) != 0) { \
            TEST_FAIL_("expected \"%s\", got \"%s\"",          \
                       e_ ? e_ : "(null)", a_ ? a_ : "(null)");\
            return;                                            \
        }                                                      \
    } while (0)

#define ASSERT_MEM_EQ(expected, actual, len)                           \
    do {                                                               \
        if (memcmp((expected), (actual), (len)) != 0) {                \
            TEST_FAIL_("%s", "memory differs: " #expected " vs " #actual); \
            return;                                                    \
        }                                                              \
    } while (0)

/* A gcry_error_t must be zero. */
#define ASSERT_OK(expr)                                                  \
    do {                                                                 \
        gcry_error_t err_ = (expr);                                      \
        if (err_) {                                                      \
            TEST_FAIL_("%s failed: %s (%s)", #expr, gcry_strerror(err_), \
                       gcry_strsource(err_));                            \
            return;                                                      \
        }                                                                \
    } while (0)

/* A gcry_error_t must carry the given error code. */
#define ASSERT_ERR(code, expr)                                               \
    do {                                                                     \
        gcry_error_t err_ = (expr);                                          \
        if (gcry_err_code(err_) != (code)) {                                 \
            TEST_FAIL_("%s: expected %s, got %s", #expr,                     \
                       gcry_strerror(gcry_error(code)), gcry_strerror(err_)); \
            return;                                                          \
        }                                                                    \
    } while (0)

/* Leave a forked test child with CODE.  This is exit(), not _exit(): a
 * coverage build flushes the library's counters from a destructor that
 * only exit() runs.  Callers must fflush(NULL) before fork() so that the
 * child does not re-emit the parent's buffered output. */
static inline void
test_child_exit(int code)
{
    exit(code);
}

/* Whether the tests tolerate a provider that lacks algorithms the
 * library's tables list, as Chainguard's strict FIPS provider does even
 * when the library is not in FIPS mode.  Each test program decides from
 * the family's test_algo function whether an algorithm is there. */
#ifdef GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT
    #define TEST_STRICT_PROVIDER 1
#else
    #define TEST_STRICT_PROVIDER 0
#endif

/* EXPR must succeed, unless COND holds, when it must fail with CODE. */
#define ASSERT_OK_UNLESS(cond, code, expr) \
    do {                                   \
        if (cond) {                        \
            ASSERT_ERR(code, expr);        \
        } else {                           \
            ASSERT_OK(expr);               \
        }                                  \
    } while (0)

/* EXPR must succeed, unless the library runs in FIPS mode, where the
 * operation is not approved and must fail with CODE instead. */
#define ASSERT_OK_OR_FIPS_ERR(code, expr) \
    ASSERT_OK_UNLESS(gcry_fips_mode_active(), code, expr)

#define TEST_RESULT()                                                    \
    (printf("%d test(s), %d failure(s)\n", test_count_, test_failures_), \
     test_failures_ == 0 ? 0 : 1)

#endif /* GCRYPT_OPENSSL_TEST_COMMON_H */
