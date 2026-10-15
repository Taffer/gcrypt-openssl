/*
 * Minimal test helpers so the test suite has no external dependencies.
 */
#ifndef GCRYPT_OPENSSL_TEST_COMMON_H
#define GCRYPT_OPENSSL_TEST_COMMON_H

#include <stdio.h>
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

#define TEST_RESULT()                                                    \
    (printf("%d test(s), %d failure(s)\n", test_count_, test_failures_), \
     test_failures_ == 0 ? 0 : 1)

#endif /* GCRYPT_OPENSSL_TEST_COMMON_H */
