/*
 * Minimal test helpers so the test suite has no external dependencies.
 *
 * Usage:
 *
 *     TEST(something_works)
 *     {
 *         ASSERT_TRUE(1 + 1 == 2);
 *     }
 *
 *     int main(void)
 *     {
 *         RUN_TEST(something_works);
 *         return TEST_RESULT();
 *     }
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

#define ASSERT_STR_EQ(expected, actual)                                   \
    do {                                                                  \
        const char *e_ = (expected);                                      \
        const char *a_ = (actual);                                        \
        if (e_ == NULL || a_ == NULL || strcmp(e_, a_) != 0) {            \
            TEST_FAIL_("expected \"%s\", got \"%s\"", e_ ? e_ : "(null)", \
                       a_ ? a_ : "(null)");                               \
            return;                                                       \
        }                                                                 \
    } while (0)

#define TEST_RESULT()                                                    \
    (printf("%d test(s), %d failure(s)\n", test_count_, test_failures_), \
     test_failures_ == 0 ? 0 : 1)

#endif /* GCRYPT_OPENSSL_TEST_COMMON_H */
