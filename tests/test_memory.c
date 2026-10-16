#include <gcrypt.h>

#include <errno.h>
#include <stdlib.h>

#include "test_common.h"

TEST(argument_checks)
{
    /* A NULL string cannot be duplicated; errno says why. */
    errno = 0;
    ASSERT_NULL(gcry_strdup(NULL));
    ASSERT_EQ(EINVAL, errno);

    /* NULL stays a no-op for the release and query functions. */
    gcry_free(NULL);
    ASSERT_FALSE(gcry_is_secure(NULL));
}

TEST(plain_allocation)
{
    void *p = gcry_malloc(100);
    char *s;

    ASSERT_NOT_NULL(p);
    ASSERT_FALSE(gcry_is_secure(p));
    memset(p, 0xaa, 100);
    gcry_free(p);

    p = gcry_calloc(10, 10);
    ASSERT_NOT_NULL(p);
    {
        static const unsigned char zeros[100];

        ASSERT_MEM_EQ(zeros, p, 100);
    }
    gcry_free(p);

    s = gcry_strdup("hello");
    ASSERT_NOT_NULL(s);
    ASSERT_STR_EQ("hello", s);
    ASSERT_FALSE(gcry_is_secure(s));
    gcry_free(s);

    p = gcry_malloc(0);
    ASSERT_NOT_NULL(p);
    gcry_free(p);
    gcry_free(NULL);
}

TEST(secure_allocation)
{
    void *p;
    void *q;
    char *s;
    int stackvar = 0;

    ASSERT_OK(gcry_control(GCRYCTL_INIT_SECMEM, 32768u, 0));

    p = gcry_malloc_secure(64);
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(gcry_is_secure(p));
    memset(p, 0x55, 64);

    q = gcry_realloc(p, 256);
    ASSERT_NOT_NULL(q);
    ASSERT_TRUE(gcry_is_secure(q));
    ASSERT_EQ(0x55, ((unsigned char *)q)[63]);
    gcry_free(q);

    p = gcry_calloc_secure(4, 16);
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(gcry_is_secure(p));
    ASSERT_EQ(0, ((unsigned char *)p)[63]);

    s = gcry_strdup((const char *)p); /* Secure input gives secure copy. */
    ASSERT_NOT_NULL(s);
    ASSERT_TRUE(gcry_is_secure(s));
    gcry_free(s);
    gcry_free(p);

    ASSERT_FALSE(gcry_is_secure(&stackvar));
    ASSERT_FALSE(gcry_is_secure(NULL));
    ASSERT_FALSE(gcry_is_secure("literal"));
}

TEST(x_allocation)
{
    void *p = gcry_xmalloc(16);
    char *s;

    ASSERT_NOT_NULL(p);
    p = gcry_xrealloc(p, 32);
    ASSERT_NOT_NULL(p);
    gcry_free(p);

    p = gcry_xcalloc(2, 8);
    ASSERT_NOT_NULL(p);
    gcry_free(p);

    p = gcry_xmalloc_secure(16);
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(gcry_is_secure(p));
    gcry_free(p);

    p = gcry_xcalloc_secure(2, 8);
    ASSERT_NOT_NULL(p);
    gcry_free(p);

    s = gcry_xstrdup("abc");
    ASSERT_STR_EQ("abc", s);
    gcry_free(s);
}

static int custom_alloc_calls;
static int custom_free_calls;

static void *
custom_alloc(size_t n)
{
    custom_alloc_calls++;
    return malloc(n);
}

static int
custom_is_secure(const void *p)
{
    (void)p;
    return 0;
}

static void *
custom_realloc(void *p, size_t n)
{
    return realloc(p, n);
}

static void
custom_free(void *p)
{
    custom_free_calls++;
    free(p);
}

TEST(allocation_handler)
{
    void *p;

    gcry_set_allocation_handler(custom_alloc, custom_alloc, custom_is_secure,
                                custom_realloc, custom_free);
    p = gcry_malloc(8);
    ASSERT_NOT_NULL(p);
    gcry_free(p);
    p = gcry_malloc_secure(8);
    ASSERT_NOT_NULL(p);

    if (gcry_fips_mode_active()) {
        /* Custom allocators are ignored in FIPS mode, as in the
         * reference: the built-in ones stay in charge. */
        ASSERT_TRUE(gcry_is_secure(p));
        gcry_free(p);
        ASSERT_EQ(0, custom_alloc_calls);
        ASSERT_EQ(0, custom_free_calls);
    } else {
        ASSERT_FALSE(gcry_is_secure(p));
        gcry_free(p);
        ASSERT_EQ(2, custom_alloc_calls);
        ASSERT_EQ(2, custom_free_calls);
    }
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(argument_checks);
    RUN_TEST(plain_allocation);
    RUN_TEST(secure_allocation);
    RUN_TEST(x_allocation);
    RUN_TEST(allocation_handler); /* Must be last: it swaps the allocator. */
    return TEST_RESULT();
}
