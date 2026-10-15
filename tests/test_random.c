#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

static int
all_same(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 1; i < n; i++) {
        if (p[i] != p[0]) {
            return 0;
        }
    }

    return 1;
}

TEST(randomize_levels)
{
    unsigned char a[64];
    unsigned char b[64];

    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    gcry_randomize(a, sizeof a, GCRY_WEAK_RANDOM);
    gcry_randomize(b, sizeof b, GCRY_STRONG_RANDOM);
    ASSERT_FALSE(all_same(a, sizeof a));
    ASSERT_FALSE(all_same(b, sizeof b));
    ASSERT_TRUE(memcmp(a, b, sizeof a) != 0);
    gcry_randomize(a, sizeof a, GCRY_VERY_STRONG_RANDOM);
    ASSERT_FALSE(all_same(a, sizeof a));
    gcry_randomize(a, 0, GCRY_STRONG_RANDOM); /* zero length is fine */
}

TEST(random_bytes_allocation)
{
    unsigned char *p = gcry_random_bytes(32, GCRY_STRONG_RANDOM);
    unsigned char *s;

    ASSERT_NOT_NULL(p);
    ASSERT_FALSE(all_same(p, 32));
    ASSERT_FALSE(gcry_is_secure(p));
    gcry_free(p);

    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    s = gcry_random_bytes_secure(32, GCRY_VERY_STRONG_RANDOM);
    ASSERT_NOT_NULL(s);
    ASSERT_TRUE(gcry_is_secure(s));
    ASSERT_FALSE(all_same(s, 32));
    gcry_free(s);
}

TEST(nonce)
{
    unsigned char n1[24];
    unsigned char n2[24];

    gcry_create_nonce(n1, sizeof n1);
    gcry_create_nonce(n2, sizeof n2);
    ASSERT_TRUE(memcmp(n1, n2, sizeof n1) != 0);
    ASSERT_FALSE(all_same(n1, sizeof n1));
}

TEST(add_bytes)
{
    static const unsigned char seed[32] = { 1, 2, 3, 4 };

    ASSERT_OK(gcry_random_add_bytes(seed, sizeof seed, -1));
    ASSERT_OK(gcry_random_add_bytes(seed, sizeof seed, 100));
    ASSERT_OK(gcry_random_add_bytes(seed, sizeof seed, 1000)); /* clamped */
    ASSERT_OK(gcry_random_add_bytes(seed, sizeof seed, 5)); /* ignored */
    ASSERT_OK(gcry_random_add_bytes(seed, 0, 50));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_random_add_bytes(NULL, 10, 50));
    ASSERT_OK(gcry_control(GCRYCTL_FAST_POLL, NULL));
}

TEST(control_rng_type)
{
    int type = 0;

    ASSERT_OK(gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &type));
    ASSERT_TRUE(type == GCRY_RNG_TYPE_STANDARD || type == GCRY_RNG_TYPE_FIPS);
    ASSERT_OK(gcry_control(GCRYCTL_FAKED_RANDOM_P));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(randomize_levels);
    RUN_TEST(random_bytes_allocation);
    RUN_TEST(nonce);
    RUN_TEST(add_bytes);
    RUN_TEST(control_rng_type);
    return TEST_RESULT();
}
