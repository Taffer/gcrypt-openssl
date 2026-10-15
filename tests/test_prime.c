#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

static gcry_mpi_t
from_hex(const char *hex)
{
    gcry_mpi_t m = NULL;

    gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, hex, 0, NULL);
    return m;
}

TEST(prime_check)
{
    gcry_mpi_t m127 = from_hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    gcry_mpi_t m89 = from_hex("1FFFFFFFFFFFFFFFFFFFFFF");
    gcry_mpi_t m67 = from_hex("7FFFFFFFFFFFFFFFF");
    gcry_mpi_t x = gcry_mpi_new(0);

    ASSERT_OK(gcry_prime_check(m127, 0));
    ASSERT_OK(gcry_prime_check(m89, 0));
    ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(m67, 0)); /* composite */

    gcry_mpi_set_ui(x, 2);
    ASSERT_OK(gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 3);
    ASSERT_OK(gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 65537);
    ASSERT_OK(gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 1);
    ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 0);
    ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 561); /* Carmichael number */
    ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 1000000);
    ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(x, 0));
    gcry_mpi_set_ui(x, 7);
    gcry_mpi_neg(x, x);
    ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(x, 0));

    gcry_mpi_release(m127);
    gcry_mpi_release(m89);
    gcry_mpi_release(m67);
    gcry_mpi_release(x);
}

TEST(generate_plain)
{
    gcry_mpi_t p = NULL;

    ASSERT_OK(gcry_prime_generate(&p, 128, 0, NULL, NULL, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    ASSERT_NOT_NULL(p);
    ASSERT_EQ(128, gcry_mpi_get_nbits(p));
    ASSERT_OK(gcry_prime_check(p, 0));
    ASSERT_FALSE(gcry_mpi_get_flag(p, GCRYMPI_FLAG_SECURE));
    gcry_mpi_release(p);

    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    ASSERT_OK(gcry_prime_generate(&p, 160, 0, NULL, NULL, NULL,
                                  GCRY_STRONG_RANDOM, GCRY_PRIME_FLAG_SECRET));
    ASSERT_EQ(160, gcry_mpi_get_nbits(p));
    ASSERT_TRUE(gcry_mpi_get_flag(p, GCRYMPI_FLAG_SECURE));
    ASSERT_OK(gcry_prime_check(p, 0));
    gcry_mpi_release(p);

    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_prime_generate(NULL, 128, 0, NULL, NULL,
                                                    NULL, GCRY_WEAK_RANDOM, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_prime_generate(&p, 32, 0, NULL, NULL,
                                                    NULL, GCRY_WEAK_RANDOM, 0));
    ASSERT_NULL(p);
}

static int
check_factors(gcry_mpi_t p, gcry_mpi_t *factors, unsigned int want_bits,
              int *found_bits)
{
    gcry_mpi_t prod = gcry_mpi_set_ui(NULL, 1);
    gcry_mpi_t pminus1 = gcry_mpi_new(0);
    gcry_mpi_t r = gcry_mpi_new(0);
    int i;
    int ok = 1;

    *found_bits = 0;
    gcry_mpi_sub_ui(pminus1, p, 1);

    for (i = 0; factors[i]; i++) {
        if (gcry_prime_check(factors[i], 0)) {
            ok = 0;
        }

        gcry_mpi_mod(r, pminus1, factors[i]);

        if (gcry_mpi_cmp_ui(r, 0)) {
            ok = 0;
        }

        gcry_mpi_mul(prod, prod, factors[i]);

        if (gcry_mpi_get_nbits(factors[i]) == want_bits) {
            *found_bits = 1;
        }
    }

    /* The factors are the complete factorisation of p - 1. */
    if (gcry_mpi_cmp(prod, pminus1)) {
        ok = 0;
    }

    if (gcry_mpi_cmp_ui(factors[0], 2)) {
        ok = 0; /* First factor is always 2. */
    }

    gcry_mpi_release(prod);
    gcry_mpi_release(pminus1);
    gcry_mpi_release(r);
    return ok;
}

TEST(generate_with_factors)
{
    gcry_mpi_t p = NULL;
    gcry_mpi_t *factors = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t start = gcry_mpi_set_ui(NULL, 5);
    int found;

    ASSERT_OK(gcry_prime_generate(&p, 256, 32, &factors, NULL, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    ASSERT_NOT_NULL(p);
    ASSERT_NOT_NULL(factors);
    ASSERT_EQ(256, gcry_mpi_get_nbits(p));
    ASSERT_OK(gcry_prime_check(p, 0));
    ASSERT_TRUE(check_factors(p, factors, 32, &found));

    /* A generator of the full group: g^((p-1)/f) != 1 for every factor. */
    ASSERT_OK(gcry_prime_group_generator(&g, p, factors, NULL));
    ASSERT_NOT_NULL(g);
    ASSERT_TRUE(gcry_mpi_cmp_ui(g, 3) >= 0);
    {
        gcry_mpi_t pminus1 = gcry_mpi_new(0);
        gcry_mpi_t e = gcry_mpi_new(0);
        gcry_mpi_t b = gcry_mpi_new(0);
        int i;

        gcry_mpi_sub_ui(pminus1, p, 1);

        for (i = 0; factors[i]; i++) {
            gcry_mpi_div(e, NULL, pminus1, factors[i], 0);
            gcry_mpi_powm(b, g, e, p);
            ASSERT_TRUE(gcry_mpi_cmp_ui(b, 1) != 0);
        }

        gcry_mpi_powm(b, g, pminus1, p);
        ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 1));
        gcry_mpi_release(pminus1);
        gcry_mpi_release(e);
        gcry_mpi_release(b);
    }
    gcry_mpi_release(g);

    ASSERT_OK(gcry_prime_group_generator(&g, p, factors, start));
    ASSERT_TRUE(gcry_mpi_cmp_ui(g, 5) >= 0);
    gcry_mpi_release(g);
    gcry_prime_release_factors(factors);
    gcry_mpi_release(p);

    /* Special factor mode: one factor of exactly factor_bits bits. */
    ASSERT_OK(gcry_prime_generate(&p, 256, 40, &factors, NULL, NULL,
                                  GCRY_WEAK_RANDOM,
                                  GCRY_PRIME_FLAG_SPECIAL_FACTOR));
    ASSERT_EQ(256, gcry_mpi_get_nbits(p));
    ASSERT_TRUE(check_factors(p, factors, 40, &found));
    ASSERT_TRUE(found);
    gcry_prime_release_factors(factors);
    gcry_mpi_release(p);

    /* Error handling of the generator search. */
    {
        gcry_mpi_t one[2];

        one[0] = start;
        one[1] = NULL;
        ASSERT_ERR(GPG_ERR_INV_ARG,
                   gcry_prime_group_generator(&g, start, one, NULL));
        ASSERT_ERR(GPG_ERR_INV_ARG,
                   gcry_prime_group_generator(NULL, start, one, NULL));
        ASSERT_ERR(GPG_ERR_INV_ARG,
                   gcry_prime_group_generator(&g, start, NULL, NULL));
    }
    gcry_mpi_release(start);
    gcry_prime_release_factors(NULL);
}

static int cb_calls[3];
static int cb_reject_mode = -1;

static int
check_cb(void *arg, int mode, gcry_mpi_t candidate)
{
    (void)arg;
    (void)candidate;

    if (mode >= 0 && mode < 3) {
        cb_calls[mode]++;
    }

    return mode != cb_reject_mode;
}

TEST(callback)
{
    gcry_mpi_t p = NULL;

    memset(cb_calls, 0, sizeof cb_calls);
    cb_reject_mode = -1;
    ASSERT_OK(gcry_prime_generate(&p, 128, 0, NULL, check_cb, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    ASSERT_NOT_NULL(p);
    ASSERT_TRUE(cb_calls[GCRY_PRIME_CHECK_AT_MAYBE_PRIME] >= 1);
    ASSERT_TRUE(cb_calls[GCRY_PRIME_CHECK_AT_GOT_PRIME] >= 1);
    ASSERT_EQ(1, cb_calls[GCRY_PRIME_CHECK_AT_FINISH]);
    gcry_mpi_release(p);

    /* Rejecting at the end fails the whole generation. */
    cb_reject_mode = GCRY_PRIME_CHECK_AT_FINISH;
    p = NULL;
    ASSERT_ERR(GPG_ERR_GENERAL, gcry_prime_generate(&p, 128, 0, NULL, check_cb,
                                                    NULL, GCRY_WEAK_RANDOM, 0));
    ASSERT_NULL(p);
}

static int veto_once_mode = -1;
static int veto_done;

static int
veto_once_cb(void *arg, int mode, gcry_mpi_t candidate)
{
    (void)arg;
    (void)candidate;

    if (mode == veto_once_mode && !veto_done) {
        veto_done = 1;
        return 0;
    }

    return 1;
}

TEST(callback_vetoes_candidates)
{
    gcry_mpi_t p = NULL;

    /* Rejecting a candidate makes the generator move on to the next. */
    veto_once_mode = GCRY_PRIME_CHECK_AT_MAYBE_PRIME;
    veto_done = 0;
    ASSERT_OK(gcry_prime_generate(&p, 128, 0, NULL, veto_once_cb, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    ASSERT_TRUE(veto_done);
    ASSERT_OK(gcry_prime_check(p, 0));
    gcry_mpi_release(p);

    veto_once_mode = GCRY_PRIME_CHECK_AT_GOT_PRIME;
    veto_done = 0;
    p = NULL;
    ASSERT_OK(gcry_prime_generate(&p, 128, 0, NULL, veto_once_cb, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    ASSERT_TRUE(veto_done);
    ASSERT_OK(gcry_prime_check(p, 0));
    gcry_mpi_release(p);
}

TEST(argument_edges)
{
    gcry_mpi_t p = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t eleven = gcry_mpi_set_ui(NULL, 11);
    gcry_mpi_t f[3];

    /* No room for a q factor of the requested size. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_prime_generate(&p, 64, 60, NULL, NULL,
                                                    NULL, GCRY_WEAK_RANDOM, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_prime_generate(&p, 128, 100, NULL, NULL, NULL,
                                   GCRY_WEAK_RANDOM,
                                   GCRY_PRIME_FLAG_SPECIAL_FACTOR));
    /* Unknown flag bits are ignored. */
    ASSERT_OK(gcry_prime_generate(&p, 128, 0, NULL, NULL, NULL,
                                  GCRY_WEAK_RANDOM, 0x100));
    gcry_mpi_release(p);

    /* p = 11, p - 1 = 2 * 5: the smallest generator from 3 is 6. */
    f[0] = gcry_mpi_set_ui(NULL, 2);
    f[1] = gcry_mpi_set_ui(NULL, 5);
    f[2] = NULL;
    ASSERT_OK(gcry_prime_group_generator(&g, eleven, f, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(g, 6));
    gcry_mpi_release(g);
    /* Zero factors are rejected (upstream divides by zero). */
    gcry_mpi_set_ui(f[1], 0);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_prime_group_generator(&g, eleven, f, NULL));
    gcry_mpi_release(f[0]);
    gcry_mpi_release(f[1]);
    gcry_mpi_release(eleven);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_prime_check(NULL, 0));
    /* An opaque MPI is simply "not a prime", as in the reference. */
    {
        gcry_mpi_t o = gcry_mpi_set_opaque_copy(NULL, "abc", 24);

        ASSERT_NOT_NULL(o);
        ASSERT_ERR(GPG_ERR_NO_PRIME, gcry_prime_check(o, 0));
        gcry_mpi_release(o);
    }
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(prime_check);
    RUN_TEST(generate_plain);
    RUN_TEST(generate_with_factors);
    RUN_TEST(callback);
    RUN_TEST(callback_vetoes_candidates);
    RUN_TEST(argument_edges);
    return TEST_RESULT();
}
