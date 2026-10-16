/*
 * prime.c - Prime number generation and testing.
 *
 * Primality testing and the generation of random primes are done by
 * OpenSSL.  What this file adds is the shape of the primes the gcrypt API
 * promises: a prime p whose p-1 has known factors (one of them optionally
 * of a requested size), the factor list, the progress callback protocol
 * and the group generator search.
 */
#include "gcrypt-int.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

/* Candidates whose bit count misses the target this often get a new q. */
#define MAX_MISSES 20

/* Consecutive composite candidates before one entry of the pool of small
 * primes is replaced.  Without this a pool whose subset products are all
 * composite would make the generator loop forever; replacing a single
 * entry at a time keeps that guarantee without paying for a whole new
 * pool every time. */
#define MAX_COMPOSITES 64

/* Trial division bound: every prime below this is tried before a
 * candidate is handed to the expensive tests.  There are 669 of them. */
#define SMALL_PRIME_LIMIT 5000
#define SMALL_PRIME_COUNT 669

static BN_ULONG small_primes[SMALL_PRIME_COUNT];
static pthread_once_t small_primes_once = PTHREAD_ONCE_INIT;

/* Sieve of Eratosthenes below SMALL_PRIME_LIMIT. */
static void
init_small_primes(void)
{
    unsigned char composite[SMALL_PRIME_LIMIT];
    unsigned int i;
    unsigned int n = 0;

    memset(composite, 0, sizeof composite);

    for (i = 2; i < SMALL_PRIME_LIMIT; i++) {
        unsigned int j;

        if (composite[i]) {
            continue;
        }

        if (n < SMALL_PRIME_COUNT) {
            small_primes[n++] = i;
        }

        for (j = i * i; j < SMALL_PRIME_LIMIT; j += i) {
            composite[j] = 1;
        }
    }
}

/* 1 if N has a factor below SMALL_PRIME_LIMIT (and is not itself that
 * prime), 0 if it survives trial division, -1 on error. */
static int
has_small_factor(const BIGNUM *n)
{
    unsigned int i;

    pthread_once(&small_primes_once, init_small_primes);

    for (i = 0; i < SMALL_PRIME_COUNT; i++) {
        BN_ULONG r = BN_mod_word(n, small_primes[i]);

        if (r == (BN_ULONG) - 1) {
            ERR_clear_error();
            return -1;
        }

        if (r == 0) {
            return BN_is_word(n, small_primes[i]) ? 0 : 1;
        }
    }

    return 0;
}

static void
progress(int c)
{
    _gcry_progress("primegen", c, 0, 0);
}

/* A random prime of exactly NBITS bits. */
static gcry_mpi_t
gen_prime(unsigned int nbits, int secret, BN_CTX *ctx)
{
    gcry_mpi_t p = _gcry_mpi_alloc(secret);

    if (!BN_generate_prime_ex2(p->bn, (int)nbits, 0, NULL, NULL, NULL,
                               ctx)) {
        ERR_clear_error();
        gcry_mpi_release(p);
        return NULL;
    }

    return p;
}

/* Is PRIME (probably) prime?  CB_FUNC may veto the candidate before and
 * after the expensive test. */
static int
check_prime(gcry_mpi_t prime, BN_CTX *ctx, gcry_prime_check_func_t cb_func,
            void *cb_arg)
{
    BIGNUM *two;
    BIGNUM *pminus1;
    BIGNUM *result;
    int ok = 0;

    if (!BN_is_odd(prime->bn)) {
        return BN_is_word(prime->bn, 2);
    }

    /* Trial division by small primes rejects more than nine in ten
     * candidates for the price of a few hundred single word divisions,
     * far cheaper than any modular exponentiation. */
    switch (has_small_factor(prime->bn)) {
    case 0:
        break;

    case 1:
        progress('.');
        return 0;

    default:
        return 0;
    }

    BN_CTX_start(ctx);
    two = BN_CTX_get(ctx);
    pminus1 = BN_CTX_get(ctx);
    result = BN_CTX_get(ctx);

    /* A Fermat test on the survivors weeds out the remaining composites,
     * so that the callback is only consulted for serious candidates. */
    if (!result || !BN_set_word(two, 2)
        || !BN_sub(pminus1, prime->bn, BN_value_one())
        || !BN_mod_exp(result, two, pminus1, prime->bn, ctx)) {
        ERR_clear_error();
        goto leave;
    }

    if (!BN_is_one(result)) {
        progress('.');
        goto leave;
    }

    if (cb_func && !cb_func(cb_arg, GCRY_PRIME_CHECK_AT_MAYBE_PRIME, prime)) {
        progress('.');
        goto leave;
    }

    if (BN_check_prime(prime->bn, ctx, NULL) != 1) {
        ERR_clear_error();
        progress('.');
        goto leave;
    }

    if (cb_func && !cb_func(cb_arg, GCRY_PRIME_CHECK_AT_GOT_PRIME, prime)) {
        progress('.');
        goto leave;
    }

    ok = 1;

leave:
    BN_CTX_end(ctx);
    return ok;
}

static void
release_mpi_array(gcry_mpi_t *array, size_t n)
{
    size_t i;

    if (!array) {
        return;
    }

    for (i = 0; i < n; i++) {
        gcry_mpi_release(array[i]);
    }

    _gcry_free(array);
}

/* Pick N distinct indices out of M at random into SEL. */
static gcry_err_code_t
pick_subset(unsigned int *sel, unsigned int n, unsigned int m)
{
    unsigned int i;
    unsigned int *perm = _gcry_malloc(m * sizeof * perm);

    if (!perm) {
        return _gcry_err_code_from_syserror();
    }

    for (i = 0; i < m; i++) {
        perm[i] = i;
    }

    for (i = 0; i < n; i++) {
        unsigned int r;
        unsigned int t;

        if (RAND_bytes_ex(_gcry_libctx(), (unsigned char *)&r, sizeof r, 0)
            <= 0) {
            _gcry_free(perm);
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        r = i + r % (m - i);
        t = perm[i];
        perm[i] = perm[r];
        perm[r] = t;
        sel[i] = perm[i];
    }

    _gcry_free(perm);
    return 0;
}

/* Generate a prime P of PBITS bits with P-1 = 2 * q * [qf] * f_1 ... f_n,
 * where q has about QBITS bits (or, with NEED_Q_FACTOR, qf has exactly
 * QBITS bits) and the f_i are smaller primes. */
static gcry_err_code_t
prime_generate_internal(int need_q_factor, gcry_mpi_t *r_prime,
                        unsigned int pbits, unsigned int qbits,
                        gcry_mpi_t **ret_factors, unsigned int flags,
                        gcry_prime_check_func_t cb_func, void *cb_arg)
{
    gcry_err_code_t err = 0;
    int is_secret = !!(flags & GCRY_PRIME_FLAG_SECRET);
    unsigned int req_qbits;
    unsigned int fbits;
    unsigned int n;
    unsigned int m;
    unsigned int i;
    unsigned int count1 = 0;
    unsigned int count2 = 0;
    unsigned int composites = 0;
    unsigned int next_replace = 0;
    unsigned int nprime;
    gcry_mpi_t q = NULL;
    gcry_mpi_t q_factor = NULL;
    gcry_mpi_t prime = NULL;
    gcry_mpi_t *pool = NULL;
    unsigned int *sel = NULL;
    gcry_mpi_t *factors_new = NULL;
    BN_CTX *ctx;

    *r_prime = NULL;

    if (ret_factors) {
        *ret_factors = NULL;
    }

    if (pbits < 48) {
        return GPG_ERR_INV_ARG;
    }

    if (!qbits) {
        qbits = pbits / 3;
    }

    /* q cannot be as wide as p: the factor count below would wrap around
     * and the search run away (the reference library spins for minutes,
     * then allocates a gigabyte). */
    if (qbits >= pbits) {
        return GPG_ERR_INV_ARG;
    }

    req_qbits = qbits;

    for (n = 1; (pbits - qbits - 1) / n >= qbits; n++) {
        ;
    }

    n--;

    if (!n || (need_q_factor && n < 2)) {
        return GPG_ERR_INV_ARG;
    }

    if (need_q_factor) {
        n--;
        fbits = (pbits - 2 * req_qbits - 1) / n;
        qbits = pbits - req_qbits - n * fbits;
    } else {
        fbits = (pbits - req_qbits - 1) / n;
        qbits = pbits - n * fbits;
    }

    ctx = BN_CTX_new_ex(_gcry_libctx());

    if (!ctx) {
        return GPG_ERR_ENOMEM;
    }

    prime = _gcry_mpi_alloc(is_secret);
    q = gen_prime(qbits, is_secret, ctx);

    if (need_q_factor) {
        q_factor = gen_prime(req_qbits, is_secret, ctx);
    }

    if (!q || (need_q_factor && !q_factor)) {
        err = GPG_ERR_INTERNAL;
        goto leave;
    }

    /* A pool of small primes from which each candidate draws N. */
    m = n * 3 + 5;

    if (need_q_factor) {
        m += 5;
    }

    if (m < 30) {
        m = 30;
    }

    pool = _gcry_calloc(m, sizeof * pool);
    sel = _gcry_malloc(n * sizeof * sel);

    if (!pool || !sel) {
        err = _gcry_err_code_from_syserror();
        goto leave;
    }

    for (i = 0; i < m; i++) {
        pool[i] = gen_prime(fbits, 0, ctx);

        if (!pool[i]) {
            err = GPG_ERR_INTERNAL;
            goto leave;
        }
    }

    for (;;) {
        err = pick_subset(sel, n, m);

        if (err) {
            goto leave;
        }

        gcry_mpi_set(prime, q);
        gcry_mpi_mul_ui(prime, prime, 2);

        if (need_q_factor) {
            gcry_mpi_mul(prime, prime, q_factor);
        }

        for (i = 0; i < n; i++) {
            gcry_mpi_mul(prime, prime, pool[sel[i]]);
        }

        gcry_mpi_add_ui(prime, prime, 1);
        nprime = gcry_mpi_get_nbits(prime);

        if (nprime < pbits) {
            if (++count1 > MAX_MISSES) {
                count1 = 0;
                qbits++;
                progress('>');
                gcry_mpi_release(q);
                q = gen_prime(qbits, is_secret, ctx);

                if (!q) {
                    err = GPG_ERR_INTERNAL;
                    goto leave;
                }
            }

            continue;
        }

        count1 = 0;

        if (nprime > pbits) {
            if (++count2 > MAX_MISSES) {
                count2 = 0;
                qbits--;
                progress('<');
                gcry_mpi_release(q);
                q = gen_prime(qbits, is_secret, ctx);

                if (!q) {
                    err = GPG_ERR_INTERNAL;
                    goto leave;
                }
            }

            continue;
        }

        count2 = 0;

        if (check_prime(prime, ctx, cb_func, cb_arg)) {
            break;
        }

        if (++composites > MAX_COMPOSITES) {
            /* Freshen the pool one entry at a time, round robin, so the
             * subset space keeps changing while most of the primes already
             * paid for stay in use. */
            composites = 0;
            progress('/');
            gcry_mpi_release(pool[next_replace]);
            pool[next_replace] = gen_prime(fbits, 0, ctx);

            if (!pool[next_replace]) {
                err = GPG_ERR_INTERNAL;
                goto leave;
            }

            next_replace = (next_replace + 1) % m;
        }
    }

    if (ret_factors) {
        unsigned int idx = 0;

        factors_new = _gcry_calloc(n + 4, sizeof * factors_new);

        if (!factors_new) {
            err = _gcry_err_code_from_syserror();
            goto leave;
        }

        factors_new[idx++] = gcry_mpi_set_ui(NULL, 2);
        factors_new[idx++] = gcry_mpi_copy(q);

        if (need_q_factor) {
            factors_new[idx++] = gcry_mpi_copy(q_factor);
        }

        for (i = 0; i < n; i++) {
            factors_new[idx++] = gcry_mpi_copy(pool[sel[i]]);
        }
    }

    progress('\n');

leave:
    release_mpi_array(pool, pool ? m : 0);
    _gcry_free(sel);
    gcry_mpi_release(q);
    gcry_mpi_release(q_factor);
    BN_CTX_free(ctx);

    if (!err) {
        *r_prime = prime;

        if (ret_factors) {
            *ret_factors = factors_new;
        }
    } else {
        gcry_mpi_release(prime);

        if (factors_new) {
            gcry_prime_release_factors(factors_new);
        }
    }

    return err;
}

gcry_error_t
gcry_prime_generate(gcry_mpi_t *prime, unsigned int prime_bits,
                    unsigned int factor_bits, gcry_mpi_t **factors,
                    gcry_prime_check_func_t cb_func, void *cb_arg,
                    gcry_random_level_t random_level, unsigned int flags)
{
    gcry_err_code_t rc;
    gcry_mpi_t prime_generated = NULL;
    gcry_mpi_t *factors_generated = NULL;
    int mode = !!(flags & GCRY_PRIME_FLAG_SPECIAL_FACTOR);

    (void)random_level; /* OpenSSL's private DRBG is always used. */

    if (!prime) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *prime = NULL;
    _gcry_global_init();

    rc = prime_generate_internal(mode, &prime_generated, prime_bits,
                                 factor_bits,
                                 factors ? &factors_generated : NULL, flags,
                                 cb_func, cb_arg);

    if (!rc && cb_func
        && !cb_func(cb_arg, GCRY_PRIME_CHECK_AT_FINISH, prime_generated)) {
        gcry_mpi_release(prime_generated);
        gcry_prime_release_factors(factors_generated);
        rc = GPG_ERR_GENERAL;
    }

    if (!rc) {
        if (factors) {
            *factors = factors_generated;
        }

        *prime = prime_generated;
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_prime_group_generator(gcry_mpi_t *r_g, gcry_mpi_t prime,
                           gcry_mpi_t *factors, gcry_mpi_t start_g)
{
    gcry_mpi_t tmp;
    gcry_mpi_t b;
    gcry_mpi_t pmin1;
    gcry_mpi_t g;
    int first = 1;
    int i;
    int n;

    if (!r_g) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *r_g = NULL;

    if (!factors || !prime || mpi_is_opaque(prime)
        || (start_g && mpi_is_opaque(start_g))) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    for (n = 0; factors[n]; n++) {
        if (mpi_is_opaque(factors[n]) || !gcry_mpi_cmp_ui(factors[n], 0)) {
            return GCRY_ERR(GPG_ERR_INV_ARG);
        }
    }

    if (n < 2) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    tmp = gcry_mpi_new(0);
    b = gcry_mpi_new(0);
    pmin1 = gcry_mpi_new(0);
    g = start_g ? gcry_mpi_copy(start_g) : gcry_mpi_set_ui(NULL, 3);
    gcry_mpi_sub_ui(pmin1, prime, 1);

    do {
        if (first) {
            first = 0;
        } else {
            gcry_mpi_add_ui(g, g, 1);
        }

        progress('^');

        for (i = 0; i < n; i++) {
            gcry_mpi_div(tmp, NULL, pmin1, factors[i], -1);
            gcry_mpi_powm(b, g, tmp, prime);

            if (!gcry_mpi_cmp_ui(b, 1)) {
                break;
            }
        }
    } while (i < n);

    gcry_mpi_release(tmp);
    gcry_mpi_release(b);
    gcry_mpi_release(pmin1);
    *r_g = g;
    return 0;
}

void
gcry_prime_release_factors(gcry_mpi_t *factors)
{
    size_t n = 0;

    if (!factors) {
        return;
    }

    while (factors[n]) {
        n++;
    }

    release_mpi_array(factors, n);
}

gcry_error_t
gcry_prime_check(gcry_mpi_t x, unsigned int flags)
{
    BN_CTX *ctx;
    int rc;

    (void)flags;

    if (!x) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (mpi_is_opaque(x)) {
        return GCRY_ERR(GPG_ERR_NO_PRIME); /* As the reference answers. */
    }

    switch (gcry_mpi_cmp_ui(x, 2)) {
    case 0:
        return 0;

    case -1:
        return GCRY_ERR(GPG_ERR_NO_PRIME);

    default:
        break;
    }

    if (gcry_mpi_is_neg(x)) {
        return GCRY_ERR(GPG_ERR_NO_PRIME);
    }

    ctx = BN_CTX_new_ex(_gcry_libctx());

    if (!ctx) {
        return GCRY_ERR(GPG_ERR_ENOMEM);
    }

    rc = BN_check_prime(x->bn, ctx, NULL);
    BN_CTX_free(ctx);

    if (rc < 0) {
        return GCRY_ERR(_gcry_err_from_openssl(GPG_ERR_INTERNAL));
    }

    return rc ? 0 : GCRY_ERR(GPG_ERR_NO_PRIME);
}
