/*
 * Everything that is not a cryptographic primitive but sits on the hot
 * path of callers: version check, S-expression handling, big-number
 * arithmetic and the random number interface.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

struct misc_state {
    gcry_mpi_t a;
    gcry_mpi_t b;
    gcry_mpi_t m;
    gcry_mpi_t r;
    gcry_sexp_t key;
    char *canon;
    size_t canonlen;
    unsigned char buf[256];
    enum gcry_random_level level;
    size_t nbytes;
};

static gcry_error_t
check_version_op(void *state)
{
    (void)state;
    return gcry_check_version(NULL) ? 0 : gpg_error(GPG_ERR_INTERNAL);
}

static gcry_error_t
mpi_setup(void *state)
{
    struct misc_state *s = state;

    s->a = gcry_mpi_new(2048);
    s->b = gcry_mpi_new(2048);
    s->m = gcry_mpi_new(2048);
    s->r = gcry_mpi_new(2048);
    gcry_mpi_randomize(s->a, 2048, GCRY_WEAK_RANDOM);
    gcry_mpi_randomize(s->b, 2048, GCRY_WEAK_RANDOM);
    gcry_mpi_randomize(s->m, 2048, GCRY_WEAK_RANDOM);
    gcry_mpi_set_bit(s->m, 0);      /* Odd modulus, as RSA has. */
    gcry_mpi_set_bit(s->m, 2047);
    gcry_mpi_clear_bit(s->a, 2047); /* a, b < m */
    gcry_mpi_clear_bit(s->b, 2047);
    return 0;
}

static void
mpi_teardown(void *state)
{
    struct misc_state *s = state;

    gcry_mpi_release(s->a);
    gcry_mpi_release(s->b);
    gcry_mpi_release(s->m);
    gcry_mpi_release(s->r);
    s->a = s->b = s->m = s->r = NULL;
}

static gcry_error_t
mpi_mulm_op(void *state)
{
    struct misc_state *s = state;

    gcry_mpi_mulm(s->r, s->a, s->b, s->m);
    return 0;
}

static gcry_error_t
mpi_powm_op(void *state)
{
    struct misc_state *s = state;

    gcry_mpi_powm(s->r, s->a, s->b, s->m);
    return 0;
}

static gcry_error_t
mpi_invm_op(void *state)
{
    struct misc_state *s = state;

    gcry_mpi_invm(s->r, s->a, s->m);
    return 0;
}

static gcry_error_t
mpi_print_scan_op(void *state)
{
    struct misc_state *s = state;
    size_t n = 0;
    gcry_mpi_t t = NULL;
    gcry_error_t err;

    err = gcry_mpi_print(GCRYMPI_FMT_USG, s->buf, sizeof s->buf, &n, s->a);

    if (!err) {
        err = gcry_mpi_scan(&t, GCRYMPI_FMT_USG, s->buf, n, NULL);
    }

    gcry_mpi_release(t);
    return err;
}

static gcry_error_t
sexp_setup(void *state)
{
    struct misc_state *s = state;
    gcry_error_t err;

    s->a = gcry_mpi_new(2048);
    s->b = gcry_mpi_new(0);
    gcry_mpi_randomize(s->a, 2048, GCRY_WEAK_RANDOM);
    gcry_mpi_set_ui(s->b, 65537);
    err = gcry_sexp_build(&s->key, NULL, "(public-key (rsa (n %m) (e %m)))",
                          s->a, s->b);

    if (err) {
        return err;
    }

    s->canonlen = gcry_sexp_sprint(s->key, GCRYSEXP_FMT_CANON, NULL, 0);
    s->canon = gcry_malloc(s->canonlen);

    if (!s->canon) {
        return gpg_error(GPG_ERR_ENOMEM);
    }

    gcry_sexp_sprint(s->key, GCRYSEXP_FMT_CANON, s->canon, s->canonlen);
    return 0;
}

static void
sexp_teardown(void *state)
{
    struct misc_state *s = state;

    gcry_mpi_release(s->a);
    gcry_mpi_release(s->b);
    gcry_sexp_release(s->key);
    gcry_free(s->canon);
    s->a = s->b = NULL;
    s->key = NULL;
    s->canon = NULL;
}

static gcry_error_t
sexp_build_op(void *state)
{
    struct misc_state *s = state;
    gcry_sexp_t x = NULL;
    gcry_error_t err = gcry_sexp_build(&x, NULL,
                                       "(public-key (rsa (n %m) (e %m)))",
                                       s->a, s->b);

    gcry_sexp_release(x);
    return err;
}

static gcry_error_t
sexp_parse_op(void *state)
{
    struct misc_state *s = state;
    gcry_sexp_t x = NULL;
    gcry_error_t err = gcry_sexp_new(&x, s->canon, s->canonlen, 0);

    gcry_sexp_release(x);
    return err;
}

static gcry_error_t
sexp_extract_op(void *state)
{
    struct misc_state *s = state;
    gcry_mpi_t n = NULL;
    gcry_mpi_t e = NULL;
    gcry_sexp_t rsa = gcry_sexp_find_token(s->key, "rsa", 0);
    gcry_error_t err;

    if (!rsa) {
        return gpg_error(GPG_ERR_INTERNAL);
    }

    err = gcry_sexp_extract_param(rsa, NULL, "ne", &n, &e, NULL);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_sexp_release(rsa);
    return err;
}

static gcry_error_t
keygrip_op(void *state)
{
    struct misc_state *s = state;

    return gcry_pk_get_keygrip(s->key, s->buf) ? 0
           : gpg_error(GPG_ERR_INTERNAL);
}

static gcry_error_t
randomize_op(void *state)
{
    struct misc_state *s = state;

    gcry_randomize(s->buf, s->nbytes, s->level);
    return 0;
}

static gcry_error_t
nonce_op(void *state)
{
    struct misc_state *s = state;

    gcry_create_nonce(s->buf, s->nbytes);
    return 0;
}

static void
run(const struct bench_opts *opts, const char *name, size_t bytes,
    bench_setup_fn setup, bench_op_fn op, bench_teardown_fn teardown,
    struct misc_state *s)
{
    struct bench_case c;

    memset(&c, 0, sizeof c);
    c.group = "misc";
    c.name = name;
    c.bytes = bytes;
    c.setup = setup;
    c.op = op;
    c.teardown = teardown;
    c.state = s;
    bench_run_case(opts, &c);
}

void
bench_misc(const struct bench_opts *opts)
{
    struct misc_state s;

    memset(&s, 0, sizeof s);

    run(opts, "gcry_check_version", 0, NULL, check_version_op, NULL, &s);
    run(opts, "mpi mulm 2048", 0, mpi_setup, mpi_mulm_op, mpi_teardown, &s);
    run(opts, "mpi powm 2048", 0, mpi_setup, mpi_powm_op, mpi_teardown, &s);
    run(opts, "mpi invm 2048", 0, mpi_setup, mpi_invm_op, mpi_teardown, &s);
    run(opts, "mpi print+scan 2048", 0, mpi_setup, mpi_print_scan_op,
        mpi_teardown, &s);
    run(opts, "sexp build rsa-2048 public key", 0, sexp_setup, sexp_build_op,
        sexp_teardown, &s);
    run(opts, "sexp parse canonical rsa-2048 key", 0, sexp_setup,
        sexp_parse_op, sexp_teardown, &s);
    run(opts, "sexp extract_param n e", 0, sexp_setup, sexp_extract_op,
        sexp_teardown, &s);
    run(opts, "pk get_keygrip rsa-2048", 0, sexp_setup, keygrip_op,
        sexp_teardown, &s);

    s.nbytes = 32;
    s.level = GCRY_WEAK_RANDOM;
    run(opts, "randomize weak 32B", 32, NULL, randomize_op, NULL, &s);
    s.level = GCRY_STRONG_RANDOM;
    run(opts, "randomize strong 32B", 32, NULL, randomize_op, NULL, &s);
    s.level = GCRY_VERY_STRONG_RANDOM;
    run(opts, "randomize very-strong 32B", 32, NULL, randomize_op, NULL, &s);
    run(opts, "create_nonce 32B", 32, NULL, nonce_op, NULL, &s);
    s.nbytes = 256;
    s.level = GCRY_STRONG_RANDOM;
    run(opts, "randomize strong 256B", 256, NULL, randomize_op, NULL, &s);
}
