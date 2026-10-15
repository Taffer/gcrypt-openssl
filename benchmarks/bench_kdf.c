/*
 * Key derivation benchmarks.  Each case derives a 32-byte key with the
 * parameters named in the case; "ops/s" is derivations per second.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

struct kdf_state {
    int algo;
    int subalgo;
    unsigned long iterations;      /* gcry_kdf_derive: iterations / p. */
    unsigned long param[4];        /* gcry_kdf_open parameter block. */
    unsigned int paramlen;
    const char *pass;
    size_t passlen;
    size_t saltlen;
    size_t keylen;                 /* Key material for the MAC-based KDFs. */
    size_t adlen;                  /* Context/info for the one-step KDFs. */
    unsigned char out[64];
};

static const char kdf_salt[] = "benchmark salt: not a secret....";
static const char kdf_info[] = "benchmark info..";

static gcry_error_t
kdf_derive_op(void *state)
{
    struct kdf_state *s = state;

    return gcry_kdf_derive(s->pass, s->passlen, s->algo, s->subalgo,
                           kdf_salt, s->saltlen, s->iterations, 32, s->out);
}

static gcry_error_t
kdf_open_op(void *state)
{
    struct kdf_state *s = state;
    gcry_kdf_hd_t hd;
    gcry_error_t err;

    err = gcry_kdf_open(&hd, s->algo, s->subalgo, s->param, s->paramlen,
                        s->pass, s->passlen, kdf_salt, s->saltlen,
                        s->keylen ? bench_input() : NULL, s->keylen,
                        s->adlen ? kdf_info : NULL, s->adlen);

    if (err) {
        return err;
    }

    err = gcry_kdf_compute(hd, NULL);

    if (!err) {
        err = gcry_kdf_final(hd, 32, s->out);
    }

    gcry_kdf_close(hd);
    return err;
}

/* The first call doubles as the support probe. */
static gcry_error_t
kdf_setup_derive(void *state)
{
    return kdf_derive_op(state);
}

static gcry_error_t
kdf_setup_open(void *state)
{
    return kdf_open_op(state);
}

static void
run_derive(const struct bench_opts *opts, const char *name, int algo,
           int subalgo, unsigned long iterations)
{
    struct kdf_state s;
    struct bench_case c;

    memset(&s, 0, sizeof s);
    s.algo = algo;
    s.subalgo = subalgo;
    s.iterations = iterations;
    s.pass = "correct horse battery staple";
    s.passlen = strlen(s.pass);
    /* OpenPGP S2K salts are exactly eight bytes. */
    s.saltlen = algo == GCRY_KDF_SALTED_S2K || algo == GCRY_KDF_ITERSALTED_S2K
                ? 8 : 16;

    memset(&c, 0, sizeof c);
    c.group = "kdf";
    c.name = name;
    c.setup = kdf_setup_derive;
    c.op = kdf_derive_op;
    c.state = &s;
    bench_run_case(opts, &c);
}

static void
run_open(const struct bench_opts *opts, const char *name, int algo,
         int subalgo, const unsigned long *param, unsigned int paramlen,
         size_t saltlen, size_t keylen, size_t adlen)
{
    struct kdf_state s;
    struct bench_case c;
    unsigned int i;

    memset(&s, 0, sizeof s);
    s.algo = algo;
    s.subalgo = subalgo;
    s.paramlen = paramlen;

    for (i = 0; i < paramlen; i++) {
        s.param[i] = param[i];
    }

    s.pass = "correct horse battery staple";
    s.passlen = strlen(s.pass);
    s.saltlen = saltlen;
    s.keylen = keylen;
    s.adlen = adlen;

    memset(&c, 0, sizeof c);
    c.group = "kdf";
    c.name = name;
    c.setup = kdf_setup_open;
    c.op = kdf_open_op;
    c.state = &s;
    bench_run_case(opts, &c);
}

void
bench_kdf(const struct bench_opts *opts)
{
    /* Argon2: 32-byte tag, t=3, 64 MiB, 4 lanes (RFC 9106 second choice). */
    static const unsigned long argon2[4] = { 32, 3, 65536, 4 };
    /* Argon2 small: t=3, 16 MiB, 1 lane, as a cheaper comparison point. */
    static const unsigned long argon2_small[4] = { 32, 3, 16384, 1 };
    /* Balloon: 32-byte tag, s_cost 1024, t_cost 3, 1 thread. */
    static const unsigned long balloon[4] = { 32, 1024, 3, 1 };
    static const unsigned long out32[1] = { 32 };

    run_derive(opts, "simple-s2k sha1", GCRY_KDF_SIMPLE_S2K, GCRY_MD_SHA1,
               0);
    run_derive(opts, "salted-s2k sha256", GCRY_KDF_SALTED_S2K,
               GCRY_MD_SHA256, 0);
    run_derive(opts, "itersalted-s2k sha1 65536B", GCRY_KDF_ITERSALTED_S2K,
               GCRY_MD_SHA1, 65536);
    run_derive(opts, "itersalted-s2k sha256 65536B",
               GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA256, 65536);
    run_derive(opts, "itersalted-s2k sha512 65011712B",
               GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA512, 65011712);
    run_derive(opts, "pbkdf1 sha1 1000", GCRY_KDF_PBKDF1, GCRY_MD_SHA1,
               1000);
    run_derive(opts, "pbkdf2 sha1 1000", GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
               1000);
    run_derive(opts, "pbkdf2 sha256 1000", GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
               1000);
    run_derive(opts, "pbkdf2 sha512 1000", GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
               1000);
    run_derive(opts, "pbkdf2 sha256 100000", GCRY_KDF_PBKDF2,
               GCRY_MD_SHA256, 100000);
    run_derive(opts, "scrypt N=16384 r=8 p=1", GCRY_KDF_SCRYPT, 16384, 1);
    run_derive(opts, "scrypt N=1024 r=8 p=1", GCRY_KDF_SCRYPT, 1024, 1);

    run_open(opts, "argon2d t=3 m=64MiB p=4", GCRY_KDF_ARGON2,
             GCRY_KDF_ARGON2D, argon2, 4, 16, 0, 0);
    run_open(opts, "argon2i t=3 m=64MiB p=4", GCRY_KDF_ARGON2,
             GCRY_KDF_ARGON2I, argon2, 4, 16, 0, 0);
    run_open(opts, "argon2id t=3 m=64MiB p=4", GCRY_KDF_ARGON2,
             GCRY_KDF_ARGON2ID, argon2, 4, 16, 0, 0);
    run_open(opts, "argon2id t=3 m=16MiB p=1", GCRY_KDF_ARGON2,
             GCRY_KDF_ARGON2ID, argon2_small, 4, 16, 0, 0);
    run_open(opts, "balloon sha256 s=1024 t=3", GCRY_KDF_BALLOON,
             GCRY_MD_SHA256, balloon, 4, 16, 0, 0);
    run_open(opts, "hkdf sha256", GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, out32,
             1, 16, 0, 16);
    run_open(opts, "hkdf sha512", GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA512, out32,
             1, 16, 0, 16);
    run_open(opts, "onestep-kdf sha256", GCRY_KDF_ONESTEP_KDF, GCRY_MD_SHA256,
             out32, 1, 0, 0, 16);
    run_open(opts, "onestep-kdf-mac hmac-sha256", GCRY_KDF_ONESTEP_KDF_MAC,
             GCRY_MAC_HMAC_SHA256, out32, 1, 0, 16, 16);
    run_open(opts, "x963-kdf sha256", GCRY_KDF_X963_KDF, GCRY_MD_SHA256,
             out32, 1, 0, 0, 16);
}
