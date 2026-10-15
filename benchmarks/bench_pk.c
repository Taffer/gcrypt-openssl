/*
 * Public key benchmarks: key generation, signing, verification,
 * encryption and decryption through the S-expression interface.
 *
 * Signing and verification cases generate a key in setup; the first
 * genkey of the slow algorithms (DSA, ElGamal) therefore shows up as setup
 * time rather than in the measured rate.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

struct keygen_state {
    const char *parms;
    gcry_sexp_t parms_sexp;
};

static gcry_error_t
keygen_setup(void *state)
{
    struct keygen_state *s = state;

    return gcry_sexp_new(&s->parms_sexp, s->parms, 0, 1);
}

static gcry_error_t
keygen_op(void *state)
{
    struct keygen_state *s = state;
    gcry_sexp_t key = NULL;
    gcry_error_t err = gcry_pk_genkey(&key, s->parms_sexp);

    gcry_sexp_release(key);
    return err;
}

static void
keygen_teardown(void *state)
{
    struct keygen_state *s = state;

    gcry_sexp_release(s->parms_sexp);
    s->parms_sexp = NULL;
}

static void
run_keygen(const struct bench_opts *opts, const char *name,
           const char *parms)
{
    struct keygen_state s;
    struct bench_case c;

    memset(&s, 0, sizeof s);
    s.parms = parms;

    memset(&c, 0, sizeof c);
    c.group = "pk";
    c.name = name;
    c.setup = keygen_setup;
    c.op = keygen_op;
    c.teardown = keygen_teardown;
    c.state = &s;
    bench_run_case(opts, &c);
}

enum pk_op { PK_SIGN, PK_VERIFY, PK_ENCRYPT, PK_DECRYPT };

struct pk_state {
    const char *parms;
    const char *data_fmt;    /* gcry_sexp_build format with %b or %m. */
    size_t data_bytes;       /* For %b: the number of input bytes. */
    unsigned int data_bits;  /* For %m: the size of the random MPI. */
    enum pk_op op;
    gcry_sexp_t pub;
    gcry_sexp_t sec;
    gcry_sexp_t data;
    gcry_sexp_t result;      /* Signature or ciphertext for the inverse. */
};

/*
 * Consecutive cases usually share key parameters, and generating an
 * ElGamal or DSA key can take seconds, so the last generated key is kept
 * and reused while the parameter string stays the same.
 */
static const char *cached_parms;
static gcry_sexp_t cached_key;

static gcry_error_t
cached_genkey(const char *parms_str, gcry_sexp_t *r_key)
{
    gcry_sexp_t parms = NULL;
    gcry_error_t err;

    if (cached_key && cached_parms == parms_str) {
        *r_key = cached_key;
        return 0;
    }

    gcry_sexp_release(cached_key);
    cached_key = NULL;
    cached_parms = NULL;

    err = gcry_sexp_new(&parms, parms_str, 0, 1);

    if (!err) {
        err = gcry_pk_genkey(&cached_key, parms);
    }

    gcry_sexp_release(parms);

    if (!err) {
        cached_parms = parms_str;
        *r_key = cached_key;
    }

    return err;
}

static gcry_error_t
pk_setup(void *state)
{
    struct pk_state *s = state;
    gcry_sexp_t key = NULL;
    gcry_error_t err;

    err = cached_genkey(s->parms, &key);

    if (err) {
        return err;
    }

    s->pub = gcry_sexp_find_token(key, "public-key", 0);
    s->sec = gcry_sexp_find_token(key, "private-key", 0);

    if (!s->pub || !s->sec) {
        err = gpg_error(GPG_ERR_INTERNAL);
    } else if (s->data_bits) {
        gcry_mpi_t m = gcry_mpi_new(s->data_bits);

        gcry_mpi_randomize(m, s->data_bits, GCRY_WEAK_RANDOM);
        err = gcry_sexp_build(&s->data, NULL, s->data_fmt, m);
        gcry_mpi_release(m);
    } else {
        err = gcry_sexp_build(&s->data, NULL, s->data_fmt,
                              (int)s->data_bytes, bench_input());
    }

    if (!err && s->op == PK_VERIFY) {
        err = gcry_pk_sign(&s->result, s->data, s->sec);
    } else if (!err && s->op == PK_DECRYPT) {
        err = gcry_pk_encrypt(&s->result, s->data, s->pub);
    }

    return err;
}

static gcry_error_t
pk_op(void *state)
{
    struct pk_state *s = state;
    gcry_sexp_t r = NULL;
    gcry_error_t err;

    switch (s->op) {
    case PK_SIGN:
        err = gcry_pk_sign(&r, s->data, s->sec);
        break;

    case PK_VERIFY:
        return gcry_pk_verify(s->result, s->data, s->pub);

    case PK_ENCRYPT:
        err = gcry_pk_encrypt(&r, s->data, s->pub);
        break;

    case PK_DECRYPT:
    default:
        err = gcry_pk_decrypt(&r, s->result, s->sec);
        break;
    }

    gcry_sexp_release(r);
    return err;
}

static void
pk_teardown(void *state)
{
    struct pk_state *s = state;

    gcry_sexp_release(s->pub);
    gcry_sexp_release(s->sec);
    gcry_sexp_release(s->data);
    gcry_sexp_release(s->result);
    s->pub = s->sec = s->data = s->result = NULL;
}

static void
run_pk(const struct bench_opts *opts, const char *name, enum pk_op op,
       const char *parms, const char *data_fmt, size_t data_bytes,
       unsigned int data_bits)
{
    struct pk_state s;
    struct bench_case c;

    memset(&s, 0, sizeof s);
    s.parms = parms;
    s.data_fmt = data_fmt;
    s.data_bytes = data_bytes;
    s.data_bits = data_bits;
    s.op = op;

    memset(&c, 0, sizeof c);
    c.group = "pk";
    c.name = name;
    c.setup = pk_setup;
    c.op = pk_op;
    c.teardown = pk_teardown;
    c.state = &s;
    bench_run_case(opts, &c);
}

/* Sign and verify with the same key parameters and data. */
static void
run_sign_verify(const struct bench_opts *opts, const char *what,
                const char *parms, const char *data_fmt, size_t data_bytes,
                unsigned int data_bits)
{
    char name[BENCH_NAME_MAX];

    snprintf(name, sizeof name, "%s sign", what);
    run_pk(opts, name, PK_SIGN, parms, data_fmt, data_bytes, data_bits);
    snprintf(name, sizeof name, "%s verify", what);
    run_pk(opts, name, PK_VERIFY, parms, data_fmt, data_bytes, data_bits);
}

static void
run_encrypt_decrypt(const struct bench_opts *opts, const char *what,
                    const char *parms, const char *data_fmt,
                    size_t data_bytes, unsigned int data_bits)
{
    char name[BENCH_NAME_MAX];

    snprintf(name, sizeof name, "%s encrypt", what);
    run_pk(opts, name, PK_ENCRYPT, parms, data_fmt, data_bytes, data_bits);
    snprintf(name, sizeof name, "%s decrypt", what);
    run_pk(opts, name, PK_DECRYPT, parms, data_fmt, data_bytes, data_bits);
}

#define RSA2048 "(genkey (rsa (nbits 4:2048)))"
#define RSA3072 "(genkey (rsa (nbits 4:3072)))"
#define RSA4096 "(genkey (rsa (nbits 4:4096)))"
#define DSA2048 "(genkey (dsa (nbits 4:2048) (qbits 3:256)))"
#define ELG2048 "(genkey (elg (nbits 4:2048)))"
#define P256 "(genkey (ecc (curve \"NIST P-256\")))"
#define P384 "(genkey (ecc (curve \"NIST P-384\")))"
#define P521 "(genkey (ecc (curve \"NIST P-521\")))"
#define SECP256K1 "(genkey (ecc (curve secp256k1)))"
#define BP256 "(genkey (ecc (curve brainpoolP256r1)))"
#define ED25519 "(genkey (ecc (curve Ed25519) (flags eddsa)))"
#define ED448 "(genkey (ecc (curve Ed448) (flags eddsa)))"
#define X25519 "(genkey (ecc (curve Curve25519) (flags djb-tweak)))"
#define X448 "(genkey (ecc (curve X448)))"

void
bench_pk(const struct bench_opts *opts)
{
    run_keygen(opts, "rsa 2048 genkey", RSA2048);
    run_keygen(opts, "rsa 3072 genkey", RSA3072);
    run_keygen(opts, "rsa 4096 genkey", RSA4096);
    run_keygen(opts, "dsa 2048/256 genkey", DSA2048);
    run_keygen(opts, "elg 2048 genkey", ELG2048);
    run_keygen(opts, "ecc nistp256 genkey", P256);
    run_keygen(opts, "ecc nistp384 genkey", P384);
    run_keygen(opts, "ecc nistp521 genkey", P521);
    run_keygen(opts, "ecc secp256k1 genkey", SECP256K1);
    run_keygen(opts, "ecc brainpoolP256r1 genkey", BP256);
    run_keygen(opts, "ecc ed25519 genkey", ED25519);
    run_keygen(opts, "ecc ed448 genkey", ED448);
    run_keygen(opts, "ecc curve25519 genkey", X25519);
    run_keygen(opts, "ecc x448 genkey", X448);

    run_sign_verify(opts, "rsa 2048 pkcs1-sha256", RSA2048,
                    "(data (flags pkcs1) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "rsa 2048 pss-sha256", RSA2048,
                    "(data (flags pss) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "rsa 3072 pkcs1-sha256", RSA3072,
                    "(data (flags pkcs1) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "rsa 4096 pkcs1-sha256", RSA4096,
                    "(data (flags pkcs1) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "dsa 2048/256 sha256", DSA2048,
                    "(data (flags rfc6979) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "elg 2048 raw", ELG2048,
                    "(data (flags raw) (value %m))", 0, 256);
    run_sign_verify(opts, "ecdsa nistp256 sha256", P256,
                    "(data (flags rfc6979) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "ecdsa nistp384 sha384", P384,
                    "(data (flags rfc6979) (hash sha384 %b))", 48, 0);
    run_sign_verify(opts, "ecdsa nistp521 sha512", P521,
                    "(data (flags rfc6979) (hash sha512 %b))", 64, 0);
    run_sign_verify(opts, "ecdsa secp256k1 sha256", SECP256K1,
                    "(data (flags rfc6979) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "ecdsa brainpoolP256r1 sha256", BP256,
                    "(data (flags rfc6979) (hash sha256 %b))", 32, 0);
    run_sign_verify(opts, "eddsa ed25519 64B", ED25519,
                    "(data (flags eddsa) (hash-algo sha512) (value %b))", 64,
                    0);
    run_sign_verify(opts, "eddsa ed448 64B", ED448,
                    "(data (flags eddsa) (hash-algo shake256) (value %b))",
                    64, 0);

    run_encrypt_decrypt(opts, "rsa 2048 pkcs1", RSA2048,
                        "(data (flags pkcs1) (value %b))", 32, 0);
    run_encrypt_decrypt(opts, "rsa 2048 oaep-sha256", RSA2048,
                        "(data (flags oaep) (hash-algo sha256) (value %b))",
                        32, 0);
    run_encrypt_decrypt(opts, "rsa 3072 pkcs1", RSA3072,
                        "(data (flags pkcs1) (value %b))", 32, 0);
    run_encrypt_decrypt(opts, "rsa 4096 pkcs1", RSA4096,
                        "(data (flags pkcs1) (value %b))", 32, 0);
    run_encrypt_decrypt(opts, "elg 2048 raw", ELG2048,
                        "(data (flags raw) (value %m))", 0, 256);
    run_encrypt_decrypt(opts, "ecdh nistp256", P256,
                        "(data (flags raw) (value %m))", 0, 255);
    run_encrypt_decrypt(opts, "ecdh nistp384", P384,
                        "(data (flags raw) (value %m))", 0, 383);
    run_encrypt_decrypt(opts, "ecdh nistp521", P521,
                        "(data (flags raw) (value %m))", 0, 520);
    run_encrypt_decrypt(opts, "ecdh brainpoolP256r1", BP256,
                        "(data (flags raw) (value %m))", 0, 255);
    run_encrypt_decrypt(opts, "ecdh curve25519", X25519,
                        "(data (flags raw) (value %m))", 0, 255);
    run_encrypt_decrypt(opts, "ecdh x448", X448,
                        "(data (flags raw) (value %m))", 0, 447);

    gcry_sexp_release(cached_key);
    cached_key = NULL;
    cached_parms = NULL;
}
