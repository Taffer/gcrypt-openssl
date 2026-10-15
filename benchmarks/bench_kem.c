/*
 * Key encapsulation benchmarks: keypair, encap and decap for every KEM
 * algorithm.  Buffer lengths are the algorithm constants; most are also
 * defined in gcrypt.h, but a few are only implied there, so they are all
 * written out here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench.h"

struct kem_desc {
    int algo;
    const char *name;
    size_t pk;
    size_t sk;
    size_t ct;
    size_t ss;
};

static const struct kem_desc kems[] = {
    { GCRY_KEM_MLKEM512, "ML-KEM-512", 800, 1632, 768, 32 },
    { GCRY_KEM_MLKEM768, "ML-KEM-768", 1184, 2400, 1088, 32 },
    { GCRY_KEM_MLKEM1024, "ML-KEM-1024", 1568, 3168, 1568, 32 },
    { GCRY_KEM_RAW_X25519, "raw-x25519", 32, 32, 32, 32 },
    { GCRY_KEM_RAW_X448, "raw-x448", 56, 56, 56, 56 },
    { GCRY_KEM_RAW_BP256, "raw-brainpoolP256r1", 65, 32, 65, 65 },
    { GCRY_KEM_RAW_BP384, "raw-brainpoolP384r1", 97, 48, 97, 97 },
    { GCRY_KEM_RAW_BP512, "raw-brainpoolP512r1", 129, 64, 129, 129 },
    { GCRY_KEM_RAW_P256R1, "raw-nistp256", 65, 32, 65, 65 },
    { GCRY_KEM_RAW_P384R1, "raw-nistp384", 97, 48, 97, 97 },
    { GCRY_KEM_RAW_P521R1, "raw-nistp521", 133, 66, 133, 133 },
    { GCRY_KEM_RAW_P256K1, "raw-secp256k1", 65, 32, 65, 65 },
    { GCRY_KEM_DHKEM25519, "dhkem-x25519", 32, 32, 32, 32 },
    /* gcrypt.h says the DHKEM(X448) shared secret is 56 bytes, but RFC 9180
     * and the reference implementation produce 64; a 56-byte buffer
     * overflows there. */
    { GCRY_KEM_DHKEM448, "dhkem-x448", 56, 56, 56, 64 },
    { GCRY_KEM_DHKEMP256R1, "dhkem-nistp256", 65, 32, 65, 32 },
    { GCRY_KEM_DHKEMP384R1, "dhkem-nistp384", 97, 48, 97, 48 },
    { GCRY_KEM_DHKEMP521R1, "dhkem-nistp521", 133, 66, 133, 64 },
    { GCRY_KEM_SNTRUP761, "sntrup761", 1158, 1763, 1039, 32 },
    { GCRY_KEM_CM6688128F, "mceliece6688128f", 1044992, 13932, 208, 32 }
};

struct kem_state {
    const struct kem_desc *d;
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *ct;
    unsigned char *ss;
};

static void
kem_teardown(void *state)
{
    struct kem_state *s = state;

    free(s->pk);
    free(s->sk);
    free(s->ct);
    free(s->ss);
    s->pk = s->sk = s->ct = s->ss = NULL;
}

/* Allocate buffers and generate the key pair every case starts from. */
static gcry_error_t
kem_setup(void *state)
{
    struct kem_state *s = state;
    gcry_error_t err;

    s->pk = malloc(s->d->pk);
    s->sk = malloc(s->d->sk);
    s->ct = malloc(s->d->ct);
    s->ss = malloc(s->d->ss);

    if (!s->pk || !s->sk || !s->ct || !s->ss) {
        kem_teardown(s);
        return gpg_error(GPG_ERR_ENOMEM);
    }

    err = gcry_kem_keypair(s->d->algo, s->pk, s->d->pk, s->sk, s->d->sk);

    if (!err) {
        err = gcry_kem_encap(s->d->algo, s->pk, s->d->pk, s->ct, s->d->ct,
                             s->ss, s->d->ss, NULL, 0);
    }

    if (err) {
        kem_teardown(s);
    }

    return err;
}

static gcry_error_t
kem_keypair_op(void *state)
{
    struct kem_state *s = state;

    return gcry_kem_keypair(s->d->algo, s->pk, s->d->pk, s->sk, s->d->sk);
}

static gcry_error_t
kem_encap_op(void *state)
{
    struct kem_state *s = state;

    return gcry_kem_encap(s->d->algo, s->pk, s->d->pk, s->ct, s->d->ct,
                          s->ss, s->d->ss, NULL, 0);
}

static gcry_error_t
kem_decap_op(void *state)
{
    struct kem_state *s = state;

    return gcry_kem_decap(s->d->algo, s->sk, s->d->sk, s->ct, s->d->ct,
                          s->ss, s->d->ss, NULL, 0);
}

void
bench_kem(const struct bench_opts *opts)
{
    size_t i;

    for (i = 0; i < sizeof kems / sizeof kems[0]; i++) {
        struct kem_state s;
        struct bench_case c;
        char name[BENCH_NAME_MAX];

        memset(&s, 0, sizeof s);
        s.d = &kems[i];

        memset(&c, 0, sizeof c);
        c.group = "kem";
        c.name = name;
        c.setup = kem_setup;
        c.teardown = kem_teardown;
        c.state = &s;

        snprintf(name, sizeof name, "%s keypair", kems[i].name);
        c.op = kem_keypair_op;
        bench_run_case(opts, &c);

        snprintf(name, sizeof name, "%s encap", kems[i].name);
        c.op = kem_encap_op;
        bench_run_case(opts, &c);

        snprintf(name, sizeof name, "%s decap", kems[i].name);
        c.op = kem_decap_op;
        bench_run_case(opts, &c);
    }
}
