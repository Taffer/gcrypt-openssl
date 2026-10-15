/*
 * MAC benchmarks: one case per algorithm, authenticating the bulk buffer
 * with a handle that is opened and keyed once.  Modes that need a nonce
 * (GMAC, Poly1305 with a cipher) get a fresh setiv on every op, as a real
 * caller would.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

struct mac_state {
    int algo;
    int first;               /* No reset before the first message. */
    size_t len;
    size_t ivlen;
    gcry_mac_hd_t hd;
    unsigned char key[128];
    unsigned char iv[16];
    unsigned char tag[64];
};

/* Names are fixed here rather than taken from gcry_mac_algo_name() so
 * that a library lacking an algorithm still prints a joinable row. */
struct mac_desc {
    int algo;
    const char *name;
};

static const struct mac_desc mac_algos[] = {
    { GCRY_MAC_HMAC_SHA256, "HMAC_SHA256" },
    { GCRY_MAC_HMAC_SHA224, "HMAC_SHA224" },
    { GCRY_MAC_HMAC_SHA512, "HMAC_SHA512" },
    { GCRY_MAC_HMAC_SHA384, "HMAC_SHA384" },
    { GCRY_MAC_HMAC_SHA1, "HMAC_SHA1" },
    { GCRY_MAC_HMAC_MD5, "HMAC_MD5" },
    { GCRY_MAC_HMAC_MD4, "HMAC_MD4" },
    { GCRY_MAC_HMAC_RMD160, "HMAC_RIPEMD160" },
    { GCRY_MAC_HMAC_TIGER1, "HMAC_TIGER" },
    { GCRY_MAC_HMAC_WHIRLPOOL, "HMAC_WHIRLPOOL" },
    { GCRY_MAC_HMAC_GOSTR3411_94, "HMAC_GOSTR3411_94" },
    { GCRY_MAC_HMAC_STRIBOG256, "HMAC_STRIBOG256" },
    { GCRY_MAC_HMAC_STRIBOG512, "HMAC_STRIBOG512" },
    { GCRY_MAC_HMAC_MD2, "HMAC_MD2" },
    { GCRY_MAC_HMAC_SHA3_224, "HMAC_SHA3_224" },
    { GCRY_MAC_HMAC_SHA3_256, "HMAC_SHA3_256" },
    { GCRY_MAC_HMAC_SHA3_384, "HMAC_SHA3_384" },
    { GCRY_MAC_HMAC_SHA3_512, "HMAC_SHA3_512" },
    { GCRY_MAC_HMAC_GOSTR3411_CP, "HMAC_GOSTR3411_CP" },
    { GCRY_MAC_HMAC_BLAKE2B_512, "HMAC_BLAKE2B_512" },
    { GCRY_MAC_HMAC_BLAKE2B_384, "HMAC_BLAKE2B_384" },
    { GCRY_MAC_HMAC_BLAKE2B_256, "HMAC_BLAKE2B_256" },
    { GCRY_MAC_HMAC_BLAKE2B_160, "HMAC_BLAKE2B_160" },
    { GCRY_MAC_HMAC_BLAKE2S_256, "HMAC_BLAKE2S_256" },
    { GCRY_MAC_HMAC_BLAKE2S_224, "HMAC_BLAKE2S_224" },
    { GCRY_MAC_HMAC_BLAKE2S_160, "HMAC_BLAKE2S_160" },
    { GCRY_MAC_HMAC_BLAKE2S_128, "HMAC_BLAKE2S_128" },
    { GCRY_MAC_HMAC_SM3, "HMAC_SM3" },
    { GCRY_MAC_HMAC_SHA512_256, "HMAC_SHA512_256" },
    { GCRY_MAC_HMAC_SHA512_224, "HMAC_SHA512_224" },
    { GCRY_MAC_CMAC_AES, "CMAC_AES" },
    { GCRY_MAC_CMAC_3DES, "CMAC_3DES" },
    { GCRY_MAC_CMAC_CAMELLIA, "CMAC_CAMELLIA" },
    { GCRY_MAC_CMAC_CAST5, "CMAC_CAST5" },
    { GCRY_MAC_CMAC_BLOWFISH, "CMAC_BLOWFISH" },
    { GCRY_MAC_CMAC_TWOFISH, "CMAC_TWOFISH" },
    { GCRY_MAC_CMAC_SERPENT, "CMAC_SERPENT" },
    { GCRY_MAC_CMAC_SEED, "CMAC_SEED" },
    { GCRY_MAC_CMAC_RFC2268, "CMAC_RFC2268" },
    { GCRY_MAC_CMAC_IDEA, "CMAC_IDEA" },
    { GCRY_MAC_CMAC_GOST28147, "CMAC_GOST28147" },
    { GCRY_MAC_CMAC_SM4, "CMAC_SM4" },
    { GCRY_MAC_CMAC_ARIA, "CMAC_ARIA" },
    { GCRY_MAC_GMAC_AES, "GMAC_AES" },
    { GCRY_MAC_GMAC_CAMELLIA, "GMAC_CAMELLIA" },
    { GCRY_MAC_GMAC_TWOFISH, "GMAC_TWOFISH" },
    { GCRY_MAC_GMAC_SERPENT, "GMAC_SERPENT" },
    { GCRY_MAC_GMAC_SEED, "GMAC_SEED" },
    { GCRY_MAC_GMAC_SM4, "GMAC_SM4" },
    { GCRY_MAC_GMAC_ARIA, "GMAC_ARIA" },
    { GCRY_MAC_POLY1305, "POLY1305" },
    { GCRY_MAC_POLY1305_AES, "POLY1305_AES" },
    { GCRY_MAC_POLY1305_CAMELLIA, "POLY1305_CAMELLIA" },
    { GCRY_MAC_POLY1305_TWOFISH, "POLY1305_TWOFISH" },
    { GCRY_MAC_POLY1305_SERPENT, "POLY1305_SERPENT" },
    { GCRY_MAC_POLY1305_SEED, "POLY1305_SEED" },
    { GCRY_MAC_POLY1305_SM4, "POLY1305_SM4" },
    { GCRY_MAC_POLY1305_ARIA, "POLY1305_ARIA" },
    { GCRY_MAC_GOST28147_IMIT, "GOST28147_IMIT" }
};

static gcry_error_t mac_op(void *state);

static size_t
mac_ivlen(int algo)
{
    if (algo >= GCRY_MAC_GMAC_AES && algo <= GCRY_MAC_GMAC_ARIA) {
        return 12;
    }

    if (algo > GCRY_MAC_POLY1305 && algo <= GCRY_MAC_POLY1305_ARIA) {
        return 16;
    }

    return 0;
}

static gcry_error_t
mac_setup(void *state)
{
    struct mac_state *s = state;
    gcry_error_t err;
    unsigned int keylen;

    err = gcry_mac_test_algo(s->algo);

    if (err) {
        return err;
    }

    keylen = gcry_mac_get_algo_keylen(s->algo);

    if (!keylen || keylen > sizeof s->key) {
        keylen = 32;
    }

    memcpy(s->key, bench_input(), keylen);
    memcpy(s->iv, bench_input() + 32, sizeof s->iv);
    s->ivlen = mac_ivlen(s->algo);

    err = gcry_mac_open(&s->hd, s->algo, 0, NULL);

    if (err) {
        return err;
    }

    err = gcry_mac_setkey(s->hd, s->key, keylen);

    if (!err) {
        /* Complete one message so the handle is in the steady state a
         * long-lived MAC handle is in: keyed, with a nonce if needed. */
        s->first = 1;
        err = mac_op(s);
    }

    if (err) {
        gcry_mac_close(s->hd);
        s->hd = NULL;
    }

    return err;
}

static gcry_error_t
mac_op(void *state)
{
    struct mac_state *s = state;
    gcry_error_t err = 0;
    size_t taglen = sizeof s->tag;

    if (s->first) {
        s->first = 0;
    } else {
        err = gcry_mac_reset(s->hd);
    }

    if (!err && s->ivlen) {
        err = gcry_mac_setiv(s->hd, s->iv, s->ivlen);
    }

    if (!err) {
        err = gcry_mac_write(s->hd, bench_input(), s->len);
    }

    if (!err) {
        err = gcry_mac_read(s->hd, s->tag, &taglen);
    }

    return err;
}

static void
mac_teardown(void *state)
{
    struct mac_state *s = state;

    gcry_mac_close(s->hd);
    s->hd = NULL;
}

void
bench_mac(const struct bench_opts *opts)
{
    size_t i;

    for (i = 0; i < sizeof mac_algos / sizeof mac_algos[0]; i++) {
        struct mac_state s;
        struct bench_case c;
        char name[BENCH_NAME_MAX];
        const char *algo_name = mac_algos[i].name;

        memset(&s, 0, sizeof s);
        s.algo = mac_algos[i].algo;
        s.len = opts->size;

        snprintf(name, sizeof name, "%s %zuB", algo_name, opts->size);

        memset(&c, 0, sizeof c);
        c.group = "mac";
        c.name = name;
        c.bytes = opts->size;
        c.setup = mac_setup;
        c.op = mac_op;
        c.teardown = mac_teardown;
        c.state = &s;
        bench_run_case(opts, &c);
    }
}
