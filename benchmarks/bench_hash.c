/*
 * Message digest benchmarks.
 *
 * Two cases per algorithm: a one-shot hash of the bulk buffer, which
 * measures compression-function throughput, and an open/write/read/close
 * cycle on a 64-byte message, which measures per-handle overhead.
 */
#include <stdio.h>
#include <string.h>

#include "bench.h"

struct md_state {
    int algo;
    size_t len;
    int xof;
    unsigned char digest[64];
};

/* Names are fixed here rather than taken from gcry_md_algo_name() so
 * that a library lacking an algorithm still prints a joinable row. */
struct md_desc {
    int algo;
    const char *name;
};

static const struct md_desc md_algos[] = {
    { GCRY_MD_MD5, "MD5" },
    { GCRY_MD_SHA1, "SHA1" },
    { GCRY_MD_RMD160, "RIPEMD160" },
    { GCRY_MD_MD2, "MD2" },
    { GCRY_MD_TIGER, "TIGER192" },
    { GCRY_MD_HAVAL, "HAVAL" },
    { GCRY_MD_SHA256, "SHA256" },
    { GCRY_MD_SHA384, "SHA384" },
    { GCRY_MD_SHA512, "SHA512" },
    { GCRY_MD_SHA224, "SHA224" },
    { GCRY_MD_MD4, "MD4" },
    { GCRY_MD_CRC32, "CRC32" },
    { GCRY_MD_CRC32_RFC1510, "CRC32RFC1510" },
    { GCRY_MD_CRC24_RFC2440, "CRC24RFC2440" },
    { GCRY_MD_WHIRLPOOL, "WHIRLPOOL" },
    { GCRY_MD_TIGER1, "TIGER" },
    { GCRY_MD_TIGER2, "TIGER2" },
    { GCRY_MD_GOSTR3411_94, "GOSTR3411_94" },
    { GCRY_MD_STRIBOG256, "STRIBOG256" },
    { GCRY_MD_STRIBOG512, "STRIBOG512" },
    { GCRY_MD_GOSTR3411_CP, "GOSTR3411_CP" },
    { GCRY_MD_SHA3_224, "SHA3-224" },
    { GCRY_MD_SHA3_256, "SHA3-256" },
    { GCRY_MD_SHA3_384, "SHA3-384" },
    { GCRY_MD_SHA3_512, "SHA3-512" },
    { GCRY_MD_SHAKE128, "SHAKE128" },
    { GCRY_MD_SHAKE256, "SHAKE256" },
    { GCRY_MD_BLAKE2B_512, "BLAKE2B_512" },
    { GCRY_MD_BLAKE2B_384, "BLAKE2B_384" },
    { GCRY_MD_BLAKE2B_256, "BLAKE2B_256" },
    { GCRY_MD_BLAKE2B_160, "BLAKE2B_160" },
    { GCRY_MD_BLAKE2S_256, "BLAKE2S_256" },
    { GCRY_MD_BLAKE2S_224, "BLAKE2S_224" },
    { GCRY_MD_BLAKE2S_160, "BLAKE2S_160" },
    { GCRY_MD_BLAKE2S_128, "BLAKE2S_128" },
    { GCRY_MD_SM3, "SM3" },
    { GCRY_MD_SHA512_256, "SHA512_256" },
    { GCRY_MD_SHA512_224, "SHA512_224" },
    { GCRY_MD_CSHAKE128, "CSHAKE128" },
    { GCRY_MD_CSHAKE256, "CSHAKE256" }
};

static int
is_xof(int algo)
{
    return algo == GCRY_MD_SHAKE128 || algo == GCRY_MD_SHAKE256
           || algo == GCRY_MD_CSHAKE128 || algo == GCRY_MD_CSHAKE256;
}

static gcry_error_t
md_setup(void *state)
{
    struct md_state *s = state;

    return gcry_md_test_algo(s->algo);
}

/* Full handle life cycle; XOFs need gcry_md_extract instead of read. */
static gcry_error_t
md_handle_op(struct md_state *s, const void *data, size_t len)
{
    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, s->algo, 0);

    if (err) {
        return err;
    }

    gcry_md_write(hd, data, len);

    if (s->xof) {
        err = gcry_md_extract(hd, s->algo, s->digest, 32);
    } else {
        unsigned char *d = gcry_md_read(hd, s->algo);

        if (!d) {
            err = gpg_error(GPG_ERR_INTERNAL);
        } else {
            memcpy(s->digest, d, gcry_md_get_algo_dlen(s->algo));
        }
    }

    gcry_md_close(hd);
    return err;
}

static gcry_error_t
md_bulk_op(void *state)
{
    struct md_state *s = state;

    if (s->xof) {
        return md_handle_op(s, bench_input(), s->len);
    }

    gcry_md_hash_buffer(s->algo, s->digest, bench_input(), s->len);
    return 0;
}

static gcry_error_t
md_small_op(void *state)
{
    return md_handle_op(state, bench_input(), 64);
}

void
bench_hash(const struct bench_opts *opts)
{
    size_t i;

    for (i = 0; i < sizeof md_algos / sizeof md_algos[0]; i++) {
        struct md_state s;
        struct bench_case c;
        char name[BENCH_NAME_MAX];
        const char *algo_name = md_algos[i].name;

        memset(&s, 0, sizeof s);
        s.algo = md_algos[i].algo;
        s.len = opts->size;
        s.xof = is_xof(s.algo);

        memset(&c, 0, sizeof c);
        c.group = "hash";
        c.name = name;
        c.setup = md_setup;
        c.teardown = NULL;
        c.state = &s;

        snprintf(name, sizeof name, "%s %zuB", algo_name, opts->size);
        c.bytes = opts->size;
        c.op = md_bulk_op;
        bench_run_case(opts, &c);

        snprintf(name, sizeof name, "%s open+64B+close", algo_name);
        c.bytes = 64;
        c.op = md_small_op;
        bench_run_case(opts, &c);
    }
}
