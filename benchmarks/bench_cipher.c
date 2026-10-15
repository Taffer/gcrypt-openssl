/*
 * Symmetric cipher benchmarks.
 *
 * For every (algorithm, mode) pair there is an encrypt case and a decrypt
 * case over the bulk buffer.  Each op does what a caller processing one
 * message does: reset the handle, set the IV or counter, run the bulk
 * call, and for authenticated modes produce or check the tag.  There is
 * also one "open+setkey+close" case per algorithm for key schedule cost.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench.h"

struct cipher_state {
    int algo;
    int mode;
    int enc;
    size_t len;              /* Plaintext length. */
    size_t inlen;            /* Input length for this direction. */
    size_t outlen;
    size_t keylen;
    size_t ivlen;
    size_t taglen;
    gcry_cipher_hd_t hd;
    unsigned char *in;
    unsigned char *out;
    unsigned char key[64];
    unsigned char iv[16];
    unsigned char tag[16];
};

struct mode_desc {
    int mode;
    const char *name;
};

static const struct mode_desc all_modes[] = {
    { GCRY_CIPHER_MODE_ECB, "ECB" },
    { GCRY_CIPHER_MODE_CBC, "CBC" },
    { GCRY_CIPHER_MODE_CFB, "CFB" },
    { GCRY_CIPHER_MODE_CFB8, "CFB8" },
    { GCRY_CIPHER_MODE_OFB, "OFB" },
    { GCRY_CIPHER_MODE_CTR, "CTR" },
    { GCRY_CIPHER_MODE_XTS, "XTS" },
    { GCRY_CIPHER_MODE_AESWRAP, "AESWRAP" },
    { GCRY_CIPHER_MODE_GCM, "GCM" },
    { GCRY_CIPHER_MODE_CCM, "CCM" },
    { GCRY_CIPHER_MODE_OCB, "OCB" },
    { GCRY_CIPHER_MODE_EAX, "EAX" },
    { GCRY_CIPHER_MODE_SIV, "SIV" },
    { GCRY_CIPHER_MODE_GCM_SIV, "GCM-SIV" }
};

static const struct mode_desc wide_modes[] = {
    { GCRY_CIPHER_MODE_CBC, "CBC" },
    { GCRY_CIPHER_MODE_CTR, "CTR" },
    { GCRY_CIPHER_MODE_GCM, "GCM" },
    { GCRY_CIPHER_MODE_OCB, "OCB" }
};

static const struct mode_desc narrow_modes[] = {
    { GCRY_CIPHER_MODE_CBC, "CBC" },
    { GCRY_CIPHER_MODE_CTR, "CTR" }
};

static const struct mode_desc stream_modes[] = {
    { GCRY_CIPHER_MODE_STREAM, "STREAM" }
};

static const struct mode_desc chacha_modes[] = {
    { GCRY_CIPHER_MODE_STREAM, "STREAM" },
    { GCRY_CIPHER_MODE_POLY1305, "POLY1305" }
};

/* Names are fixed here rather than taken from gcry_cipher_algo_name() so
 * that a library lacking an algorithm still prints a joinable row. */
struct algo_desc {
    int algo;
    const char *name;
    const struct mode_desc *modes;
    size_t nmodes;
};

#define MODES(m) m, sizeof m / sizeof m[0]

static const struct algo_desc algos[] = {
    { GCRY_CIPHER_AES, "AES", MODES(all_modes) },
    { GCRY_CIPHER_AES192, "AES192", MODES(all_modes) },
    { GCRY_CIPHER_AES256, "AES256", MODES(all_modes) },
    { GCRY_CIPHER_CAMELLIA128, "CAMELLIA128", MODES(wide_modes) },
    { GCRY_CIPHER_CAMELLIA256, "CAMELLIA256", MODES(wide_modes) },
    { GCRY_CIPHER_ARIA128, "ARIA128", MODES(wide_modes) },
    { GCRY_CIPHER_ARIA256, "ARIA256", MODES(wide_modes) },
    { GCRY_CIPHER_SM4, "SM4", MODES(wide_modes) },
    { GCRY_CIPHER_SEED, "SEED", MODES(wide_modes) },
    { GCRY_CIPHER_TWOFISH, "TWOFISH", MODES(wide_modes) },
    { GCRY_CIPHER_SERPENT128, "SERPENT128", MODES(wide_modes) },
    { GCRY_CIPHER_3DES, "3DES", MODES(narrow_modes) },
    { GCRY_CIPHER_BLOWFISH, "BLOWFISH", MODES(narrow_modes) },
    { GCRY_CIPHER_CAST5, "CAST5", MODES(narrow_modes) },
    { GCRY_CIPHER_IDEA, "IDEA", MODES(narrow_modes) },
    { GCRY_CIPHER_RFC2268_128, "RFC2268_128", MODES(narrow_modes) },
    { GCRY_CIPHER_DES, "DES", MODES(narrow_modes) },
    { GCRY_CIPHER_GOST28147, "GOST28147", MODES(narrow_modes) },
    { GCRY_CIPHER_ARCFOUR, "ARCFOUR", MODES(stream_modes) },
    { GCRY_CIPHER_CHACHA20, "CHACHA20", MODES(chacha_modes) },
    { GCRY_CIPHER_SALSA20, "SALSA20", MODES(stream_modes) }
};

static int
is_aead(int mode)
{
    switch (mode) {
    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_CCM:
    case GCRY_CIPHER_MODE_OCB:
    case GCRY_CIPHER_MODE_EAX:
    case GCRY_CIPHER_MODE_SIV:
    case GCRY_CIPHER_MODE_GCM_SIV:
    case GCRY_CIPHER_MODE_POLY1305:
        return 1;

    default:
        return 0;
    }
}

static size_t
iv_length(int algo, int mode, size_t blklen)
{
    switch (mode) {
    case GCRY_CIPHER_MODE_ECB:
    case GCRY_CIPHER_MODE_AESWRAP:
    case GCRY_CIPHER_MODE_SIV:
        return 0;

    case GCRY_CIPHER_MODE_STREAM:
        if (algo == GCRY_CIPHER_CHACHA20) {
            return 12;
        }

        if (algo == GCRY_CIPHER_SALSA20 || algo == GCRY_CIPHER_SALSA20R12) {
            return 8;
        }

        return 0;

    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_CCM:
    case GCRY_CIPHER_MODE_GCM_SIV:
    case GCRY_CIPHER_MODE_POLY1305:
        return 12;

    case GCRY_CIPHER_MODE_OCB:
        return 15;

    case GCRY_CIPHER_MODE_XTS:
    case GCRY_CIPHER_MODE_EAX:
        return 16;

    default:
        return blklen;
    }
}

/* Prepare the handle for one message in the given direction. */
static gcry_error_t
cipher_prepare(struct cipher_state *s, int enc)
{
    gcry_error_t err = gcry_cipher_reset(s->hd);

    if (err) {
        return err;
    }

    if (s->ivlen) {
        if (s->mode == GCRY_CIPHER_MODE_CTR) {
            err = gcry_cipher_setctr(s->hd, s->iv, s->ivlen);
        } else {
            err = gcry_cipher_setiv(s->hd, s->iv, s->ivlen);
        }

        if (err) {
            return err;
        }
    }

    /* OCB must be told that the next call carries the end of the message
     * before its tag can be read. */
    if (!err && s->mode == GCRY_CIPHER_MODE_OCB) {
        err = gcry_cipher_final(s->hd);
    }

    if (!err && s->mode == GCRY_CIPHER_MODE_CCM) {
        /* gcrypt takes the lengths as its own 64-bit integer type. */
        unsigned long long lengths[3];

        lengths[0] = s->len;
        lengths[1] = 0;
        lengths[2] = s->taglen;
        err = gcry_cipher_ctl(s->hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths);
    }

    if (!err && !enc
        && (s->mode == GCRY_CIPHER_MODE_SIV
            || s->mode == GCRY_CIPHER_MODE_GCM_SIV)) {
        err = gcry_cipher_set_decryption_tag(s->hd, s->tag, s->taglen);
    }

    return err;
}

static gcry_error_t
cipher_encrypt_once(struct cipher_state *s, unsigned char *out, size_t outlen,
                    const unsigned char *in, size_t inlen)
{
    gcry_error_t err = cipher_prepare(s, 1);

    if (!err) {
        err = gcry_cipher_encrypt(s->hd, out, outlen, in, inlen);
    }

    if (!err && is_aead(s->mode)) {
        err = gcry_cipher_gettag(s->hd, s->tag, s->taglen);
    }

    return err;
}

static gcry_error_t
cipher_decrypt_once(struct cipher_state *s, unsigned char *out, size_t outlen,
                    const unsigned char *in, size_t inlen)
{
    gcry_error_t err = cipher_prepare(s, 0);

    if (!err) {
        err = gcry_cipher_decrypt(s->hd, out, outlen, in, inlen);
    }

    if (!err && is_aead(s->mode) && s->mode != GCRY_CIPHER_MODE_SIV
        && s->mode != GCRY_CIPHER_MODE_GCM_SIV) {
        err = gcry_cipher_checktag(s->hd, s->tag, s->taglen);
    }

    return err;
}

static gcry_error_t
cipher_setup(void *state)
{
    struct cipher_state *s = state;
    gcry_error_t err;
    size_t blklen;

    err = gcry_cipher_test_algo(s->algo);

    if (err) {
        return err;
    }

    err = gcry_cipher_open(&s->hd, s->algo, s->mode, 0);

    if (err) {
        return err;
    }

    s->keylen = gcry_cipher_get_algo_keylen(s->algo);
    blklen = gcry_cipher_get_algo_blklen(s->algo);

    if (s->mode == GCRY_CIPHER_MODE_XTS || s->mode == GCRY_CIPHER_MODE_SIV) {
        s->keylen *= 2;
    }

    if (!s->keylen || s->keylen > sizeof s->key) {
        gcry_cipher_close(s->hd);
        s->hd = NULL;
        return gpg_error(GPG_ERR_INV_KEYLEN);
    }

    memcpy(s->key, bench_input(), s->keylen);
    memcpy(s->iv, bench_input() + 64 - sizeof s->iv, sizeof s->iv);
    s->ivlen = iv_length(s->algo, s->mode, blklen);
    s->taglen = 16;

    err = gcry_cipher_setkey(s->hd, s->key, s->keylen);

    if (err) {
        gcry_cipher_close(s->hd);
        s->hd = NULL;
        return err;
    }

    /* AESWRAP output carries an 8-byte integrity check. */
    s->inlen = s->len;
    s->outlen = s->len;

    if (s->mode == GCRY_CIPHER_MODE_AESWRAP) {
        s->outlen = s->len + 8;
    }

    s->in = malloc(s->outlen);
    s->out = malloc(s->outlen);

    if (!s->in || !s->out) {
        err = gpg_error(GPG_ERR_ENOMEM);
    } else {
        memcpy(s->in, bench_input(), s->len);

        if (!s->enc) {
            /* Produce a genuine ciphertext (and tag) to decrypt. */
            err = cipher_encrypt_once(s, s->out, s->outlen, s->in, s->len);

            if (!err) {
                unsigned char *t = s->in;
                size_t tl = s->inlen;

                s->in = s->out;
                s->inlen = s->outlen;
                s->out = t;
                s->outlen = tl;
            }
        }
    }

    if (err) {
        free(s->in);
        free(s->out);
        s->in = s->out = NULL;
        gcry_cipher_close(s->hd);
        s->hd = NULL;
    }

    return err;
}

static gcry_error_t
cipher_encrypt_op(void *state)
{
    struct cipher_state *s = state;

    return cipher_encrypt_once(s, s->out, s->outlen, s->in, s->inlen);
}

static gcry_error_t
cipher_decrypt_op(void *state)
{
    struct cipher_state *s = state;

    return cipher_decrypt_once(s, s->out, s->outlen, s->in, s->inlen);
}

static void
cipher_teardown(void *state)
{
    struct cipher_state *s = state;

    gcry_cipher_close(s->hd);
    free(s->in);
    free(s->out);
    s->hd = NULL;
    s->in = s->out = NULL;
}

/* Key schedule cost: open, setkey, close. */
static gcry_error_t
setkey_setup(void *state)
{
    struct cipher_state *s = state;
    gcry_error_t err = gcry_cipher_test_algo(s->algo);

    if (err) {
        return err;
    }

    s->keylen = gcry_cipher_get_algo_keylen(s->algo);

    if (!s->keylen || s->keylen > sizeof s->key) {
        return gpg_error(GPG_ERR_INV_KEYLEN);
    }

    memcpy(s->key, bench_input(), s->keylen);
    return 0;
}

static gcry_error_t
setkey_op(void *state)
{
    struct cipher_state *s = state;
    gcry_cipher_hd_t hd;
    gcry_error_t err;

    err = gcry_cipher_open(&hd, s->algo, s->mode, 0);

    if (err) {
        return err;
    }

    err = gcry_cipher_setkey(hd, s->key, s->keylen);
    gcry_cipher_close(hd);
    return err;
}

void
bench_cipher(const struct bench_opts *opts)
{
    size_t i;
    size_t j;
    /* Block modes need whole blocks; AESWRAP needs a multiple of 8. */
    size_t len = opts->size & ~(size_t)15;

    for (i = 0; i < sizeof algos / sizeof algos[0]; i++) {
        const char *algo_name = algos[i].name;
        struct cipher_state s;
        struct bench_case c;
        char name[BENCH_NAME_MAX];

        memset(&s, 0, sizeof s);
        s.algo = algos[i].algo;
        s.mode = algos[i].modes[0].mode;
        s.len = len;

        memset(&c, 0, sizeof c);
        c.group = "cipher";
        c.name = name;
        c.state = &s;

        snprintf(name, sizeof name, "%s open+setkey+close", algo_name);
        c.bytes = 0;
        c.setup = setkey_setup;
        c.op = setkey_op;
        c.teardown = NULL;
        bench_run_case(opts, &c);

        for (j = 0; j < algos[i].nmodes; j++) {
            s.mode = algos[i].modes[j].mode;

            c.bytes = len;
            c.setup = cipher_setup;
            c.teardown = cipher_teardown;

            s.enc = 1;
            c.op = cipher_encrypt_op;
            snprintf(name, sizeof name, "%s %s encrypt %zuB", algo_name,
                     algos[i].modes[j].name, len);
            bench_run_case(opts, &c);

            s.enc = 0;
            c.op = cipher_decrypt_op;
            snprintf(name, sizeof name, "%s %s decrypt %zuB", algo_name,
                     algos[i].modes[j].name, len);
            bench_run_case(opts, &c);
        }
    }
}
