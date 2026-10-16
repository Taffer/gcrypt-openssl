/*
 * cipher.c - Symmetric cipher interface (gcry_cipher_*).
 *
 * Every cipher primitive and every mode comes from OpenSSL: the handle
 * wraps an EVP_CIPHER_CTX for the requested algorithm/mode combination.
 * This file only performs the bookkeeping Libgcrypt's API needs on top:
 * algorithm tables, key/IV validation, deferred initialisation (the
 * direction of an AEAD operation is only known at the first data call),
 * OpenPGP's CFB resynchronisation, CBC-MAC, and the Libgcrypt call order
 * for CCM (data first, tag afterwards) which is realised with OpenSSL's
 * CTR mode for the data and a CBC-MAC over the RFC 3610 formatted input
 * for the tag.  AES OCB uses OpenSSL's native OCB cipher; OCB on other
 * block ciphers uses OpenSSL's OCB128 mode driver on top of EVP ECB.
 *
 * Fetched EVP_CIPHER objects are cached per algorithm and mode, and a
 * keyed EVP context is re-initialised with just the IV between messages
 * so the key schedule is computed once per key.
 */
#include "gcrypt-int.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/modes.h>
#include <openssl/params.h>

#define MAX_BLOCKSIZE 16
#define MAX_KEYLEN 64 /* Two AES-256 keys for XTS and SIV. */
#define CTX_MAGIC_NORMAL 0x24091964u
#define CTX_MAGIC_SECURE 0x46919042u
#define POLY1305_TAGLEN 16
#define CCM_MAX_TAGLEN 16

/* ------------------------------------------------------------------ */
/* Algorithm table                                                     */
/* ------------------------------------------------------------------ */

struct oid_entry {
    const char *oid;
    int mode;
};

enum algo_flags {
    ALGO_STREAM = 1,   /* Stream cipher: only STREAM (and POLY1305) modes. */
    ALGO_FIPS = 2,     /* Approved in FIPS mode. */
    ALGO_RC2 = 4       /* Needs the RC2 effective key bits parameter. */
};

struct algo_spec {
    int algo;
    const char *name;
    const char *const *aliases;   /* NULL terminated, or NULL. */
    const struct oid_entry *oids; /* Terminated by a NULL oid, or NULL. */
    unsigned int blocksize;       /* Bytes; 1 for stream ciphers. */
    unsigned int keylen;          /* Default key length in bits. */
    unsigned int min_keylen;      /* Bytes; equal to max for fixed keys. */
    unsigned int max_keylen;
    const char *ossl;             /* OpenSSL base name, NULL if unavailable. */
    unsigned int flags;
};

static const char *const aes_aliases[] = { "RIJNDAEL", "AES128", "AES-128",
                                           NULL
                                         };
static const char *const aes192_aliases[] = { "RIJNDAEL192", "AES-192", NULL };
static const char *const aes256_aliases[] = { "RIJNDAEL256", "AES-256", NULL };

static const struct oid_entry aes_oids[] = {
    { "2.16.840.1.101.3.4.1.1", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.2", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.3", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.4", GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.6", GCRY_CIPHER_MODE_GCM },
    { "2.16.840.1.101.3.4.1.7", GCRY_CIPHER_MODE_CCM },
    { NULL, 0 }
};

static const struct oid_entry aes192_oids[] = {
    { "2.16.840.1.101.3.4.1.21", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.22", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.23", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.24", GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.26", GCRY_CIPHER_MODE_GCM },
    { "2.16.840.1.101.3.4.1.27", GCRY_CIPHER_MODE_CCM },
    { NULL, 0 }
};

static const struct oid_entry aes256_oids[] = {
    { "2.16.840.1.101.3.4.1.41", GCRY_CIPHER_MODE_ECB },
    { "2.16.840.1.101.3.4.1.42", GCRY_CIPHER_MODE_CBC },
    { "2.16.840.1.101.3.4.1.43", GCRY_CIPHER_MODE_OFB },
    { "2.16.840.1.101.3.4.1.44", GCRY_CIPHER_MODE_CFB },
    { "2.16.840.1.101.3.4.1.46", GCRY_CIPHER_MODE_GCM },
    { "2.16.840.1.101.3.4.1.47", GCRY_CIPHER_MODE_CCM },
    { NULL, 0 }
};

static const struct oid_entry tripledes_oids[] = {
    { "1.2.840.113549.3.7", GCRY_CIPHER_MODE_CBC },
    { "1.3.36.3.1.3.2.1", GCRY_CIPHER_MODE_CBC },
    { "1.2.840.113549.1.12.1.3", GCRY_CIPHER_MODE_CBC },
    { NULL, 0 }
};

static const struct oid_entry rfc2268_40_oids[] = {
    { "1.2.840.113549.1.12.1.6", GCRY_CIPHER_MODE_CBC },
    { NULL, 0 }
};

static const struct oid_entry rfc2268_128_oids[] = {
    { "1.2.840.113549.1.12.1.5", GCRY_CIPHER_MODE_CBC },
    { NULL, 0 }
};

static const struct oid_entry seed_oids[] = {
    { "1.2.410.200004.1.3", GCRY_CIPHER_MODE_ECB },
    { "1.2.410.200004.1.4", GCRY_CIPHER_MODE_CBC },
    { "1.2.410.200004.1.5", GCRY_CIPHER_MODE_CFB },
    { "1.2.410.200004.1.6", GCRY_CIPHER_MODE_OFB },
    { NULL, 0 }
};

static const struct oid_entry camellia128_oids[] = {
    { "1.2.392.200011.61.1.1.1.2", GCRY_CIPHER_MODE_CBC },
    { "0.3.4401.5.3.1.9.1", GCRY_CIPHER_MODE_ECB },
    { "0.3.4401.5.3.1.9.3", GCRY_CIPHER_MODE_OFB },
    { "0.3.4401.5.3.1.9.4", GCRY_CIPHER_MODE_CFB },
    { NULL, 0 }
};

static const struct oid_entry camellia192_oids[] = {
    { "1.2.392.200011.61.1.1.1.3", GCRY_CIPHER_MODE_CBC },
    { "0.3.4401.5.3.1.9.21", GCRY_CIPHER_MODE_ECB },
    { "0.3.4401.5.3.1.9.23", GCRY_CIPHER_MODE_OFB },
    { "0.3.4401.5.3.1.9.24", GCRY_CIPHER_MODE_CFB },
    { NULL, 0 }
};

static const struct oid_entry camellia256_oids[] = {
    { "1.2.392.200011.61.1.1.1.4", GCRY_CIPHER_MODE_CBC },
    { "0.3.4401.5.3.1.9.41", GCRY_CIPHER_MODE_ECB },
    { "0.3.4401.5.3.1.9.43", GCRY_CIPHER_MODE_OFB },
    { "0.3.4401.5.3.1.9.44", GCRY_CIPHER_MODE_CFB },
    { NULL, 0 }
};

static const struct oid_entry sm4_oids[] = {
    { "1.2.156.10197.1.104.1", GCRY_CIPHER_MODE_ECB },
    { "1.2.156.10197.1.104.2", GCRY_CIPHER_MODE_CBC },
    { "1.2.156.10197.1.104.3", GCRY_CIPHER_MODE_OFB },
    { "1.2.156.10197.1.104.4", GCRY_CIPHER_MODE_CFB },
    { "1.2.156.10197.1.104.7", GCRY_CIPHER_MODE_CTR },
    { NULL, 0 }
};

static const struct oid_entry aria128_oids[] = {
    { "1.2.410.200046.1.1.1", GCRY_CIPHER_MODE_ECB },
    { "1.2.410.200046.1.1.2", GCRY_CIPHER_MODE_CBC },
    { "1.2.410.200046.1.1.3", GCRY_CIPHER_MODE_CFB },
    { "1.2.410.200046.1.1.4", GCRY_CIPHER_MODE_OFB },
    { "1.2.410.200046.1.1.5", GCRY_CIPHER_MODE_CTR },
    { "1.2.410.200046.1.1.34", GCRY_CIPHER_MODE_GCM },
    { "1.2.410.200046.1.1.37", GCRY_CIPHER_MODE_CCM },
    { NULL, 0 }
};

static const struct oid_entry aria192_oids[] = {
    { "1.2.410.200046.1.1.6", GCRY_CIPHER_MODE_ECB },
    { "1.2.410.200046.1.1.7", GCRY_CIPHER_MODE_CBC },
    { "1.2.410.200046.1.1.8", GCRY_CIPHER_MODE_CFB },
    { "1.2.410.200046.1.1.9", GCRY_CIPHER_MODE_OFB },
    { "1.2.410.200046.1.1.10", GCRY_CIPHER_MODE_CTR },
    { "1.2.410.200046.1.1.35", GCRY_CIPHER_MODE_GCM },
    { "1.2.410.200046.1.1.38", GCRY_CIPHER_MODE_CCM },
    { NULL, 0 }
};

static const struct oid_entry aria256_oids[] = {
    { "1.2.410.200046.1.1.11", GCRY_CIPHER_MODE_ECB },
    { "1.2.410.200046.1.1.12", GCRY_CIPHER_MODE_CBC },
    { "1.2.410.200046.1.1.13", GCRY_CIPHER_MODE_CFB },
    { "1.2.410.200046.1.1.14", GCRY_CIPHER_MODE_OFB },
    { "1.2.410.200046.1.1.15", GCRY_CIPHER_MODE_CTR },
    { "1.2.410.200046.1.1.36", GCRY_CIPHER_MODE_GCM },
    { "1.2.410.200046.1.1.39", GCRY_CIPHER_MODE_CCM },
    { NULL, 0 }
};

/* Algorithms without an OpenSSL implementation keep their names and sizes
 * so that gcry_cipher_algo_name() and the length queries keep working,
 * but gcry_cipher_open() rejects them. */
static const struct algo_spec algos[] = {
    {
        GCRY_CIPHER_IDEA, "IDEA", NULL, NULL, 8, 128, 16, 16, "IDEA", 0
    },
    {
        GCRY_CIPHER_3DES, "3DES", NULL, tripledes_oids, 8, 192, 24, 24,
        "DES-EDE3", 0
    },
    {
        GCRY_CIPHER_CAST5, "CAST5", NULL, NULL, 8, 128, 16, 16, "CAST5", 0
    },
    {
        GCRY_CIPHER_BLOWFISH, "BLOWFISH", NULL, NULL, 8, 128, 8, 56, "BF", 0
    },
    {
        GCRY_CIPHER_AES, "AES", aes_aliases, aes_oids, 16, 128, 16, 16,
        "AES-128", ALGO_FIPS
    },
    {
        GCRY_CIPHER_AES192, "AES192", aes192_aliases, aes192_oids, 16, 192,
        24, 24, "AES-192", ALGO_FIPS
    },
    {
        GCRY_CIPHER_AES256, "AES256", aes256_aliases, aes256_oids, 16, 256,
        32, 32, "AES-256", ALGO_FIPS
    },
    {
        GCRY_CIPHER_TWOFISH, "TWOFISH", NULL, NULL, 16, 256, 32, 32, NULL, 0
    },
    {
        GCRY_CIPHER_ARCFOUR, "ARCFOUR", NULL, NULL, 1, 128, 5, 256, "RC4",
        ALGO_STREAM
    },
    {
        GCRY_CIPHER_DES, "DES", NULL, NULL, 8, 64, 8, 8, "DES", 0
    },
    {
        GCRY_CIPHER_TWOFISH128, "TWOFISH128", NULL, NULL, 16, 128, 16, 16,
        NULL, 0
    },
    {
        GCRY_CIPHER_SERPENT128, "SERPENT128", NULL, NULL, 16, 128, 16, 16,
        NULL, 0
    },
    {
        GCRY_CIPHER_SERPENT192, "SERPENT192", NULL, NULL, 16, 192, 24, 24,
        NULL, 0
    },
    {
        GCRY_CIPHER_SERPENT256, "SERPENT256", NULL, NULL, 16, 256, 32, 32,
        NULL, 0
    },
    {
        GCRY_CIPHER_RFC2268_40, "RFC2268_40", NULL, rfc2268_40_oids, 8, 40,
        5, 128, "RC2", ALGO_RC2
    },
    {
        GCRY_CIPHER_RFC2268_128, "RFC2268_128", NULL, rfc2268_128_oids, 8,
        128, 5, 128, "RC2", ALGO_RC2
    },
    {
        GCRY_CIPHER_SEED, "SEED", NULL, seed_oids, 16, 128, 16, 16, "SEED", 0
    },
    {
        GCRY_CIPHER_CAMELLIA128, "CAMELLIA128", NULL, camellia128_oids, 16,
        128, 16, 16, "CAMELLIA-128", 0
    },
    {
        GCRY_CIPHER_CAMELLIA192, "CAMELLIA192", NULL, camellia192_oids, 16,
        192, 24, 24, "CAMELLIA-192", 0
    },
    {
        GCRY_CIPHER_CAMELLIA256, "CAMELLIA256", NULL, camellia256_oids, 16,
        256, 32, 32, "CAMELLIA-256", 0
    },
    {
        GCRY_CIPHER_SALSA20, "SALSA20", NULL, NULL, 1, 256, 32, 32, NULL,
        ALGO_STREAM
    },
    {
        GCRY_CIPHER_SALSA20R12, "SALSA20R12", NULL, NULL, 1, 256, 32, 32,
        NULL, ALGO_STREAM
    },
    {
        GCRY_CIPHER_GOST28147, "GOST28147", NULL, NULL, 8, 256, 32, 32, NULL,
        0
    },
    {
        GCRY_CIPHER_CHACHA20, "CHACHA20", NULL, NULL, 1, 256, 32, 32,
        "ChaCha20", ALGO_STREAM
    },
    {
        GCRY_CIPHER_GOST28147_MESH, "GOST28147_MESH", NULL, NULL, 8, 256, 32,
        32, NULL, 0
    },
    {
        GCRY_CIPHER_SM4, "SM4", NULL, sm4_oids, 16, 128, 16, 16, "SM4", 0
    },
    {
        GCRY_CIPHER_ARIA128, "ARIA128", NULL, aria128_oids, 16, 128, 16, 16,
        "ARIA-128", 0
    },
    {
        GCRY_CIPHER_ARIA192, "ARIA192", NULL, aria192_oids, 16, 192, 24, 24,
        "ARIA-192", 0
    },
    {
        GCRY_CIPHER_ARIA256, "ARIA256", NULL, aria256_oids, 16, 256, 32, 32,
        "ARIA-256", 0
    },
};

/* Algorithms disabled with GCRYCTL_DISABLE_ALGO, and the cached result of
 * asking OpenSSL whether an algorithm is available (0 unknown, 1 yes,
 * -1 no).  Both are plain ints written once; the races are benign. */
static int algo_disabled[DIM(algos)];
static int algo_available_cache[DIM(algos)];

static const struct algo_spec *
spec_from_algo(int algo)
{
    size_t i;

    for (i = 0; i < DIM(algos); i++) {
        if (algos[i].algo == algo) {
            return &algos[i];
        }
    }

    return NULL;
}

static size_t
spec_index(const struct algo_spec *spec)
{
    return (size_t)(spec - algos);
}

static int
stricmp_ascii(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        int ca = (*a >= 'a' && *a <= 'z') ? *a - 'a' + 'A' : *a;
        int cb = (*b >= 'a' && *b <= 'z') ? *b - 'a' + 'A' : *b;

        if (ca != cb) {
            return ca - cb;
        }
    }

    return (unsigned char) * a - (unsigned char) * b;
}

static const struct algo_spec *
spec_from_name(const char *name)
{
    size_t i;

    for (i = 0; i < DIM(algos); i++) {
        const char *const *alias;

        if (!stricmp_ascii(name, algos[i].name)) {
            return &algos[i];
        }

        for (alias = algos[i].aliases; alias && *alias; alias++) {
            if (!stricmp_ascii(name, *alias)) {
                return &algos[i];
            }
        }
    }

    return NULL;
}

/* Find the algorithm owning OID (optionally prefixed with "oid.") and
 * return the mode associated with it in R_MODE. */
static const struct algo_spec *
spec_from_oid(const char *oid, int *r_mode)
{
    size_t i;

    if (!oid) {
        return NULL;
    }

    if (!strncmp(oid, "oid.", 4) || !strncmp(oid, "OID.", 4)) {
        oid += 4;
    }

    for (i = 0; i < DIM(algos); i++) {
        const struct oid_entry *e;

        for (e = algos[i].oids; e && e->oid; e++) {
            if (!stricmp_ascii(oid, e->oid)) {
                if (r_mode) {
                    *r_mode = e->mode;
                }

                return &algos[i];
            }
        }
    }

    return NULL;
}

/* The OpenSSL cipher variants a handle may need, one per name suffix. */
enum cipher_slot {
    SLOT_ECB,
    SLOT_CBC,
    SLOT_CBC_CTS,
    SLOT_CFB,
    SLOT_CFB8,
    SLOT_OFB,
    SLOT_CTR,
    SLOT_GCM,
    SLOT_XTS,
    SLOT_SIV,
    SLOT_GCM_SIV,
    SLOT_WRAP,
    SLOT_WRAP_PAD,
    SLOT_STREAM,
    SLOT_POLY1305,
    SLOT_CCM,
    SLOT_OCB,
    SLOT_COUNT
};

static const char *const slot_suffix[SLOT_COUNT] = {
    "-ECB", "-CBC", "-CBC-CTS", "-CFB", "-CFB8", "-OFB", "-CTR", "-GCM",
    "-XTS", "-SIV", "-GCM-SIV", "-WRAP", "-WRAP-PAD", "", "", "-CCM", "-OCB"
};

/* Fetching a cipher means a name lookup through the provider method store,
 * which costs more than opening a handle should.  Every (algorithm, slot)
 * pair is fetched once and kept for the life of the process; the cache
 * owns the references, handles only borrow them. */
static const EVP_CIPHER *cipher_cache[DIM(algos)][SLOT_COUNT];
static signed char cipher_cache_state[DIM(algos)][SLOT_COUNT];
static pthread_mutex_t cipher_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static const EVP_CIPHER *
cached_cipher(const struct algo_spec *spec, enum cipher_slot slot)
{
    size_t idx = spec_index(spec);
    const EVP_CIPHER *c;

    if (!spec->ossl) {
        return NULL;
    }

    pthread_mutex_lock(&cipher_cache_lock);

    if (!cipher_cache_state[idx][slot]) {
        char name[64];
        EVP_CIPHER *f;

        if (slot == SLOT_POLY1305) {
            snprintf(name, sizeof name, "%s", "ChaCha20-Poly1305");
        } else {
            snprintf(name, sizeof name, "%s%s", spec->ossl,
                     slot_suffix[slot]);
        }

        f = EVP_CIPHER_fetch(_gcry_libctx(), name, _gcry_propq());

        if (!f) {
            ERR_clear_error();
        }

        cipher_cache[idx][slot] = f;
        cipher_cache_state[idx][slot] = f ? 1 : -1;
    }

    c = cipher_cache[idx][slot];
    pthread_mutex_unlock(&cipher_cache_lock);
    return c;
}

/* Whether OpenSSL implements the algorithm at all. */
static int
algo_available(const struct algo_spec *spec)
{
    size_t idx = spec_index(spec);
    const EVP_CIPHER *c;

    if (!spec->ossl) {
        return 0;
    }

    if (algo_available_cache[idx]) {
        return algo_available_cache[idx] > 0;
    }

    c = cached_cipher(spec, (spec->flags & ALGO_STREAM) ? SLOT_STREAM
                      : SLOT_ECB);
    algo_available_cache[idx] = c ? 1 : -1;
    return c != NULL;
}

static gcry_err_code_t
check_cipher_algo(const struct algo_spec *spec)
{
    if (!spec || algo_disabled[spec_index(spec)] || !algo_available(spec)) {
        return GPG_ERR_CIPHER_ALGO;
    }

    if (_gcry_fips_mode() && !(spec->flags & ALGO_FIPS)
        && (_gcry_fips_reject_flags() & GCRY_FIPS_FLAG_REJECT_CIPHER)) {
        return GPG_ERR_CIPHER_ALGO;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Handle                                                              */
/* ------------------------------------------------------------------ */

struct aad_chunk {
    size_t len;
};

struct gcry_cipher_handle {
    unsigned int magic;
    const struct algo_spec *spec;
    int algo;
    int mode;
    unsigned int flags;
    int secure;

    /* The mode cipher and its context.  CTX_READY tells whether CTX has
     * been initialised with the current key, IV and direction ENC.
     * CTX_KEYED tells whether CTX still holds the key schedule for the
     * current key in direction CTX_ENC, so that the next message only
     * needs an IV re-initialisation. */
    const struct algo_spec *ospec; /* Variant OpenSSL implements for the
                                    * current key length (AES-192 for a 24
                                    * byte key on the AES id, and so on). */
    const EVP_CIPHER *cipher;    /* Borrowed from the cache. */
    EVP_CIPHER_CTX *ctx;
    int ctx_ready;
    int ctx_keyed;
    int ctx_enc;
    int enc;
    int generic_ctr; /* CTR mode composed from ECB (no native CTR). */

    /* ECB contexts: generic CTR keystream and the OCB block functions. */
    const EVP_CIPHER *ecb;       /* Borrowed from the cache. */
    EVP_CIPHER_CTX *ecb_enc;
    EVP_CIPHER_CTX *ecb_dec;
    int ecb_enc_keyed;
    int ecb_dec_keyed;

    unsigned char key[MAX_KEYLEN];
    size_t keylen;
    int have_key;

    unsigned char iv[MAX_BLOCKSIZE];
    size_t ivlen;
    int have_iv;
    unsigned char *longiv;       /* GCM and SIV nonces longer than IV. */
    size_t longivcap;

    unsigned char ctr[MAX_BLOCKSIZE];     /* Counter block for CTR mode. */
    unsigned char keystream[MAX_BLOCKSIZE];
    size_t ks_unused;                     /* Unused keystream bytes. */

    /* OpenPGP CFB resync: last block of ciphertext and the number of
     * bytes of the current partial block. */
    unsigned char lastct[MAX_BLOCKSIZE];
    size_t unused;

    int allow_weak_key;
    int finalize;

    /* AEAD state. */
    unsigned char *aad;
    size_t aadlen;
    size_t aadcap;
    struct aad_chunk *aad_chunks; /* SIV: boundaries of AAD components. */
    size_t aad_nchunks;
    size_t aad_chunkcap;
    int aad_done;                 /* No more AAD accepted. */
    int data_started;
    int data_done;                /* Single shot data was processed. */
    int tag_ready;
    unsigned char tag[16];
    size_t taglen;                /* OCB: configured; CCM: M. */
    int dectag_set;
    unsigned char dectag[16];
    int verify_failed;

    /* CCM: the data goes through CTR, the tag is a CBC-MAC over the
     * RFC 3610 formatted blocks, computed alongside the data. */
    unsigned long long ccm_encryptlen;
    unsigned long long ccm_aadlen;
    unsigned long long ccm_processed;
    int ccm_lengths_set;
    int ccm_enc;                  /* Direction of the current message. */
    EVP_CIPHER_CTX *ccm_mac;      /* CBC context for the MAC. */
    int ccm_mac_keyed;
    int ccm_mac_started;
    unsigned char ccm_mac_buf[16]; /* Partial MAC input block. */
    size_t ccm_mac_buflen;
    unsigned char ccm_mac_last[16]; /* Last CBC output block. */

    /* OCB.  AES uses OpenSSL's native OCB cipher through CTX; other
     * block ciphers use the OCB128 driver over the ECB contexts. */
    OCB128_CONTEXT *ocb;
    int ocb_native;
    int ocb_nonce_applied;        /* Nonce applied for this message. */

    /* XTS for variants OpenSSL has no native cipher for (AES-192, other
     * 128 bit block ciphers): the XTS128 driver over two ECB contexts. */
    int xts_generic;
    EVP_CIPHER_CTX *ecb2_enc;     /* Keyed with the tweak key. */
    int ecb2_enc_keyed;

    /* Key wrap for block ciphers without a native wrap cipher. */
    int wrap_generic;
    unsigned char wrap_plen[4];

    /* IV generation for AEAD modes. */
    int geniv_method;
    unsigned char geniv_fixed[MAX_BLOCKSIZE];
    unsigned char geniv_dyn[MAX_BLOCKSIZE];
    size_t geniv_fixedlen;
    size_t geniv_dynlen;
};

static int
is_aead_mode(int mode)
{
    switch (mode) {
    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_CCM:
    case GCRY_CIPHER_MODE_OCB:
    case GCRY_CIPHER_MODE_POLY1305:
    case GCRY_CIPHER_MODE_SIV:
    case GCRY_CIPHER_MODE_GCM_SIV:
    case GCRY_CIPHER_MODE_EAX:
        return 1;

    default:
        return 0;
    }
}

/* Modes that hand the whole message to OpenSSL in a single call. */
static int
is_single_shot_mode(int mode)
{
    return mode == GCRY_CIPHER_MODE_SIV || mode == GCRY_CIPHER_MODE_GCM_SIV;
}

static void *
handle_alloc(gcry_cipher_hd_t h, size_t n)
{
    return h->secure ? _gcry_malloc_secure(n) : _gcry_malloc(n);
}

/* Grow a buffer owned by the handle. */
static gcry_err_code_t
buffer_append(gcry_cipher_hd_t h, unsigned char **buf, size_t *len,
              size_t *cap, const void *data, size_t n)
{
    if (*len + n > *cap) {
        size_t newcap = *cap ? *cap : 64;
        unsigned char *p;

        while (newcap < *len + n) {
            newcap *= 2;
        }

        p = handle_alloc(h, newcap);

        if (!p) {
            return _gcry_err_code_from_syserror();
        }

        if (*len) {
            memcpy(p, *buf, *len);
        }

        if (*buf) {
            _gcry_wipememory(*buf, *cap);
            _gcry_free(*buf);
        }

        *buf = p;
        *cap = newcap;
    }

    if (n) {
        memcpy(*buf + *len, data, n);
    }

    *len += n;
    return 0;
}

static void
buffer_free(unsigned char **buf, size_t *len, size_t *cap)
{
    if (*buf) {
        _gcry_wipememory(*buf, *cap);
        _gcry_free(*buf);
    }

    *buf = NULL;
    *len = 0;
    *cap = 0;
}

static void
aad_reset(gcry_cipher_hd_t h)
{
    buffer_free(&h->aad, &h->aadlen, &h->aadcap);
    _gcry_free(h->aad_chunks);
    h->aad_chunks = NULL;
    h->aad_nchunks = 0;
    h->aad_chunkcap = 0;
    h->aad_done = 0;
}

static gcry_err_code_t
aad_store(gcry_cipher_hd_t h, const void *abuf, size_t abuflen)
{
    gcry_err_code_t rc = buffer_append(h, &h->aad, &h->aadlen, &h->aadcap,
                                       abuf, abuflen);

    if (rc) {
        return rc;
    }

    if (h->aad_nchunks == h->aad_chunkcap) {
        size_t newcap = h->aad_chunkcap ? h->aad_chunkcap * 2 : 8;
        struct aad_chunk *p = _gcry_malloc(newcap * sizeof * p);

        if (!p) {
            return _gcry_err_code_from_syserror();
        }

        if (h->aad_nchunks) {
            memcpy(p, h->aad_chunks, h->aad_nchunks * sizeof * p);
        }

        _gcry_free(h->aad_chunks);
        h->aad_chunks = p;
        h->aad_chunkcap = newcap;
    }

    h->aad_chunks[h->aad_nchunks++].len = abuflen;
    return 0;
}

/* Reset every per-message state but keep the key. */
static void
reset_message_state(gcry_cipher_hd_t h)
{
    h->ctx_ready = 0;
    h->have_iv = 0;
    h->ivlen = 0;
    memset(h->iv, 0, sizeof h->iv);
    memset(h->ctr, 0, sizeof h->ctr);

    if (h->ks_unused) {
        /* Only the keystream is sensitive; tags and IVs are public. */
        _gcry_wipememory(h->keystream, sizeof h->keystream);
        h->ks_unused = 0;
    }

    memset(h->lastct, 0, sizeof h->lastct);
    h->unused = 0;
    h->finalize = 0;

    if (h->aad || h->aad_chunks || h->aad_done) {
        aad_reset(h);
    }

    h->data_started = 0;
    h->data_done = 0;
    h->tag_ready = 0;
    memset(h->tag, 0, sizeof h->tag);
    h->dectag_set = 0;
    memset(h->dectag, 0, sizeof h->dectag);
    h->verify_failed = 0;
    h->ccm_encryptlen = 0;
    h->ccm_aadlen = 0;
    h->ccm_processed = 0;
    h->ccm_lengths_set = 0;
    h->ccm_mac_started = 0;
    h->ccm_mac_buflen = 0;
    h->ocb_nonce_applied = 0;
    memset(h->wrap_plen, 0, sizeof h->wrap_plen);

    if (h->mode == GCRY_CIPHER_MODE_OCB) {
        h->taglen = 16;
    } else if (h->mode == GCRY_CIPHER_MODE_CCM) {
        h->taglen = 0;
    }
}

/* ------------------------------------------------------------------ */
/* OpenSSL plumbing                                                    */
/* ------------------------------------------------------------------ */

/* EVP_CipherUpdate for arbitrary lengths; the output is expected to be
 * as long as the input (no padding, stream like modes). */
static gcry_err_code_t
evp_update(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
           size_t len)
{
    while (len) {
        int chunk = len > (size_t)INT_MAX / 2 ? INT_MAX / 2 : (int)len;
        int outl = 0;

        if (!EVP_CipherUpdate(ctx, out, &outl, in, chunk)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        if (out) {
            out += outl;
        }

        in += chunk;
        len -= (size_t)chunk;
    }

    return 0;
}

/* The cache slot of the OpenSSL cipher implementing MODE for the handle,
 * or -1 if the combination cannot be expressed. */
static int
mode_cipher_slot(gcry_cipher_hd_t h)
{
    switch (h->mode) {
    case GCRY_CIPHER_MODE_ECB:
        return SLOT_ECB;

    case GCRY_CIPHER_MODE_CBC:
        return (h->flags & GCRY_CIPHER_CBC_CTS) ? SLOT_CBC_CTS : SLOT_CBC;

    case GCRY_CIPHER_MODE_CFB:
        return SLOT_CFB;

    case GCRY_CIPHER_MODE_CFB8:
        return SLOT_CFB8;

    case GCRY_CIPHER_MODE_OFB:
        return SLOT_OFB;

    case GCRY_CIPHER_MODE_CTR:
    case GCRY_CIPHER_MODE_CCM:
        return SLOT_CTR; /* CCM data goes through CTR. */

    case GCRY_CIPHER_MODE_GCM:
        return SLOT_GCM;

    case GCRY_CIPHER_MODE_XTS:
        return SLOT_XTS;

    case GCRY_CIPHER_MODE_SIV:
        return SLOT_SIV;

    case GCRY_CIPHER_MODE_GCM_SIV:
        return SLOT_GCM_SIV;

    case GCRY_CIPHER_MODE_AESWRAP:
        return (h->flags & GCRY_CIPHER_EXTENDED) ? SLOT_WRAP_PAD : SLOT_WRAP;

    case GCRY_CIPHER_MODE_STREAM:
        return SLOT_STREAM;

    case GCRY_CIPHER_MODE_POLY1305:
        return SLOT_POLY1305;

    case GCRY_CIPHER_MODE_OCB:
        return SLOT_OCB;

    default:
        return -1;
    }
}

static int
is_aes_algo(int algo)
{
    return algo == GCRY_CIPHER_AES || algo == GCRY_CIPHER_AES192
           || algo == GCRY_CIPHER_AES256;
}

/* Look up the cipher objects needed by the handle's mode. */
static gcry_err_code_t
fetch_mode_ciphers(gcry_cipher_hd_t h)
{
    int slot = mode_cipher_slot(h);

    h->cipher = NULL;
    h->ctx_keyed = 0;
    h->generic_ctr = 0;
    h->ocb_native = 0;

    if (slot < 0) {
        return GPG_ERR_INV_CIPHER_MODE;
    }

    h->xts_generic = 0;
    h->wrap_generic = 0;

    if (h->mode == GCRY_CIPHER_MODE_OCB) {
        /* OpenSSL only has a native OCB for AES; the OCB128 driver over
         * ECB covers the other 128 bit block ciphers. */
        if (is_aes_algo(h->algo)) {
            h->cipher = cached_cipher(h->ospec, SLOT_OCB);
            h->ocb_native = h->cipher != NULL;
        }

        return 0;
    }

    h->cipher = cached_cipher(h->ospec, (enum cipher_slot)slot);

    if (!h->cipher) {
        switch (h->mode) {
        case GCRY_CIPHER_MODE_CTR:
        case GCRY_CIPHER_MODE_CCM:
            h->generic_ctr = 1; /* Compose CTR from ECB below. */
            return 0;

        case GCRY_CIPHER_MODE_XTS:
            h->xts_generic = 1; /* XTS128 driver over ECB. */
            return 0;

        case GCRY_CIPHER_MODE_AESWRAP:
            /* The key wrap driver over ECB; 64 bit block ciphers open
             * but fail at the first data call, as in the reference. */
            h->wrap_generic = 1;
            return 0;

        default:
            return GPG_ERR_NOT_SUPPORTED;
        }
    }

    return 0;
}

static gcry_err_code_t
ensure_ecb_cipher(gcry_cipher_hd_t h)
{
    if (h->ecb) {
        return 0;
    }

    h->ecb = cached_cipher(h->ospec, SLOT_ECB);
    return h->ecb ? 0 : GPG_ERR_NOT_SUPPORTED;
}

static gcry_err_code_t ocb_native_keyinit(gcry_cipher_hd_t h);

/* Set up one ECB context with the current key in direction ENC.  ECB has
 * no per-message state, so a context keyed once (*KEYED) is left alone. */
static gcry_err_code_t
init_ecb_ctx_key(gcry_cipher_hd_t h, EVP_CIPHER_CTX **ctxp, int *keyed,
                 int enc, const unsigned char *key, size_t keylen)
{
    gcry_err_code_t rc = ensure_ecb_cipher(h);

    if (rc) {
        return rc;
    }

    if (*ctxp && *keyed) {
        return 0;
    }

    if (!*ctxp) {
        *ctxp = EVP_CIPHER_CTX_new();

        if (!*ctxp) {
            return GPG_ERR_ENOMEM;
        }
    }

    if (!EVP_CipherInit_ex2(*ctxp, h->ecb, NULL, NULL, enc, NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    if (keylen != (size_t)EVP_CIPHER_get_key_length(h->ecb)
        && !EVP_CIPHER_CTX_set_key_length(*ctxp, (int)keylen)) {
        return _gcry_err_from_openssl(GPG_ERR_INV_KEYLEN);
    }

    if (h->spec->flags & ALGO_RC2) {
        OSSL_PARAM params[2];
        unsigned int bits = (unsigned int)keylen * 8;

        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_RC2_KEYBITS,
                                              &bits);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_CIPHER_CTX_set_params(*ctxp, params)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    if (!EVP_CipherInit_ex2(*ctxp, NULL, key, NULL, enc, NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    EVP_CIPHER_CTX_set_padding(*ctxp, 0);
    *keyed = 1;
    return 0;
}

static gcry_err_code_t
init_ecb_ctx(gcry_cipher_hd_t h, EVP_CIPHER_CTX **ctxp, int *keyed, int enc)
{
    return init_ecb_ctx_key(h, ctxp, keyed, enc, h->key, h->keylen);
}

/* Block functions for OpenSSL's OCB128 driver, backed by EVP ECB. */
static void
ecb_block_encrypt(const unsigned char in[16], unsigned char out[16],
                  const void *key)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(uintptr_t)key;
    int outl = 0;

    if (!EVP_EncryptUpdate(ctx, out, &outl, in, 16)) {
        ERR_clear_error();
        memset(out, 0, 16);
    }
}

static void
ecb_block_decrypt(const unsigned char in[16], unsigned char out[16],
                  const void *key)
{
    EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)(uintptr_t)key;
    int outl = 0;

    if (!EVP_DecryptUpdate(ctx, out, &outl, in, 16)) {
        ERR_clear_error();
        memset(out, 0, 16);
    }
}

/* Keep IV of IVLEN bytes in the handle; GCM and SIV nonces may be longer
 * than a block and go to a heap buffer. */
static gcry_err_code_t
store_iv(gcry_cipher_hd_t h, const unsigned char *iv, size_t ivlen)
{
    if (ivlen > MAX_BLOCKSIZE) {
        if (ivlen > h->longivcap) {
            unsigned char *p = handle_alloc(h, ivlen);

            if (!p) {
                return _gcry_err_code_from_syserror();
            }

            _gcry_free(h->longiv);
            h->longiv = p;
            h->longivcap = ivlen;
        }

        memcpy(h->longiv, iv, ivlen);
    } else {
        memset(h->iv, 0, sizeof h->iv);

        if (ivlen) {
            memcpy(h->iv, iv, ivlen);
        }
    }

    h->ivlen = ivlen;
    h->have_iv = 1;
    return 0;
}

static const unsigned char *
iv_ptr(gcry_cipher_hd_t h)
{
    return h->ivlen > MAX_BLOCKSIZE ? h->longiv : h->iv;
}

/* Translate the Libgcrypt IV conventions into what OpenSSL expects.
 * On return *IVP points at the IV (BUF or the handle's own storage). */
static gcry_err_code_t
effective_iv(gcry_cipher_hd_t h, unsigned char *buf,
             const unsigned char **ivp, size_t *ivlen)
{
    *ivp = buf;
    *ivlen = 0;

    switch (h->mode) {
    case GCRY_CIPHER_MODE_ECB:
        return 0;

    case GCRY_CIPHER_MODE_AESWRAP:

        /* RFC 3394 takes an 8 byte integrity check value; the reference
         * zero pads a shorter one and ignores the rest of a longer one.
         * The padded variant (RFC 5649) always uses its default. */
        if (h->have_iv && !(h->flags & GCRY_CIPHER_EXTENDED)) {
            memset(buf, 0, 8);
            memcpy(buf, h->iv, h->ivlen < 8 ? h->ivlen : 8);
            *ivlen = 8;
        }

        return 0;

    case GCRY_CIPHER_MODE_CTR:
    case GCRY_CIPHER_MODE_CCM:
        memcpy(buf, h->ctr, h->spec->blocksize);
        *ivlen = h->spec->blocksize;
        return 0;

    case GCRY_CIPHER_MODE_STREAM:
        if (h->algo != GCRY_CIPHER_CHACHA20) {
            return 0;
        }

        /* ChaCha20 takes a 16 byte counter||nonce.  An 8 byte nonce means
         * the original 64 bit counter variant, a 12 byte nonce the IETF
         * variant; both start at counter zero.  Other lengths were turned
         * into an all zero IV by setiv, as the reference does. */
        memset(buf, 0, 16);

        if (h->have_iv) {
            memcpy(buf + 16 - h->ivlen, h->iv, h->ivlen);
        }

        *ivlen = 16;
        return 0;

    case GCRY_CIPHER_MODE_POLY1305:
        if (!h->have_iv) {
            return GPG_ERR_INV_STATE;
        }

        memset(buf, 0, 12);

        if (h->ivlen == 16) {
            /* Counter||nonce: OpenSSL's AEAD cipher cannot start at a
             * non-zero block counter. */
            if (h->iv[0] || h->iv[1] || h->iv[2] || h->iv[3]) {
                return GPG_ERR_NOT_SUPPORTED;
            }

            memcpy(buf, h->iv + 4, 12);
        } else if (h->ivlen) {
            memcpy(buf + 12 - h->ivlen, h->iv, h->ivlen);
        }

        *ivlen = 12;
        return 0;

    case GCRY_CIPHER_MODE_GCM:
        if (!h->have_iv) {
            /* Libgcrypt uses an all zero 16 byte IV in that case. */
            memset(buf, 0, 16);
            *ivlen = 16;
        } else {
            *ivp = iv_ptr(h);
            *ivlen = h->ivlen;
        }

        return 0;

    case GCRY_CIPHER_MODE_GCM_SIV:
        if (!h->have_iv) {
            return GPG_ERR_INV_STATE;
        }

        memcpy(buf, h->iv, h->ivlen);
        *ivlen = h->ivlen;
        return 0;

    case GCRY_CIPHER_MODE_XTS:
        /* The tweak is one block; short ones are zero padded. */
        memset(buf, 0, 16);

        if (h->have_iv) {
            memcpy(buf, h->iv, h->ivlen < 16 ? h->ivlen : 16);
        }

        *ivlen = 16;
        return 0;

    case GCRY_CIPHER_MODE_SIV:
        return 0; /* The nonce is an associated data component. */

    default:
        /* Block chaining modes: the IV is one block; Libgcrypt zero
         * pads short IVs and truncates long ones. */
        memset(buf, 0, h->spec->blocksize);

        if (h->have_iv) {
            memcpy(buf, h->iv, h->ivlen < h->spec->blocksize
                   ? h->ivlen : h->spec->blocksize);
        }

        *ivlen = h->spec->blocksize;
        return 0;
    }
}

/* Feed buffered AAD into a freshly initialised AEAD context. */
static gcry_err_code_t
flush_aad(gcry_cipher_hd_t h, EVP_CIPHER_CTX *ctx)
{
    gcry_err_code_t rc;

    if (h->mode == GCRY_CIPHER_MODE_SIV) {
        size_t i;
        size_t off = 0;

        /* Each gcry_cipher_authenticate() call is one S2V component and
         * the nonce, if any, is the last one before the plaintext. */
        for (i = 0; i < h->aad_nchunks; i++) {
            rc = evp_update(ctx, NULL, h->aad + off, h->aad_chunks[i].len);

            if (rc) {
                return rc;
            }

            off += h->aad_chunks[i].len;
        }

        if (h->have_iv) {
            return evp_update(ctx, NULL, iv_ptr(h), h->ivlen);
        }

        return 0;
    }

    if (h->aadlen) {
        return evp_update(ctx, NULL, h->aad, h->aadlen);
    }

    return 0;
}

/* Initialise the main context for direction ENC with the current key and
 * IV unless that already happened. */
static gcry_err_code_t
ensure_ctx(gcry_cipher_hd_t h, int enc)
{
    gcry_err_code_t rc;
    unsigned char ivbuf[MAX_BLOCKSIZE];
    const unsigned char *iv;
    size_t ivlen;
    int chained = h->mode == GCRY_CIPHER_MODE_CBC
                  || h->mode == GCRY_CIPHER_MODE_CFB
                  || h->mode == GCRY_CIPHER_MODE_CFB8
                  || h->mode == GCRY_CIPHER_MODE_OFB;

    if (!h->have_key) {
        return GPG_ERR_MISSING_KEY;
    }

    if (h->ctx_ready && h->enc == enc) {
        return 0;
    }

    if (h->ctx_ready && chained && !(h->flags & GCRY_CIPHER_CBC_CTS)) {
        /* Switching direction in the middle of a message: carry the
         * chaining state over. */
        if (EVP_CIPHER_CTX_get_updated_iv(h->ctx, h->iv,
                                          h->spec->blocksize)) {
            h->ivlen = h->spec->blocksize;
            h->have_iv = 1;
        } else {
            ERR_clear_error();
        }
    }

    if (h->generic_ctr) {
        rc = init_ecb_ctx(h, &h->ecb_enc, &h->ecb_enc_keyed, 1);

        if (rc) {
            return rc;
        }

        h->ctx_ready = 1;
        h->enc = enc;
        return 0;
    }

    if (!h->ctx) {
        h->ctx = EVP_CIPHER_CTX_new();

        if (!h->ctx) {
            return GPG_ERR_ENOMEM;
        }
    }

    rc = effective_iv(h, ivbuf, &iv, &ivlen);

    if (rc) {
        return rc;
    }

    /* A context that still holds this key's schedule for this direction
     * only needs the new IV; OpenSSL keeps the key when none is given.
     * The single shot modes and key wrap carry per-message parameters
     * through their initialisation and always start afresh. */
    if (h->ctx_keyed && h->ctx_enc == enc && !is_single_shot_mode(h->mode)
        && h->mode != GCRY_CIPHER_MODE_AESWRAP) {
        if ((h->mode == GCRY_CIPHER_MODE_GCM
             || h->mode == GCRY_CIPHER_MODE_POLY1305)
            && ivlen != (size_t)EVP_CIPHER_CTX_get_iv_length(h->ctx)
            && !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    (int)ivlen, NULL)) {
            return _gcry_err_from_openssl(GPG_ERR_INV_LENGTH);
        }

        if (!EVP_CipherInit_ex2(h->ctx, NULL, NULL, ivlen ? iv : NULL, enc,
                                NULL)) {
            h->ctx_keyed = 0;
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        goto ready;
    }

    h->ctx_keyed = 0;

    if (!EVP_CIPHER_CTX_reset(h->ctx)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    if (h->mode == GCRY_CIPHER_MODE_AESWRAP) {
        EVP_CIPHER_CTX_set_flags(h->ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    }

    if (!EVP_CipherInit_ex2(h->ctx, h->cipher, NULL, NULL, enc, NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    if (h->keylen != (size_t)EVP_CIPHER_get_key_length(h->cipher)
        && !EVP_CIPHER_CTX_set_key_length(h->ctx, (int)h->keylen)) {
        return _gcry_err_from_openssl(GPG_ERR_INV_KEYLEN);
    }

    if (h->spec->flags & ALGO_RC2) {
        OSSL_PARAM params[2];
        unsigned int bits = (unsigned int)h->keylen * 8;

        params[0] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_RC2_KEYBITS,
                                              &bits);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_CIPHER_CTX_set_params(h->ctx, params)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    if (h->mode == GCRY_CIPHER_MODE_CBC && (h->flags & GCRY_CIPHER_CBC_CTS)) {
        OSSL_PARAM params[2];
        char cs3[] = "CS3";

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE,
                                                     cs3, 0);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_CIPHER_CTX_set_params(h->ctx, params)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    if ((h->mode == GCRY_CIPHER_MODE_GCM || h->mode == GCRY_CIPHER_MODE_POLY1305
         || h->mode == GCRY_CIPHER_MODE_GCM_SIV)
        && ivlen != (size_t)EVP_CIPHER_CTX_get_iv_length(h->ctx)
        && !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)ivlen,
                                NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_INV_LENGTH);
    }

    if (h->mode == GCRY_CIPHER_MODE_SIV && !enc) {
        if (!h->dectag_set) {
            return GPG_ERR_INV_STATE;
        }

        if (!EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                 h->dectag)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    if (!EVP_CipherInit_ex2(h->ctx, NULL, h->key, ivlen ? iv : NULL, enc,
                            NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    EVP_CIPHER_CTX_set_padding(h->ctx, 0);

    if (h->mode == GCRY_CIPHER_MODE_GCM_SIV && !enc) {
        if (!h->dectag_set) {
            return GPG_ERR_INV_STATE;
        }

        if (!EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                 h->dectag)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    h->ctx_keyed = 1;
    h->ctx_enc = enc;

ready:
    h->ctx_ready = 1;
    h->enc = enc;

    if (is_aead_mode(h->mode) && h->mode != GCRY_CIPHER_MODE_CCM) {
        rc = flush_aad(h, h->ctx);

        if (rc) {
            return rc;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Open / close                                                        */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
check_mode(const struct algo_spec *spec, int mode)
{
    int stream = !!(spec->flags & ALGO_STREAM);

    switch (mode) {
    case GCRY_CIPHER_MODE_ECB:
    case GCRY_CIPHER_MODE_CBC:
    case GCRY_CIPHER_MODE_CFB:
    case GCRY_CIPHER_MODE_CFB8:
    case GCRY_CIPHER_MODE_OFB:
    case GCRY_CIPHER_MODE_CTR:
    case GCRY_CIPHER_MODE_AESWRAP:
    case GCRY_CIPHER_MODE_EAX:
        return stream ? GPG_ERR_INV_CIPHER_MODE : 0;

    case GCRY_CIPHER_MODE_CCM:
    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_OCB:
    case GCRY_CIPHER_MODE_XTS:
    case GCRY_CIPHER_MODE_SIV:
    case GCRY_CIPHER_MODE_GCM_SIV:
        return (stream || spec->blocksize != 16) ? GPG_ERR_INV_CIPHER_MODE : 0;

    case GCRY_CIPHER_MODE_POLY1305:
        return spec->algo == GCRY_CIPHER_CHACHA20 ? 0 : GPG_ERR_INV_CIPHER_MODE;

    case GCRY_CIPHER_MODE_STREAM:
        return stream ? 0 : GPG_ERR_INV_CIPHER_MODE;

    default:
        return GPG_ERR_INV_CIPHER_MODE;
    }
}

static gcry_err_code_t
cipher_open(gcry_cipher_hd_t *handle, int algo, int mode, unsigned int flags)
{
    const struct algo_spec *spec = spec_from_algo(algo);
    gcry_cipher_hd_t h;
    gcry_err_code_t rc;
    int secure = !!(flags & GCRY_CIPHER_SECURE);

    *handle = NULL;
    rc = check_cipher_algo(spec);

    if (rc) {
        return rc;
    }

    if ((flags & ~(unsigned int)(GCRY_CIPHER_SECURE | GCRY_CIPHER_ENABLE_SYNC
                                 | GCRY_CIPHER_CBC_CTS | GCRY_CIPHER_CBC_MAC
                                 | GCRY_CIPHER_EXTENDED))
        || ((flags & GCRY_CIPHER_CBC_CTS) && (flags & GCRY_CIPHER_CBC_MAC))) {
        return GPG_ERR_CIPHER_ALGO;
    }

    rc = check_mode(spec, mode);

    if (rc) {
        return rc;
    }

    if (mode == GCRY_CIPHER_MODE_EAX) {
        return GPG_ERR_NOT_SUPPORTED; /* No EAX in OpenSSL. */
    }

    h = secure ? _gcry_calloc_secure(1, sizeof * h) : _gcry_calloc(1, sizeof * h);

    if (!h) {
        return _gcry_err_code_from_syserror();
    }

    h->magic = secure ? CTX_MAGIC_SECURE : CTX_MAGIC_NORMAL;
    h->spec = spec;
    h->ospec = spec;
    h->algo = algo;
    h->mode = mode;
    h->flags = flags;
    h->secure = secure;

    /* The handle is zeroed; only the mode defaults need setting. */
    if (mode == GCRY_CIPHER_MODE_OCB) {
        h->taglen = 16;
    }

    rc = fetch_mode_ciphers(h);

    if (!rc && ((mode == GCRY_CIPHER_MODE_OCB && !h->ocb_native)
                || h->generic_ctr || h->xts_generic
                || (h->wrap_generic && spec->blocksize == 16))) {
        rc = ensure_ecb_cipher(h);
    }

    if (!rc && mode == GCRY_CIPHER_MODE_GCM) {
        /* Decryption needs the block function and a CTR stream. */
        rc = ensure_ecb_cipher(h);

        if (!rc && !cached_cipher(spec, SLOT_CTR)) {
            rc = GPG_ERR_NOT_SUPPORTED;
        }
    }

    if (!rc && mode == GCRY_CIPHER_MODE_CCM) {
        /* The tag is a CBC-MAC and the final XOR needs one ECB block. */
        if (!cached_cipher(spec, SLOT_CBC)) {
            rc = GPG_ERR_NOT_SUPPORTED;
        } else {
            rc = ensure_ecb_cipher(h);
        }
    }

    if (rc) {
        gcry_cipher_close(h);
        return rc;
    }

    *handle = h;
    return 0;
}

gcry_error_t
gcry_cipher_open(gcry_cipher_hd_t *handle, int algo, int mode,
                 unsigned int flags)
{
    if (!handle) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_open(handle, algo, mode, flags));
}

void
gcry_cipher_close(gcry_cipher_hd_t h)
{
    if (!h) {
        return;
    }

    if (h->magic != CTX_MAGIC_SECURE && h->magic != CTX_MAGIC_NORMAL) {
        _gcry_fatal_error(GPG_ERR_INTERNAL,
                          "gcry_cipher_close: already closed/invalid handle");
    }

    h->magic = 0;
    EVP_CIPHER_CTX_free(h->ctx);
    EVP_CIPHER_CTX_free(h->ecb_enc);
    EVP_CIPHER_CTX_free(h->ecb_dec);
    EVP_CIPHER_CTX_free(h->ecb2_enc);
    EVP_CIPHER_CTX_free(h->ccm_mac);

    if (h->ocb) {
        CRYPTO_ocb128_cleanup(h->ocb);
        OPENSSL_free(h->ocb);
    }

    aad_reset(h);
    _gcry_free(h->longiv);

    /* The key material; the rest of the handle holds nothing secret. */
    _gcry_wipememory(h->key, sizeof h->key);
    _gcry_wipememory(h->keystream, sizeof h->keystream);
    _gcry_wipememory(h->ccm_mac_buf, sizeof h->ccm_mac_buf);
    _gcry_free(h);
}

/* ------------------------------------------------------------------ */
/* Key and IV                                                          */
/* ------------------------------------------------------------------ */

/* The 64 DES keys the reference library rejects: the four weak and
 * twelve semi-weak keys of FIPS 74 plus the 48 possibly weak keys, that is
 * every key whose two 28 bit key schedule registers both follow a pattern
 * of period four or less.  Parity bits are cleared for the comparison. */
static const unsigned char des_weak_keys[64][8] = {
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e },
    { 0x00, 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0 },
    { 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe },
    { 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e },
    { 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00 },
    { 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe },
    { 0x00, 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0 },
    { 0x00, 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0 },
    { 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe },
    { 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00 },
    { 0x00, 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e },
    { 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe },
    { 0x00, 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0 },
    { 0x00, 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e },
    { 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00 },
    { 0x1e, 0x00, 0x00, 0x1e, 0x0e, 0x00, 0x00, 0x0e },
    { 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e, 0x00 },
    { 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0, 0xfe },
    { 0x1e, 0x00, 0xfe, 0xe0, 0x0e, 0x00, 0xfe, 0xf0 },
    { 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00, 0x00 },
    { 0x1e, 0x1e, 0x1e, 0x1e, 0x0e, 0x0e, 0x0e, 0x0e },
    { 0x1e, 0x1e, 0xe0, 0xe0, 0x0e, 0x0e, 0xf0, 0xf0 },
    { 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe, 0xfe },
    { 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00, 0xfe },
    { 0x1e, 0xe0, 0x1e, 0xe0, 0x0e, 0xf0, 0x0e, 0xf0 },
    { 0x1e, 0xe0, 0xe0, 0x1e, 0x0e, 0xf0, 0xf0, 0x0e },
    { 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe, 0x00 },
    { 0x1e, 0xfe, 0x00, 0xe0, 0x0e, 0xfe, 0x00, 0xf0 },
    { 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe },
    { 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0, 0x00 },
    { 0x1e, 0xfe, 0xfe, 0x1e, 0x0e, 0xfe, 0xfe, 0x0e },
    { 0xe0, 0x00, 0x00, 0xe0, 0xf0, 0x00, 0x00, 0xf0 },
    { 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e, 0xfe },
    { 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0, 0x00 },
    { 0xe0, 0x00, 0xfe, 0x1e, 0xf0, 0x00, 0xfe, 0x0e },
    { 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00, 0xfe },
    { 0xe0, 0x1e, 0x1e, 0xe0, 0xf0, 0x0e, 0x0e, 0xf0 },
    { 0xe0, 0x1e, 0xe0, 0x1e, 0xf0, 0x0e, 0xf0, 0x0e },
    { 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe, 0x00 },
    { 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00 },
    { 0xe0, 0xe0, 0x1e, 0x1e, 0xf0, 0xf0, 0x0e, 0x0e },
    { 0xe0, 0xe0, 0xe0, 0xe0, 0xf0, 0xf0, 0xf0, 0xf0 },
    { 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe, 0xfe },
    { 0xe0, 0xfe, 0x00, 0x1e, 0xf0, 0xfe, 0x00, 0x0e },
    { 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e, 0x00 },
    { 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0, 0xfe },
    { 0xe0, 0xfe, 0xfe, 0xe0, 0xf0, 0xfe, 0xfe, 0xf0 },
    { 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe },
    { 0xfe, 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0 },
    { 0xfe, 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e },
    { 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00 },
    { 0xfe, 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0 },
    { 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe },
    { 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00 },
    { 0xfe, 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e },
    { 0xfe, 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e },
    { 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00 },
    { 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe },
    { 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0 },
    { 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00 },
    { 0xfe, 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e },
    { 0xfe, 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0 },
    { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
};

static int
des_is_weak_key(const unsigned char *key)
{
    unsigned char work[8];
    size_t i;
    int j;

    for (j = 0; j < 8; j++) {
        work[j] = key[j] & 0xfe;
    }

    for (i = 0; i < DIM(des_weak_keys); i++) {
        if (!CRYPTO_memcmp(work, des_weak_keys[i], 8)) {
            return 1;
        }
    }

    return 0;
}

/* The reference library lets any member of a cipher family take any of
 * the family's key lengths: a 32 byte key on the AES id selects AES-256.
 * Return the variant that implements KEYLEN, or NULL if none does. */
static const struct algo_spec *
family_spec(const struct algo_spec *spec, size_t keylen)
{
    static const int families[][3] = {
        { GCRY_CIPHER_AES, GCRY_CIPHER_AES192, GCRY_CIPHER_AES256 },
        {
            GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_CAMELLIA192,
            GCRY_CIPHER_CAMELLIA256
        },
        {
            GCRY_CIPHER_SERPENT128, GCRY_CIPHER_SERPENT192,
            GCRY_CIPHER_SERPENT256
        },
    };
    size_t f;
    int i;

    for (f = 0; f < DIM(families); f++) {
        for (i = 0; i < 3; i++) {
            if (families[f][i] == spec->algo) {
                for (i = 0; i < 3; i++) {
                    const struct algo_spec *m = spec_from_algo(families[f][i]);

                    if (m && keylen >= m->min_keylen
                        && keylen <= m->max_keylen) {
                        return m;
                    }
                }

                return NULL;
            }
        }
    }

    return keylen >= spec->min_keylen && keylen <= spec->max_keylen ? spec
           : NULL;
}

/* Validate KEYLEN and pick the OpenSSL variant for it. */
static gcry_err_code_t
check_keylen(gcry_cipher_hd_t h, size_t keylen,
             const struct algo_spec **r_ospec)
{
    const struct algo_spec *fam;
    size_t single = keylen;

    if (h->mode == GCRY_CIPHER_MODE_XTS || h->mode == GCRY_CIPHER_MODE_SIV) {
        if (keylen % 2) {
            return GPG_ERR_INV_KEYLEN;
        }

        single = keylen / 2;
    }

    if (keylen > MAX_KEYLEN) {
        return GPG_ERR_INV_KEYLEN;
    }

    fam = family_spec(h->spec, single);

    if (!fam) {
        return GPG_ERR_INV_KEYLEN;
    }

    *r_ospec = fam;
    return 0;
}

static gcry_err_code_t
cipher_setkey(gcry_cipher_hd_t h, const void *key, size_t keylen)
{
    const struct algo_spec *ospec = h->ospec;
    gcry_err_code_t rc = check_keylen(h, keylen, &ospec);
    int weak = 0;

    if (rc) {
        return rc;
    }

    /* RFC 8452 defines AES-GCM-SIV for 128 and 256 bit keys only. */
    if (h->mode == GCRY_CIPHER_MODE_GCM_SIV && keylen != 16 && keylen != 32) {
        return GPG_ERR_INV_KEYLEN;
    }

    if (ospec != h->ospec) {
        /* Another variant of the family: look its ciphers up anew. */
        h->ospec = ospec;
        h->ecb = NULL;
        rc = fetch_mode_ciphers(h);

        if (rc) {
            return rc;
        }
    }

    if (h->algo == GCRY_CIPHER_DES || h->algo == GCRY_CIPHER_3DES) {
        const unsigned char *k = key;
        size_t i;

        for (i = 0; i < keylen; i += 8) {
            if (des_is_weak_key(k + i)) {
                weak = 1;
            }
        }

        if (weak && !h->allow_weak_key) {
            h->have_key = 0;
            return GPG_ERR_WEAK_KEY;
        }
    }

    /* XTS with two equal keys is weak and the FIPS provider refuses it
     * outright, so report it here rather than as an internal error at the
     * first data call; the reference library gives the same code. */
    if (h->mode == GCRY_CIPHER_MODE_XTS && _gcry_fips_mode()
        && !CRYPTO_memcmp(key, (const unsigned char *)key + keylen / 2,
                          keylen / 2)) {
        return GPG_ERR_WEAK_KEY;
    }

    _gcry_wipememory(h->key, sizeof h->key);
    memcpy(h->key, key, keylen);
    h->keylen = keylen;
    h->have_key = 1;
    h->ctx_ready = 0;
    h->ctx_keyed = 0;
    h->ecb_enc_keyed = 0;
    h->ecb_dec_keyed = 0;
    h->ecb2_enc_keyed = 0;
    h->ccm_mac_keyed = 0;

    /* Validate the key with OpenSSL right away so that errors surface here
     * instead of at the first encryption. */
    if (h->mode == GCRY_CIPHER_MODE_OCB && h->ocb_native) {
        rc = ocb_native_keyinit(h);
    } else if (h->mode == GCRY_CIPHER_MODE_OCB) {
        rc = init_ecb_ctx(h, &h->ecb_enc, &h->ecb_enc_keyed, 1);

        if (!rc) {
            rc = init_ecb_ctx(h, &h->ecb_dec, &h->ecb_dec_keyed, 0);
        }

        if (!rc) {
            if (h->ocb) {
                CRYPTO_ocb128_cleanup(h->ocb);
                OPENSSL_free(h->ocb);
            }

            h->ocb = CRYPTO_ocb128_new(h->ecb_enc, h->ecb_dec,
                                       ecb_block_encrypt, ecb_block_decrypt,
                                       NULL);

            if (!h->ocb) {
                rc = _gcry_err_from_openssl(GPG_ERR_ENOMEM);
            }
        }
    } else if (h->generic_ctr) {
        rc = init_ecb_ctx(h, &h->ecb_enc, &h->ecb_enc_keyed, 1);
    } else if (h->wrap_generic) {
        if (h->spec->blocksize == 16) {
            rc = init_ecb_ctx(h, &h->ecb_enc, &h->ecb_enc_keyed, 1);
        }
    } else if (h->xts_generic) {
        rc = init_ecb_ctx_key(h, &h->ecb_enc, &h->ecb_enc_keyed, 1, h->key,
                              keylen / 2);

        if (!rc) {
            rc = init_ecb_ctx_key(h, &h->ecb_dec, &h->ecb_dec_keyed, 0,
                                  h->key, keylen / 2);
        }

        if (!rc) {
            rc = init_ecb_ctx_key(h, &h->ecb2_enc, &h->ecb2_enc_keyed, 1,
                                  h->key + keylen / 2, keylen / 2);
        }
    } else if (!is_aead_mode(h->mode) && h->mode != GCRY_CIPHER_MODE_XTS
               && h->mode != GCRY_CIPHER_MODE_AESWRAP) {
        rc = ensure_ctx(h, 1);
        h->ctx_ready = 0; /* The IV may still change. */
    }

    if (rc) {
        h->have_key = 0;
        return rc;
    }

    /* A new key starts a new message; the OCB tag length is a handle
     * setting and survives, as it does in the reference library. */
    {
        int allow = h->allow_weak_key;
        size_t taglen = h->taglen;

        reset_message_state(h);
        h->allow_weak_key = allow;

        if (h->mode == GCRY_CIPHER_MODE_OCB) {
            h->taglen = taglen;
        }
    }

    return weak ? GPG_ERR_WEAK_KEY : 0;
}

gcry_error_t
gcry_cipher_setkey(gcry_cipher_hd_t hd, const void *key, size_t keylen)
{
    if (!hd || (!key && keylen)) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_setkey(hd, key, keylen));
}

static gcry_err_code_t
cipher_setiv(gcry_cipher_hd_t h, const void *iv, size_t ivlen)
{
    size_t bs = h->spec->blocksize;
    const unsigned char *ivb = iv;
    int keep_dectag = 0;
    int allow;
    size_t taglen;
    unsigned char dectag[16];
    int dectag_set;

    switch (h->mode) {
    case GCRY_CIPHER_MODE_GCM:
        if (!iv || !ivlen) {
            return GPG_ERR_INV_LENGTH;
        }

        break;

    case GCRY_CIPHER_MODE_CCM:
        if (!iv) {
            return GPG_ERR_INV_ARG;
        }

        if (ivlen < 7 || ivlen > 13) {
            return GPG_ERR_INV_LENGTH;
        }

        break;

    case GCRY_CIPHER_MODE_OCB:
        if (!h->have_key) {
            return GPG_ERR_INV_STATE;
        }

        if (!iv || ivlen < 8 || ivlen > 15) {
            return GPG_ERR_INV_LENGTH;
        }

        break;

    case GCRY_CIPHER_MODE_POLY1305:
        if (!iv) {
            return GPG_ERR_INV_ARG;
        }

        if (ivlen != 8 && ivlen != 12 && ivlen != 16) {
            /* The reference warns and continues with an all zero nonce. */
            log_info("WARNING: cipher_setiv: bad ivlen=%u for Poly1305\n",
                     (unsigned int)ivlen);
            ivlen = 0;
        }

        break;

    case GCRY_CIPHER_MODE_GCM_SIV:
        if (!iv || ivlen != 12) {
            return GPG_ERR_INV_ARG;
        }

        if (h->data_started || h->data_done || h->tag_ready) {
            return GPG_ERR_INV_STATE; /* Finished: reset first. */
        }

        keep_dectag = 1; /* A tag set before the nonce stays valid. */
        break;

    case GCRY_CIPHER_MODE_XTS:
        if (!iv) {
            return GPG_ERR_INV_ARG;
        }

        if (ivlen != 16) {
            log_info("WARNING: cipher_setiv: ivlen=%u blklen=16\n",
                     (unsigned int)ivlen);
        }

        if (ivlen > 16) {
            ivlen = 16;
        }

        break;

    case GCRY_CIPHER_MODE_AESWRAP:

        /* Any length is taken; what is used of it is decided when the
         * data comes (see effective_iv).  A NULL IV means the default. */
        if (ivlen > MAX_BLOCKSIZE) {
            ivlen = MAX_BLOCKSIZE;
        }

        break;

    case GCRY_CIPHER_MODE_SIV:

        /* The nonce is the last S2V component: it comes after all the
         * associated data and only once per message, and it does not
         * disturb the message state built so far. */
        if (!iv) {
            return GPG_ERR_INV_ARG;
        }

        if (h->have_iv || h->data_started || h->data_done || h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        return store_iv(h, ivb, ivlen);

    case GCRY_CIPHER_MODE_STREAM:
        if (h->algo == GCRY_CIPHER_CHACHA20) {
            if (iv && ivlen != 8 && ivlen != 12 && ivlen != 16) {
                log_info("WARNING: cipher_setiv: bad ivlen=%u for "
                         "ChaCha20\n", (unsigned int)ivlen);
                ivlen = 0;
            }
        } else {
            ivlen = 0; /* ARCFOUR has no IV; the call is a no-op. */
        }

        break;

    default:
        if (iv && ivlen != bs) {
            log_info("WARNING: cipher_setiv: ivlen=%u blklen=%u\n",
                     (unsigned int)ivlen, (unsigned int)bs);
        }

        if (ivlen > MAX_BLOCKSIZE) {
            ivlen = MAX_BLOCKSIZE;
        }

        break;
    }

    /* A new IV starts a new message; the key and settings stay. */
    allow = h->allow_weak_key;
    taglen = h->taglen;
    dectag_set = h->dectag_set;
    memcpy(dectag, h->dectag, sizeof dectag);
    reset_message_state(h);
    h->allow_weak_key = allow;

    if (h->mode == GCRY_CIPHER_MODE_OCB) {
        h->taglen = taglen;
    }

    if (keep_dectag && dectag_set) {
        h->dectag_set = 1;
        memcpy(h->dectag, dectag, sizeof dectag);
    }

    if (iv) {
        gcry_err_code_t rc = store_iv(h, ivb, ivlen);

        if (rc) {
            return rc;
        }
    }

    if (h->mode == GCRY_CIPHER_MODE_CCM && iv) {
        /* Counter block A_0: flags = L - 1, then nonce, then counter. */
        memset(h->ctr, 0, 16);
        h->ctr[0] = (unsigned char)(15 - ivlen - 1);
        memcpy(h->ctr + 1, iv, ivlen);
    }

    return 0;
}

gcry_error_t
gcry_cipher_setiv(gcry_cipher_hd_t hd, const void *iv, size_t ivlen)
{
    if (!hd || (!iv && ivlen)) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_setiv(hd, iv, ivlen));
}

gpg_error_t
gcry_cipher_setctr(gcry_cipher_hd_t hd, const void *ctr, size_t ctrlen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (ctr && ctrlen == hd->spec->blocksize) {
        memcpy(hd->ctr, ctr, ctrlen);
    } else if (!ctr || !ctrlen) {
        memset(hd->ctr, 0, sizeof hd->ctr);
    } else {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    hd->ks_unused = 0;
    hd->ctx_ready = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CTR composed from ECB                                               */
/* ------------------------------------------------------------------ */

static void
increment_counter(unsigned char *ctr, size_t len)
{
    size_t i = len;

    while (i-- > 0) {
        if (++ctr[i] != 0) {
            break;
        }
    }
}

static gcry_err_code_t
generic_ctr_crypt(gcry_cipher_hd_t h, unsigned char *out,
                  const unsigned char *in, size_t len)
{
    size_t bs = h->spec->blocksize;
    unsigned char blocks[64 * MAX_BLOCKSIZE];
    unsigned char ks[64 * MAX_BLOCKSIZE];
    gcry_err_code_t rc = ensure_ctx(h, 1);

    if (rc) {
        return rc;
    }

    /* Leftover keystream from the previous call first. */
    while (len && h->ks_unused) {
        *out++ = (unsigned char)(*in++ ^ h->keystream[bs - h->ks_unused]);
        h->ks_unused--;
        len--;
    }

    while (len) {
        size_t nblocks = (len + bs - 1) / bs;
        size_t i;
        size_t n;
        int outl = 0;

        if (nblocks > 64) {
            nblocks = 64;
        }

        for (i = 0; i < nblocks; i++) {
            memcpy(blocks + i * bs, h->ctr, bs);
            increment_counter(h->ctr, bs);
        }

        if (!EVP_EncryptUpdate(h->ecb_enc, ks, &outl, blocks,
                               (int)(nblocks * bs))) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        n = nblocks * bs;

        if (n > len) {
            /* Keep the unused tail of the last keystream block. */
            memcpy(h->keystream, ks + (nblocks - 1) * bs, bs);
            h->ks_unused = n - len;
            n = len;
        }

        for (i = 0; i < n; i++) {
            out[i] = (unsigned char)(in[i] ^ ks[i]);
        }

        out += n;
        in += n;
        len -= n;
    }

    _gcry_wipememory(ks, sizeof ks);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Encrypt / decrypt                                                   */
/* ------------------------------------------------------------------ */

/* Remember the last block of ciphertext for CFB resynchronisation. */
static void
track_ciphertext(gcry_cipher_hd_t h, const unsigned char *ct, size_t len)
{
    size_t bs = h->spec->blocksize;

    if (!(h->flags & GCRY_CIPHER_ENABLE_SYNC)) {
        return;
    }

    if (len >= bs) {
        memcpy(h->lastct, ct + len - bs, bs);
    } else if (len) {
        memmove(h->lastct, h->lastct + len, bs - len);
        memcpy(h->lastct + bs - len, ct, len);
    }

    h->unused = (h->unused + len) % bs;
}

static gcry_err_code_t
do_cbc_mac(gcry_cipher_hd_t h, unsigned char *out, size_t outsize,
           const unsigned char *in, size_t inlen)
{
    size_t bs = h->spec->blocksize;
    unsigned char tmp[MAX_BLOCKSIZE];
    gcry_err_code_t rc;

    if (outsize < bs) {
        return GPG_ERR_BUFFER_TOO_SHORT;
    }

    if (inlen % bs) {
        return GPG_ERR_INV_LENGTH;
    }

    rc = ensure_ctx(h, 1);

    if (rc) {
        return rc;
    }

    while (inlen) {
        rc = evp_update(h->ctx, tmp, in, bs);

        if (rc) {
            return rc;
        }

        in += bs;
        inlen -= bs;
    }

    memcpy(out, tmp, bs);
    return 0;
}

static gcry_err_code_t
do_cts(gcry_cipher_hd_t h, int enc, unsigned char *out, size_t outsize,
       const unsigned char *in, size_t inlen)
{
    size_t bs = h->spec->blocksize;
    gcry_err_code_t rc;

    if (outsize < inlen) {
        return GPG_ERR_BUFFER_TOO_SHORT;
    }

    if ((inlen % bs) && inlen <= bs) {
        return GPG_ERR_INV_LENGTH;
    }

    if (!inlen) {
        return 0;
    }

    /* OpenSSL's CTS cipher processes one message per initialisation. */
    h->ctx_ready = 0;
    rc = ensure_ctx(h, enc);

    if (rc) {
        return rc;
    }

    rc = evp_update(h->ctx, out, in, inlen);
    h->ctx_ready = 0;
    return rc;
}

/* XTS (IEEE 1619) composed from the ECB contexts for the variants OpenSSL
 * has no native cipher for: the tweak is encrypted with the second key,
 * each block is masked with the running tweak before and after the block
 * cipher, the tweak is multiplied by alpha between blocks, and a final
 * partial block uses ciphertext stealing.  Blocks go to OpenSSL in
 * batches. */
static void
xts_next_tweak(unsigned char t[16])
{
    unsigned int carry = 0;
    size_t i;

    for (i = 0; i < 16; i++) {
        unsigned int b = t[i];

        t[i] = (unsigned char)((b << 1) | carry);
        carry = b >> 7;
    }

    if (carry) {
        t[0] ^= 0x87;
    }
}

static gcry_err_code_t
generic_xts_crypt(gcry_cipher_hd_t h, int enc, unsigned char *out,
                  const unsigned char *in, size_t inlen)
{
    EVP_CIPHER_CTX *data_ctx = enc ? h->ecb_enc : h->ecb_dec;
    unsigned char tweakbuf[16];
    unsigned char t[16];
    unsigned char tweaks[64 * 16];
    unsigned char work[64 * 16];
    const unsigned char *ivp;
    size_t ivlen;
    size_t nfull = inlen / 16;
    size_t tail = inlen % 16;
    gcry_err_code_t rc;
    int outl = 0;

    rc = effective_iv(h, tweakbuf, &ivp, &ivlen);

    if (rc) {
        return rc;
    }

    if (!EVP_EncryptUpdate(h->ecb2_enc, t, &outl, tweakbuf, 16)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    /* With ciphertext stealing the last full block is handled together
     * with the partial one below. */
    if (tail) {
        nfull--;
    }

    while (nfull) {
        size_t n = nfull > 64 ? 64 : nfull;
        size_t i;

        for (i = 0; i < n; i++) {
            size_t j;

            memcpy(tweaks + i * 16, t, 16);

            for (j = 0; j < 16; j++) {
                work[i * 16 + j] = (unsigned char)(in[i * 16 + j] ^ t[j]);
            }

            xts_next_tweak(t);
        }

        if (!EVP_CipherUpdate(data_ctx, work, &outl, work, (int)(n * 16))) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        for (i = 0; i < n * 16; i++) {
            out[i] = (unsigned char)(work[i] ^ tweaks[i]);
        }

        in += n * 16;
        out += n * 16;
        nfull -= n;
    }

    if (tail) {
        unsigned char t2[16];
        unsigned char block[16];
        size_t j;

        memcpy(t2, t, 16);
        xts_next_tweak(t2);

        /* Decryption processes the stolen block with the later tweak. */
        if (!enc) {
            unsigned char tmp[16];

            memcpy(tmp, t, 16);
            memcpy(t, t2, 16);
            memcpy(t2, tmp, 16);
        }

        for (j = 0; j < 16; j++) {
            block[j] = (unsigned char)(in[j] ^ t[j]);
        }

        if (!EVP_CipherUpdate(data_ctx, block, &outl, block, 16)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        for (j = 0; j < 16; j++) {
            block[j] ^= t[j];
        }

        /* The last partial output is the head of this block; the block is
         * completed with the partial input and processed with the other
         * tweak to become the full output block. */
        memcpy(out + 16, block, tail);

        for (j = 0; j < tail; j++) {
            block[j] = in[16 + j];
        }

        for (j = 0; j < 16; j++) {
            block[j] = (unsigned char)(block[j] ^ t2[j]);
        }

        if (!EVP_CipherUpdate(data_ctx, block, &outl, block, 16)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        for (j = 0; j < 16; j++) {
            out[j] = (unsigned char)(block[j] ^ t2[j]);
        }
    }

    _gcry_wipememory(work, sizeof work);
    return 0;
}

static gcry_err_code_t
do_xts(gcry_cipher_hd_t h, int enc, unsigned char *out, size_t outsize,
       const unsigned char *in, size_t inlen)
{
    gcry_err_code_t rc;

    if (outsize < inlen || inlen < 16) {
        return GPG_ERR_BUFFER_TOO_SHORT;
    }

    if (inlen > ((size_t)16 << 20)) {
        return GPG_ERR_INV_LENGTH;
    }

    if (h->xts_generic) {
        return generic_xts_crypt(h, enc, out, in, inlen);
    }

    h->ctx_ready = 0; /* One data unit per call, always from the tweak. */
    rc = ensure_ctx(h, enc);

    if (rc) {
        return rc;
    }

    rc = evp_update(h->ctx, out, in, inlen);
    h->ctx_ready = 0;
    return rc;
}

static gcry_err_code_t
do_wrap(gcry_cipher_hd_t h, int enc, unsigned char *out, size_t outsize,
        const unsigned char *in, size_t inlen)
{
    int extended = !!(h->flags & GCRY_CIPHER_EXTENDED);
    gcry_err_code_t rc;
    int outl = 0;
    size_t need;

    if (inlen > (size_t)INT_MAX / 2) {
        return GPG_ERR_INV_LENGTH;
    }

    if (enc) {
        if (extended) {
            need = ((inlen + 7) / 8) * 8 + 8;
        } else {
            if (inlen % 8) {
                return GPG_ERR_INV_ARG;
            }

            if (inlen / 8 < 2) {
                return GPG_ERR_INV_ARG;
            }

            need = inlen + 8;
        }

        if (outsize < need) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }
    } else {
        if (outsize + 8 < inlen) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }

        if (inlen % 8) {
            return GPG_ERR_INV_ARG;
        }

        if (inlen == 16) {
            if (!extended) {
                return GPG_ERR_BUFFER_TOO_SHORT;
            }
        } else if (inlen / 8 < 3) {
            return GPG_ERR_INV_ARG;
        }
    }

    if (h->wrap_generic) {
        unsigned char ivbuf[MAX_BLOCKSIZE];
        const unsigned char *iv;
        size_t ivlen;
        size_t n;

        /* The driver works on 128 bit block ciphers only. */
        if (h->spec->blocksize != 16) {
            return GPG_ERR_INV_LENGTH;
        }

        rc = effective_iv(h, ivbuf, &iv, &ivlen);

        if (!rc) {
            rc = init_ecb_ctx(h, enc ? &h->ecb_enc : &h->ecb_dec,
                              enc ? &h->ecb_enc_keyed : &h->ecb_dec_keyed,
                              enc);
        }

        if (rc) {
            return rc;
        }

        if (extended) {
            n = enc ? CRYPTO_128_wrap_pad(h->ecb_enc, NULL, out, in, inlen,
                                          ecb_block_encrypt)
                : CRYPTO_128_unwrap_pad(h->ecb_dec, NULL, out, in, inlen,
                                        ecb_block_decrypt);
        } else {
            n = enc ? CRYPTO_128_wrap(h->ecb_enc, ivlen ? iv : NULL, out, in,
                                      inlen, ecb_block_encrypt)
                : CRYPTO_128_unwrap(h->ecb_dec, ivlen ? iv : NULL, out, in,
                                    inlen, ecb_block_decrypt);
        }

        if (!n) {
            ERR_clear_error();
            return enc ? GPG_ERR_INTERNAL : GPG_ERR_CHECKSUM;
        }

        outl = (int)n;
    } else {
        h->ctx_ready = 0;
        rc = ensure_ctx(h, enc);

        if (rc) {
            return rc;
        }

        if (!EVP_CipherUpdate(h->ctx, out, &outl, in, (int)inlen)) {
            ERR_clear_error();
            h->ctx_ready = 0;
            return enc ? GPG_ERR_INTERNAL : GPG_ERR_CHECKSUM;
        }

        h->ctx_ready = 0;
    }

    if (!enc) {
        size_t plen = (size_t)outl;
        size_t avail = inlen - 8;

        if (extended) {
            h->wrap_plen[0] = (unsigned char)(plen >> 24);
            h->wrap_plen[1] = (unsigned char)(plen >> 16);
            h->wrap_plen[2] = (unsigned char)(plen >> 8);
            h->wrap_plen[3] = (unsigned char)plen;

            /* Libgcrypt returns the padded plaintext. */
            if (plen < avail && avail <= outsize) {
                memset(out + plen, 0, avail - plen);
            }
        } else {
            memset(h->wrap_plen, 0, sizeof h->wrap_plen);
        }
    }

    return 0;
}

/* GCM, ChaCha20-Poly1305, SIV and GCM-SIV data processing. */
static gcry_err_code_t evp_finish_encrypt(gcry_cipher_hd_t h);

/*
 * OpenSSL's AES-GCM decryption context refuses to hand out the tag it has
 * computed, but re-initialising the context for encryption without a key
 * or IV only flips its direction, and the following EncryptFinal then
 * exposes the tag over the data that was decrypted.  That lets the fused
 * AES-GCM kernel be used for decryption while still being able to read
 * the tag, as the reference library allows.  Because this relies on the
 * provider keeping its state across the flip, it is checked once against
 * a known answer; a provider that fails the check cannot decrypt GCM
 * through this library.
 */
static pthread_once_t gcm_flip_once = PTHREAD_ONCE_INIT;
static int gcm_flip_ok;

static void
gcm_flip_probe(void)
{
    /* NIST GCM test case 2: zero key, zero IV, one zero block. */
    static const unsigned char ct[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    static const unsigned char want[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    unsigned char zero[16] = { 0 };
    unsigned char out[16];
    unsigned char tag[16];
    EVP_CIPHER *gcm;
    EVP_CIPHER_CTX *ctx;
    int outl = 0;

    gcm = EVP_CIPHER_fetch(_gcry_libctx(), "AES-128-GCM", _gcry_propq());
    ctx = EVP_CIPHER_CTX_new();

    if (gcm && ctx
        && EVP_DecryptInit_ex2(ctx, gcm, zero, zero, NULL)
        && EVP_DecryptUpdate(ctx, out, &outl, ct, 16)
        && EVP_CipherInit_ex2(ctx, NULL, NULL, NULL, 1, NULL)
        && EVP_EncryptFinal_ex(ctx, out, &outl)
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)
        && !memcmp(tag, want, 16)) {
        gcm_flip_ok = 1;
    }

    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(gcm);
}

static int
gcm_flip_supported(void)
{
    pthread_once(&gcm_flip_once, gcm_flip_probe);
    return gcm_flip_ok;
}

/* Finish a GCM decryption that ran through the EVP context: flip it to
 * encryption and read the tag computed over the ciphertext. */
static gcry_err_code_t
gcm_finish_evp_decrypt(gcry_cipher_hd_t h)
{
    unsigned char dummy[16];
    int outl = 0;

    if (!EVP_CipherInit_ex2(h->ctx, NULL, NULL, NULL, 1, NULL)
        || !EVP_EncryptFinal_ex(h->ctx, dummy, &outl)
        || !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_GET_TAG, 16, h->tag)) {
        h->ctx_keyed = 0;
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    h->aad_done = 1;
    h->tag_ready = 1;
    h->data_done = 1;
    return 0;
}

/* Compute the tag of a GCM message: by flipping the context when
 * decrypting, from the EVP context directly otherwise. */
static gcry_err_code_t
gcm_finish(gcry_cipher_hd_t h)
{
    if (h->tag_ready) {
        return 0;
    }

    if (h->data_started && !h->enc) {
        if (!h->ctx_ready) {
            return GPG_ERR_INV_STATE;
        }

        return gcm_finish_evp_decrypt(h);
    }

    return evp_finish_encrypt(h);
}

/* GCM, ChaCha20-Poly1305, SIV and GCM-SIV data processing. */
static gcry_err_code_t
do_evp_aead(gcry_cipher_hd_t h, int enc, unsigned char *out, size_t outsize,
            const unsigned char *in, size_t inlen)
{
    gcry_err_code_t rc;

    if (outsize < inlen) {
        return GPG_ERR_BUFFER_TOO_SHORT;
    }

    if (h->tag_ready || h->data_done) {
        return GPG_ERR_INV_STATE;
    }

    if (h->data_started && h->enc != enc) {
        return GPG_ERR_INV_STATE; /* Cannot turn around mid-message. */
    }

    if (h->mode == GCRY_CIPHER_MODE_GCM && !enc && !gcm_flip_supported()) {
        log_error("gcry_cipher_decrypt: this OpenSSL provider cannot "
                  "expose the GCM tag of a decryption\n");
        return GPG_ERR_NOT_SUPPORTED;
    }

    if (is_single_shot_mode(h->mode)) {
        /* A handle given a decryption tag is a decryption handle. */
        if (enc && h->dectag_set) {
            return GPG_ERR_INV_STATE;
        }

        if (inlen > (size_t)INT_MAX) {
            return GPG_ERR_INV_LENGTH;
        }
    }

    rc = ensure_ctx(h, enc);

    if (rc) {
        return rc;
    }

    h->aad_done = 1;
    h->data_started = 1;

    if (is_single_shot_mode(h->mode)) {
        int outl = 0;
        unsigned char dummy[16];

        /* SIV verifies the tag while it decrypts, so either call may
         * report the mismatch.  Wrong tag: the reference discards the
         * plaintext and the message is over. */
        if (!EVP_CipherUpdate(h->ctx, inlen ? out : dummy, &outl,
                              inlen ? in : dummy, (int)inlen)) {
            if (enc) {
                return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
            }

            ERR_clear_error();
            h->data_done = 1;
            h->verify_failed = 1;
            memset(out, 0, inlen);
            return GPG_ERR_CHECKSUM;
        }

        h->data_done = 1;

        if (!EVP_CipherFinal_ex(h->ctx, dummy, &outl)) {
            ERR_clear_error();

            if (enc) {
                return GPG_ERR_INTERNAL;
            }

            h->verify_failed = 1;
            memset(out, 0, inlen);
            return GPG_ERR_CHECKSUM;
        }

        return 0;
    }

    return evp_update(h->ctx, out, in, inlen);
}

/* Run the full blocks of the CCM MAC input buffer through CBC, keeping
 * the last output block, which is the running MAC. */
static gcry_err_code_t
ccm_mac_flush(gcry_cipher_hd_t h)
{
    int outl = 0;

    if (h->ccm_mac_buflen != 16) {
        return 0;
    }

    if (!EVP_EncryptUpdate(h->ccm_mac, h->ccm_mac_last, &outl,
                           h->ccm_mac_buf, 16)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    h->ccm_mac_buflen = 0;
    return 0;
}

/* Feed LEN bytes into the CCM CBC-MAC. */
static gcry_err_code_t
ccm_mac_feed(gcry_cipher_hd_t h, const unsigned char *data, size_t len)
{
    gcry_err_code_t rc;
    unsigned char scratch[64 * 16];

    /* Complete a pending partial block first. */
    if (h->ccm_mac_buflen) {
        size_t n = 16 - h->ccm_mac_buflen;

        if (n > len) {
            n = len;
        }

        memcpy(h->ccm_mac_buf + h->ccm_mac_buflen, data, n);
        h->ccm_mac_buflen += n;
        data += n;
        len -= n;
        rc = ccm_mac_flush(h);

        if (rc) {
            return rc;
        }
    }

    /* Whole blocks straight from the caller's buffer. */
    while (len >= 16) {
        size_t n = len & ~(size_t)15;
        int outl = 0;

        if (n > sizeof scratch) {
            n = sizeof scratch;
        }

        if (!EVP_EncryptUpdate(h->ccm_mac, scratch, &outl, data, (int)n)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        memcpy(h->ccm_mac_last, scratch + n - 16, 16);
        data += n;
        len -= n;
    }

    if (len) {
        memcpy(h->ccm_mac_buf, data, len);
        h->ccm_mac_buflen = len;
    }

    return 0;
}

/* Start the CBC-MAC for the message: key the CBC context with a zero IV
 * and feed the RFC 3610 B_0 block followed by the length-prefixed and
 * zero-padded associated data. */
static gcry_err_code_t
ccm_mac_start(gcry_cipher_hd_t h)
{
    static const unsigned char zero_iv[16];
    gcry_err_code_t rc;
    unsigned char b0[16];
    unsigned char alen[10];
    size_t alenlen;
    size_t noncelen = h->ivlen;
    size_t lfield = 15 - noncelen;
    unsigned long long q = h->ccm_encryptlen;
    size_t i;

    if (!h->ccm_mac) {
        h->ccm_mac = EVP_CIPHER_CTX_new();

        if (!h->ccm_mac) {
            return GPG_ERR_ENOMEM;
        }
    }

    if (h->ccm_mac_keyed) {
        if (!EVP_EncryptInit_ex2(h->ccm_mac, NULL, NULL, zero_iv, NULL)) {
            h->ccm_mac_keyed = 0;
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    } else {
        const EVP_CIPHER *cbc = cached_cipher(h->ospec, SLOT_CBC);

        if (!cbc) {
            return GPG_ERR_NOT_SUPPORTED;
        }

        if (!EVP_EncryptInit_ex2(h->ccm_mac, cbc, NULL, NULL, NULL)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        if (h->keylen != (size_t)EVP_CIPHER_get_key_length(cbc)
            && !EVP_CIPHER_CTX_set_key_length(h->ccm_mac, (int)h->keylen)) {
            return _gcry_err_from_openssl(GPG_ERR_INV_KEYLEN);
        }

        if (!EVP_EncryptInit_ex2(h->ccm_mac, NULL, h->key, zero_iv, NULL)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        EVP_CIPHER_CTX_set_padding(h->ccm_mac, 0);
        h->ccm_mac_keyed = 1;
    }

    h->ccm_mac_buflen = 0;
    h->ccm_mac_started = 1;

    /* B_0 = flags || nonce || Q, with flags = Adata | M' << 3 | L'. */
    b0[0] = (unsigned char)((h->ccm_aadlen ? 0x40 : 0)
                            | (((h->taglen - 2) / 2) << 3) | (lfield - 1));
    memcpy(b0 + 1, h->iv, noncelen);

    for (i = 0; i < lfield; i++) {
        b0[15 - i] = (unsigned char)q;
        q >>= 8;
    }

    rc = ccm_mac_feed(h, b0, 16);

    if (rc || !h->ccm_aadlen) {
        return rc;
    }

    /* The associated data is prefixed with its encoded length and the
     * whole is padded to a block boundary. */
    if (h->ccm_aadlen < 0xff00) {
        alen[0] = (unsigned char)(h->ccm_aadlen >> 8);
        alen[1] = (unsigned char)h->ccm_aadlen;
        alenlen = 2;
    } else if (h->ccm_aadlen <= 0xffffffffULL) {
        alen[0] = 0xff;
        alen[1] = 0xfe;

        for (i = 0; i < 4; i++) {
            alen[2 + i] = (unsigned char)(h->ccm_aadlen >> (8 * (3 - i)));
        }

        alenlen = 6;
    } else {
        alen[0] = 0xff;
        alen[1] = 0xff;

        for (i = 0; i < 8; i++) {
            alen[2 + i] = (unsigned char)(h->ccm_aadlen >> (8 * (7 - i)));
        }

        alenlen = 10;
    }

    rc = ccm_mac_feed(h, alen, alenlen);

    if (!rc) {
        rc = ccm_mac_feed(h, h->aad, h->aadlen);
    }

    if (!rc && h->ccm_mac_buflen) {
        memset(h->ccm_mac_buf + h->ccm_mac_buflen, 0,
               16 - h->ccm_mac_buflen);
        h->ccm_mac_buflen = 16;
        rc = ccm_mac_flush(h);
    }

    return rc;
}

static gcry_err_code_t
do_ccm_crypt(gcry_cipher_hd_t h, int enc, unsigned char *out, size_t outsize,
             const unsigned char *in, size_t inlen)
{
    gcry_err_code_t rc;

    if (outsize < inlen) {
        return GPG_ERR_BUFFER_TOO_SHORT;
    }

    if (!h->have_iv || h->tag_ready || !h->ccm_lengths_set
        || h->aadlen != h->ccm_aadlen) {
        return GPG_ERR_INV_STATE;
    }

    /* The CTR context always runs in the encryption direction, so the
     * message direction is tracked separately from h->enc. */
    if (h->data_started && h->ccm_enc != enc) {
        return GPG_ERR_INV_STATE;
    }

    if (inlen > h->ccm_encryptlen - h->ccm_processed) {
        return GPG_ERR_INV_LENGTH;
    }

    if (!h->data_started) {
        /* The data counter starts at one; A_0 is reserved for the tag. */
        h->ctr[15] = 1;
        h->ks_unused = 0;
        h->ctx_ready = 0;
    }

    h->data_started = 1;
    h->ccm_enc = enc;

    if (!h->ccm_mac_started) {
        rc = ccm_mac_start(h);

        if (rc) {
            return rc;
        }
    }

    if (h->generic_ctr) {
        rc = generic_ctr_crypt(h, out, in, inlen);
    } else {
        rc = ensure_ctx(h, 1); /* CTR is the same in both directions. */

        if (!rc) {
            rc = evp_update(h->ctx, out, in, inlen);
        }
    }

    if (rc) {
        return rc;
    }

    h->ccm_processed += inlen;
    return ccm_mac_feed(h, enc ? in : out, inlen);
}

/* Finish the CBC-MAC: pad the last block and XOR the result with the
 * first counter block (S_0), as RFC 3610 section 2.3 specifies. */
static gcry_err_code_t
ccm_compute_tag(gcry_cipher_hd_t h, unsigned char *tag)
{
    gcry_err_code_t rc;
    unsigned char a0[16];
    unsigned char s0[16];
    size_t noncelen = h->ivlen;
    size_t i;
    int outl = 0;

    if (!h->ccm_mac_started) {
        rc = ccm_mac_start(h);

        if (rc) {
            return rc;
        }
    }

    if (h->ccm_mac_buflen) {
        memset(h->ccm_mac_buf + h->ccm_mac_buflen, 0,
               16 - h->ccm_mac_buflen);
        h->ccm_mac_buflen = 16;
        rc = ccm_mac_flush(h);

        if (rc) {
            return rc;
        }
    }

    /* A_0: flags, nonce, zero counter.  CTR mode has left the flags and
     * the nonce in place and only advanced the counter bytes. */
    memcpy(a0, h->ctr, 16);
    memset(a0 + noncelen + 1, 0, 15 - noncelen);

    rc = init_ecb_ctx(h, &h->ecb_enc, &h->ecb_enc_keyed, 1);

    if (rc) {
        return rc;
    }

    if (!EVP_EncryptUpdate(h->ecb_enc, s0, &outl, a0, 16)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    for (i = 0; i < h->taglen; i++) {
        tag[i] = (unsigned char)(h->ccm_mac_last[i] ^ s0[i]);
    }

    _gcry_wipememory(s0, sizeof s0);
    return 0;
}

/* Key the native OCB context for encryption so that a bad key is
 * reported by setkey; messages re-initialise it with their nonce. */
static gcry_err_code_t
ocb_native_keyinit(gcry_cipher_hd_t h)
{
    if (!h->ctx) {
        h->ctx = EVP_CIPHER_CTX_new();

        if (!h->ctx) {
            return GPG_ERR_ENOMEM;
        }
    }

    if (!EVP_CIPHER_CTX_reset(h->ctx)
        || !EVP_CipherInit_ex2(h->ctx, h->cipher, h->key, NULL, 1, NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_INV_KEYLEN);
    }

    h->ctx_keyed = 1;
    h->ctx_enc = 1;
    return 0;
}

/* Initialise the native OCB context for this message's nonce, tag length
 * and direction ENC, then feed any associated data given so far. */
static gcry_err_code_t
ocb_native_start(gcry_cipher_hd_t h, int enc)
{
    gcry_err_code_t rc;

    if (!h->have_key) {
        return GPG_ERR_INV_STATE;
    }

    if (!h->have_iv) {
        return GPG_ERR_INV_STATE;
    }

    if (h->ocb_nonce_applied) {
        return h->enc == enc ? 0 : GPG_ERR_INV_STATE;
    }

    if (!h->ctx) {
        h->ctx = EVP_CIPHER_CTX_new();

        if (!h->ctx) {
            return GPG_ERR_ENOMEM;
        }
    }

    if (!h->ctx_keyed || h->ctx_enc != enc) {
        h->ctx_keyed = 0;

        if (!EVP_CIPHER_CTX_reset(h->ctx)
            || !EVP_CipherInit_ex2(h->ctx, h->cipher, NULL, NULL, enc, NULL)
            || !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                    (int)h->ivlen, NULL)
            || !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_TAG,
                                    (int)h->taglen, NULL)
            || !EVP_CipherInit_ex2(h->ctx, NULL, h->key, h->iv, enc, NULL)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        h->ctx_keyed = 1;
        h->ctx_enc = enc;
    } else {
        /* The key schedule is in place: only nonce length, tag length and
         * nonce change between messages. */
        if (!EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 (int)h->ivlen, NULL)
            || !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_TAG,
                                    (int)h->taglen, NULL)
            || !EVP_CipherInit_ex2(h->ctx, NULL, NULL, h->iv, enc, NULL)) {
            h->ctx_keyed = 0;
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    h->ocb_nonce_applied = 1;
    h->ctx_ready = 1;
    h->enc = enc;

    rc = flush_aad(h, h->ctx);

    if (!rc) {
        buffer_free(&h->aad, &h->aadlen, &h->aadcap);
    }

    return rc;
}

/* Data for the native OCB context.  Whole blocks come straight back
 * from OpenSSL; a final partial block is held back until the tag is
 * computed, so it is produced from a copy of the context: the copy is
 * finished now for the output, the original keeps the pending block and
 * is finished when the tag is requested (or checked). */
static gcry_err_code_t
ocb_native_crypt(gcry_cipher_hd_t h, int enc, unsigned char *out,
                 const unsigned char *in, size_t inlen)
{
    gcry_err_code_t rc = ocb_native_start(h, enc);
    size_t partial = inlen % 16;
    size_t whole = inlen - partial;

    if (rc) {
        return rc;
    }

    if (whole) {
        rc = evp_update(h->ctx, out, in, whole);

        if (rc) {
            return rc;
        }
    }

    if (partial) {
        EVP_CIPHER_CTX *dup = EVP_CIPHER_CTX_new();
        unsigned char tail[16];
        int outl = 0;
        int ok;

        if (!dup) {
            return GPG_ERR_ENOMEM;
        }

        /* Hand the partial block to the original (it is buffered) and
         * finish a copy to learn its output now. */
        if (!EVP_CipherUpdate(h->ctx, tail, &outl, in + whole, (int)partial)
            || outl != 0 || !EVP_CIPHER_CTX_copy(dup, h->ctx)) {
            EVP_CIPHER_CTX_free(dup);
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        /* Without the real tag the copy's decryption reports a mismatch
         * after it has produced the plaintext; only the bytes matter. */
        memset(tail, 0, sizeof tail);
        ok = EVP_CipherFinal_ex(dup, tail, &outl);
        EVP_CIPHER_CTX_free(dup);

        if (!ok) {
            ERR_clear_error();

            if (enc) {
                return GPG_ERR_INTERNAL;
            }
        }

        memcpy(out + whole, tail, partial);
    }

    return 0;
}

/* Finish the native OCB context: produce the tag on encryption, or verify
 * INTAG on decryption. */
static gcry_err_code_t
ocb_native_finish(gcry_cipher_hd_t h, const unsigned char *intag)
{
    unsigned char tail[16];
    int outl = 0;

    if (h->tag_ready) {
        return 0;
    }

    if (!h->enc) {
        if (!EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_TAG,
                                 (int)h->taglen, (void *)(uintptr_t)intag)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        if (!EVP_CipherFinal_ex(h->ctx, tail, &outl)) {
            ERR_clear_error();
            h->verify_failed = 1;
        }

        memcpy(h->dectag, intag, h->taglen);
    } else {
        if (!EVP_CipherFinal_ex(h->ctx, tail, &outl)
            || !EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_GET_TAG,
                                    (int)h->taglen, h->tag)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }
    }

    _gcry_wipememory(tail, sizeof tail);
    h->tag_ready = 1;
    return 0;
}

static gcry_err_code_t
ocb_apply_nonce(gcry_cipher_hd_t h)
{
    if (!h->ocb || !h->have_key) {
        return GPG_ERR_INV_STATE;
    }

    if (!h->have_iv) {
        return GPG_ERR_INV_STATE;
    }

    if (h->ocb_nonce_applied) {
        return 0;
    }

    if (!CRYPTO_ocb128_setiv(h->ocb, h->iv, h->ivlen, h->taglen)) {
        ERR_clear_error();
        return GPG_ERR_INV_LENGTH;
    }

    h->ocb_nonce_applied = 1;
    return 0;
}

static gcry_err_code_t
do_ocb_crypt(gcry_cipher_hd_t h, int enc, unsigned char *out, size_t outsize,
             const unsigned char *in, size_t inlen)
{
    gcry_err_code_t rc;

    if (outsize < inlen) {
        return GPG_ERR_BUFFER_TOO_SHORT;
    }

    if (h->tag_ready || h->data_done) {
        return GPG_ERR_INV_STATE;
    }

    if (h->data_started && h->enc != enc) {
        return GPG_ERR_INV_STATE;
    }

    if ((inlen % 16) && !h->finalize) {
        return GPG_ERR_INV_LENGTH; /* Partial blocks only at the end. */
    }

    if (h->ocb_native) {
        rc = ocb_native_crypt(h, enc, out, in, inlen);

        if (rc) {
            return rc;
        }

        h->data_started = 1;

        if (inlen % 16 || h->finalize) {
            h->data_done = 1;
        }

        return 0;
    }

    rc = ocb_apply_nonce(h);

    if (rc) {
        return rc;
    }

    h->data_started = 1;
    h->enc = enc;

    if (inlen) {
        int ok = enc ? CRYPTO_ocb128_encrypt(h->ocb, in, out, inlen)
                 : CRYPTO_ocb128_decrypt(h->ocb, in, out, inlen);

        if (!ok) {
            ERR_clear_error();
            return GPG_ERR_INV_LENGTH;
        }
    }

    if (inlen % 16 || h->finalize) {
        h->data_done = 1;
    }

    return 0;
}

static gcry_err_code_t
cipher_crypt(gcry_cipher_hd_t h, int enc, void *outbuf, size_t outsize,
             const void *inbuf, size_t inlen)
{
    unsigned char *out = outbuf;
    const unsigned char *in = inbuf;
    size_t bs = h->spec->blocksize;
    gcry_err_code_t rc;

    if (!in) {
        in = out;
        inlen = outsize;
    }

    if (!h->have_key) {
        log_error("cipher_%s: key not set\n", enc ? "encrypt" : "decrypt");
        return GPG_ERR_MISSING_KEY;
    }

    switch (h->mode) {
    case GCRY_CIPHER_MODE_ECB:
    case GCRY_CIPHER_MODE_CBC:

        /* The MAC flag only changes encryption; decryption is plain CBC. */
        if (h->mode == GCRY_CIPHER_MODE_CBC && (h->flags & GCRY_CIPHER_CBC_MAC)
            && enc) {
            return do_cbc_mac(h, out, outsize, in, inlen);
        }

        if (h->mode == GCRY_CIPHER_MODE_CBC && (h->flags & GCRY_CIPHER_CBC_CTS)) {
            return do_cts(h, enc, out, outsize, in, inlen);
        }

        if (outsize < inlen) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }

        if (inlen % bs) {
            return GPG_ERR_INV_LENGTH;
        }

        rc = ensure_ctx(h, enc);

        if (rc) {
            return rc;
        }

        return evp_update(h->ctx, out, in, inlen);

    case GCRY_CIPHER_MODE_CFB:
    case GCRY_CIPHER_MODE_CFB8:
    case GCRY_CIPHER_MODE_OFB:
    case GCRY_CIPHER_MODE_STREAM:
        if (outsize < inlen) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }

        rc = ensure_ctx(h, enc);

        if (rc) {
            return rc;
        }

        if (h->mode == GCRY_CIPHER_MODE_CFB && !enc) {
            track_ciphertext(h, in, inlen);
        }

        rc = evp_update(h->ctx, out, in, inlen);

        if (!rc && h->mode == GCRY_CIPHER_MODE_CFB && enc) {
            track_ciphertext(h, out, inlen);
        }

        return rc;

    case GCRY_CIPHER_MODE_CTR:
        if (outsize < inlen) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }

        if (h->generic_ctr) {
            return generic_ctr_crypt(h, out, in, inlen);
        }

        rc = ensure_ctx(h, 1);

        if (rc) {
            return rc;
        }

        return evp_update(h->ctx, out, in, inlen);

    case GCRY_CIPHER_MODE_CCM:
        return do_ccm_crypt(h, enc, out, outsize, in, inlen);

    case GCRY_CIPHER_MODE_OCB:
        return do_ocb_crypt(h, enc, out, outsize, in, inlen);

    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_POLY1305:
    case GCRY_CIPHER_MODE_SIV:
    case GCRY_CIPHER_MODE_GCM_SIV:
        return do_evp_aead(h, enc, out, outsize, in, inlen);

    case GCRY_CIPHER_MODE_XTS:
        return do_xts(h, enc, out, outsize, in, inlen);

    case GCRY_CIPHER_MODE_AESWRAP:
        return do_wrap(h, enc, out, outsize, in, inlen);

    default:
        return GPG_ERR_INV_CIPHER_MODE;
    }
}

gcry_error_t
gcry_cipher_encrypt(gcry_cipher_hd_t h, void *out, size_t outsize,
                    const void *in, size_t inlen)
{
    gcry_err_code_t rc;

    /* A NULL IN with INLEN 0 requests an in-place operation on OUT. */
    if (!h || (!out && outsize) || (!in && inlen)) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    rc = cipher_crypt(h, 1, out, outsize, in, inlen);

    if (rc && out) {
        /* Never leave plaintext behind in the output buffer. */
        memset(out, 0x42, outsize);
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_cipher_decrypt(gcry_cipher_hd_t h, void *out, size_t outsize,
                    const void *in, size_t inlen)
{
    /* A NULL IN with INLEN 0 requests an in-place operation on OUT. */
    if (!h || (!out && outsize) || (!in && inlen)) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_crypt(h, 0, out, outsize, in, inlen));
}

/* ------------------------------------------------------------------ */
/* AEAD: associated data and tags                                      */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
cipher_authenticate(gcry_cipher_hd_t h, const void *abuf, size_t abuflen)
{
    gcry_err_code_t rc;

    if (!abuf && abuflen) {
        return GPG_ERR_INV_ARG;
    }

    switch (h->mode) {
    case GCRY_CIPHER_MODE_GCM:
        if (h->aad_done || h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        if (h->ctx_ready) {
            return evp_update(h->ctx, NULL, abuf, abuflen);
        }

        return buffer_append(h, &h->aad, &h->aadlen, &h->aadcap, abuf,
                             abuflen);

    case GCRY_CIPHER_MODE_POLY1305:
        if (h->aad_done || h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        if (h->ctx_ready) {
            return evp_update(h->ctx, NULL, abuf, abuflen);
        }

        return buffer_append(h, &h->aad, &h->aadlen, &h->aadcap, abuf,
                             abuflen);

    case GCRY_CIPHER_MODE_GCM_SIV:

        /* The nonce comes first, the decryption tag closes the AAD. */
        if (!h->have_iv || h->dectag_set || h->aad_done || h->tag_ready
            || h->data_done) {
            return GPG_ERR_INV_STATE;
        }

        return buffer_append(h, &h->aad, &h->aadlen, &h->aadcap, abuf,
                             abuflen);

    case GCRY_CIPHER_MODE_SIV:

        /* Components come before the nonce (the last S2V input). */
        if (h->have_iv || h->data_started || h->data_done || h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        return aad_store(h, abuf, abuflen);

    case GCRY_CIPHER_MODE_CCM:
        if (!h->have_iv || !h->ccm_lengths_set || h->data_started
            || h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        if (abuflen > h->ccm_aadlen - h->aadlen) {
            return GPG_ERR_INV_LENGTH;
        }

        return buffer_append(h, &h->aad, &h->aadlen, &h->aadcap, abuf,
                             abuflen);

    case GCRY_CIPHER_MODE_OCB:
        if (h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        if (h->ocb_native) {
            /* Before the direction is known the data is buffered and fed
             * when the context starts; afterwards it goes straight in. */
            if (h->ocb_nonce_applied) {
                h->aad_done = 1; /* Marks that AAD went into the state. */
                return evp_update(h->ctx, NULL, abuf, abuflen);
            }

            return buffer_append(h, &h->aad, &h->aadlen, &h->aadcap, abuf,
                                 abuflen);
        }

        rc = ocb_apply_nonce(h);

        if (rc) {
            return rc;
        }

        if (abuflen && !CRYPTO_ocb128_aad(h->ocb, abuf, abuflen)) {
            ERR_clear_error();
            return GPG_ERR_INTERNAL;
        }

        h->aad_done = 1; /* Marks that AAD went into the OCB state. */
        return 0;

    default:
        log_error("gcry_cipher_authenticate: invalid mode %d\n", h->mode);
        return GPG_ERR_INV_CIPHER_MODE;
    }
}

gcry_error_t
gcry_cipher_authenticate(gcry_cipher_hd_t hd, const void *abuf,
                         size_t abuflen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_authenticate(hd, abuf, abuflen));
}

/* The GCM tag lengths NIST allows; the reference accepts exactly these. */
static int
gcm_tag_length_valid(size_t taglen)
{
    return taglen == 4 || taglen == 8 || (taglen >= 12 && taglen <= 16);
}

/* Finish an EVP AEAD encryption and fetch the full tag. */
static gcry_err_code_t
evp_finish_encrypt(gcry_cipher_hd_t h)
{
    gcry_err_code_t rc;
    int outl = 0;
    unsigned char dummy[16];

    if (h->tag_ready) {
        return 0;
    }

    rc = ensure_ctx(h, 1);

    if (rc) {
        return rc;
    }

    if (!h->enc) {
        return GPG_ERR_INV_STATE;
    }

    h->aad_done = 1;

    if (!h->data_done && !EVP_EncryptFinal_ex(h->ctx, dummy, &outl)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    if (!EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_GET_TAG, 16, h->tag)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    h->tag_ready = 1;
    h->data_done = 1;
    return 0;
}

/* Finish an EVP AEAD decryption against the tag INTAG of TAGLEN bytes. */
static gcry_err_code_t
evp_finish_decrypt(gcry_cipher_hd_t h, const unsigned char *intag,
                   size_t taglen)
{
    gcry_err_code_t rc;
    int outl = 0;
    unsigned char dummy[16];

    if (h->tag_ready) {
        /* Already verified: repeat the previous answer for the same tag. */
        if (!h->verify_failed && taglen <= 16
            && !CRYPTO_memcmp(intag, h->dectag, taglen)) {
            return 0;
        }

        return GPG_ERR_CHECKSUM;
    }

    rc = ensure_ctx(h, 0);

    if (rc) {
        return rc;
    }

    if (h->enc) {
        return GPG_ERR_INV_STATE;
    }

    h->aad_done = 1;

    if (!h->data_done) {
        if (!EVP_CIPHER_CTX_ctrl(h->ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen,
                                 (void *)(uintptr_t)intag)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        if (!EVP_DecryptFinal_ex(h->ctx, dummy, &outl)) {
            ERR_clear_error();
            h->verify_failed = 1;
        }
    }

    memcpy(h->dectag, intag, taglen);
    h->tag_ready = 1;
    h->data_done = 1;
    return h->verify_failed ? GPG_ERR_CHECKSUM : 0;
}

/* The tag of a single shot (SIV, GCM-SIV) message on the encryption side;
 * asking for it before any data closes an empty message, as the reference
 * does. */
static gcry_err_code_t
siv_encrypt_tag(gcry_cipher_hd_t h)
{
    gcry_err_code_t rc;

    if (h->tag_ready) {
        return 0;
    }

    if (!h->data_done) {
        rc = do_evp_aead(h, 1, NULL, 0, NULL, 0);

        if (rc) {
            return rc;
        }
    }

    return evp_finish_encrypt(h);
}

static gcry_err_code_t
ccm_tag(gcry_cipher_hd_t h, size_t taglen)
{
    gcry_err_code_t rc;

    if (!taglen) {
        return GPG_ERR_INV_ARG;
    }

    if (!h->ccm_lengths_set) {
        return GPG_ERR_INV_LENGTH;
    }

    if (!h->have_iv || h->aadlen != h->ccm_aadlen) {
        return GPG_ERR_INV_STATE;
    }

    if (taglen != h->taglen) {
        return GPG_ERR_INV_LENGTH;
    }

    if (h->ccm_processed != h->ccm_encryptlen) {
        return GPG_ERR_UNFINISHED;
    }

    if (!h->tag_ready) {
        rc = ccm_compute_tag(h, h->tag);

        if (rc) {
            return rc;
        }

        h->tag_ready = 1;
    }

    return 0;
}

static gcry_err_code_t
cipher_gettag(gcry_cipher_hd_t h, void *outtag, size_t taglen)
{
    gcry_err_code_t rc;

    if (!outtag) {
        return GPG_ERR_INV_ARG;
    }

    switch (h->mode) {
    case GCRY_CIPHER_MODE_GCM:
        if (taglen < 16 && !gcm_tag_length_valid(taglen)) {
            return GPG_ERR_INV_LENGTH;
        }

        rc = gcm_finish(h);

        if (rc) {
            return rc;
        }

        memcpy(outtag, h->tag, taglen > 16 ? 16 : taglen);
        return 0;

    case GCRY_CIPHER_MODE_POLY1305:
        if (taglen < 16) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }

        if (h->data_started && !h->enc) {
            /* The reference returns the computed tag of a decryption;
             * OpenSSL's AEAD cipher only verifies it. */
            return GPG_ERR_INV_STATE;
        }

        rc = evp_finish_encrypt(h);

        if (rc) {
            return rc;
        }

        memcpy(outtag, h->tag, 16);
        return 0;

    case GCRY_CIPHER_MODE_SIV:
        if (h->dectag_set) {
            return GPG_ERR_INV_STATE; /* A decryption handle has no tag. */
        }

        rc = siv_encrypt_tag(h);

        if (rc) {
            return rc;
        }

        memcpy(outtag, h->tag, taglen > 16 ? 16 : taglen);
        return 0;

    case GCRY_CIPHER_MODE_GCM_SIV:
        if (h->dectag_set) {
            /* The reference hands back the tag it was given. */
            memcpy(outtag, h->dectag, taglen > 16 ? 16 : taglen);
            return 0;
        }

        rc = siv_encrypt_tag(h);

        if (rc) {
            return rc;
        }

        memcpy(outtag, h->tag, taglen > 16 ? 16 : taglen);
        return 0;

    case GCRY_CIPHER_MODE_CCM:
        rc = ccm_tag(h, taglen);

        if (rc) {
            return rc;
        }

        memcpy(outtag, h->tag, taglen);
        return 0;

    case GCRY_CIPHER_MODE_OCB:

        /* The caller must announce the last data chunk with
         * gcry_cipher_final() before the tag exists. */
        if (!h->data_done) {
            return GPG_ERR_INV_STATE;
        }

        if (h->ocb_native) {
            rc = ocb_native_start(h, 1);

            if (!rc) {
                rc = ocb_native_finish(h, NULL);
            }

            if (rc) {
                return rc;
            }

            memcpy(outtag, h->tag, taglen > h->taglen ? h->taglen : taglen);
            return 0;
        }

        rc = ocb_apply_nonce(h);

        if (rc) {
            return rc;
        }

        if (!h->tag_ready) {
            if (!CRYPTO_ocb128_tag(h->ocb, h->tag, h->taglen)) {
                ERR_clear_error();
                return GPG_ERR_INV_STATE;
            }

            h->tag_ready = 1;
        }

        memcpy(outtag, h->tag, taglen > h->taglen ? h->taglen : taglen);
        return 0;

    default:
        log_error("gcry_cipher_gettag: invalid mode %d\n", h->mode);
        return GPG_ERR_INV_CIPHER_MODE;
    }
}

gcry_error_t
gcry_cipher_gettag(gcry_cipher_hd_t hd, void *outtag, size_t taglen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_gettag(hd, outtag, taglen));
}

static gcry_err_code_t
cipher_checktag(gcry_cipher_hd_t h, const void *intag, size_t taglen)
{
    gcry_err_code_t rc;
    unsigned char tag[16];

    if (!intag) {
        return GPG_ERR_INV_ARG;
    }

    switch (h->mode) {
    case GCRY_CIPHER_MODE_GCM:
        if (!gcm_tag_length_valid(taglen)) {
            return taglen > 16 ? GPG_ERR_CHECKSUM : GPG_ERR_INV_LENGTH;
        }

        rc = gcm_finish(h);

        if (rc) {
            return rc;
        }

        if (h->verify_failed) {
            return GPG_ERR_CHECKSUM;
        }

        return CRYPTO_memcmp(intag, h->tag, taglen) ? GPG_ERR_CHECKSUM : 0;

    case GCRY_CIPHER_MODE_POLY1305:
        if (taglen < 16) {
            return GPG_ERR_BUFFER_TOO_SHORT;
        }

        if (taglen > 16) {
            return GPG_ERR_CHECKSUM;
        }

        if (h->enc && (h->data_started || h->tag_ready)) {
            rc = evp_finish_encrypt(h);

            if (rc) {
                return rc;
            }

            return CRYPTO_memcmp(intag, h->tag, 16) ? GPG_ERR_CHECKSUM : 0;
        }

        return evp_finish_decrypt(h, intag, taglen);

    case GCRY_CIPHER_MODE_SIV:
        if (taglen != 16) {
            return GPG_ERR_CHECKSUM;
        }

        if (h->dectag_set) {
            if (!h->data_done) {
                return GPG_ERR_INV_STATE;
            }

            if (h->verify_failed || CRYPTO_memcmp(intag, h->dectag, 16)) {
                return GPG_ERR_CHECKSUM;
            }

            return 0;
        }

        rc = siv_encrypt_tag(h);

        if (rc) {
            return rc;
        }

        return CRYPTO_memcmp(intag, h->tag, 16) ? GPG_ERR_CHECKSUM : 0;

    case GCRY_CIPHER_MODE_GCM_SIV:
        if (taglen != 16) {
            return GPG_ERR_CHECKSUM;
        }

        if (h->dectag_set) {
            /* Compared against the tag that was set, as the reference
             * does, so it also answers after a failed decryption. */
            return CRYPTO_memcmp(intag, h->dectag, 16) ? GPG_ERR_CHECKSUM
                   : 0;
        }

        rc = siv_encrypt_tag(h);

        if (rc) {
            return rc;
        }

        return CRYPTO_memcmp(intag, h->tag, 16) ? GPG_ERR_CHECKSUM : 0;

    case GCRY_CIPHER_MODE_CCM:
        rc = ccm_tag(h, taglen);

        if (rc) {
            return rc;
        }

        return CRYPTO_memcmp(intag, h->tag, taglen) ? GPG_ERR_CHECKSUM : 0;

    case GCRY_CIPHER_MODE_OCB:
        if (!h->data_done) {
            return GPG_ERR_INV_STATE;
        }

        if (taglen != h->taglen) {
            return GPG_ERR_INV_LENGTH;
        }

        if (h->ocb_native) {
            if (h->tag_ready) {
                /* Verified once; repeat the answer for the same tag. */
                return (!h->verify_failed
                        && !CRYPTO_memcmp(intag, h->dectag, taglen))
                       ? 0 : GPG_ERR_CHECKSUM;
            }

            rc = ocb_native_start(h, 0);

            if (!rc) {
                rc = ocb_native_finish(h, intag);
            }

            if (rc) {
                return rc;
            }

            return h->verify_failed ? GPG_ERR_CHECKSUM : 0;
        }

        rc = ocb_apply_nonce(h);

        if (rc) {
            return rc;
        }

        if (!h->tag_ready) {
            if (!CRYPTO_ocb128_tag(h->ocb, h->tag, h->taglen)) {
                ERR_clear_error();
                return GPG_ERR_INV_STATE;
            }

            h->tag_ready = 1;
        }

        memcpy(tag, h->tag, h->taglen);
        return CRYPTO_memcmp(intag, tag, taglen) ? GPG_ERR_CHECKSUM : 0;

    default:
        log_error("gcry_cipher_checktag: invalid mode %d\n", h->mode);
        return GPG_ERR_INV_CIPHER_MODE;
    }
}

gcry_error_t
gcry_cipher_checktag(gcry_cipher_hd_t hd, const void *intag, size_t taglen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(cipher_checktag(hd, intag, taglen));
}

/* ------------------------------------------------------------------ */
/* IV generation                                                       */
/* ------------------------------------------------------------------ */

gcry_error_t
gcry_cipher_setup_geniv(gcry_cipher_hd_t hd, int method, const void *fixed_iv,
                        size_t fixed_ivlen, const void *dyn_iv,
                        size_t dyn_ivlen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (method != GCRY_CIPHER_GENIV_METHOD_CONCAT) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (fixed_ivlen + dyn_ivlen > MAX_BLOCKSIZE) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if ((!fixed_iv && fixed_ivlen) || (!dyn_iv && dyn_ivlen)) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    hd->geniv_method = method;
    hd->geniv_fixedlen = fixed_ivlen;
    hd->geniv_dynlen = dyn_ivlen;
    memset(hd->geniv_fixed, 0, sizeof hd->geniv_fixed);
    memset(hd->geniv_dyn, 0, sizeof hd->geniv_dyn);

    if (fixed_ivlen) {
        memcpy(hd->geniv_fixed, fixed_iv, fixed_ivlen);
    }

    if (dyn_ivlen) {
        memcpy(hd->geniv_dyn, dyn_iv, dyn_ivlen);
    }

    return 0;
}

gcry_error_t
gcry_cipher_geniv(gcry_cipher_hd_t hd, void *iv, size_t ivlen)
{
    gcry_err_code_t rc;
    unsigned char *p = iv;
    size_t i;

    if (!hd || !iv) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (hd->geniv_method != GCRY_CIPHER_GENIV_METHOD_CONCAT) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (ivlen != hd->geniv_fixedlen + hd->geniv_dynlen) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    memcpy(p, hd->geniv_fixed, hd->geniv_fixedlen);
    memcpy(p + hd->geniv_fixedlen, hd->geniv_dyn, hd->geniv_dynlen);
    rc = cipher_setiv(hd, iv, ivlen);

    for (i = hd->geniv_dynlen; i > 0; i--) {
        if (++hd->geniv_dyn[i - 1] != 0) {
            break;
        }
    }

    return GCRY_ERR(rc);
}

/* ------------------------------------------------------------------ */
/* Control and information                                             */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
cipher_sync(gcry_cipher_hd_t h)
{
    if ((h->flags & GCRY_CIPHER_ENABLE_SYNC) && h->unused
        && h->mode == GCRY_CIPHER_MODE_CFB) {
        /* OpenPGP resynchronisation: the next block is fed with the last
         * block of ciphertext, discarding the pending keystream. */
        memcpy(h->iv, h->lastct, h->spec->blocksize);
        h->ivlen = h->spec->blocksize;
        h->have_iv = 1;
        h->unused = 0;
        h->ctx_ready = 0;
    }

    return 0;
}

static gcry_err_code_t
ccm_set_lengths(gcry_cipher_hd_t h, unsigned long long encryptlen,
                unsigned long long aadlen, unsigned long long taglen)
{
    size_t noncelen = h->ivlen;
    size_t lfield = 15 - noncelen;
    unsigned int i;

    if (taglen < 4 || taglen > CCM_MAX_TAGLEN || (taglen % 2)) {
        return GPG_ERR_INV_LENGTH;
    }

    if (!h->have_iv || h->tag_ready) {
        return GPG_ERR_INV_STATE;
    }

    if (h->ccm_lengths_set) {
        return GPG_ERR_INV_STATE;
    }

    /* A message longer than the L byte length field can encode is taken
     * as the reference library takes it: the length is truncated in B_0. */
    (void)lfield;

    h->taglen = (size_t)taglen;
    h->ccm_encryptlen = encryptlen;
    h->ccm_aadlen = aadlen;
    h->ccm_lengths_set = 1;

    /* Counter block: flags, nonce, zero counter. */
    for (i = (unsigned int)noncelen + 1; i < 16; i++) {
        h->ctr[i] = 0;
    }

    return 0;
}

static void
disable_cipher_algo(int algo)
{
    const struct algo_spec *spec = spec_from_algo(algo);

    if (spec) {
        algo_disabled[spec_index(spec)] = 1;
    }
}

static gcry_err_code_t
cipher_ctl(gcry_cipher_hd_t h, int cmd, void *buffer, size_t buflen)
{
    gcry_err_code_t rc = 0;

    switch (cmd) {
    case GCRYCTL_RESET: {
        int allow;

        if (!h) {
            return GPG_ERR_INV_ARG;
        }

        allow = h->allow_weak_key;
        reset_message_state(h);
        h->allow_weak_key = allow;
        break;
    }

    case GCRYCTL_FINALIZE:
        if (!h || buffer || buflen) {
            return GPG_ERR_INV_ARG;
        }

        h->finalize = 1;
        break;

    case GCRYCTL_CFB_SYNC:
        if (!h) {
            return GPG_ERR_INV_ARG;
        }

        rc = cipher_sync(h);
        break;

    case GCRYCTL_SET_CBC_CTS:
        if (!h) {
            return GPG_ERR_INV_ARG;
        }

        if (buflen) {
            if (h->flags & GCRY_CIPHER_CBC_MAC) {
                rc = GPG_ERR_INV_FLAG;
            } else if (!(h->flags & GCRY_CIPHER_CBC_CTS)) {
                h->flags |= GCRY_CIPHER_CBC_CTS;

                if (h->mode == GCRY_CIPHER_MODE_CBC) {
                    rc = fetch_mode_ciphers(h);
                    h->ctx_ready = 0;
                }
            }
        } else if (h->flags & GCRY_CIPHER_CBC_CTS) {
            h->flags &= ~(unsigned int)GCRY_CIPHER_CBC_CTS;

            if (h->mode == GCRY_CIPHER_MODE_CBC) {
                rc = fetch_mode_ciphers(h);
                h->ctx_ready = 0;
            }
        }

        break;

    case GCRYCTL_SET_CBC_MAC:
        if (!h) {
            return GPG_ERR_INV_ARG;
        }

        if (buflen) {
            if (h->flags & GCRY_CIPHER_CBC_CTS) {
                rc = GPG_ERR_INV_FLAG;
            } else {
                h->flags |= GCRY_CIPHER_CBC_MAC;
            }
        } else {
            h->flags &= ~(unsigned int)GCRY_CIPHER_CBC_MAC;
        }

        break;

    case GCRYCTL_SET_CCM_LENGTHS: {
        unsigned long long params[3];

        if (!h) {
            return GPG_ERR_INV_ARG;
        }

        if (h->mode != GCRY_CIPHER_MODE_CCM) {
            return GPG_ERR_INV_CIPHER_MODE;
        }

        if (!buffer || buflen != 3 * sizeof(unsigned long long)) {
            return GPG_ERR_INV_ARG;
        }

        memcpy(params, buffer, sizeof params);
        rc = ccm_set_lengths(h, params[0], params[1], params[2]);
        break;
    }

    case GCRYCTL_SET_DECRYPTION_TAG:
        if (!h || !buffer) {
            return GPG_ERR_INV_ARG;
        }

        if (h->mode != GCRY_CIPHER_MODE_SIV && h->mode != GCRY_CIPHER_MODE_GCM_SIV) {
            return GPG_ERR_INV_CIPHER_MODE;
        }

        if (buflen != 16) {
            return GPG_ERR_INV_ARG;
        }

        if (h->data_started || h->data_done || h->tag_ready) {
            return GPG_ERR_INV_STATE;
        }

        if (h->mode == GCRY_CIPHER_MODE_GCM_SIV && h->dectag_set) {
            return GPG_ERR_INV_STATE; /* Only once per message. */
        }

        memcpy(h->dectag, buffer, 16);
        h->dectag_set = 1;
        h->ctx_ready = 0;
        break;

    case GCRYCTL_SET_TAGLEN:
        if (!h || !buffer || buflen != sizeof(int)) {
            return GPG_ERR_INV_ARG;
        }

        if (h->mode != GCRY_CIPHER_MODE_OCB) {
            return GPG_ERR_INV_CIPHER_MODE;
        }

        switch (*(int *)buffer) {
        case 8:
        case 12:
        case 16:

            /* Refused only while a message is in progress; otherwise the
             * new length applies to the next nonce. */
            if (h->ocb_nonce_applied && !h->tag_ready
                && (h->data_started || h->aad_done)) {
                return GPG_ERR_INV_STATE;
            }

            h->taglen = (size_t) * (int *)buffer;
            /* The tag length is part of the nonce formatting. */
            h->ocb_nonce_applied = 0;
            h->ctx_ready = 0;
            break;

        default:
            rc = GPG_ERR_INV_LENGTH;
            break;
        }

        break;

    case GCRYCTL_DISABLE_ALGO:
        if (h || !buffer || buflen != sizeof(int)) {
            return GPG_ERR_CIPHER_ALGO;
        }

        disable_cipher_algo(*(int *)buffer);
        break;

    case GCRYCTL_SET_SBOX:
        rc = GPG_ERR_NOT_SUPPORTED;
        break;

    case GCRYCTL_SET_ALLOW_WEAK_KEY:
        if (!h || buffer || buflen > 1) {
            return GPG_ERR_CIPHER_ALGO;
        }

        h->allow_weak_key = buflen ? 1 : 0;
        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return rc;
}

gcry_error_t
gcry_cipher_ctl(gcry_cipher_hd_t h, int cmd, void *buffer, size_t buflen)
{
    return GCRY_ERR(cipher_ctl(h, cmd, buffer, buflen));
}

gcry_error_t
gcry_cipher_info(gcry_cipher_hd_t h, int what, void *buffer, size_t *nbytes)
{
    gcry_err_code_t rc = 0;

    switch (what) {
    case GCRYCTL_GET_TAGLEN:
        if (!h || buffer || !nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            switch (h->mode) {
            case GCRY_CIPHER_MODE_OCB:
            case GCRY_CIPHER_MODE_CCM:
                *nbytes = h->taglen;
                break;

            case GCRY_CIPHER_MODE_GCM:
                *nbytes = GCRY_GCM_BLOCK_LEN;
                break;

            case GCRY_CIPHER_MODE_POLY1305:
                *nbytes = POLY1305_TAGLEN;
                break;

            case GCRY_CIPHER_MODE_SIV:
            case GCRY_CIPHER_MODE_GCM_SIV:
                *nbytes = GCRY_SIV_BLOCK_LEN;
                break;

            default:
                rc = GPG_ERR_INV_CIPHER_MODE;
                break;
            }
        }

        break;

    case GCRYCTL_GET_KEYLEN:
        if (!h || !buffer || !nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else if (h->mode == GCRY_CIPHER_MODE_AESWRAP) {
            *nbytes = 4;
            memcpy(buffer, h->wrap_plen, 4);
        } else {
            rc = GPG_ERR_INV_CIPHER_MODE;
        }

        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_cipher_algo_info(int algo, int what, void *buffer, size_t *nbytes)
{
    const struct algo_spec *spec = spec_from_algo(algo);
    gcry_err_code_t rc = 0;

    switch (what) {
    case GCRYCTL_GET_KEYLEN:
        if (buffer || !nbytes) {
            rc = GPG_ERR_CIPHER_ALGO;
        } else if (spec && spec->keylen > 0 && spec->keylen <= 512) {
            *nbytes = spec->keylen / 8;
        } else {
            rc = GPG_ERR_CIPHER_ALGO;
        }

        break;

    case GCRYCTL_GET_BLKLEN:
        if (buffer || !nbytes) {
            rc = GPG_ERR_CIPHER_ALGO;
        } else if (spec && spec->blocksize > 0) {
            *nbytes = spec->blocksize;
        } else {
            rc = GPG_ERR_CIPHER_ALGO;
        }

        break;

    case GCRYCTL_TEST_ALGO:
        if (buffer || nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            rc = check_cipher_algo(spec);
        }

        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

const char *
gcry_cipher_algo_name(int algorithm)
{
    const struct algo_spec *spec = spec_from_algo(algorithm);

    return spec ? spec->name : "?";
}

int
gcry_cipher_map_name(const char *name)
{
    const struct algo_spec *spec;

    if (!name) {
        return 0;
    }

    spec = spec_from_oid(name, NULL);

    if (!spec) {
        spec = spec_from_name(name);
    }

    return spec ? spec->algo : 0;
}

int
gcry_cipher_mode_from_oid(const char *string)
{
    int mode = 0;

    if (!string) {
        return 0;
    }

    if (!spec_from_oid(string, &mode)) {
        return 0;
    }

    return mode;
}

size_t
gcry_cipher_get_algo_keylen(int algo)
{
    size_t n;

    if (gcry_cipher_algo_info(algo, GCRYCTL_GET_KEYLEN, NULL, &n)) {
        n = 0;
    }

    return n;
}

size_t
gcry_cipher_get_algo_blklen(int algo)
{
    size_t n;

    if (gcry_cipher_algo_info(algo, GCRYCTL_GET_BLKLEN, NULL, &n)) {
        n = 0;
    }

    return n;
}
