/*
 * mac.c - Message authentication codes (gcry_mac_*).
 *
 * All MACs are OpenSSL EVP_MAC algorithms: "HMAC" (parameterised with the
 * digest), "CMAC" and "GMAC" (parameterised with the block cipher) and
 * "POLY1305".
 */
#include "gcrypt-int.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

enum mac_kind {
    MAC_HMAC,
    MAC_CMAC,
    MAC_GMAC,
    MAC_POLY1305
};

struct mac_spec {
    int algo;
    const char *name;
    enum mac_kind kind;
    int mdalgo;               /* HMAC: the digest algorithm. */
    const char *cipher;       /* CMAC/GMAC: OpenSSL cipher family name
                               * or NULL when OpenSSL lacks the cipher. */
    int keyed_by_length;      /* Cipher name carries the key size. */
    unsigned int keylen;      /* Default key length. */
    unsigned int maclen;
    unsigned int fips;
};

static const struct mac_spec mac_specs[] = {
    { GCRY_MAC_GOST28147_IMIT, "GOST28147_IMIT", MAC_CMAC, 0, NULL, 0, 32, 4, 0 },

    { GCRY_MAC_HMAC_SHA256, "HMAC_SHA256", MAC_HMAC, GCRY_MD_SHA256, NULL, 0, 64, 32, 1 },
    { GCRY_MAC_HMAC_SHA224, "HMAC_SHA224", MAC_HMAC, GCRY_MD_SHA224, NULL, 0, 64, 28, 1 },
    { GCRY_MAC_HMAC_SHA512, "HMAC_SHA512", MAC_HMAC, GCRY_MD_SHA512, NULL, 0, 128, 64, 1 },
    { GCRY_MAC_HMAC_SHA384, "HMAC_SHA384", MAC_HMAC, GCRY_MD_SHA384, NULL, 0, 128, 48, 1 },
    { GCRY_MAC_HMAC_SHA1, "HMAC_SHA1", MAC_HMAC, GCRY_MD_SHA1, NULL, 0, 64, 20, 1 },
    { GCRY_MAC_HMAC_MD5, "HMAC_MD5", MAC_HMAC, GCRY_MD_MD5, NULL, 0, 64, 16, 0 },
    { GCRY_MAC_HMAC_MD4, "HMAC_MD4", MAC_HMAC, GCRY_MD_MD4, NULL, 0, 64, 16, 0 },
    { GCRY_MAC_HMAC_RMD160, "HMAC_RIPEMD160", MAC_HMAC, GCRY_MD_RMD160, NULL, 0, 64, 20, 0 },
    { GCRY_MAC_HMAC_TIGER1, "HMAC_TIGER", MAC_HMAC, GCRY_MD_TIGER1, NULL, 0, 64, 24, 0 },
    { GCRY_MAC_HMAC_WHIRLPOOL, "HMAC_WHIRLPOOL", MAC_HMAC, GCRY_MD_WHIRLPOOL, NULL, 0, 64, 64, 0 },
    { GCRY_MAC_HMAC_GOSTR3411_94, "HMAC_GOSTR3411_94", MAC_HMAC, GCRY_MD_GOSTR3411_94, NULL, 0, 32, 32, 0 },
    { GCRY_MAC_HMAC_STRIBOG256, "HMAC_STRIBOG256", MAC_HMAC, GCRY_MD_STRIBOG256, NULL, 0, 64, 32, 0 },
    { GCRY_MAC_HMAC_STRIBOG512, "HMAC_STRIBOG512", MAC_HMAC, GCRY_MD_STRIBOG512, NULL, 0, 64, 64, 0 },
    { GCRY_MAC_HMAC_MD2, "HMAC_MD2", MAC_HMAC, GCRY_MD_MD2, NULL, 0, 64, 16, 0 },
    { GCRY_MAC_HMAC_SHA3_224, "HMAC_SHA3_224", MAC_HMAC, GCRY_MD_SHA3_224, NULL, 0, 64, 28, 1 },
    { GCRY_MAC_HMAC_SHA3_256, "HMAC_SHA3_256", MAC_HMAC, GCRY_MD_SHA3_256, NULL, 0, 64, 32, 1 },
    { GCRY_MAC_HMAC_SHA3_384, "HMAC_SHA3_384", MAC_HMAC, GCRY_MD_SHA3_384, NULL, 0, 64, 48, 1 },
    { GCRY_MAC_HMAC_SHA3_512, "HMAC_SHA3_512", MAC_HMAC, GCRY_MD_SHA3_512, NULL, 0, 64, 64, 1 },
    { GCRY_MAC_HMAC_GOSTR3411_CP, "HMAC_GOSTR3411_CP", MAC_HMAC, GCRY_MD_GOSTR3411_CP, NULL, 0, 32, 32, 0 },
    { GCRY_MAC_HMAC_BLAKE2B_512, "HMAC_BLAKE2B_512", MAC_HMAC, GCRY_MD_BLAKE2B_512, NULL, 0, 64, 64, 0 },
    { GCRY_MAC_HMAC_BLAKE2B_384, "HMAC_BLAKE2B_384", MAC_HMAC, GCRY_MD_BLAKE2B_384, NULL, 0, 64, 48, 0 },
    { GCRY_MAC_HMAC_BLAKE2B_256, "HMAC_BLAKE2B_256", MAC_HMAC, GCRY_MD_BLAKE2B_256, NULL, 0, 64, 32, 0 },
    { GCRY_MAC_HMAC_BLAKE2B_160, "HMAC_BLAKE2B_160", MAC_HMAC, GCRY_MD_BLAKE2B_160, NULL, 0, 64, 20, 0 },
    { GCRY_MAC_HMAC_BLAKE2S_256, "HMAC_BLAKE2S_256", MAC_HMAC, GCRY_MD_BLAKE2S_256, NULL, 0, 64, 32, 0 },
    { GCRY_MAC_HMAC_BLAKE2S_224, "HMAC_BLAKE2S_224", MAC_HMAC, GCRY_MD_BLAKE2S_224, NULL, 0, 64, 28, 0 },
    { GCRY_MAC_HMAC_BLAKE2S_160, "HMAC_BLAKE2S_160", MAC_HMAC, GCRY_MD_BLAKE2S_160, NULL, 0, 64, 20, 0 },
    { GCRY_MAC_HMAC_BLAKE2S_128, "HMAC_BLAKE2S_128", MAC_HMAC, GCRY_MD_BLAKE2S_128, NULL, 0, 64, 16, 0 },
    { GCRY_MAC_HMAC_SM3, "HMAC_SM3", MAC_HMAC, GCRY_MD_SM3, NULL, 0, 64, 32, 0 },
    { GCRY_MAC_HMAC_SHA512_256, "HMAC_SHA512_256", MAC_HMAC, GCRY_MD_SHA512_256, NULL, 0, 64, 32, 1 },
    { GCRY_MAC_HMAC_SHA512_224, "HMAC_SHA512_224", MAC_HMAC, GCRY_MD_SHA512_224, NULL, 0, 64, 28, 1 },

    { GCRY_MAC_CMAC_AES, "CMAC_AES", MAC_CMAC, 0, "AES", 1, 16, 16, 1 },
    { GCRY_MAC_CMAC_3DES, "CMAC_3DES", MAC_CMAC, 0, "DES-EDE", 0, 24, 8, 0 },
    { GCRY_MAC_CMAC_CAMELLIA, "CMAC_CAMELLIA", MAC_CMAC, 0, "CAMELLIA", 1, 16, 16, 0 },
    { GCRY_MAC_CMAC_CAST5, "CMAC_CAST5", MAC_CMAC, 0, "CAST5", 0, 16, 8, 0 },
    { GCRY_MAC_CMAC_BLOWFISH, "CMAC_BLOWFISH", MAC_CMAC, 0, "BF", 0, 16, 8, 0 },
    { GCRY_MAC_CMAC_TWOFISH, "CMAC_TWOFISH", MAC_CMAC, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_CMAC_SERPENT, "CMAC_SERPENT", MAC_CMAC, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_CMAC_SEED, "CMAC_SEED", MAC_CMAC, 0, "SEED", 0, 16, 16, 0 },
    { GCRY_MAC_CMAC_RFC2268, "CMAC_RFC2268", MAC_CMAC, 0, "RC2", 0, 16, 8, 0 },
    { GCRY_MAC_CMAC_IDEA, "CMAC_IDEA", MAC_CMAC, 0, "IDEA", 0, 16, 8, 0 },
    { GCRY_MAC_CMAC_GOST28147, "CMAC_GOST28147", MAC_CMAC, 0, NULL, 0, 32, 8, 0 },
    { GCRY_MAC_CMAC_SM4, "CMAC_SM4", MAC_CMAC, 0, "SM4", 0, 16, 16, 0 },
    { GCRY_MAC_CMAC_ARIA, "CMAC_ARIA", MAC_CMAC, 0, "ARIA", 1, 16, 16, 0 },

    { GCRY_MAC_GMAC_AES, "GMAC_AES", MAC_GMAC, 0, "AES", 1, 16, 16, 1 },
    { GCRY_MAC_GMAC_CAMELLIA, "GMAC_CAMELLIA", MAC_GMAC, 0, NULL, 1, 16, 16, 0 },
    { GCRY_MAC_GMAC_TWOFISH, "GMAC_TWOFISH", MAC_GMAC, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_GMAC_SERPENT, "GMAC_SERPENT", MAC_GMAC, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_GMAC_SEED, "GMAC_SEED", MAC_GMAC, 0, NULL, 0, 16, 16, 0 },
    { GCRY_MAC_GMAC_SM4, "GMAC_SM4", MAC_GMAC, 0, NULL, 0, 16, 16, 0 },
    { GCRY_MAC_GMAC_ARIA, "GMAC_ARIA", MAC_GMAC, 0, NULL, 1, 16, 16, 0 },

    { GCRY_MAC_POLY1305, "POLY1305", MAC_POLY1305, 0, "", 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_AES, "POLY1305_AES", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_CAMELLIA, "POLY1305_CAMELLIA", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_TWOFISH, "POLY1305_TWOFISH", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_SERPENT, "POLY1305_SERPENT", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_SEED, "POLY1305_SEED", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_SM4, "POLY1305_SM4", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
    { GCRY_MAC_POLY1305_ARIA, "POLY1305_ARIA", MAC_POLY1305, 0, NULL, 0, 32, 16, 0 },
};

struct gcry_mac_handle {
    int algo;
    const struct mac_spec *spec;
    int secure;
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
    unsigned char *key;
    size_t keylen;
    int key_set;
    unsigned char *iv;
    size_t ivlen;
    int iv_set;
    int initialized;        /* EVP_MAC_init done with current key/iv. */
    int finalized;
    unsigned char tag[64];
    size_t taglen;
};

static const struct mac_spec *
spec_from_algo(int algo)
{
    size_t i;

    for (i = 0; i < DIM(mac_specs); i++) {
        if (mac_specs[i].algo == algo) {
            return &mac_specs[i];
        }
    }

    return NULL;
}

static const struct mac_spec *
spec_from_name(const char *name)
{
    size_t i;

    for (i = 0; i < DIM(mac_specs); i++) {
        if (!strcasecmp(name, mac_specs[i].name)) {
            return &mac_specs[i];
        }
    }

    return NULL;
}

static const char *
evp_mac_name(const struct mac_spec *spec)
{
    switch (spec->kind) {
    case MAC_HMAC:
        return "HMAC";

    case MAC_CMAC:
        return "CMAC";

    case MAC_GMAC:
        return "GMAC";

    case MAC_POLY1305:
        return "POLY1305";

    default:
        return NULL;
    }
}

/* The OpenSSL cipher name for SPEC with a key of KEYLEN bytes, written to
 * BUF.  Returns GPG_ERR_INV_KEYLEN for lengths the cipher cannot take. */
static gcry_err_code_t
cipher_name(const struct mac_spec *spec, size_t keylen, char *buf,
            size_t bufsize)
{
    const char *mode = spec->kind == MAC_GMAC ? "GCM" : "CBC";

    if (!spec->cipher) {
        return GPG_ERR_MAC_ALGO;
    }

    if (spec->keyed_by_length) {
        if (keylen != 16 && keylen != 24 && keylen != 32) {
            return GPG_ERR_INV_KEYLEN;
        }

        snprintf(buf, bufsize, "%s-%u-%s", spec->cipher,
                 (unsigned int)keylen * 8, mode);
        return 0;
    }

    if (!strcmp(spec->cipher, "DES-EDE")) {
        if (keylen == 24) {
            snprintf(buf, bufsize, "DES-EDE3-CBC");
        } else if (keylen == 16) {
            snprintf(buf, bufsize, "DES-EDE-CBC");
        } else {
            return GPG_ERR_INV_KEYLEN;
        }

        return 0;
    }

    if (!strcmp(spec->cipher, "CAST5")) {
        if (keylen < 5 || keylen > 16) {
            return GPG_ERR_INV_KEYLEN;
        }
    } else if (!strcmp(spec->cipher, "BF")) {
        if (keylen < 1 || keylen > 56) {
            return GPG_ERR_INV_KEYLEN;
        }
    } else if (!strcmp(spec->cipher, "RC2")) {
        if (keylen < 1 || keylen > 128) {
            return GPG_ERR_INV_KEYLEN;
        }
    } else if (keylen != spec->keylen) {
        return GPG_ERR_INV_KEYLEN;
    }

    snprintf(buf, bufsize, "%s-%s", spec->cipher, mode);
    return 0;
}

/* Can the algorithm be used at all with this OpenSSL? */
static gcry_err_code_t
check_mac_algo(int algo)
{
    const struct mac_spec *spec = spec_from_algo(algo);
    EVP_MAC *mac;

    if (!spec) {
        return GPG_ERR_MAC_ALGO;
    }

    switch (spec->kind) {
    case MAC_HMAC: {
        EVP_MD *md;

        if (_gcry_md_reduced_size(spec->mdalgo)) {
            return GPG_ERR_MAC_ALGO; /* No truncated BLAKE2 in HMAC. */
        }

        md = _gcry_md_fetch(spec->mdalgo);

        if (!md) {
            return GPG_ERR_MAC_ALGO;
        }

        EVP_MD_free(md);
        break;
    }

    case MAC_CMAC:
    case MAC_GMAC: {
        char name[64];
        EVP_CIPHER *cipher;

        if (cipher_name(spec, spec->keylen, name, sizeof name)) {
            return GPG_ERR_MAC_ALGO;
        }

        cipher = EVP_CIPHER_fetch(_gcry_libctx(), name, _gcry_propq());

        if (!cipher) {
            ERR_clear_error();
            return GPG_ERR_MAC_ALGO;
        }

        EVP_CIPHER_free(cipher);
        break;
    }

    case MAC_POLY1305:
        if (!spec->cipher) {
            return GPG_ERR_MAC_ALGO; /* Poly1305-cipher variants. */
        }

        break;

    default:
        return GPG_ERR_MAC_ALGO;
    }

    mac = EVP_MAC_fetch(_gcry_libctx(), evp_mac_name(spec), _gcry_propq());

    if (!mac) {
        ERR_clear_error();
        return GPG_ERR_MAC_ALGO;
    }

    EVP_MAC_free(mac);
    return 0;
}

static void *
mac_alloc(gcry_mac_hd_t hd, size_t n)
{
    return hd->secure ? _gcry_malloc_secure(n) : _gcry_malloc(n);
}

/* Run EVP_MAC_init with the stored key (and IV); this is also how a
 * handle is reset. */
static gcry_err_code_t
mac_init_ctx(gcry_mac_hd_t hd)
{
    OSSL_PARAM params[4];
    size_t np = 0;
    char name[64];
    gcry_err_code_t rc;

    hd->finalized = 0;
    hd->taglen = 0;
    hd->initialized = 0;

    if (!hd->key_set) {
        return 0; /* Nothing to initialise yet. */
    }

    switch (hd->spec->kind) {
    case MAC_HMAC:
        params[np++] = OSSL_PARAM_construct_utf8_string(
                           OSSL_MAC_PARAM_DIGEST,
                           (char *)(uintptr_t)_gcry_md_openssl_name(
                               hd->spec->mdalgo),
                           0);
        break;

    case MAC_CMAC:
        rc = cipher_name(hd->spec, hd->keylen, name, sizeof name);

        if (rc) {
            return rc;
        }

        params[np++] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                        name, 0);
        break;

    case MAC_GMAC:
        if (!hd->iv_set) {
            return 0; /* Wait for the IV. */
        }

        rc = cipher_name(hd->spec, hd->keylen, name, sizeof name);

        if (rc) {
            return rc;
        }

        params[np++] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                        name, 0);
        params[np++] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV,
                                                         hd->iv, hd->ivlen);
        break;

    case MAC_POLY1305:
        break;

    default:
        return GPG_ERR_MAC_ALGO;
    }

    params[np] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(hd->ctx, hd->key, hd->keylen, params)) {
        return _gcry_err_from_openssl(GPG_ERR_INV_KEYLEN);
    }

    hd->initialized = 1;
    return 0;
}

static gcry_err_code_t
mac_open(gcry_mac_hd_t *r_hd, int algo, unsigned int flags)
{
    const struct mac_spec *spec = spec_from_algo(algo);
    gcry_mac_hd_t hd;
    gcry_err_code_t rc;

    *r_hd = NULL;

    if (flags & ~(unsigned int)GCRY_MAC_FLAG_SECURE) {
        return GPG_ERR_INV_ARG;
    }

    if (!spec) {
        return GPG_ERR_MAC_ALGO;
    }

    rc = check_mac_algo(algo);

    if (rc) {
        return rc;
    }

    hd = (flags & GCRY_MAC_FLAG_SECURE) ? _gcry_calloc_secure(1, sizeof * hd)
         : _gcry_calloc(1, sizeof * hd);

    if (!hd) {
        return _gcry_err_code_from_syserror();
    }

    hd->algo = algo;
    hd->spec = spec;
    hd->secure = !!(flags & GCRY_MAC_FLAG_SECURE);
    hd->mac = EVP_MAC_fetch(_gcry_libctx(), evp_mac_name(spec), _gcry_propq());

    if (!hd->mac) {
        _gcry_free(hd);
        return _gcry_err_from_openssl(GPG_ERR_MAC_ALGO);
    }

    hd->ctx = EVP_MAC_CTX_new(hd->mac);

    if (!hd->ctx) {
        EVP_MAC_free(hd->mac);
        _gcry_free(hd);
        return GPG_ERR_ENOMEM;
    }

    *r_hd = hd;
    return 0;
}

static void
mac_close(gcry_mac_hd_t hd)
{
    EVP_MAC_CTX_free(hd->ctx);
    EVP_MAC_free(hd->mac);

    if (hd->key) {
        _gcry_wipememory(hd->key, hd->keylen);
        _gcry_free(hd->key);
    }

    _gcry_free(hd->iv);
    _gcry_wipememory(hd, sizeof * hd);
    _gcry_free(hd);
}

static gcry_err_code_t
mac_setkey(gcry_mac_hd_t hd, const void *key, size_t keylen)
{
    unsigned char *copy;
    char name[64];
    gcry_err_code_t rc;

    if (keylen && !key) {
        return GPG_ERR_INV_ARG;
    }

    switch (hd->spec->kind) {
    case MAC_HMAC:
        break;

    case MAC_CMAC:
    case MAC_GMAC:
        rc = cipher_name(hd->spec, keylen, name, sizeof name);

        if (rc) {
            return rc;
        }

        break;

    case MAC_POLY1305:
        if (keylen != 32) {
            return GPG_ERR_INV_KEYLEN;
        }

        break;

    default:
        return GPG_ERR_MAC_ALGO;
    }

    copy = mac_alloc(hd, keylen ? keylen : 1);

    if (!copy) {
        return _gcry_err_code_from_syserror();
    }

    if (keylen) {
        memcpy(copy, key, keylen);
    }

    if (hd->key) {
        _gcry_wipememory(hd->key, hd->keylen);
        _gcry_free(hd->key);
    }

    hd->key = copy;
    hd->keylen = keylen;
    hd->key_set = 1;
    return mac_init_ctx(hd);
}

static gcry_err_code_t
mac_setiv(gcry_mac_hd_t hd, const void *iv, size_t ivlen)
{
    unsigned char *copy;

    if (hd->spec->kind != MAC_GMAC) {
        return GPG_ERR_INV_ARG;
    }

    if (ivlen && !iv) {
        return GPG_ERR_INV_ARG;
    }

    if (!ivlen) {
        return GPG_ERR_INV_ARG;
    }

    copy = mac_alloc(hd, ivlen);

    if (!copy) {
        return _gcry_err_code_from_syserror();
    }

    memcpy(copy, iv, ivlen);
    _gcry_free(hd->iv);
    hd->iv = copy;
    hd->ivlen = ivlen;
    hd->iv_set = 1;
    return mac_init_ctx(hd);
}

static gcry_err_code_t
mac_write(gcry_mac_hd_t hd, const void *buf, size_t len)
{
    if (len && !buf) {
        return GPG_ERR_INV_ARG;
    }

    if (!hd->initialized || hd->finalized) {
        return GPG_ERR_INV_STATE;
    }

    if (len && !EVP_MAC_update(hd->ctx, buf, len)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    return 0;
}

static gcry_err_code_t
mac_finalize(gcry_mac_hd_t hd)
{
    if (hd->finalized) {
        return 0;
    }

    if (!hd->initialized) {
        return GPG_ERR_INV_STATE;
    }

    if (!EVP_MAC_final(hd->ctx, hd->tag, &hd->taglen, sizeof hd->tag)) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    hd->finalized = 1;
    return 0;
}

static gcry_err_code_t
mac_read(gcry_mac_hd_t hd, void *buf, size_t *buflen)
{
    gcry_err_code_t rc;

    if (!buf || !buflen || !*buflen) {
        return GPG_ERR_INV_ARG;
    }

    rc = mac_finalize(hd);

    if (rc) {
        return rc;
    }

    if (*buflen > hd->taglen) {
        *buflen = hd->taglen;
    }

    memcpy(buf, hd->tag, *buflen);
    return 0;
}

static gcry_err_code_t
mac_verify(gcry_mac_hd_t hd, const void *buf, size_t buflen)
{
    gcry_err_code_t rc;

    if (!buf || !buflen) {
        return GPG_ERR_INV_ARG;
    }

    rc = mac_finalize(hd);

    if (rc) {
        return rc;
    }

    if (buflen > hd->taglen) {
        return GPG_ERR_INV_LENGTH;
    }

    return CRYPTO_memcmp(buf, hd->tag, buflen) ? GPG_ERR_CHECKSUM : 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

gcry_error_t
gcry_mac_open(gcry_mac_hd_t *handle, int algo, unsigned int flags,
              gcry_ctx_t ctx)
{
    (void)ctx;

    if (!handle) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    _gcry_global_init();
    return GCRY_ERR(mac_open(handle, algo, flags));
}

void
gcry_mac_close(gcry_mac_hd_t h)
{
    if (h) {
        mac_close(h);
    }
}

gcry_error_t
gcry_mac_ctl(gcry_mac_hd_t h, int cmd, void *buffer, size_t buflen)
{
    gcry_err_code_t rc;

    (void)buffer;
    (void)buflen;

    if (!h) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    switch (cmd) {
    case GCRYCTL_RESET:
        rc = mac_init_ctx(h);
        break;

    case GCRYCTL_SET_SBOX:
        rc = GPG_ERR_NOT_SUPPORTED;
        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_mac_algo_info(int algo, int what, void *buffer, size_t *nbytes)
{
    gcry_err_code_t rc = 0;

    _gcry_global_init();

    switch (what) {
    case GCRYCTL_GET_KEYLEN:
        if (buffer || !nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            unsigned int ui = gcry_mac_get_algo_keylen(algo);

            if (ui > 0) {
                *nbytes = ui;
            } else {
                rc = GPG_ERR_MAC_ALGO;
            }
        }

        break;

    case GCRYCTL_TEST_ALGO:
        if (buffer || nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            rc = check_mac_algo(algo);
        }

        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_mac_setkey(gcry_mac_hd_t hd, const void *key, size_t keylen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(mac_setkey(hd, key, keylen));
}

gcry_error_t
gcry_mac_setiv(gcry_mac_hd_t hd, const void *iv, size_t ivlen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(mac_setiv(hd, iv, ivlen));
}

gcry_error_t
gcry_mac_write(gcry_mac_hd_t hd, const void *buffer, size_t length)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(mac_write(hd, buffer, length));
}

gcry_error_t
gcry_mac_read(gcry_mac_hd_t hd, void *buffer, size_t *buflen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(mac_read(hd, buffer, buflen));
}

gcry_error_t
gcry_mac_verify(gcry_mac_hd_t hd, const void *buffer, size_t buflen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(mac_verify(hd, buffer, buflen));
}

int
gcry_mac_get_algo(gcry_mac_hd_t hd)
{
    return hd ? hd->algo : 0;
}

unsigned int
gcry_mac_get_algo_maclen(int algo)
{
    const struct mac_spec *spec = spec_from_algo(algo);

    return spec ? spec->maclen : 0;
}

unsigned int
gcry_mac_get_algo_keylen(int algo)
{
    const struct mac_spec *spec = spec_from_algo(algo);

    return spec ? spec->keylen : 0;
}

const char *
gcry_mac_algo_name(int algorithm)
{
    const struct mac_spec *spec = spec_from_algo(algorithm);

    return spec ? spec->name : "?";
}

int
gcry_mac_map_name(const char *name)
{
    const struct mac_spec *spec;

    if (!name) {
        return 0;
    }

    spec = spec_from_name(name);
    return spec ? spec->algo : 0;
}
