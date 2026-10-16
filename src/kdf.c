/*
 * kdf.c - Key derivation functions.
 *
 * PBKDF2, scrypt, Argon2, HKDF, the SP 800-56C one-step KDFs and the
 * X9.63 KDF are OpenSSL EVP_KDF algorithms.  The OpenPGP string-to-key
 * variants (RFC 4880, 3.7.1) have no OpenSSL counterpart; they are
 * iterated digests and are composed here from EVP_MD.
 */
#include "gcrypt-int.h"

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

/* Maximum memory scrypt may use (the default 32 MiB is too small for the
 * published test vectors). */
#define SCRYPT_MAXMEM (1024u * 1024u * 1024u)

/* --- Digest and MAC algorithm mapping ---------------------------------
 * The digest and MAC modules own the mapping of gcrypt algorithm ids to
 * OpenSSL names. */

/* Fetch the digest for a gcrypt digest algorithm id. */
static EVP_MD *
fetch_digest(int algo)
{
    return _gcry_md_fetch(algo);
}

/* The OpenSSL digest name behind an HMAC algorithm id, or NULL. */
static const char *
hmac_digest_name(int macalgo)
{
    int mdalgo = _gcry_mac_hmac_digest_algo(macalgo);

    return mdalgo ? _gcry_md_openssl_name(mdalgo) : NULL;
}

/* The output size of the digest behind a gcrypt digest id, 0 if OpenSSL
 * does not provide it.  Goes through the digest module's cache rather
 * than fetching by name. */
static int
digest_size(int mdalgo)
{
    EVP_MD *md = mdalgo ? _gcry_md_fetch(mdalgo) : NULL;
    int size;

    if (!md) {
        return 0;
    }

    size = EVP_MD_get_size(md);
    EVP_MD_free(md);
    return size > 0 ? size : 0;
}

/* --- OpenPGP string-to-key ------------------------------------------- */

static gcry_err_code_t
openpgp_s2k(const void *passphrase, size_t passphraselen, int algo,
            int hashalgo, const void *salt, size_t saltlen,
            unsigned long iterations, size_t keysize, void *keybuffer)
{
    EVP_MD *md;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen;
    unsigned char *key = keybuffer;
    size_t used = 0;
    unsigned int pass;
    gcry_err_code_t rc = 0;
    int salted = algo == GCRY_KDF_SALTED_S2K
                 || algo == GCRY_KDF_ITERSALTED_S2K;

    if (salted && (!salt || saltlen != 8)) {
        return GPG_ERR_INV_VALUE;
    }

    md = fetch_digest(hashalgo);

    if (!md) {
        return GPG_ERR_DIGEST_ALGO;
    }

    mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        EVP_MD_free(md);
        return GPG_ERR_ENOMEM;
    }

    for (pass = 0; used < keysize; pass++) {
        unsigned int i;
        static const unsigned char zero = 0;

        if (!EVP_DigestInit_ex2(mdctx, md, NULL)) {
            rc = GPG_ERR_INTERNAL;
            goto leave;
        }

        /* Each additional pass is preloaded with that many zero bytes. */
        for (i = 0; i < pass; i++) {
            if (!EVP_DigestUpdate(mdctx, &zero, 1)) {
                rc = GPG_ERR_INTERNAL;
                goto leave;
            }
        }

        if (salted) {
            size_t len2 = passphraselen + 8;
            unsigned long count = len2;

            if (algo == GCRY_KDF_ITERSALTED_S2K) {
                count = iterations;

                if (count < len2) {
                    count = len2;
                }
            }

            while (count > len2) {
                if (!EVP_DigestUpdate(mdctx, salt, saltlen)
                    || !EVP_DigestUpdate(mdctx, passphrase,
                                         passphraselen)) {
                    rc = GPG_ERR_INTERNAL;
                    goto leave;
                }

                count -= len2;
            }

            if (count < saltlen) {
                if (!EVP_DigestUpdate(mdctx, salt, (size_t)count)) {
                    rc = GPG_ERR_INTERNAL;
                    goto leave;
                }
            } else {
                if (!EVP_DigestUpdate(mdctx, salt, saltlen)
                    || !EVP_DigestUpdate(mdctx, passphrase,
                                         (size_t)count - saltlen)) {
                    rc = GPG_ERR_INTERNAL;
                    goto leave;
                }
            }
        } else if (!EVP_DigestUpdate(mdctx, passphrase, passphraselen)) {
            rc = GPG_ERR_INTERNAL;
            goto leave;
        }

        if (!EVP_DigestFinal_ex(mdctx, digest, &dlen)) {
            rc = GPG_ERR_INTERNAL;
            goto leave;
        }

        if (dlen > keysize - used) {
            dlen = (unsigned int)(keysize - used);
        }

        memcpy(key + used, digest, dlen);
        used += dlen;
    }

leave:

    if (rc) {
        ERR_clear_error();
    }

    _gcry_wipememory(digest, sizeof digest);
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    return rc;
}

/* --- EVP_KDF helpers -------------------------------------------------- */

/* Run the named KDF with PARAMS and write OUTLEN bytes to OUT. */
/* The EVP_KDF algorithms used below, fetched once each on first use and
 * kept for the lifetime of the process, like the digest module does with
 * its EVP_MD objects.  A name missing from this list is fetched directly. */
static struct kdf_cache_entry {
    const char *name;
    EVP_KDF *kdf;
} kdf_cache[] = {
    { "PBKDF2", NULL },  { "SCRYPT", NULL },   { "ARGON2D", NULL },
    { "ARGON2I", NULL }, { "ARGON2ID", NULL }, { "SSKDF", NULL },
    { "HKDF", NULL },    { "X963KDF", NULL }
};
static pthread_mutex_t kdf_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* A reference to the named KDF, released by the caller with EVP_KDF_free. */
static EVP_KDF *
fetch_kdf(const char *kdfname)
{
    OSSL_LIB_CTX *libctx = _gcry_libctx();
    const char *propq = _gcry_propq();
    struct kdf_cache_entry *entry = NULL;
    EVP_KDF *kdf;
    size_t i;

    for (i = 0; i < DIM(kdf_cache); i++) {
        if (!strcmp(kdf_cache[i].name, kdfname)) {
            entry = &kdf_cache[i];
            break;
        }
    }

    if (!entry) {
        kdf = EVP_KDF_fetch(libctx, kdfname, propq);

        if (!kdf) {
            ERR_clear_error();
        }

        return kdf;
    }

    pthread_mutex_lock(&kdf_cache_lock);
    kdf = entry->kdf;

    if (!kdf) {
        kdf = EVP_KDF_fetch(libctx, kdfname, propq);

        if (!kdf) {
            ERR_clear_error();
        }

        entry->kdf = kdf;
    }

    if (kdf && !EVP_KDF_up_ref(kdf)) {
        ERR_clear_error();
        kdf = NULL;
    }

    pthread_mutex_unlock(&kdf_cache_lock);
    return kdf;
}

static gcry_err_code_t
run_kdf(const char *kdfname, OSSL_PARAM *params, void *out, size_t outlen,
        gcry_err_code_t fallback)
{
    EVP_KDF *kdf = fetch_kdf(kdfname);
    EVP_KDF_CTX *kctx;
    int ok;

    if (!kdf) {
        return GPG_ERR_UNSUPPORTED_ALGORITHM;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    if (!kctx) {
        return _gcry_err_from_openssl(GPG_ERR_ENOMEM);
    }

    ok = EVP_KDF_derive(kctx, out, outlen, params);
    EVP_KDF_CTX_free(kctx);

    if (ok <= 0) {
        return _gcry_err_from_openssl(fallback);
    }

    return 0;
}

/* OSSL_PARAM_construct_octet_string wants a non-const pointer. */
static OSSL_PARAM
octets(const char *key, const void *data, size_t len)
{
    union {
        const void *c;
        void *v;
    } u;

    u.c = data;
    return OSSL_PARAM_construct_octet_string(key, u.v, len);
}

static OSSL_PARAM
utf8(const char *key, const char *str)
{
    union {
        const char *c;
        char *v;
    } u;

    u.c = str;
    return OSSL_PARAM_construct_utf8_string(key, u.v, 0);
}

static gcry_err_code_t
pbkdf2(const void *passphrase, size_t passphraselen, int hashalgo,
       const void *salt, size_t saltlen, unsigned long iterations,
       size_t keysize, void *keybuffer)
{
    const char *digest = _gcry_md_openssl_name(
                             hashalgo);
    OSSL_PARAM params[6];
    size_t n = 0;
    uint64_t iter = iterations;
    int pkcs5 = 1;

    if (!salt || !iterations || !keysize) {
        return GPG_ERR_INV_VALUE;
    }

    if (!digest || !digest_size(hashalgo)) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (keysize > 0xffffffffu) {
        return GPG_ERR_INV_VALUE;
    }

    params[n++] = octets(OSSL_KDF_PARAM_PASSWORD, passphrase, passphraselen);
    params[n++] = octets(OSSL_KDF_PARAM_SALT, salt, saltlen);
    params[n++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ITER, &iter);
    params[n++] = utf8(OSSL_KDF_PARAM_DIGEST, digest);

    if (!_gcry_fips_mode()) {
        /* Allow short salts and keys as RFC 8018 does; the FIPS provider
         * keeps its SP 800-132 limits. */
        params[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);
    }

    params[n] = OSSL_PARAM_construct_end();
    return run_kdf("PBKDF2", params, keybuffer, keysize, GPG_ERR_INV_VALUE);
}

static gcry_err_code_t
scrypt(const void *passphrase, size_t passphraselen, int algo, int subalgo,
       const void *salt, size_t saltlen, unsigned long iterations,
       size_t keysize, void *keybuffer)
{
    OSSL_PARAM params[7];
    uint64_t cost_n;
    uint32_t r;
    uint32_t p;
    uint64_t maxmem = SCRYPT_MAXMEM;
    size_t n = 0;

    if (subalgo < 1 || !iterations) {
        return GPG_ERR_INV_VALUE;
    }

    if (algo == GCRY_KDF_SCRYPT) {
        r = 8;
    } else if (algo == 41) {
        /* Undocumented variant with r = 1, kept for the published test
         * vectors like the reference implementation does. */
        r = 1;
    } else {
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }

    cost_n = (uint64_t)subalgo;

    if (iterations > 0xffffffffu) {
        return GPG_ERR_INV_VALUE;
    }

    p = (uint32_t)iterations;
    params[n++] = octets(OSSL_KDF_PARAM_PASSWORD, passphrase, passphraselen);
    params[n++] = octets(OSSL_KDF_PARAM_SALT, salt ? salt : "", saltlen);
    params[n++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N,
                                              &cost_n);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &r);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &p);
    params[n++] = OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_MAXMEM,
                                              &maxmem);
    params[n] = OSSL_PARAM_construct_end();
    return run_kdf("SCRYPT", params, keybuffer, keysize, GPG_ERR_INV_VALUE);
}

gpg_error_t
gcry_kdf_derive(const void *passphrase, size_t passphraselen, int algo,
                int subalgo, const void *salt, size_t saltlen,
                unsigned long iterations, size_t keysize, void *keybuffer)
{
    gcry_err_code_t ec;

    if (!passphrase) {
        return GCRY_ERR(GPG_ERR_INV_DATA);
    }

    if (!keybuffer || !keysize) {
        return GCRY_ERR(GPG_ERR_INV_VALUE);
    }

    if (!salt && saltlen) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    _gcry_global_init();

    switch (algo) {
    case GCRY_KDF_SIMPLE_S2K:
    case GCRY_KDF_SALTED_S2K:
    case GCRY_KDF_ITERSALTED_S2K:
        if (!passphraselen) {
            ec = GPG_ERR_INV_DATA;
        } else {
            ec = openpgp_s2k(passphrase, passphraselen, algo, subalgo, salt,
                             saltlen, iterations, keysize, keybuffer);
        }

        break;

    case GCRY_KDF_PBKDF1:
        /* Not offered by the reference implementation either. */
        ec = GPG_ERR_UNSUPPORTED_ALGORITHM;
        break;

    case GCRY_KDF_PBKDF2:
        if (!saltlen || !iterations) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            ec = pbkdf2(passphrase, passphraselen, subalgo, salt, saltlen,
                        iterations, keysize, keybuffer);
        }

        break;

    case 41:
    case GCRY_KDF_SCRYPT:
        ec = scrypt(passphrase, passphraselen, algo, subalgo, salt, saltlen,
                    iterations, keysize, keybuffer);
        break;

    default:
        ec = GPG_ERR_UNKNOWN_ALGORITHM;
        break;
    }

    return GCRY_ERR(ec);
}

/* --- Handle based API ------------------------------------------------- */

struct gcry_kdf_handle {
    int algo;
    int subalgo;
    const char *digest;      /* OpenSSL digest name where applicable. */
    size_t outlen;
    const void *input;
    size_t inputlen;
    const void *salt;
    size_t saltlen;
    const void *key;
    size_t keylen;
    const void *ad;
    size_t adlen;
    unsigned long param[4];
    unsigned int paramlen;
    unsigned char *out;      /* Result once computed. */
    int computed;
};

static gcry_err_code_t
argon2_open(gcry_kdf_hd_t h)
{
    unsigned long m_cost;

    if (h->subalgo != GCRY_KDF_ARGON2D && h->subalgo != GCRY_KDF_ARGON2I
        && h->subalgo != GCRY_KDF_ARGON2ID) {
        return GPG_ERR_INV_VALUE;
    }

    /* param: [ tag length, t_cost, m_cost (KiB), parallelism ] */
    if (h->paramlen < 3 || h->paramlen > 4) {
        return GPG_ERR_INV_VALUE;
    }

    if (h->paramlen < 4) {
        h->param[3] = 1;
    }

    if (!h->param[3] || !h->param[0] || !h->param[1]) {
        return GPG_ERR_INV_VALUE;
    }

    m_cost = h->param[2];

    if (m_cost > SIZE_MAX / 1024) {
        return GPG_ERR_INV_VALUE;
    }

    h->outlen = h->param[0];
    return 0;
}

static gcry_err_code_t
argon2_compute(gcry_kdf_hd_t h)
{
    const char *name = h->subalgo == GCRY_KDF_ARGON2D ? "ARGON2D"
                       : h->subalgo == GCRY_KDF_ARGON2I ? "ARGON2I"
                       : "ARGON2ID";
    OSSL_PARAM params[10];
    size_t n = 0;
    uint32_t iter = (uint32_t)h->param[1];
    uint32_t memcost = (uint32_t)h->param[2];
    uint32_t lanes = (uint32_t)h->param[3];
    uint32_t threads = 1;
    size_t size = h->outlen;

    params[n++] = octets(OSSL_KDF_PARAM_PASSWORD, h->input ? h->input : "",
                         h->inputlen);
    params[n++] = octets(OSSL_KDF_PARAM_SALT, h->salt, h->saltlen);

    if (h->keylen) {
        params[n++] = octets(OSSL_KDF_PARAM_SECRET, h->key, h->keylen);
    }

    if (h->adlen) {
        params[n++] = octets(OSSL_KDF_PARAM_ARGON2_AD, h->ad, h->adlen);
    }

    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST,
                                              &memcost);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,
                                              &lanes);
    params[n++] = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS,
                                              &threads);
    params[n++] = OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &size);
    params[n] = OSSL_PARAM_construct_end();
    return run_kdf(name, params, h->out, h->outlen, GPG_ERR_INV_VALUE);
}

static gcry_err_code_t
sskdf_compute(gcry_kdf_hd_t h)
{
    OSSL_PARAM params[6];
    size_t n = 0;

    params[n++] = octets(OSSL_KDF_PARAM_KEY, h->input, h->inputlen);
    params[n++] = octets(OSSL_KDF_PARAM_INFO, h->ad, h->adlen);
    params[n++] = utf8(OSSL_KDF_PARAM_DIGEST, h->digest);

    if (h->algo == GCRY_KDF_ONESTEP_KDF_MAC) {
        params[n++] = utf8(OSSL_KDF_PARAM_MAC, "HMAC");
        params[n++] = octets(OSSL_KDF_PARAM_SALT, h->key, h->keylen);
    }

    params[n] = OSSL_PARAM_construct_end();
    return run_kdf("SSKDF", params, h->out, h->outlen, GPG_ERR_INV_VALUE);
}

static gcry_err_code_t
hkdf_compute(gcry_kdf_hd_t h)
{
    OSSL_PARAM params[5];
    size_t n = 0;

    params[n++] = octets(OSSL_KDF_PARAM_KEY, h->input, h->inputlen);

    if (h->keylen) {
        params[n++] = octets(OSSL_KDF_PARAM_SALT, h->key, h->keylen);
    }

    if (h->adlen) {
        params[n++] = octets(OSSL_KDF_PARAM_INFO, h->ad, h->adlen);
    }

    params[n++] = utf8(OSSL_KDF_PARAM_DIGEST, h->digest);
    params[n] = OSSL_PARAM_construct_end();
    return run_kdf("HKDF", params, h->out, h->outlen, GPG_ERR_INV_VALUE);
}

static gcry_err_code_t
x963_compute(gcry_kdf_hd_t h)
{
    OSSL_PARAM params[4];
    size_t n = 0;

    params[n++] = octets(OSSL_KDF_PARAM_KEY, h->input, h->inputlen);

    if (h->adlen) {
        params[n++] = octets(OSSL_KDF_PARAM_INFO, h->ad, h->adlen);
    }

    params[n++] = utf8(OSSL_KDF_PARAM_DIGEST, h->digest);
    params[n] = OSSL_PARAM_construct_end();
    return run_kdf("X963KDF", params, h->out, h->outlen, GPG_ERR_INV_VALUE);
}

gcry_error_t
gcry_kdf_open(gcry_kdf_hd_t *hd, int algo, int subalgo,
              const unsigned long *param, unsigned int paramlen,
              const void *passphrase, size_t passphraselen, const void *salt,
              size_t saltlen, const void *key, size_t keylen, const void *ad,
              size_t adlen)
{
    gcry_err_code_t ec = 0;
    gcry_kdf_hd_t h;
    unsigned int i;

    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *hd = NULL;
    _gcry_global_init();

    if (paramlen && !param) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if ((!passphrase && passphraselen) || (!salt && saltlen)
        || (!key && keylen) || (!ad && adlen)) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    h = _gcry_calloc(1, sizeof * h);

    if (!h) {
        return GCRY_ERR(_gcry_err_code_from_syserror());
    }

    h->algo = algo;
    h->subalgo = subalgo;
    h->input = passphrase;
    h->inputlen = passphraselen;
    h->salt = salt;
    h->saltlen = saltlen;
    h->key = key;
    h->keylen = keylen;
    h->ad = ad;
    h->adlen = adlen;
    h->paramlen = paramlen > DIM(h->param) ? (unsigned int)DIM(h->param)
                  : paramlen;

    for (i = 0; i < h->paramlen; i++) {
        h->param[i] = param[i];
    }

    switch (algo) {
    case GCRY_KDF_ARGON2:
        if (!saltlen) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            h->paramlen = paramlen;
            ec = argon2_open(h);
        }

        break;

    case GCRY_KDF_BALLOON:
        if (!passphraselen || !saltlen || keylen || adlen) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            /* OpenSSL has no Balloon hashing. */
            ec = GPG_ERR_NOT_SUPPORTED;
        }

        break;

    case GCRY_KDF_ONESTEP_KDF:
        if (!passphraselen || !paramlen || !adlen) {
            ec = GPG_ERR_INV_VALUE;
        } else if (paramlen != 1) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            h->digest = _gcry_md_openssl_name(
                            subalgo);

            if (!h->digest || !digest_size(subalgo)) {
                ec = GPG_ERR_DIGEST_ALGO;
            } else {
                h->outlen = param[0];
            }
        }

        break;

    case GCRY_KDF_ONESTEP_KDF_MAC:
        if (!passphraselen || !paramlen || !keylen || !adlen) {
            ec = GPG_ERR_INV_VALUE;
        } else if (paramlen != 1) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            h->digest = hmac_digest_name(subalgo);

            if (!h->digest
                || !digest_size(_gcry_mac_hmac_digest_algo(subalgo))) {
                ec = GPG_ERR_MAC_ALGO;
            } else {
                h->outlen = param[0];
            }
        }

        break;

    case GCRY_KDF_HKDF:
        if (!passphraselen || !paramlen) {
            ec = GPG_ERR_INV_VALUE;
        } else if (paramlen != 1 && paramlen != 2) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            int dsize;

            h->digest = hmac_digest_name(subalgo);
            dsize = h->digest
                    ? digest_size(_gcry_mac_hmac_digest_algo(subalgo)) : 0;

            if (!dsize) {
                ec = GPG_ERR_MAC_ALGO;
            } else if (param[0] > 255u * (unsigned int)dsize) {
                ec = GPG_ERR_INV_VALUE;
            } else {
                h->outlen = param[0];
            }
        }

        break;

    case GCRY_KDF_X963_KDF:
        if (!passphraselen || !paramlen) {
            ec = GPG_ERR_INV_VALUE;
        } else if (paramlen != 1) {
            ec = GPG_ERR_INV_VALUE;
        } else {
            h->digest = _gcry_md_openssl_name(
                            subalgo);

            if (!h->digest || !digest_size(subalgo)) {
                ec = GPG_ERR_DIGEST_ALGO;
            } else {
                h->outlen = param[0];
            }
        }

        break;

    default:
        ec = GPG_ERR_UNKNOWN_ALGORITHM;
        break;
    }

    if (!ec && !h->outlen) {
        ec = GPG_ERR_INV_VALUE;
    }

    if (!ec) {
        h->out = _gcry_malloc(h->outlen);

        if (!h->out) {
            ec = _gcry_err_code_from_syserror();
        }
    }

    if (ec) {
        _gcry_free(h);
        return GCRY_ERR(ec);
    }

    *hd = h;
    return 0;
}

static gcry_err_code_t
do_compute(gcry_kdf_hd_t h)
{
    gcry_err_code_t ec;

    if (h->computed) {
        return 0;
    }

    switch (h->algo) {
    case GCRY_KDF_ARGON2:
        ec = argon2_compute(h);
        break;

    case GCRY_KDF_ONESTEP_KDF:
    case GCRY_KDF_ONESTEP_KDF_MAC:
        ec = sskdf_compute(h);
        break;

    case GCRY_KDF_HKDF:
        ec = hkdf_compute(h);
        break;

    case GCRY_KDF_X963_KDF:
        ec = x963_compute(h);
        break;

    default:
        ec = GPG_ERR_UNKNOWN_ALGORITHM;
        break;
    }

    if (!ec) {
        h->computed = 1;
    }

    return ec;
}

gcry_error_t
gcry_kdf_compute(gcry_kdf_hd_t h, const gcry_kdf_thread_ops_t *ops)
{
    if (!h) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    /* Thread dispatch only ever applied to Argon2; OpenSSL runs it in the
     * calling thread, so the callbacks are simply not needed. */
    if (ops && h->algo != GCRY_KDF_ARGON2) {
        return GCRY_ERR(GPG_ERR_INV_VALUE);
    }

    return GCRY_ERR(do_compute(h));
}

gcry_error_t
gcry_kdf_final(gcry_kdf_hd_t h, size_t resultlen, void *result)
{
    gcry_err_code_t ec;

    if (!h || !result) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (resultlen != h->outlen) {
        return GCRY_ERR(GPG_ERR_INV_VALUE);
    }

    ec = do_compute(h);

    if (ec) {
        return GCRY_ERR(ec);
    }

    memcpy(result, h->out, h->outlen);
    return 0;
}

void
gcry_kdf_close(gcry_kdf_hd_t h)
{
    if (!h) {
        return;
    }

    if (h->out) {
        _gcry_wipememory(h->out, h->outlen);
        _gcry_free(h->out);
    }

    _gcry_free(h);
}
