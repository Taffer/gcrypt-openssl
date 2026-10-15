/*
 * pk-util.c - Helpers shared by the public key algorithm modules:
 * parsing of flag lists, "(data ...)", "(sig-val ...)" and "(enc-val ...)"
 * S-expressions, digest helpers and byte string conversions.
 */
#include "gcrypt-int.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/crypto.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>

/* ------------------------------------------------------------------ */
/* Digest table                                                        */
/* ------------------------------------------------------------------ */

static const struct {
    int algo;
    const char *name;      /* Libgcrypt name. */
    const char *ossl;      /* OpenSSL name. */
    unsigned int dlen;
    const char *alias1;
    const char *alias2;
} digests[] = {
    { GCRY_MD_MD5, "MD5", "MD5", 16, "1.2.840.113549.2.5", NULL },
    { GCRY_MD_SHA1, "SHA1", "SHA1", 20, "SHA-1", "1.3.14.3.2.26" },
    { GCRY_MD_RMD160, "RIPEMD160", "RIPEMD160", 20, "RMD160", "1.3.36.3.2.1" },
    { GCRY_MD_MD4, "MD4", "MD4", 16, "1.2.840.113549.2.4", NULL },
    {
        GCRY_MD_SHA224, "SHA224", "SHA224", 28, "SHA-224",
        "2.16.840.1.101.3.4.2.4"
    },
    {
        GCRY_MD_SHA256, "SHA256", "SHA256", 32, "SHA-256",
        "2.16.840.1.101.3.4.2.1"
    },
    {
        GCRY_MD_SHA384, "SHA384", "SHA384", 48, "SHA-384",
        "2.16.840.1.101.3.4.2.2"
    },
    {
        GCRY_MD_SHA512, "SHA512", "SHA512", 64, "SHA-512",
        "2.16.840.1.101.3.4.2.3"
    },
    {
        GCRY_MD_SHA512_224, "SHA512-224", "SHA512-224", 28, "SHA-512/224",
        "2.16.840.1.101.3.4.2.5"
    },
    {
        GCRY_MD_SHA512_256, "SHA512-256", "SHA512-256", 32, "SHA-512/256",
        "2.16.840.1.101.3.4.2.6"
    },
    {
        GCRY_MD_SHA3_224, "SHA3-224", "SHA3-224", 28, "2.16.840.1.101.3.4.2.7",
        NULL
    },
    {
        GCRY_MD_SHA3_256, "SHA3-256", "SHA3-256", 32, "2.16.840.1.101.3.4.2.8",
        NULL
    },
    {
        GCRY_MD_SHA3_384, "SHA3-384", "SHA3-384", 48, "2.16.840.1.101.3.4.2.9",
        NULL
    },
    {
        GCRY_MD_SHA3_512, "SHA3-512", "SHA3-512", 64, "2.16.840.1.101.3.4.2.10",
        NULL
    },
    {
        GCRY_MD_SHAKE128, "SHAKE128", "SHAKE128", 32, "2.16.840.1.101.3.4.2.11",
        NULL
    },
    {
        GCRY_MD_SHAKE256, "SHAKE256", "SHAKE256", 64, "2.16.840.1.101.3.4.2.12",
        NULL
    },
    { GCRY_MD_SM3, "SM3", "SM3", 32, "1.2.156.10197.1.401", NULL },
    {
        GCRY_MD_WHIRLPOOL, "WHIRLPOOL", "WHIRLPOOL", 64, "1.0.10118.3.0.55",
        NULL
    },
    {
        GCRY_MD_BLAKE2B_512, "BLAKE2B_512", "BLAKE2B512", 64,
        "1.3.6.1.4.1.1722.12.2.1.16", NULL
    },
    {
        GCRY_MD_BLAKE2S_256, "BLAKE2S_256", "BLAKE2S256", 32,
        "1.3.6.1.4.1.1722.12.2.2.8", NULL
    },
};

static int
strieq_n(const char *a, const char *b, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (!a[i] || tolower((unsigned char)a[i])
            != tolower((unsigned char)b[i])) {
            return 0;
        }
    }

    return a[n] == 0;
}

int
_gcry_pk_util_hash_algo_from_name(const char *s, size_t n)
{
    size_t i;
    int algo = 0;

    for (i = 0; i < DIM(digests) && !algo; i++) {
        if (strieq_n(digests[i].name, s, n)
            || strieq_n(digests[i].ossl, s, n)
            || (digests[i].alias1 && strieq_n(digests[i].alias1, s, n))
            || (digests[i].alias2 && strieq_n(digests[i].alias2, s, n))) {
            algo = digests[i].algo;
        }
    }

    /* Historic lower case spellings. */
    if (!algo && (strieq_n("rmd160", s, n) || strieq_n("ripemd160", s, n))) {
        algo = GCRY_MD_RMD160;
    }

    /* Anything else the digest module knows, e.g. CRC32 for PKCS#1. */
    if (!algo && n < 64) {
        char name[64];

        memcpy(name, s, n);
        name[n] = 0;
        algo = gcry_md_map_name(name);
    }

    /* A listed but unavailable digest is as good as an unknown one. */
    if (algo && gcry_md_test_algo(algo)) {
        algo = 0;
    }

    return algo;
}

const char *
_gcry_pk_md_openssl_name(int algo)
{
    size_t i;

    for (i = 0; i < DIM(digests); i++) {
        if (digests[i].algo == algo) {
            return digests[i].ossl;
        }
    }

    return NULL;
}

const char *
_gcry_pk_md_gcry_name(int algo)
{
    size_t i;

    for (i = 0; i < DIM(digests); i++) {
        if (digests[i].algo == algo) {
            return digests[i].name;
        }
    }

    return "?";
}

unsigned int
_gcry_pk_md_dlen(int algo)
{
    size_t i;

    for (i = 0; i < DIM(digests); i++) {
        if (digests[i].algo == algo) {
            return digests[i].dlen;
        }
    }

    return 0;
}

gcry_err_code_t
_gcry_pk_md_hash(int algo, const void *data, size_t len, unsigned char *out,
                 size_t outlen)
{
    const char *name = _gcry_pk_md_openssl_name(algo);
    EVP_MD *md;
    EVP_MD_CTX *ctx;
    int ok;

    if (!name) {
        return GPG_ERR_DIGEST_ALGO;
    }

    md = EVP_MD_fetch(_gcry_libctx(), name, _gcry_propq());

    if (!md) {
        ERR_clear_error();
        return GPG_ERR_DIGEST_ALGO;
    }

    ctx = EVP_MD_CTX_new();
    ok = ctx && EVP_DigestInit_ex2(ctx, md, NULL)
         && EVP_DigestUpdate(ctx, data, len);

    if (ok) {
        if (EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) {
            ok = EVP_DigestFinalXOF(ctx, out, outlen);
        } else {
            unsigned int n = 0;

            ok = outlen >= (size_t)EVP_MD_get_size(md)
                 && EVP_DigestFinal_ex(ctx, out, &n);
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);

    if (!ok) {
        return _gcry_err_from_openssl(GPG_ERR_DIGEST_ALGO);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Byte string helpers                                                 */
/* ------------------------------------------------------------------ */

gcry_err_code_t
_gcry_pk_bn_to_fixed(const BIGNUM *bn, unsigned char *buf, size_t len)
{
    if (BN_is_negative(bn) || BN_bn2binpad(bn, buf, (int)len) < 0) {
        ERR_clear_error();
        return GPG_ERR_TOO_LARGE;
    }

    return 0;
}

/* Big endian value of A left padded with zeros to LEN bytes. */
gcry_err_code_t
_gcry_pk_mpi_to_fixed(gcry_mpi_t a, unsigned char *buf, size_t len)
{
    if (mpi_is_opaque(a)) {
        const unsigned char *p;
        unsigned int nbits;
        size_t n;

        p = gcry_mpi_get_opaque(a, &nbits);
        n = (nbits + 7) / 8;

        if (n > len) {
            return GPG_ERR_TOO_LARGE;
        }

        memset(buf, 0, len - n);

        if (n) {
            memcpy(buf + (len - n), p, n);
        }

        return 0;
    }

    return _gcry_pk_bn_to_fixed(_gcry_mpi_bn(a), buf, len);
}

/* Minimal big endian bytes (or the raw bytes of an opaque value). */
gcry_err_code_t
_gcry_pk_mpi_to_bytes(gcry_mpi_t a, unsigned char **r_buf, size_t *r_len)
{
    unsigned char *buf;
    size_t len;

    if (mpi_is_opaque(a)) {
        const unsigned char *p;
        unsigned int nbits;

        p = gcry_mpi_get_opaque(a, &nbits);
        len = (nbits + 7) / 8;
        buf = _gcry_malloc(len ? len : 1);

        if (!buf) {
            return _gcry_err_code_from_syserror();
        }

        if (len) {
            memcpy(buf, p, len);
        }
    } else {
        len = (size_t)BN_num_bytes(_gcry_mpi_bn(a));
        buf = _gcry_malloc(len ? len : 1);

        if (!buf) {
            return _gcry_err_code_from_syserror();
        }

        if (len) {
            BN_bn2bin(_gcry_mpi_bn(a), buf);
        }
    }

    *r_buf = buf;
    *r_len = len;
    return 0;
}

gcry_mpi_t
_gcry_pk_mpi_from_bn(const BIGNUM *bn)
{
    BIGNUM *copy = BN_dup(bn);

    if (!copy) {
        _gcry_fatal_error(GPG_ERR_ENOMEM, NULL);
    }

    return _gcry_mpi_new_from_bn(copy, 0);
}

/* DER encoded SEQUENCE { r, s } <-> MPIs, for DSA and ECDSA. */
gcry_err_code_t
_gcry_pk_rs_from_der(const unsigned char *der, size_t derlen, int is_ecdsa,
                     gcry_mpi_t *r_r, gcry_mpi_t *r_s)
{
    const unsigned char *p = der;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG *esig = NULL;
    DSA_SIG *dsig = NULL;

    *r_r = *r_s = NULL;

    if (is_ecdsa) {
        esig = d2i_ECDSA_SIG(NULL, &p, (long)derlen);

        if (esig) {
            ECDSA_SIG_get0(esig, &r, &s);
        }
    } else {
        dsig = d2i_DSA_SIG(NULL, &p, (long)derlen);

        if (dsig) {
            DSA_SIG_get0(dsig, &r, &s);
        }
    }

    if (!r || !s) {
        ECDSA_SIG_free(esig);
        DSA_SIG_free(dsig);
        return _gcry_err_from_openssl(GPG_ERR_BAD_SIGNATURE);
    }

    *r_r = _gcry_pk_mpi_from_bn(r);
    *r_s = _gcry_pk_mpi_from_bn(s);
    ECDSA_SIG_free(esig);
    DSA_SIG_free(dsig);
    return 0;
}

gcry_err_code_t
_gcry_pk_rs_to_der(gcry_mpi_t r, gcry_mpi_t s, int is_ecdsa,
                   unsigned char **r_der, size_t *r_derlen)
{
    BIGNUM *rb = BN_dup(_gcry_mpi_bn(r));
    BIGNUM *sb = BN_dup(_gcry_mpi_bn(s));
    unsigned char *der = NULL;
    int len = -1;

    if (!rb || !sb) {
        BN_free(rb);
        BN_free(sb);
        return GPG_ERR_ENOMEM;
    }

    if (is_ecdsa) {
        ECDSA_SIG *sig = ECDSA_SIG_new();

        if (sig && ECDSA_SIG_set0(sig, rb, sb)) {
            rb = sb = NULL;
            len = i2d_ECDSA_SIG(sig, &der);
        }

        ECDSA_SIG_free(sig);
    } else {
        DSA_SIG *sig = DSA_SIG_new();

        if (sig && DSA_SIG_set0(sig, rb, sb)) {
            rb = sb = NULL;
            len = i2d_DSA_SIG(sig, &der);
        }

        DSA_SIG_free(sig);
    }

    BN_free(rb);
    BN_free(sb);

    if (len <= 0 || !der) {
        OPENSSL_free(der);
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    *r_der = _gcry_malloc((size_t)len);

    if (!*r_der) {
        OPENSSL_free(der);
        return GPG_ERR_ENOMEM;
    }

    memcpy(*r_der, der, (size_t)len);
    *r_derlen = (size_t)len;
    OPENSSL_free(der);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Flag lists and simple parameters                                    */
/* ------------------------------------------------------------------ */

gcry_err_code_t
_gcry_pk_util_parse_flaglist(gcry_sexp_t list, int *r_flags,
                             enum pk_encoding *r_encoding)
{
    gcry_err_code_t rc = 0;
    const char *s;
    size_t n;
    int i;
    enum pk_encoding encoding = PUBKEY_ENC_UNKNOWN;
    int flags = 0;
    int igninvflag = 0;

    for (i = list ? gcry_sexp_length(list) - 1 : 0; i > 0; i--) {
        s = gcry_sexp_nth_data(list, i, &n);

        if (!s) {
            continue;
        }

#define FLAG_IS(str) (n == strlen(str) && !memcmp(s, (str), n))

        if (FLAG_IS("pss") && encoding == PUBKEY_ENC_UNKNOWN) {
            encoding = PUBKEY_ENC_PSS;
            flags |= PUBKEY_FLAG_FIXEDLEN;
        } else if (FLAG_IS("raw") && encoding == PUBKEY_ENC_UNKNOWN) {
            encoding = PUBKEY_ENC_RAW;
            flags |= PUBKEY_FLAG_RAW_FLAG;
        } else if (FLAG_IS("sm2")) {
            encoding = PUBKEY_ENC_RAW;
            flags |= PUBKEY_FLAG_SM2 | PUBKEY_FLAG_RAW_FLAG;
        } else if (FLAG_IS("comp")) {
            flags |= PUBKEY_FLAG_COMP;
        } else if (FLAG_IS("oaep") && encoding == PUBKEY_ENC_UNKNOWN) {
            encoding = PUBKEY_ENC_OAEP;
            flags |= PUBKEY_FLAG_FIXEDLEN;
        } else if (FLAG_IS("gost")) {
            encoding = PUBKEY_ENC_RAW;
            flags |= PUBKEY_FLAG_GOST;
        } else if (FLAG_IS("eddsa")) {
            encoding = PUBKEY_ENC_RAW;
            flags |= PUBKEY_FLAG_EDDSA | PUBKEY_FLAG_DJB_TWEAK;
        } else if (FLAG_IS("pkcs1") && encoding == PUBKEY_ENC_UNKNOWN) {
            encoding = PUBKEY_ENC_PKCS1;
            flags |= PUBKEY_FLAG_FIXEDLEN;
        } else if (FLAG_IS("param")) {
            flags |= PUBKEY_FLAG_PARAM;
        } else if (FLAG_IS("nocomp")) {
            flags |= PUBKEY_FLAG_NOCOMP;
        } else if (FLAG_IS("rfc6979")) {
            flags |= PUBKEY_FLAG_RFC6979;
        } else if (FLAG_IS("noparam")) {
            ;
        } else if (FLAG_IS("prehash")) {
            flags |= PUBKEY_FLAG_PREHASH;
        } else if (FLAG_IS("use-x931")) {
            flags |= PUBKEY_FLAG_USE_X931;
        } else if (FLAG_IS("pkcs1-raw") && encoding == PUBKEY_ENC_UNKNOWN) {
            encoding = PUBKEY_ENC_PKCS1_RAW;
            flags |= PUBKEY_FLAG_FIXEDLEN;
        } else if (FLAG_IS("djb-tweak")) {
            encoding = PUBKEY_ENC_RAW;
            flags |= PUBKEY_FLAG_DJB_TWEAK;
        } else if (FLAG_IS("no-prefix")) {
            flags |= PUBKEY_FLAG_NO_PREFIX;
        } else if (FLAG_IS("igninvflag")) {
            igninvflag = 1;
        } else if (FLAG_IS("no-keytest")) {
            flags |= PUBKEY_FLAG_NO_KEYTEST;
        } else if (FLAG_IS("no-blinding")) {
            flags |= PUBKEY_FLAG_NO_BLINDING;
        } else if (FLAG_IS("use-fips186")) {
            flags |= PUBKEY_FLAG_USE_FIPS186;
        } else if (FLAG_IS("use-fips186-2")) {
            flags |= PUBKEY_FLAG_USE_FIPS186_2;
        } else if (FLAG_IS("transient-key")) {
            flags |= PUBKEY_FLAG_TRANSIENT_KEY;
        } else if (!igninvflag) {
            rc = GPG_ERR_INV_FLAG;
        }

#undef FLAG_IS
    }

    if (r_flags) {
        *r_flags = flags;
    }

    if (r_encoding) {
        *r_encoding = encoding;
    }

    return rc;
}

/* Read a small decimal parameter such as "(nbits 4:2048)". */
static gcry_err_code_t
get_uint_param(gcry_sexp_t list, const char *name, unsigned long *r_value,
               int *r_found)
{
    gcry_sexp_t l1;
    const char *s;
    size_t n;
    char buf[50];

    *r_value = 0;
    *r_found = 0;
    l1 = gcry_sexp_find_token(list, name, 0);

    if (!l1) {
        return 0;
    }

    s = gcry_sexp_nth_data(l1, 1, &n);

    if (!s || n >= sizeof buf - 1) {
        gcry_sexp_release(l1);
        return GPG_ERR_INV_OBJ;
    }

    memcpy(buf, s, n);
    buf[n] = 0;
    *r_value = strtoul(buf, NULL, 0);
    *r_found = 1;
    gcry_sexp_release(l1);
    return 0;
}

gcry_err_code_t
_gcry_pk_util_get_nbits(gcry_sexp_t list, unsigned int *r_nbits)
{
    unsigned long v;
    int found;
    gcry_err_code_t rc;

    *r_nbits = 0;

    if (!list) {
        return 0;
    }

    rc = get_uint_param(list, "nbits", &v, &found);

    if (!rc) {
        *r_nbits = (unsigned int)v;
    }

    return rc;
}

gcry_err_code_t
_gcry_pk_util_get_rsa_use_e(gcry_sexp_t list, unsigned long *r_e)
{
    int found;
    gcry_err_code_t rc;

    rc = get_uint_param(list, "rsa-use-e", r_e, &found);

    if (rc) {
        *r_e = 0;
        return rc;
    }

    if (!found) {
        *r_e = 65537;
    }

    return 0;
}

static int
name_in_list(const char *name, const char *const *algo_names)
{
    int i;

    for (i = 0; algo_names[i]; i++) {
        if (!strcasecmp(name, algo_names[i])) {
            return 1;
        }
    }

    return 0;
}

gcry_err_code_t
_gcry_pk_util_preparse_sigval(gcry_sexp_t s_sig, const char *const *algo_names,
                              gcry_sexp_t *r_parms, int *r_eccflags)
{
    gcry_err_code_t rc;
    gcry_sexp_t l1 = NULL;
    gcry_sexp_t l2 = NULL;
    char *name = NULL;

    *r_parms = NULL;

    if (r_eccflags) {
        *r_eccflags = 0;
    }

    l1 = gcry_sexp_find_token(s_sig, "sig-val", 0);

    if (!l1) {
        rc = GPG_ERR_INV_OBJ;
        goto leave;
    }

    l2 = gcry_sexp_nth(l1, 1);

    if (!l2) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    name = gcry_sexp_nth_string(l2, 0);

    if (!name) {
        rc = GPG_ERR_INV_OBJ;
        goto leave;
    }

    if (!strcmp(name, "flags")) {
        gcry_sexp_release(l2);
        l2 = gcry_sexp_nth(l1, 2);

        if (!l2) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }

        _gcry_free(name);
        name = gcry_sexp_nth_string(l2, 0);

        if (!name) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }
    }

    if (!name_in_list(name, algo_names)) {
        rc = GPG_ERR_CONFLICT;
        goto leave;
    }

    if (r_eccflags) {
        if (!strcmp(name, "eddsa")) {
            *r_eccflags = PUBKEY_FLAG_EDDSA;
        } else if (!strcmp(name, "gost")) {
            *r_eccflags = PUBKEY_FLAG_GOST;
        } else if (!strcmp(name, "sm2")) {
            *r_eccflags = PUBKEY_FLAG_SM2;
        }
    }

    *r_parms = l2;
    l2 = NULL;
    rc = 0;

leave:
    _gcry_free(name);
    gcry_sexp_release(l2);
    gcry_sexp_release(l1);
    return rc;
}

/* Copy the data of element 1 of the sublist named TOKEN into a fresh
 * buffer.  Returns 0 and NULL buffer if the sublist does not exist. */
static gcry_err_code_t
get_bytes_param(gcry_sexp_t list, const char *token, unsigned char **r_buf,
                size_t *r_len, int required_nonempty)
{
    gcry_sexp_t l1 = gcry_sexp_find_token(list, token, 0);
    const char *s;
    size_t n;

    *r_buf = NULL;
    *r_len = 0;

    if (!l1) {
        return 0;
    }

    s = gcry_sexp_nth_data(l1, 1, &n);

    if (!s) {
        gcry_sexp_release(l1);
        return GPG_ERR_NO_OBJ;
    }

    if (n > 0) {
        *r_buf = _gcry_malloc(n);

        if (!*r_buf) {
            gcry_sexp_release(l1);
            return _gcry_err_code_from_syserror();
        }

        memcpy(*r_buf, s, n);
        *r_len = n;
    } else if (required_nonempty) {
        gcry_sexp_release(l1);
        return GPG_ERR_INV_ARG;
    }

    gcry_sexp_release(l1);
    return 0;
}

static gcry_err_code_t
get_hash_algo_param(gcry_sexp_t list, int *r_algo)
{
    gcry_sexp_t l1 = gcry_sexp_find_token(list, "hash-algo", 0);
    const char *s;
    size_t n;

    if (!l1) {
        return 0;
    }

    s = gcry_sexp_nth_data(l1, 1, &n);

    if (!s) {
        gcry_sexp_release(l1);
        return GPG_ERR_NO_OBJ;
    }

    *r_algo = _gcry_pk_util_hash_algo_from_name(s, n);
    gcry_sexp_release(l1);
    return *r_algo ? 0 : GPG_ERR_DIGEST_ALGO;
}

gcry_err_code_t
_gcry_pk_util_preparse_encval(gcry_sexp_t sexp, const char *const *algo_names,
                              gcry_sexp_t *r_parms, struct pk_data *pd)
{
    gcry_err_code_t rc = 0;
    gcry_sexp_t l1 = NULL;
    gcry_sexp_t l2 = NULL;
    char *name = NULL;
    int parsed_flags = 0;
    int i;

    *r_parms = NULL;
    l1 = gcry_sexp_find_token(sexp, "enc-val", 0);

    if (!l1) {
        rc = GPG_ERR_INV_OBJ;
        goto leave;
    }

    l2 = gcry_sexp_nth(l1, 1);

    if (!l2) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    name = gcry_sexp_nth_string(l2, 0);

    if (!name) {
        rc = GPG_ERR_INV_OBJ;
        goto leave;
    }

    if (!strcmp(name, "flags")) {
        rc = _gcry_pk_util_parse_flaglist(l2, &parsed_flags, &pd->encoding);

        if (rc) {
            goto leave;
        }

        if (pd->encoding == PUBKEY_ENC_PSS) {
            rc = GPG_ERR_CONFLICT;
            goto leave;
        }

        if (pd->encoding == PUBKEY_ENC_OAEP) {
            rc = get_hash_algo_param(l1, &pd->hash_algo);

            if (rc) {
                goto leave;
            }

            rc = get_bytes_param(l1, "label", &pd->label, &pd->labellen, 0);

            if (rc) {
                goto leave;
            }
        }

        /* Skip hash-algo, label and random-override to reach the data. */
        for (i = 2;; i++) {
            const char *s;
            size_t n;

            gcry_sexp_release(l2);
            l2 = gcry_sexp_nth(l1, i);

            if (!l2) {
                break;
            }

            s = gcry_sexp_nth_data(l2, 0, &n);

            if (!s) {
                rc = GPG_ERR_INV_OBJ; /* A list where a name belongs. */
                goto leave;
            }

            if (!(n == 9 && !memcmp(s, "hash-algo", 9))
                && !(n == 5 && !memcmp(s, "label", 5))
                && !(n == 15 && !memcmp(s, "random-override", 15))) {
                break;
            }
        }

        if (!l2) {
            rc = GPG_ERR_NO_OBJ;
            goto leave;
        }

        _gcry_free(name);
        name = gcry_sexp_nth_string(l2, 0);

        if (!name) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }
    } else {
        parsed_flags |= PUBKEY_FLAG_LEGACYRESULT;
    }

    if (!name_in_list(name, algo_names)) {
        rc = GPG_ERR_CONFLICT;
        goto leave;
    }

    *r_parms = l2;
    l2 = NULL;
    pd->flags |= parsed_flags;
    rc = 0;

leave:
    _gcry_free(name);
    gcry_sexp_release(l2);
    gcry_sexp_release(l1);
    return rc;
}

/* ------------------------------------------------------------------ */
/* "(data ...)" parsing                                                */
/* ------------------------------------------------------------------ */

void
_gcry_pk_data_init(struct pk_data *pd, enum pk_operation op,
                   unsigned int nbits)
{
    memset(pd, 0, sizeof * pd);
    pd->op = op;
    pd->nbits = nbits;
    pd->encoding = PUBKEY_ENC_UNKNOWN;
    pd->hash_algo = _gcry_fips_mode() ? GCRY_MD_SHA256 : GCRY_MD_SHA1;
    pd->saltlen = 20;
}

void
_gcry_pk_data_free(struct pk_data *pd)
{
    _gcry_free(pd->value);
    _gcry_free(pd->label);
    _gcry_free(pd->rnd);
    gcry_mpi_release(pd->mpi);
    pd->value = pd->label = pd->rnd = NULL;
    pd->mpi = NULL;
}

/* Store the (hash <algo> <value>) element: algorithm and digest bytes. */
static gcry_err_code_t
take_hash_element(gcry_sexp_t lhash, struct pk_data *pd)
{
    const char *s;
    size_t n;
    void *value;
    size_t valuelen;

    if (gcry_sexp_length(lhash) != 3) {
        return GPG_ERR_INV_OBJ;
    }

    s = gcry_sexp_nth_data(lhash, 1, &n);

    if (!s || !n) {
        return GPG_ERR_INV_OBJ;
    }

    pd->hash_algo = _gcry_pk_util_hash_algo_from_name(s, n);

    if (!pd->hash_algo) {
        return GPG_ERR_DIGEST_ALGO;
    }

    value = gcry_sexp_nth_buffer(lhash, 2, &valuelen);

    if (!value || !valuelen) {
        _gcry_free(value);
        return GPG_ERR_INV_OBJ;
    }

    pd->value = value;
    pd->valuelen = valuelen;
    pd->value_is_hash = 1;
    return 0;
}

/* Store the (value ...) element as bytes; an empty "(value)" is allowed
 * when ALLOW_EMPTY is set. */
static gcry_err_code_t
take_value_bytes(gcry_sexp_t lvalue, struct pk_data *pd, int allow_empty)
{
    size_t valuelen;
    void *value = gcry_sexp_nth_buffer(lvalue, 1, &valuelen);

    if (!value) {
        if (!allow_empty) {
            return GPG_ERR_INV_OBJ;
        }

        value = _gcry_malloc(1);

        if (!value) {
            return _gcry_err_code_from_syserror();
        }

        valuelen = 0;
    }

    pd->value = value;
    pd->valuelen = valuelen;
    pd->value_is_hash = 0;
    return 0;
}

gcry_err_code_t
_gcry_pk_data_parse(gcry_sexp_t input, struct pk_data *pd)
{
    gcry_err_code_t rc = 0;
    gcry_sexp_t ldata;
    gcry_sexp_t lhash = NULL;
    gcry_sexp_t lvalue = NULL;
    gcry_sexp_t lflags;
    int unknown_flag = 0;
    int parsed_flags = 0;

    ldata = gcry_sexp_find_token(input, "data", 0);

    if (!ldata) {
        /* Old style: a bare MPI. */
        pd->mpi = gcry_sexp_nth_mpi(input, 0,
                                    (pd->flags & PUBKEY_FLAG_RAW_FLAG)
                                    ? GCRYMPI_FMT_OPAQUE : GCRYMPI_FMT_STD);

        if (pd->encoding == PUBKEY_ENC_UNKNOWN) {
            pd->encoding = PUBKEY_ENC_RAW;
        }

        return pd->mpi ? 0 : GPG_ERR_INV_OBJ;
    }

    lflags = gcry_sexp_find_token(ldata, "flags", 0);

    if (lflags) {
        if (_gcry_pk_util_parse_flaglist(lflags, &parsed_flags,
                                         &pd->encoding)) {
            unknown_flag = 1;
        }

        gcry_sexp_release(lflags);
    }

    if (pd->encoding == PUBKEY_ENC_UNKNOWN) {
        pd->encoding = PUBKEY_ENC_RAW;
    }

    lhash = gcry_sexp_find_token(ldata, "hash", 0);
    lvalue = lhash ? NULL : gcry_sexp_find_token(ldata, "value", 0);

    if (!(!lhash ^ !lvalue)) {
        rc = GPG_ERR_INV_OBJ;
    } else if (unknown_flag) {
        rc = GPG_ERR_INV_FLAG;
    } else if (pd->encoding == PUBKEY_ENC_RAW
               && ((parsed_flags & PUBKEY_FLAG_EDDSA)
                   || (pd->flags & PUBKEY_FLAG_EDDSA))) {
        /* EdDSA: the message itself, with optional hash-algo and label. */
        if (!lvalue) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }

        rc = get_hash_algo_param(ldata, &pd->hash_algo);

        if (!rc) {
            rc = get_bytes_param(ldata, "label", &pd->label, &pd->labellen, 0);
        }

        if (!rc) {
            rc = take_value_bytes(lvalue, pd, 1);
        }
    } else if (pd->encoding == PUBKEY_ENC_RAW
               && (lhash || (lvalue && (parsed_flags & PUBKEY_FLAG_PREHASH)))
               && ((parsed_flags & PUBKEY_FLAG_RAW_FLAG)
                   || (parsed_flags & PUBKEY_FLAG_RFC6979))) {
        /* Raw encoding with a hash: the DSA/ECDSA way. */
        if (lvalue) {
            rc = get_hash_algo_param(ldata, &pd->hash_algo);

            if (!rc) {
                rc = get_bytes_param(ldata, "label", &pd->label, &pd->labellen,
                                     1);
            }

            if (!rc) {
                rc = take_value_bytes(lvalue, pd, 0);
            }
        } else {
            rc = get_bytes_param(ldata, "label", &pd->label, &pd->labellen, 1);

            if (!rc) {
                rc = take_hash_element(lhash, pd);
            }
        }
    } else if (pd->encoding == PUBKEY_ENC_RAW && lvalue) {
        if (parsed_flags & PUBKEY_FLAG_RFC6979) {
            rc = GPG_ERR_CONFLICT;
            goto leave;
        }

        pd->mpi = gcry_sexp_nth_mpi(lvalue, 1, GCRYMPI_FMT_USG);

        if (!pd->mpi) {
            rc = GPG_ERR_INV_OBJ;
        }
    } else if (pd->encoding == PUBKEY_ENC_PKCS1 && lvalue
               && pd->op == PUBKEY_OP_ENCRYPT) {
        rc = take_value_bytes(lvalue, pd, 0);

        if (!rc) {
            rc = get_bytes_param(ldata, "random-override", &pd->rnd,
                                 &pd->rndlen, 0);
        }
    } else if (pd->encoding == PUBKEY_ENC_PKCS1
               && (lhash || (lvalue && (parsed_flags & PUBKEY_FLAG_PREHASH)))
               && (pd->op == PUBKEY_OP_SIGN || pd->op == PUBKEY_OP_VERIFY)) {
        if (lvalue) {
            rc = get_hash_algo_param(ldata, &pd->hash_algo);

            if (!rc) {
                rc = take_value_bytes(lvalue, pd, 0);
            }
        } else {
            rc = take_hash_element(lhash, pd);
        }
    } else if (pd->encoding == PUBKEY_ENC_PKCS1_RAW && lvalue
               && (pd->op == PUBKEY_OP_SIGN || pd->op == PUBKEY_OP_VERIFY)) {
        if (gcry_sexp_length(lvalue) != 2) {
            rc = GPG_ERR_INV_OBJ;
        } else {
            rc = take_value_bytes(lvalue, pd, 0);
        }
    } else if (pd->encoding == PUBKEY_ENC_OAEP && lvalue
               && pd->op == PUBKEY_OP_ENCRYPT) {
        rc = take_value_bytes(lvalue, pd, 0);

        if (!rc) {
            rc = get_hash_algo_param(ldata, &pd->hash_algo);
        }

        if (!rc) {
            rc = get_bytes_param(ldata, "label", &pd->label, &pd->labellen, 0);
        }

        if (!rc) {
            rc = get_bytes_param(ldata, "random-override", &pd->rnd,
                                 &pd->rndlen, 0);
        }
    } else if (pd->encoding == PUBKEY_ENC_PSS
               && (pd->op == PUBKEY_OP_SIGN || pd->op == PUBKEY_OP_VERIFY)) {
        unsigned long v;
        int found;

        if (lvalue) {
            rc = get_hash_algo_param(ldata, &pd->hash_algo);

            if (!rc) {
                rc = take_value_bytes(lvalue, pd, 0);
            }

            parsed_flags |= PUBKEY_FLAG_PREHASH;
        } else {
            rc = take_hash_element(lhash, pd);
        }

        if (!rc) {
            rc = get_uint_param(ldata, "salt-length", &v, &found);

            if (rc == GPG_ERR_INV_OBJ) {
                rc = GPG_ERR_NO_OBJ; /* "(salt-length)" without a value. */
            }

            if (!rc && found) {
                if (v > 65536) {
                    rc = GPG_ERR_TOO_SHORT;
                } else {
                    pd->saltlen = (unsigned int)v;
                }
            }
        }

        if (!rc) {
            rc = get_bytes_param(ldata, "random-override", &pd->rnd,
                                 &pd->rndlen, 0);

            if (!rc && pd->rnd && pd->rndlen != pd->saltlen) {
                rc = GPG_ERR_INV_ARG;
            }
        }
    } else {
        rc = GPG_ERR_CONFLICT;
    }

leave:
    pd->flags |= parsed_flags;
    gcry_sexp_release(lhash);
    gcry_sexp_release(lvalue);
    gcry_sexp_release(ldata);
    return rc;
}

/* ------------------------------------------------------------------ */
/* PKCS#1 encodings (RFC 8017)                                         */
/* ------------------------------------------------------------------ */
/*
 * These are the padding and encoding methods of RFC 8017 expressed on
 * byte strings: EME-PKCS1-v1_5, EMSA-PKCS1-v1_5, EME-OAEP and EMSA-PSS.
 * They are implemented here instead of through OpenSSL's padding modes
 * because the gcrypt API exposes details OpenSSL does not: a caller may
 * supply the random padding, the seed or the salt ("random-override"),
 * any digest known to gcrypt may be used (CRC-32 has a PKCS#1 prefix
 * here, OpenSSL has no CRC-32 digest at all), the length rules and error
 * codes follow the reference library, and ElGamal uses the same frames.
 * The hashes come from the md module, the random bytes from the random
 * module; this is formatting, not cryptography.
 */

/* Digest length as the encodings see it: the XOFs have fixed sizes. */
static unsigned int
enc_hash_len(int algo)
{
    if (algo == GCRY_MD_SHAKE128) {
        return 32;
    }

    if (algo == GCRY_MD_SHAKE256) {
        return 64;
    }

    return gcry_md_get_algo_dlen(algo);
}

/* Read HLEN digest bytes out of HD, using the XOF interface if needed. */
static gcry_err_code_t
enc_hash_final(gcry_md_hd_t hd, int algo, unsigned char *out,
               unsigned int hlen)
{
    if (gcry_md_get_algo_dlen(algo) == hlen) {
        unsigned char *d = gcry_md_read(hd, algo);

        if (!d) {
            return GPG_ERR_DIGEST_ALGO;
        }

        memcpy(out, d, hlen);
        return 0;
    }

    return gcry_err_code(gcry_md_extract(hd, algo, out, hlen));
}

/* Hash DATA with ALGO into OUT (HLEN bytes). */
static gcry_err_code_t
enc_hash(int algo, const void *data, size_t len, unsigned char *out,
         unsigned int hlen)
{
    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, algo, 0);
    gcry_err_code_t rc;

    if (err) {
        return gcry_err_code(err);
    }

    gcry_md_write(hd, data, len);
    rc = enc_hash_final(hd, algo, out, hlen);
    gcry_md_close(hd);
    return rc;
}

/* MGF1: OUT (OUTLEN bytes) = Hash(SEED || 0) || Hash(SEED || 1) || ... */
static gcry_err_code_t
mgf1(unsigned char *out, size_t outlen, const unsigned char *seed,
     size_t seedlen, int algo)
{
    gcry_md_hd_t hd;
    unsigned int dlen = enc_hash_len(algo);
    unsigned char block[64];
    gcry_error_t err;
    gcry_err_code_t rc = 0;
    size_t done = 0;
    unsigned int idx = 0;

    if (!dlen || dlen > sizeof block) {
        return GPG_ERR_DIGEST_ALGO;
    }

    err = gcry_md_open(&hd, algo, 0);

    if (err) {
        return gcry_err_code(err);
    }

    if (algo == GCRY_MD_SHAKE128 || algo == GCRY_MD_SHAKE256) {
        /* With an XOF the mask is simply the XOF output (RFC 8702). */
        gcry_md_write(hd, seed, seedlen);
        rc = gcry_err_code(gcry_md_extract(hd, algo, out, outlen));
        gcry_md_close(hd);
        return rc;
    }

    while (done < outlen && !rc) {
        unsigned char c[4];
        size_t n = outlen - done < dlen ? outlen - done : dlen;

        if (idx) {
            gcry_md_reset(hd);
        }

        c[0] = (unsigned char)(idx >> 24);
        c[1] = (unsigned char)(idx >> 16);
        c[2] = (unsigned char)(idx >> 8);
        c[3] = (unsigned char)idx;
        gcry_md_write(hd, seed, seedlen);
        gcry_md_write(hd, c, 4);
        rc = enc_hash_final(hd, algo, block, dlen);
        memcpy(out + done, block, n);
        done += n;
        idx++;
    }

    gcry_md_close(hd);
    return rc;
}

gcry_err_code_t
_gcry_pk_pkcs1_encode_for_enc(unsigned int nbits, const unsigned char *value,
                              size_t valuelen, const unsigned char *rnd,
                              size_t rndlen, unsigned char **r_frame,
                              size_t *r_framelen)
{
    size_t nframe = (nbits + 7) / 8;
    unsigned char *frame;
    size_t pslen;
    size_t i;

    *r_frame = NULL;
    *r_framelen = 0;

    /* The reference library only insists on the three fixed bytes and a
     * few bytes of padding, not on PKCS#1's eight. */
    if (!nframe || valuelen + 7 > nframe) {
        return GPG_ERR_TOO_SHORT;
    }

    pslen = nframe - 3 - valuelen;

    if (rnd) {
        if (rndlen != pslen) {
            return GPG_ERR_INV_ARG;
        }

        for (i = 0; i < rndlen; i++) {
            if (!rnd[i]) {
                return GPG_ERR_INV_ARG;
            }
        }
    }

    frame = _gcry_malloc(nframe);

    if (!frame) {
        return _gcry_err_code_from_syserror();
    }

    frame[0] = 0;
    frame[1] = 2;

    if (rnd) {
        memcpy(frame + 2, rnd, pslen);
    } else {
        unsigned char *p = frame + 2;
        size_t need = pslen;

        /* Random non-zero padding: draw a little extra and skip zeros. */
        while (need) {
            unsigned char buf[64];
            size_t n = need + need / 8 + 1;
            size_t j;

            if (n > sizeof buf) {
                n = sizeof buf;
            }

            gcry_randomize(buf, n, GCRY_STRONG_RANDOM);

            for (j = 0; j < n && need; j++) {
                if (buf[j]) {
                    *p++ = buf[j];
                    need--;
                }
            }
        }
    }

    frame[2 + pslen] = 0;
    memcpy(frame + 3 + pslen, value, valuelen);
    *r_frame = frame;
    *r_framelen = nframe;
    return 0;
}

gcry_err_code_t
_gcry_pk_pkcs1_decode_for_enc(const unsigned char *frame, size_t nframe,
                              unsigned char **r_value, size_t *r_valuelen)
{
    size_t n = 0;
    size_t sep;
    unsigned char *value;

    *r_value = NULL;
    *r_valuelen = 0;

    if (nframe < 4) {
        return GPG_ERR_ENCODING_PROBLEM;
    }

    /* The leading zero may already have been stripped by the conversion
     * from a number. */
    if (frame[n] == 0) {
        n++;
    }

    if (frame[n++] != 2) {
        return GPG_ERR_ENCODING_PROBLEM;
    }

    for (sep = n; sep < nframe && frame[sep]; sep++) {
        ;
    }

    if (sep >= nframe || sep - n < 8) {
        return GPG_ERR_ENCODING_PROBLEM;
    }

    sep++;
    value = _gcry_malloc(nframe - sep + 1);

    if (!value) {
        return _gcry_err_code_from_syserror();
    }

    memcpy(value, frame + sep, nframe - sep);
    *r_value = value;
    *r_valuelen = nframe - sep;
    return 0;
}

gcry_err_code_t
_gcry_pk_pkcs1_encode_for_sig(unsigned int nbits, int algo,
                              const unsigned char *digest, size_t digestlen,
                              unsigned char **r_frame, size_t *r_framelen)
{
    size_t nframe = (nbits + 7) / 8;
    unsigned char asn[100];
    size_t asnlen = sizeof asn;
    unsigned int dlen;
    unsigned char *frame;
    size_t pslen;

    *r_frame = NULL;
    *r_framelen = 0;

    if (gcry_md_algo_info(algo, GCRYCTL_GET_ASNOID, asn, &asnlen)) {
        return GPG_ERR_NOT_IMPLEMENTED;
    }

    dlen = gcry_md_get_algo_dlen(algo);

    if (digestlen != dlen) {
        return GPG_ERR_CONFLICT;
    }

    if (!dlen || dlen + asnlen + 4 > nframe) {
        return GPG_ERR_TOO_SHORT;
    }

    frame = _gcry_malloc(nframe);

    if (!frame) {
        return _gcry_err_code_from_syserror();
    }

    pslen = nframe - dlen - asnlen - 3;
    frame[0] = 0;
    frame[1] = 1;
    memset(frame + 2, 0xff, pslen);
    frame[2 + pslen] = 0;
    memcpy(frame + 3 + pslen, asn, asnlen);
    memcpy(frame + 3 + pslen + asnlen, digest, dlen);
    *r_frame = frame;
    *r_framelen = nframe;
    return 0;
}

gcry_err_code_t
_gcry_pk_pkcs1_encode_raw_for_sig(unsigned int nbits,
                                  const unsigned char *value, size_t valuelen,
                                  unsigned char **r_frame, size_t *r_framelen)
{
    size_t nframe = (nbits + 7) / 8;
    unsigned char *frame;
    size_t pslen;

    *r_frame = NULL;
    *r_framelen = 0;

    if (_gcry_fips_mode()
        && (_gcry_fips_reject_flags() & GCRY_FIPS_FLAG_REJECT_PK_MD)) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (!valuelen || valuelen + 4 > nframe) {
        return GPG_ERR_TOO_SHORT;
    }

    frame = _gcry_malloc(nframe);

    if (!frame) {
        return _gcry_err_code_from_syserror();
    }

    pslen = nframe - valuelen - 3;
    frame[0] = 0;
    frame[1] = 1;
    memset(frame + 2, 0xff, pslen);
    frame[2 + pslen] = 0;
    memcpy(frame + 3 + pslen, value, valuelen);
    *r_frame = frame;
    *r_framelen = nframe;
    return 0;
}

gcry_err_code_t
_gcry_pk_oaep_encode(unsigned int nbits, int algo, const unsigned char *value,
                     size_t valuelen, const unsigned char *label,
                     size_t labellen, const unsigned char *rnd, size_t rndlen,
                     unsigned char **r_frame, size_t *r_framelen)
{
    size_t nframe = (nbits + 7) / 8;
    unsigned int hlen = enc_hash_len(algo);
    unsigned char *frame = NULL;
    unsigned char *mask = NULL;
    unsigned char *db;
    size_t dblen;
    size_t i;
    gcry_err_code_t rc;

    *r_frame = NULL;
    *r_framelen = 0;

    if (!hlen || nframe < 2 * (size_t)hlen + 2) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (valuelen > nframe - 2 * hlen - 2) {
        return GPG_ERR_TOO_SHORT;
    }

    if (rnd && rndlen != hlen) {
        return GPG_ERR_INV_ARG;
    }

    frame = _gcry_calloc(1, nframe);
    dblen = nframe - 1 - hlen;
    mask = _gcry_malloc(dblen);

    if (!frame || !mask) {
        rc = _gcry_err_code_from_syserror();
        goto leave;
    }

    /* frame = 00 || seed || DB, DB = lHash || PS || 01 || M */
    db = frame + 1 + hlen;
    rc = enc_hash(algo, label ? label : (const unsigned char *)"",
                  label ? labellen : 0, db, hlen);

    if (rc) {
        goto leave;
    }

    db[dblen - valuelen - 1] = 1;
    memcpy(db + dblen - valuelen, value, valuelen);

    if (rnd) {
        memcpy(frame + 1, rnd, hlen);
    } else {
        gcry_randomize(frame + 1, hlen, GCRY_STRONG_RANDOM);
    }

    rc = mgf1(mask, dblen, frame + 1, hlen, algo);

    if (rc) {
        goto leave;
    }

    for (i = 0; i < dblen; i++) {
        db[i] ^= mask[i];
    }

    rc = mgf1(mask, hlen, db, dblen, algo);

    if (rc) {
        goto leave;
    }

    for (i = 0; i < hlen; i++) {
        frame[1 + i] ^= mask[i];
    }

    *r_frame = frame;
    *r_framelen = nframe;
    frame = NULL;

leave:
    _gcry_free(frame);
    _gcry_free(mask);
    return rc;
}

gcry_err_code_t
_gcry_pk_oaep_decode(const unsigned char *frame, size_t nframe, int algo,
                     const unsigned char *label, size_t labellen,
                     unsigned char **r_value, size_t *r_valuelen)
{
    unsigned int hlen = enc_hash_len(algo);
    unsigned char *buf = NULL;
    unsigned char *mask = NULL;
    unsigned char lhash[64];
    unsigned char *db;
    size_t dblen;
    size_t i;
    size_t one = 0;
    int bad;
    gcry_err_code_t rc;

    *r_value = NULL;
    *r_valuelen = 0;

    if (!hlen || hlen > sizeof lhash) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (nframe < 2 * (size_t)hlen + 2) {
        return GPG_ERR_ENCODING_PROBLEM;
    }

    buf = _gcry_malloc(nframe);
    dblen = nframe - 1 - hlen;
    mask = _gcry_malloc(dblen);

    if (!buf || !mask) {
        rc = _gcry_err_code_from_syserror();
        goto leave;
    }

    memcpy(buf, frame, nframe);
    rc = enc_hash(algo, label ? label : (const unsigned char *)"",
                  label ? labellen : 0, lhash, hlen);

    if (rc) {
        goto leave;
    }

    db = buf + 1 + hlen;
    rc = mgf1(mask, hlen, db, dblen, algo);

    if (rc) {
        goto leave;
    }

    for (i = 0; i < hlen; i++) {
        buf[1 + i] ^= mask[i];
    }

    rc = mgf1(mask, dblen, buf + 1, hlen, algo);

    if (rc) {
        goto leave;
    }

    for (i = 0; i < dblen; i++) {
        db[i] ^= mask[i];
    }

    /* Run every check regardless of earlier failures. */
    bad = buf[0] != 0;
    bad |= CRYPTO_memcmp(db, lhash, hlen) != 0;

    for (i = hlen; i < dblen && !db[i]; i++) {
        ;
    }

    if (i >= dblen || db[i] != 1) {
        bad |= 1;
    } else {
        one = i;
    }

    if (bad) {
        rc = GPG_ERR_ENCODING_PROBLEM;
        goto leave;
    }

    *r_valuelen = dblen - one - 1;
    *r_value = _gcry_malloc(*r_valuelen + 1);

    if (!*r_value) {
        *r_valuelen = 0;
        rc = _gcry_err_code_from_syserror();
        goto leave;
    }

    memcpy(*r_value, db + one + 1, *r_valuelen);

leave:

    if (buf) {
        _gcry_wipememory(buf, nframe);
    }

    _gcry_free(buf);
    _gcry_free(mask);
    return rc;
}

/* H = Hash(eight zero bytes || MHASH || SALT) into OUT. */
static gcry_err_code_t
pss_hash(int algo, const unsigned char *mhash, unsigned int hlen,
         const unsigned char *salt, size_t saltlen, unsigned char *out)
{
    static const unsigned char zeros[8];
    gcry_md_hd_t hd;
    gcry_error_t err = gcry_md_open(&hd, algo, 0);
    gcry_err_code_t rc;

    if (err) {
        return gcry_err_code(err);
    }

    gcry_md_write(hd, zeros, sizeof zeros);
    gcry_md_write(hd, mhash, hlen);
    gcry_md_write(hd, salt, saltlen);
    rc = enc_hash_final(hd, algo, out, hlen);
    gcry_md_close(hd);
    return rc;
}

gcry_err_code_t
_gcry_pk_pss_encode(unsigned int nbits, int algo, unsigned int saltlen,
                    const unsigned char *rnd, size_t rndlen,
                    const unsigned char *value, size_t valuelen,
                    int hashed_already, unsigned char **r_frame,
                    size_t *r_framelen)
{
    unsigned int hlen = enc_hash_len(algo);
    size_t embits = nbits - 1;
    size_t emlen = (embits + 7) / 8;
    unsigned char mhash[64];
    unsigned char h[64];
    unsigned char *salt = NULL;
    unsigned char *em = NULL;
    unsigned char *mask = NULL;
    size_t dblen;
    size_t i;
    gcry_err_code_t rc;

    *r_frame = NULL;
    *r_framelen = 0;

    if (!hlen || hlen > sizeof mhash) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (_gcry_fips_mode() && saltlen > hlen
        && (_gcry_fips_reject_flags() & GCRY_FIPS_FLAG_REJECT_PK_FLAGS)) {
        return GPG_ERR_INV_ARG;
    }

    if (emlen < (size_t)hlen + saltlen + 2) {
        return GPG_ERR_TOO_SHORT;
    }

    if (hashed_already) {
        if (valuelen != hlen) {
            return GPG_ERR_INV_LENGTH;
        }

        memcpy(mhash, value, hlen);
    } else {
        rc = enc_hash(algo, value, valuelen, mhash, hlen);

        if (rc) {
            return rc;
        }
    }

    if (rnd && rndlen != saltlen) {
        return GPG_ERR_INV_ARG;
    }

    salt = _gcry_malloc(saltlen ? saltlen : 1);
    em = _gcry_calloc(1, emlen);
    dblen = emlen - hlen - 1;
    mask = _gcry_malloc(dblen);

    if (!salt || !em || !mask) {
        rc = _gcry_err_code_from_syserror();
        goto leave;
    }

    if (rnd) {
        memcpy(salt, rnd, saltlen);
    } else if (saltlen) {
        gcry_randomize(salt, saltlen, GCRY_STRONG_RANDOM);
    }

    rc = pss_hash(algo, mhash, hlen, salt, saltlen, h);

    if (rc) {
        goto leave;
    }

    /* DB = PS || 01 || salt, masked; then H and the trailer. */
    em[dblen - saltlen - 1] = 1;
    memcpy(em + dblen - saltlen, salt, saltlen);
    rc = mgf1(mask, dblen, h, hlen, algo);

    if (rc) {
        goto leave;
    }

    for (i = 0; i < dblen; i++) {
        em[i] ^= mask[i];
    }

    em[0] &= (unsigned char)(0xff >> (8 * emlen - embits));
    memcpy(em + dblen, h, hlen);
    em[emlen - 1] = 0xbc;
    *r_frame = em;
    *r_framelen = emlen;
    em = NULL;

leave:
    _gcry_free(em);
    _gcry_free(mask);
    _gcry_free(salt);
    return rc;
}

gcry_err_code_t
_gcry_pk_pss_verify(unsigned int nbits, int algo, unsigned int saltlen,
                    const unsigned char *value, size_t valuelen,
                    int hashed_already, const unsigned char *em_in,
                    size_t em_inlen)
{
    unsigned int hlen = enc_hash_len(algo);
    size_t embits = nbits - 1;
    size_t emlen = (embits + 7) / 8;
    unsigned char mhash[64];
    unsigned char h[64];
    unsigned char *em = NULL;
    unsigned char *mask = NULL;
    size_t dblen;
    size_t i;
    gcry_err_code_t rc;

    if (!hlen || hlen > sizeof mhash) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (_gcry_fips_mode() && saltlen > hlen
        && (_gcry_fips_reject_flags() & GCRY_FIPS_FLAG_REJECT_PK_FLAGS)) {
        return GPG_ERR_INV_ARG;
    }

    if (emlen < (size_t)hlen + saltlen + 2) {
        return GPG_ERR_TOO_SHORT;
    }

    if (hashed_already) {
        if (valuelen != hlen) {
            return GPG_ERR_INV_ARG;
        }

        memcpy(mhash, value, hlen);
    } else {
        rc = enc_hash(algo, value, valuelen, mhash, hlen);

        if (rc) {
            return rc;
        }
    }

    /* Leading zero bytes of the value may have been stripped. */
    while (em_inlen > emlen && !*em_in) {
        em_in++;
        em_inlen--;
    }

    if (em_inlen > emlen) {
        return GPG_ERR_BAD_SIGNATURE;
    }

    em = _gcry_calloc(1, emlen);
    dblen = emlen - hlen - 1;
    mask = _gcry_malloc(dblen);

    if (!em || !mask) {
        rc = _gcry_err_code_from_syserror();
        goto leave;
    }

    memcpy(em + emlen - em_inlen, em_in, em_inlen);

    if (em[emlen - 1] != 0xbc
        || (em[0] & ~(unsigned char)(0xff >> (8 * emlen - embits)))) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    rc = mgf1(mask, dblen, em + dblen, hlen, algo);

    if (rc) {
        goto leave;
    }

    for (i = 0; i < dblen; i++) {
        em[i] ^= mask[i];
    }

    em[0] &= (unsigned char)(0xff >> (8 * emlen - embits));

    for (i = 0; i < dblen - saltlen - 1; i++) {
        if (em[i]) {
            rc = GPG_ERR_BAD_SIGNATURE;
            goto leave;
        }
    }

    if (em[dblen - saltlen - 1] != 1) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    rc = pss_hash(algo, mhash, hlen, em + dblen - saltlen, saltlen, h);

    if (!rc && CRYPTO_memcmp(h, em + dblen, hlen)) {
        rc = GPG_ERR_BAD_SIGNATURE;
    }

leave:
    _gcry_free(em);
    _gcry_free(mask);
    return rc;
}

/*
 * The frame a (data ...) S-expression stands for, as (NBITS+7)/8 bytes
 * (PSS frames are one bit shorter and come back right aligned in that
 * many bytes).  This is the common part of the RSA and ElGamal paths:
 * raw data is the number itself, everything else is one of the encodings
 * above.  For PKCS#1 signatures a message given with (value ...) and the
 * prehash flag is hashed first.
 */
gcry_err_code_t
_gcry_pk_data_to_frame(struct pk_data *pd, unsigned int nbits,
                       unsigned char **r_frame, size_t *r_framelen)
{
    size_t nframe = (nbits + 7) / 8;
    gcry_err_code_t rc;

    *r_frame = NULL;
    *r_framelen = 0;

    switch (pd->encoding) {
    case PUBKEY_ENC_RAW:
        if (!pd->mpi || mpi_is_opaque(pd->mpi)) {
            return GPG_ERR_INV_DATA;
        }

        *r_frame = _gcry_malloc(nframe);

        if (!*r_frame) {
            return _gcry_err_code_from_syserror();
        }

        if (_gcry_pk_mpi_to_fixed(pd->mpi, *r_frame, nframe)) {
            _gcry_free(*r_frame);
            *r_frame = NULL;
            return GPG_ERR_TOO_LARGE;
        }

        *r_framelen = nframe;
        return 0;

    case PUBKEY_ENC_PKCS1:
        if (!pd->value) {
            return GPG_ERR_INV_DATA;
        }

        if (pd->op == PUBKEY_OP_ENCRYPT || pd->op == PUBKEY_OP_DECRYPT) {
            return _gcry_pk_pkcs1_encode_for_enc(nbits, pd->value,
                                                 pd->valuelen, pd->rnd,
                                                 pd->rndlen, r_frame,
                                                 r_framelen);
        }

        if (pd->value_is_hash) {
            return _gcry_pk_pkcs1_encode_for_sig(nbits, pd->hash_algo,
                                                 pd->value, pd->valuelen,
                                                 r_frame, r_framelen);
        } else {
            unsigned int dlen = gcry_md_get_algo_dlen(pd->hash_algo);
            unsigned char digest[64];

            if (!dlen || dlen > sizeof digest) {
                return GPG_ERR_DIGEST_ALGO;
            }

            rc = enc_hash(pd->hash_algo, pd->value, pd->valuelen, digest,
                          dlen);

            if (rc) {
                return rc;
            }

            return _gcry_pk_pkcs1_encode_for_sig(nbits, pd->hash_algo,
                                                 digest, dlen, r_frame,
                                                 r_framelen);
        }

    case PUBKEY_ENC_PKCS1_RAW:
        if (!pd->value) {
            return GPG_ERR_INV_DATA;
        }

        return _gcry_pk_pkcs1_encode_raw_for_sig(nbits, pd->value,
                                                 pd->valuelen, r_frame,
                                                 r_framelen);

    case PUBKEY_ENC_OAEP:
        if (!pd->value) {
            return GPG_ERR_INV_DATA;
        }

        return _gcry_pk_oaep_encode(nbits, pd->hash_algo, pd->value,
                                    pd->valuelen, pd->label, pd->labellen,
                                    pd->rnd, pd->rndlen, r_frame, r_framelen);

    case PUBKEY_ENC_PSS: {
        unsigned char *em = NULL;
        size_t emlen = 0;

        if (!pd->value) {
            return GPG_ERR_INV_DATA;
        }

        rc = _gcry_pk_pss_encode(nbits, pd->hash_algo, pd->saltlen, pd->rnd,
                                 pd->rndlen, pd->value, pd->valuelen,
                                 pd->value_is_hash, &em, &emlen);

        if (rc) {
            return rc;
        }

        if (emlen == nframe) {
            *r_frame = em;
        } else {
            *r_frame = _gcry_calloc(1, nframe);

            if (!*r_frame) {
                _gcry_free(em);
                return _gcry_err_code_from_syserror();
            }

            memcpy(*r_frame + nframe - emlen, em, emlen);
            _gcry_free(em);
        }

        *r_framelen = nframe;
        return 0;
    }

    default:
        return GPG_ERR_CONFLICT;
    }
}
