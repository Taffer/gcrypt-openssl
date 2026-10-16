/*
 * pk-dsa.c - DSA on top of OpenSSL's EVP_PKEY interface.
 */
#include "gcrypt-int.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/param_build.h>

static const char *const dsa_names[] = { "dsa", "openpgp-dsa", NULL };

static unsigned int
dsa_get_nbits(gcry_sexp_t parms)
{
    gcry_sexp_t l1 = gcry_sexp_find_token(parms, "p", 1);
    gcry_mpi_t p;
    unsigned int nbits;

    if (!l1) {
        return 0;
    }

    p = gcry_sexp_nth_mpi(l1, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(l1);
    nbits = p ? gcry_mpi_get_nbits(p) : 0;
    gcry_mpi_release(p);
    return nbits;
}

/* A copy of BN carrying BN_FLG_SECURE.  OSSL_PARAM_BLD_push_BN puts such a
 * number into the blob that OSSL_PARAM_free wipes, the others into one it
 * merely frees. */
static BIGNUM *
secure_bn_copy(const BIGNUM *bn)
{
    BIGNUM *copy = BN_secure_new();

    if (copy && !BN_copy(copy, bn)) {
        BN_clear_free(copy);
        copy = NULL;
    }

    return copy;
}

/* A secure MPI with the value of BN, for private key material. */
static gcry_mpi_t
secure_mpi_from_bn(const BIGNUM *bn)
{
    BIGNUM *copy = secure_bn_copy(bn);

    if (!copy) {
        _gcry_fatal_error(GPG_ERR_ENOMEM, NULL);
    }

    return _gcry_mpi_new_from_bn(copy, 1);
}

/* Build an EVP_PKEY from p, q, g, y and optionally x.  Q is returned for
 * range checks of signatures. */
static gcry_err_code_t
dsa_evp_key(gcry_sexp_t parms, int want_private, EVP_PKEY **r_key,
            gcry_mpi_t *r_q)
{
    gcry_err_code_t rc;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    BIGNUM *sx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    *r_key = NULL;

    if (r_q) {
        *r_q = NULL;
    }

    if (want_private) {
        rc = _gcry_sexp_extract_param(parms, NULL, "pqgyx", &p, &q, &g, &y, &x,
                                      NULL);
    } else {
        rc = _gcry_sexp_extract_param(parms, NULL, "pqgy", &p, &q, &g, &y,
                                      NULL);
    }

    if (rc) {
        return rc;
    }

    bld = OSSL_PARAM_BLD_new();

    /* The private value goes in as a secure copy, see secure_bn_copy. */
    if (want_private) {
        sx = secure_bn_copy(_gcry_mpi_bn(x));
    }

    if (!bld || (want_private && !sx)
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, _gcry_mpi_bn(p))
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, _gcry_mpi_bn(q))
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, _gcry_mpi_bn(g))
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                   _gcry_mpi_bn(y))
        || (want_private
            && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, sx))) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "DSA", _gcry_propq());

    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, r_key, want_private ? EVP_PKEY_KEYPAIR
                             : EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        rc = _gcry_err_from_openssl(want_private ? GPG_ERR_BAD_SECKEY
                                    : GPG_ERR_BAD_PUBKEY);
        *r_key = NULL;
        goto leave;
    }

    if (r_q) {
        *r_q = q;
        q = NULL;
    }

    rc = 0;

leave:
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(sx);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    return rc;
}

/* The digest bytes to sign or verify.  A numeric value is converted to
 * its big endian bytes; with the prehash flag the message is hashed. */
static gcry_err_code_t
dsa_digest(struct pk_data *pd, unsigned char **r_buf, size_t *r_len)
{
    if (pd->value) {
        if (pd->value_is_hash) {
            *r_buf = _gcry_malloc(pd->valuelen);

            if (!*r_buf) {
                return _gcry_err_code_from_syserror();
            }

            memcpy(*r_buf, pd->value, pd->valuelen);
            *r_len = pd->valuelen;
            return 0;
        }

        *r_len = _gcry_pk_md_dlen(pd->hash_algo);

        if (!*r_len) {
            return GPG_ERR_DIGEST_ALGO;
        }

        *r_buf = _gcry_malloc(*r_len);

        if (!*r_buf) {
            return _gcry_err_code_from_syserror();
        }

        return _gcry_pk_md_hash(pd->hash_algo, pd->value, pd->valuelen,
                                *r_buf, *r_len);
    }

    if (pd->mpi) {
        return _gcry_pk_mpi_to_bytes(pd->mpi, r_buf, r_len);
    }

    return GPG_ERR_INV_DATA;
}

/* Set the deterministic (RFC 6979) nonce parameters on CTX. */
static gcry_err_code_t
set_rfc6979(EVP_PKEY_CTX *ctx, int hash_algo)
{
    const char *name = _gcry_pk_md_openssl_name(hash_algo);
    unsigned int nonce_type = 1;
    OSSL_PARAM params[3];

    if (!name) {
        return GPG_ERR_DIGEST_ALGO;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                                 (char *)(uintptr_t)name, 0);
    params[1] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE,
                                          &nonce_type);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        return _gcry_err_from_openssl(GPG_ERR_NOT_SUPPORTED);
    }

    return 0;
}

static gcry_err_code_t
dsa_sign(gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    unsigned int nbits = dsa_get_nbits(keyparms);
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *digest = NULL;
    size_t digestlen = 0;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    gcry_mpi_t sig_r = NULL;
    gcry_mpi_t sig_s = NULL;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_SIGN, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.label && _gcry_log_verbosity()) {
        log_info("dsa: a caller supplied nonce is not supported and ignored\n");
    }

    rc = dsa_digest(&pd, &digest, &digestlen);

    if (rc) {
        goto leave;
    }

    rc = dsa_evp_key(keyparms, 1, &key, NULL);

    if (rc) {
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    if ((pd.flags & PUBKEY_FLAG_RFC6979) && pd.hash_algo) {
        rc = set_rfc6979(ctx, pd.hash_algo);

        if (rc) {
            goto leave;
        }
    }

    if (EVP_PKEY_sign(ctx, NULL, &siglen, digest, digestlen) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_DATA);
        goto leave;
    }

    sig = _gcry_malloc(siglen);

    if (!sig) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (EVP_PKEY_sign(ctx, sig, &siglen, digest, digestlen) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_DATA);
        goto leave;
    }

    rc = _gcry_pk_rs_from_der(sig, siglen, 0, &sig_r, &sig_s);

    if (!rc) {
        rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(dsa(r%M)(s%M)))", sig_r,
                              sig_s);
    }

leave:
    gcry_mpi_release(sig_r);
    gcry_mpi_release(sig_s);
    _gcry_free(sig);
    _gcry_free(digest);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
dsa_verify(gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t sig_r = NULL;
    gcry_mpi_t sig_s = NULL;
    gcry_mpi_t q = NULL;
    unsigned int nbits = dsa_get_nbits(keyparms);
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *digest = NULL;
    size_t digestlen = 0;
    unsigned char *der = NULL;
    size_t derlen = 0;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_VERIFY, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    rc = _gcry_pk_util_preparse_sigval(s_sig, dsa_names, &l1, NULL);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL, "rs", &sig_r, &sig_s, NULL);

    if (rc) {
        goto leave;
    }

    rc = dsa_evp_key(keyparms, 0, &key, &q);

    if (rc) {
        goto leave;
    }

    if (gcry_mpi_cmp_ui(sig_r, 0) <= 0 || gcry_mpi_cmp(sig_r, q) >= 0
        || gcry_mpi_cmp_ui(sig_s, 0) <= 0 || gcry_mpi_cmp(sig_s, q) >= 0) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    rc = dsa_digest(&pd, &digest, &digestlen);

    if (rc) {
        goto leave;
    }

    rc = _gcry_pk_rs_to_der(sig_r, sig_s, 0, &der, &derlen);

    if (rc) {
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!ctx || EVP_PKEY_verify_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    if (EVP_PKEY_verify(ctx, der, derlen, digest, digestlen) != 1) {
        ERR_clear_error();
        rc = GPG_ERR_BAD_SIGNATURE;
    }

leave:
    _gcry_free(der);
    _gcry_free(digest);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    gcry_mpi_release(q);
    gcry_mpi_release(sig_r);
    gcry_mpi_release(sig_s);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
dsa_check_secret_key(gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t t;

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pqgyx", &p, &q, &g, &y, &x,
                                  NULL);

    if (rc) {
        return rc;
    }

    t = gcry_mpi_new(0);
    gcry_mpi_powm(t, g, x, p);

    if (gcry_mpi_cmp(t, y)) {
        rc = GPG_ERR_BAD_SECKEY;
    }

    gcry_mpi_release(t);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    return rc;
}

static gcry_err_code_t
dsa_generate(gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{
    gcry_err_code_t rc;
    unsigned int nbits;
    unsigned int qbits = 0;
    gcry_sexp_t l1;
    gcry_sexp_t domainsexp;
    int flags = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY *key = NULL;
    BIGNUM *bn[5] = { NULL, NULL, NULL, NULL, NULL };
    gcry_mpi_t m[5] = { NULL, NULL, NULL, NULL, NULL };
    static const char *const names[5] = {
        OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_G,
        OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_PRIV_KEY
    };
    int i;

    rc = _gcry_pk_util_get_nbits(genparms, &nbits);

    if (rc) {
        return rc;
    }

    l1 = gcry_sexp_find_token(genparms, "flags", 0);

    if (l1) {
        rc = _gcry_pk_util_parse_flaglist(l1, &flags, NULL);
        gcry_sexp_release(l1);

        if (rc) {
            return rc;
        }
    }

    /* The FIPS 186 selectors are also accepted as plain elements. */
    l1 = gcry_sexp_find_token(genparms, "use-fips186", 0);

    if (l1) {
        flags |= PUBKEY_FLAG_USE_FIPS186;
        gcry_sexp_release(l1);
    }

    l1 = gcry_sexp_find_token(genparms, "use-fips186-2", 0);

    if (l1) {
        flags |= PUBKEY_FLAG_USE_FIPS186_2;
        gcry_sexp_release(l1);
    }

    l1 = gcry_sexp_find_token(genparms, "qbits", 0);

    if (l1) {
        const char *s;
        size_t n;
        char buf[50];

        s = gcry_sexp_nth_data(l1, 1, &n);

        if (!s || n >= sizeof buf - 1) {
            gcry_sexp_release(l1);
            return GPG_ERR_INV_OBJ;
        }

        memcpy(buf, s, n);
        buf[n] = 0;
        qbits = (unsigned int)strtoul(buf, NULL, 0);
        gcry_sexp_release(l1);
    }

    domainsexp = gcry_sexp_find_token(genparms, "domain", 0);

    if (domainsexp) {
        /* Use the given domain parameters. */
        gcry_mpi_t dp = NULL;
        gcry_mpi_t dq = NULL;
        gcry_mpi_t dg = NULL;
        OSSL_PARAM_BLD *bld;
        OSSL_PARAM *prm = NULL;

        if (qbits || nbits) {
            gcry_sexp_release(domainsexp);
            return GPG_ERR_INV_VALUE;
        }

        rc = _gcry_sexp_extract_param(domainsexp, NULL, "pqg", &dp, &dq, &dg,
                                      NULL);
        gcry_sexp_release(domainsexp);

        if (rc) {
            return GPG_ERR_MISSING_VALUE;
        }

        bld = OSSL_PARAM_BLD_new();
        pctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "DSA", _gcry_propq());

        if (!bld || !pctx
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P,
                                       _gcry_mpi_bn(dp))
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q,
                                       _gcry_mpi_bn(dq))
            || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G,
                                       _gcry_mpi_bn(dg))
            || !(prm = OSSL_PARAM_BLD_to_param(bld))
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_KEY_PARAMETERS,
                                 prm) <= 0) {
            rc = _gcry_err_from_openssl(GPG_ERR_INV_VALUE);
            params = NULL;
        }

        OSSL_PARAM_free(prm);
        OSSL_PARAM_BLD_free(bld);
        gcry_mpi_release(dp);
        gcry_mpi_release(dq);
        gcry_mpi_release(dg);

        if (rc) {
            goto leave;
        }
    } else {
        if (!qbits) {
            if (nbits >= 512 && nbits <= 1024) {
                qbits = 160;
            } else if (nbits == 2048) {
                qbits = 224;
            } else if (nbits == 3072) {
                qbits = 256;
            } else if (nbits == 7680) {
                qbits = 384;
            } else if (nbits == 15360) {
                qbits = 512;
            } else {
                return GPG_ERR_INV_VALUE;
            }
        }

        if (qbits < 160 || qbits > 512 || (qbits % 8) || nbits < 2 * qbits
            || nbits > 15360) {
            return GPG_ERR_INV_VALUE;
        }

        /* FIPS 186-3 allows three sizes, FIPS 186-2 just one. */
        if ((flags & PUBKEY_FLAG_USE_FIPS186)
            && !((nbits == 2048 && (qbits == 224 || qbits == 256))
                 || (nbits == 3072 && qbits == 256))) {
            return GPG_ERR_INV_VALUE;
        }

        if ((flags & PUBKEY_FLAG_USE_FIPS186_2)
            && !(nbits == 1024 && qbits == 160)) {
            return GPG_ERR_INV_VALUE;
        }

        pctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "DSA", _gcry_propq());

        /* OpenSSL generates, signs and verifies only with the FIPS 186
         * sizes of q (160, 224 and 256 bits); the reference library
         * accepts other multiples of 8 here. */
        if (!pctx || EVP_PKEY_paramgen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, (int)nbits) <= 0
            || EVP_PKEY_CTX_set_dsa_paramgen_q_bits(pctx, (int)qbits) <= 0
            || EVP_PKEY_paramgen(pctx, &params) <= 0) {
            rc = _gcry_err_from_openssl(GPG_ERR_INV_VALUE);
            params = NULL;
            goto leave;
        }
    }

    kctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), params, _gcry_propq());

    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_keygen(kctx, &key) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_VALUE);
        key = NULL;
        goto leave;
    }

    for (i = 0; i < 5; i++) {
        if (!EVP_PKEY_get_bn_param(key, names[i], &bn[i])) {
            rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
            goto leave;
        }

        /* x, the last one, is secret: a secure MPI makes the key
         * S-expression secure. */
        m[i] = i == 4 ? secure_mpi_from_bn(bn[i])
               : _gcry_pk_mpi_from_bn(bn[i]);
    }

    rc = _gcry_sexp_build(r_skey, NULL,
                          "(key-data"
                          " (public-key"
                          "  (dsa(p%m)(q%m)(g%m)(y%m)))"
                          " (private-key"
                          "  (dsa(p%m)(q%m)(g%m)(y%m)(x%m))))",
                          m[0], m[1], m[2], m[3], m[0], m[1], m[2], m[3], m[4]);

leave:

    for (i = 0; i < 5; i++) {
        gcry_mpi_release(m[i]);
        BN_clear_free(bn[i]);
    }

    EVP_PKEY_free(key);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    return rc;
}

const struct gcry_pk_spec _gcry_pubkey_spec_dsa = {
    GCRY_PK_DSA,
    0,
    GCRY_PK_USAGE_SIGN,
    "DSA",
    dsa_names,
    "pqgy",
    "pqgyx",
    "",
    "rs",
    "pqgy",
    dsa_generate,
    dsa_check_secret_key,
    NULL,
    NULL,
    dsa_sign,
    dsa_verify,
    dsa_get_nbits,
    NULL,
    NULL,
    NULL
};
