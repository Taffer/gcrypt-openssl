/*
 * pk-ecc.c - ECC: ECDSA and ECDH on Weierstrass curves, EdDSA on
 * Ed25519/Ed448 and X25519/X448 key agreement, all through OpenSSL.
 */
#include "gcrypt-int.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

static const char *const ecc_names[] = {
    "ecc", "ecdsa", "ecdh", "eddsa", "gost", "sm2", NULL
};

/* The curve named NAME, or NULL when it is unknown or, as in the
 * reference library, when FIPS mode does not allow it. */
static const struct gcry_ecc_curve *
usable_curve(const char *name)
{
    const struct gcry_ecc_curve *curve = _gcry_ecc_curve_find(name);

    if (curve && _gcry_fips_mode() && !curve->fips) {
        return NULL;
    }

    return curve;
}

static unsigned int
ecc_get_nbits(gcry_sexp_t parms)
{
    gcry_sexp_t l1;
    unsigned int nbits = 0;

    l1 = gcry_sexp_find_token(parms, "p", 1);

    if (l1) {
        gcry_mpi_t p = gcry_sexp_nth_mpi(l1, 1, GCRYMPI_FMT_USG);

        gcry_sexp_release(l1);

        if (p) {
            nbits = gcry_mpi_get_nbits(p);
            gcry_mpi_release(p);
        }

        return nbits;
    }

    l1 = gcry_sexp_find_token(parms, "curve", 5);

    if (l1) {
        char *name = gcry_sexp_nth_string(l1, 1);
        const struct gcry_ecc_curve *curve;

        gcry_sexp_release(l1);

        if (!name) {
            return 0;
        }

        curve = usable_curve(name);
        _gcry_free(name);
        return curve ? curve->nbits : 0;
    }

    return 0;
}

/* OpenSSL implements SM2 only on its own curve, as a separate key type. */
static int
is_sm2_curve(mpi_ec_t ec)
{
    return ec->curve && !strcmp(ec->curve->name, "sm2p256v1");
}

static int
is_eddsa(mpi_ec_t ec, int flags)
{
    return (flags & PUBKEY_FLAG_EDDSA)
           || (ec->model == GCRY_ECC_MODEL_EDWARDS
               && ec->dialect == GCRY_ECC_DIALECT_SAFECURVE);
}

/* ------------------------------------------------------------------ */
/* Digest helpers                                                      */
/* ------------------------------------------------------------------ */

/* Digest bytes for ECDSA: given directly, computed from a message
 * (prehash), or the bytes of a numeric value. */
static gcry_err_code_t
ecdsa_digest(struct pk_data *pd, unsigned char **r_buf, size_t *r_len)
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

/* ------------------------------------------------------------------ */
/* EdDSA                                                               */
/* ------------------------------------------------------------------ */

/* Signature parameters for Ed25519/Ed448 variants: pure, prehashed or
 * with a context string. */
static gcry_err_code_t
eddsa_params(mpi_ec_t ec, struct pk_data *pd, OSSL_PARAM *params)
{
    const char *instance;
    int i = 0;
    int ph = !!(pd->flags & PUBKEY_FLAG_PREHASH);

    if (ec->nbits == 448) {
        instance = ph ? "Ed448ph" : "Ed448";
    } else if (ph) {
        instance = "Ed25519ph";
    } else if (pd->labellen) {
        instance = "Ed25519ctx";
    } else {
        instance = "Ed25519";
    }

    params[i++] = OSSL_PARAM_construct_utf8_string(
                      OSSL_SIGNATURE_PARAM_INSTANCE,
                      (char *)(uintptr_t)instance, 0);

    if (pd->labellen) {
        params[i++] = OSSL_PARAM_construct_octet_string(
                          OSSL_SIGNATURE_PARAM_CONTEXT_STRING, pd->label,
                          pd->labellen);
    }

    params[i] = OSSL_PARAM_construct_end();

    if (pd->hash_algo) {
        int expected = ec->nbits == 448 ? GCRY_MD_SHAKE256 : GCRY_MD_SHA512;

        if (pd->hash_algo != expected) {
            return GPG_ERR_DIGEST_ALGO;
        }
    }

    /* FIPS 186-5 approves Ed25519, Ed25519ph, Ed448 and Ed448ph only;
     * the FIPS provider accordingly has no Ed25519ctx. */
    if (_gcry_fips_mode() && !strcmp(instance, "Ed25519ctx")) {
        return GPG_ERR_NOT_SUPPORTED;
    }

    return 0;
}

static gcry_err_code_t
eddsa_sign(mpi_ec_t ec, struct pk_data *pd, gcry_mpi_t *r_r, gcry_mpi_t *r_s)
{
    gcry_err_code_t rc;
    EVP_PKEY *key;
    EVP_MD_CTX *mctx = NULL;
    OSSL_PARAM params[3];
    unsigned char sig[114];
    size_t siglen = sizeof sig;
    size_t b;

    if (!pd->value) {
        return GPG_ERR_INV_DATA;
    }

    rc = eddsa_params(ec, pd, params);

    if (rc) {
        return rc;
    }

    key = _gcry_ecc_evp_key(ec, 1, &rc);

    if (!key) {
        return rc;
    }

    mctx = EVP_MD_CTX_new();

    if (!mctx
        || EVP_DigestSignInit_ex(mctx, NULL, NULL, _gcry_libctx(),
                                 _gcry_propq(), key, params) <= 0
        || EVP_DigestSign(mctx, sig, &siglen, pd->value, pd->valuelen) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    b = siglen / 2;
    *r_r = gcry_mpi_set_opaque_copy(NULL, sig, (unsigned int)b * 8);
    *r_s = gcry_mpi_set_opaque_copy(NULL, sig + b, (unsigned int)b * 8);
    rc = (*r_r && *r_s) ? 0 : GPG_ERR_ENOMEM;

leave:
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(key);
    return rc;
}

static gcry_err_code_t
eddsa_verify(mpi_ec_t ec, struct pk_data *pd, gcry_mpi_t sig_r,
             gcry_mpi_t sig_s)
{
    gcry_err_code_t rc;
    EVP_PKEY *key;
    EVP_MD_CTX *mctx = NULL;
    OSSL_PARAM params[3];
    unsigned char sig[114];
    unsigned int b = ec->nbits == 448 ? 57u : 32u;
    const unsigned char *rbuf;
    const unsigned char *sbuf;
    unsigned int rlen;
    unsigned int slen;
    int ok;

    if (!pd->value || !mpi_is_opaque(sig_r) || !mpi_is_opaque(sig_s)) {
        return GPG_ERR_INV_DATA;
    }

    rbuf = gcry_mpi_get_opaque(sig_r, &rlen);
    sbuf = gcry_mpi_get_opaque(sig_s, &slen);

    if (!rbuf || !sbuf || (rlen + 7) / 8 != b || (slen + 7) / 8 != b) {
        return GPG_ERR_INV_LENGTH;
    }

    rc = eddsa_params(ec, pd, params);

    if (rc) {
        return rc;
    }

    if (!ec->Q) {
        return GPG_ERR_NO_PUBKEY;
    }

    if (!_gcry_mpi_ec_on_curve(ec->Q, ec)) {
        return GPG_ERR_BROKEN_PUBKEY;
    }

    key = _gcry_ecc_evp_key(ec, 0, &rc);

    if (!key) {
        return rc;
    }

    memcpy(sig, rbuf, b);
    memcpy(sig + b, sbuf, b);
    mctx = EVP_MD_CTX_new();
    ok = mctx
         && EVP_DigestVerifyInit_ex(mctx, NULL, NULL, _gcry_libctx(),
                                    _gcry_propq(), key, params) > 0
         && EVP_DigestVerify(mctx, sig, 2 * b, pd->value, pd->valuelen) == 1;
    ERR_clear_error();
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(key);
    return ok ? 0 : GPG_ERR_BAD_SIGNATURE;
}

/* ------------------------------------------------------------------ */
/* ECDSA                                                               */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
ecdsa_sign(mpi_ec_t ec, struct pk_data *pd, gcry_mpi_t *r_r, gcry_mpi_t *r_s)
{
    gcry_err_code_t rc;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *digest = NULL;
    size_t digestlen = 0;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS) {
        return GPG_ERR_INV_CURVE;
    }

    rc = ecdsa_digest(pd, &digest, &digestlen);

    if (rc) {
        return rc;
    }

    key = _gcry_ecc_evp_key(ec, 1, &rc);

    if (!key) {
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    if ((pd->flags & PUBKEY_FLAG_RFC6979) && pd->hash_algo) {
        const char *name = _gcry_pk_md_openssl_name(pd->hash_algo);
        unsigned int nonce_type = 1;
        OSSL_PARAM params[3];

        if (!name) {
            rc = GPG_ERR_DIGEST_ALGO;
            goto leave;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(
                        OSSL_SIGNATURE_PARAM_DIGEST, (char *)(uintptr_t)name, 0);
        params[1] = OSSL_PARAM_construct_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE,
                                              &nonce_type);
        params[2] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
            rc = _gcry_err_from_openssl(GPG_ERR_NOT_SUPPORTED);
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

    rc = _gcry_pk_rs_from_der(sig, siglen, 1, r_r, r_s);

leave:
    _gcry_free(sig);
    _gcry_free(digest);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

static gcry_err_code_t
ecdsa_verify(mpi_ec_t ec, struct pk_data *pd, gcry_mpi_t sig_r,
             gcry_mpi_t sig_s)
{
    gcry_err_code_t rc;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *digest = NULL;
    size_t digestlen = 0;
    unsigned char *der = NULL;
    size_t derlen = 0;

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS) {
        return GPG_ERR_INV_CURVE;
    }

    if (mpi_is_opaque(sig_r) || mpi_is_opaque(sig_s)
        || gcry_mpi_cmp_ui(sig_r, 0) <= 0 || gcry_mpi_cmp(sig_r, ec->n) >= 0
        || gcry_mpi_cmp_ui(sig_s, 0) <= 0 || gcry_mpi_cmp(sig_s, ec->n) >= 0) {
        return GPG_ERR_BAD_SIGNATURE;
    }

    rc = ecdsa_digest(pd, &digest, &digestlen);

    if (rc) {
        return rc;
    }

    rc = _gcry_pk_rs_to_der(sig_r, sig_s, 1, &der, &derlen);

    if (rc) {
        goto leave;
    }

    key = _gcry_ecc_evp_key(ec, 0, &rc);

    if (!key) {
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
    return rc;
}

/* ------------------------------------------------------------------ */
/* SM2                                                                 */
/* ------------------------------------------------------------------ */

/* An OpenSSL "SM2" key object for EC (which must be on the SM2 curve). */
static EVP_PKEY *
sm2_evp_key(mpi_ec_t ec, int want_private, gcry_err_code_t *r_rc)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    gcry_mpi_t pub = NULL;
    const unsigned char *pubbuf = NULL;
    unsigned int publen = 0;
    gcry_err_code_t rc = 0;

    if (!bld) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (!ec->Q && ec->d) {
        rc = _gcry_ecc_compute_public(ec);

        if (rc) {
            goto leave;
        }
    }

    if (!ec->Q) {
        rc = GPG_ERR_NO_PUBKEY;
        goto leave;
    }

    pub = _gcry_mpi_ec_ec2os(ec->Q, ec);
    pubbuf = pub ? gcry_mpi_get_opaque(pub, &publen) : NULL;

    if (!pubbuf
        || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                            "SM2", 0)
        || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             pubbuf, (publen + 7) / 8)
        || (want_private
            && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                       _gcry_mpi_bn(ec->d)))) {
        rc = GPG_ERR_INTERNAL;
        goto leave;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    pctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "SM2", _gcry_propq());

    /* No "SM2" key type at all: the provider was built without SM2, the
     * same situation as FIPS mode refusing the curve. */
    if (!pctx) {
        rc = GPG_ERR_NOT_SUPPORTED;
        goto leave;
    }

    if (!params || EVP_PKEY_fromdata_init(pctx) <= 0
        || EVP_PKEY_fromdata(pctx, &key,
                             want_private ? EVP_PKEY_KEYPAIR
                             : EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        rc = _gcry_err_from_openssl(want_private ? GPG_ERR_BAD_SECKEY
                                    : GPG_ERR_BAD_PUBKEY);
        key = NULL;
    }

leave:
    ERR_clear_error();
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    gcry_mpi_release(pub);
    *r_rc = key ? 0 : (rc ? rc : GPG_ERR_INTERNAL);
    return key;
}

/* SM2 signatures over a caller supplied hash value, as the gcrypt API
 * defines them (no Z value is computed here). */
static gcry_err_code_t
sm2_sign(mpi_ec_t ec, struct pk_data *pd, gcry_mpi_t *r_r, gcry_mpi_t *r_s)
{
    gcry_err_code_t rc;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *digest = NULL;
    size_t digestlen = 0;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    rc = ecdsa_digest(pd, &digest, &digestlen);

    if (rc) {
        return rc;
    }

    key = sm2_evp_key(ec, 1, &rc);

    if (!key) {
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0
        || EVP_PKEY_sign(ctx, NULL, &siglen, digest, digestlen) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
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

    rc = _gcry_pk_rs_from_der(sig, siglen, 1, r_r, r_s);

leave:
    _gcry_free(sig);
    _gcry_free(digest);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return rc;
}

static gcry_err_code_t
sm2_verify(mpi_ec_t ec, struct pk_data *pd, gcry_mpi_t sig_r,
           gcry_mpi_t sig_s)
{
    gcry_err_code_t rc;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *digest = NULL;
    size_t digestlen = 0;
    unsigned char *der = NULL;
    size_t derlen = 0;

    if (mpi_is_opaque(sig_r) || mpi_is_opaque(sig_s)
        || gcry_mpi_cmp_ui(sig_r, 0) <= 0 || gcry_mpi_cmp(sig_r, ec->n) >= 0
        || gcry_mpi_cmp_ui(sig_s, 0) <= 0 || gcry_mpi_cmp(sig_s, ec->n) >= 0) {
        return GPG_ERR_BAD_SIGNATURE;
    }

    rc = ecdsa_digest(pd, &digest, &digestlen);

    if (rc) {
        return rc;
    }

    rc = _gcry_pk_rs_to_der(sig_r, sig_s, 1, &der, &derlen);

    if (rc) {
        goto leave;
    }

    key = sm2_evp_key(ec, 0, &rc);

    if (!key) {
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
    return rc;
}

/* For GOST (and SM2 away from its curve) nothing can be verified here;
 * a signature with values outside the group is still certainly bad. */
static gcry_err_code_t
unverifiable_sig(mpi_ec_t ec, gcry_mpi_t sig_r, gcry_mpi_t sig_s)
{
    if (mpi_is_opaque(sig_r) || mpi_is_opaque(sig_s)
        || gcry_mpi_cmp_ui(sig_r, 0) <= 0 || gcry_mpi_cmp(sig_r, ec->n) >= 0
        || gcry_mpi_cmp_ui(sig_s, 0) <= 0 || gcry_mpi_cmp(sig_s, ec->n) >= 0) {
        return GPG_ERR_BAD_SIGNATURE;
    }

    return GPG_ERR_NOT_IMPLEMENTED;
}

/* ------------------------------------------------------------------ */
/* Sign / verify dispatch                                              */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
ecc_sign(gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    mpi_ec_t ec = NULL;
    int flags = 0;
    gcry_mpi_t sig_r = NULL;
    gcry_mpi_t sig_s = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_SIGN, 0);
    rc = _gcry_mpi_ec_internal_new(&ec, &flags, keyparms, NULL);

    if (rc) {
        goto leave;
    }

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->d) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    pd.flags |= flags;

    if (is_eddsa(ec, flags)) {
        pd.flags |= PUBKEY_FLAG_EDDSA;
        pd.hash_algo = 0;
    }

    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if ((pd.flags & PUBKEY_FLAG_EDDSA) && ec->model != GCRY_ECC_MODEL_EDWARDS) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_GOST) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_SM2) {
        if (!is_sm2_curve(ec)) {
            rc = GPG_ERR_NOT_IMPLEMENTED;
            goto leave;
        }

        rc = sm2_sign(ec, &pd, &sig_r, &sig_s);

        if (!rc) {
            rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(sm2(r%M)(s%M)))",
                                  sig_r, sig_s);
        }

        goto leave;
    }

    if (pd.label && !(pd.flags & PUBKEY_FLAG_EDDSA) && _gcry_log_verbosity()) {
        log_info("ecc: a caller supplied nonce is not supported and ignored\n");
    }

    if (pd.flags & PUBKEY_FLAG_EDDSA) {
        rc = eddsa_sign(ec, &pd, &sig_r, &sig_s);

        if (!rc) {
            rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(eddsa(r%M)(s%M)))",
                                  sig_r, sig_s);
        }
    } else {
        rc = ecdsa_sign(ec, &pd, &sig_r, &sig_s);

        if (!rc) {
            rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(ecdsa(r%M)(s%M)))",
                                  sig_r, sig_s);
        }
    }

leave:
    gcry_mpi_release(sig_r);
    gcry_mpi_release(sig_s);
    _gcry_mpi_ec_free(ec);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
ecc_verify(gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t sig_r = NULL;
    gcry_mpi_t sig_s = NULL;
    int sigflags = 0;
    mpi_ec_t ec = NULL;
    int flags = 0;

    _gcry_pk_data_init(&pd, PUBKEY_OP_VERIFY, ecc_get_nbits(keyparms));
    rc = _gcry_mpi_ec_internal_new(&ec, &flags, keyparms, NULL);

    if (rc) {
        goto leave;
    }

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->Q) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        rc = GPG_ERR_INTERNAL;
        goto leave;
    }

    pd.flags |= flags;

    if (is_eddsa(ec, flags)) {
        pd.flags |= PUBKEY_FLAG_EDDSA;
        pd.hash_algo = 0;
    }

    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if ((pd.flags & PUBKEY_FLAG_EDDSA) && ec->model != GCRY_ECC_MODEL_EDWARDS) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_GOST) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    if ((pd.flags & PUBKEY_FLAG_SM2) && !is_sm2_curve(ec)) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    rc = _gcry_pk_util_preparse_sigval(s_sig, ecc_names, &l1, &sigflags);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL,
                                  (sigflags & PUBKEY_FLAG_EDDSA) ? "/rs" : "rs",
                                  &sig_r, &sig_s, NULL);

    if (rc) {
        goto leave;
    }

    if ((pd.flags & PUBKEY_FLAG_EDDSA) ^ (sigflags & PUBKEY_FLAG_EDDSA)) {
        rc = GPG_ERR_CONFLICT;
        goto leave;
    }

    if (sigflags & PUBKEY_FLAG_EDDSA) {
        rc = eddsa_verify(ec, &pd, sig_r, sig_s);
    } else if (!_gcry_mpi_ec_on_curve(ec->Q, ec)) {
        rc = GPG_ERR_BROKEN_PUBKEY;
    } else if ((sigflags & PUBKEY_FLAG_SM2) || (pd.flags & PUBKEY_FLAG_SM2)) {
        rc = is_sm2_curve(ec) ? sm2_verify(ec, &pd, sig_r, sig_s)
             : unverifiable_sig(ec, sig_r, sig_s);
    } else if (sigflags & PUBKEY_FLAG_GOST) {
        rc = unverifiable_sig(ec, sig_r, sig_s);
    } else {
        rc = ecdsa_verify(ec, &pd, sig_r, sig_s);
    }

leave:
    gcry_mpi_release(sig_r);
    gcry_mpi_release(sig_s);
    gcry_sexp_release(l1);
    _gcry_mpi_ec_free(ec);
    _gcry_pk_data_free(&pd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* ECDH                                                                */
/* ------------------------------------------------------------------ */

/* Encode an affine X (Montgomery) or (X, Y) as the s/e value. */
static gcry_mpi_t
encode_shared(mpi_ec_t ec, gcry_mpi_point_t R, int *r_infinity)
{
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = NULL;
    gcry_mpi_t result = NULL;

    *r_infinity = 0;

    if (ec->model != GCRY_ECC_MODEL_MONTGOMERY) {
        y = gcry_mpi_new(0);
    }

    if (_gcry_mpi_ec_affine(x, y, R, ec)) {
        *r_infinity = 1;
        gcry_mpi_set_ui(x, 0);
    }

    if (y) {
        if (!*r_infinity) {
            result = _gcry_ecc_ec2os(x, y, ec->p);
        }
    } else {
        unsigned char *enc;
        unsigned int enclen;

        if (!_gcry_ecc_mont_encodepoint(x, ec->nbits,
                                        ec->dialect != GCRY_ECC_DIALECT_SAFECURVE,
                                        &enc, &enclen)) {
            result = gcry_mpi_set_opaque(NULL, enc, enclen * 8);
        }
    }

    gcry_mpi_release(x);
    gcry_mpi_release(y);
    return result;
}

static gcry_err_code_t
ecc_encrypt_raw(gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    mpi_ec_t ec = NULL;
    int flags = 0;
    int no_error_on_infinity;
    gcry_mpi_point_t R = NULL;
    gcry_mpi_t mpi_s = NULL;
    gcry_mpi_t mpi_e = NULL;
    int infinity;

    _gcry_pk_data_init(&pd, PUBKEY_OP_ENCRYPT, ecc_get_nbits(keyparms));
    rc = _gcry_mpi_ec_internal_new(&ec, &flags, keyparms, NULL);

    if (rc) {
        goto leave;
    }

    if (ec->dialect == GCRY_ECC_DIALECT_SAFECURVE) {
        pd.flags |= PUBKEY_FLAG_RAW_FLAG;
        no_error_on_infinity = 1;
    } else if (flags & PUBKEY_FLAG_DJB_TWEAK) {
        no_error_on_infinity = 1;
    } else {
        no_error_on_infinity = 0;
    }

    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_SM2) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    if (!pd.mpi || mpi_is_opaque(pd.mpi)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    if (flags & PUBKEY_FLAG_DJB_TWEAK) {
        unsigned int i;

        for (i = 0; (ec->h & (1u << i)) == 0; i++) {
            gcry_mpi_clear_bit(pd.mpi, i);
        }

        gcry_mpi_set_highbit(pd.mpi, ec->nbits - 1);
    }

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->Q) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    R = gcry_mpi_point_new(0);
    rc = _gcry_mpi_ec_mul(R, pd.mpi, ec->Q, ec);

    if (rc) {
        if (!no_error_on_infinity) {
            rc = GPG_ERR_INV_DATA;
            goto leave;
        }

        /* X25519 with a low order peer key: the shared value is zero. */
        gcry_mpi_set_ui(R->x, 0);
        gcry_mpi_set_ui(R->y, 0);
        gcry_mpi_set_ui(R->z, 1);
        rc = 0;
    }

    mpi_s = encode_shared(ec, R, &infinity);

    if (!mpi_s || (infinity && !no_error_on_infinity)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_mpi_ec_mul(R, pd.mpi, ec->G, ec);

    if (rc) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    mpi_e = encode_shared(ec, R, &infinity);

    if (!mpi_e || infinity) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(ecdh(s%m)(e%m)))", mpi_s,
                          mpi_e);

leave:
    gcry_mpi_point_release(R);
    gcry_mpi_release(mpi_s);
    gcry_mpi_release(mpi_e);
    _gcry_mpi_ec_free(ec);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
ecc_decrypt_raw(gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t data_e = NULL;
    mpi_ec_t ec = NULL;
    int flags = 0;
    gcry_mpi_point_t kG = NULL;
    gcry_mpi_point_t R = NULL;
    gcry_mpi_t r = NULL;
    int infinity;

    _gcry_pk_data_init(&pd, PUBKEY_OP_DECRYPT, ecc_get_nbits(keyparms));
    rc = _gcry_mpi_ec_internal_new(&ec, &flags, keyparms, NULL);

    if (rc) {
        goto leave;
    }

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->d) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    rc = _gcry_pk_util_preparse_encval(s_data, ecc_names, &l1, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_SM2) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL, "/e", &data_e, NULL);

    if (rc) {
        goto leave;
    }

    kG = gcry_mpi_point_new(0);
    rc = _gcry_ecc_decode_point(kG, data_e, ec);

    if (rc) {
        goto leave;
    }

    if (ec->model == GCRY_ECC_MODEL_WEIERSTRASS
        && !_gcry_mpi_ec_on_curve(kG, ec)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    R = gcry_mpi_point_new(0);
    rc = _gcry_mpi_ec_mul(R, ec->d, kG, ec);

    if (rc) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    r = encode_shared(ec, R, &infinity);

    if (!r || infinity) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_sexp_build(r_plain, NULL, "(value %m)", r);

leave:
    gcry_mpi_point_release(R);
    gcry_mpi_point_release(kG);
    gcry_mpi_release(r);
    gcry_mpi_release(data_e);
    gcry_sexp_release(l1);
    _gcry_mpi_ec_free(ec);
    _gcry_pk_data_free(&pd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Key generation and checking                                         */
/* ------------------------------------------------------------------ */

/* Key generation for a curve OpenSSL has no name for: a random scalar in
 * [1, n-1] from OpenSSL's RNG and Q = dG through EC_POINT_mul. */
static gcry_err_code_t
explicit_curve_keygen(mpi_ec_t ec)
{
    BN_CTX *bctx = BN_CTX_new_ex(_gcry_libctx());
    BIGNUM *d = BN_secure_new();
    BIGNUM *nm1 = BN_new();
    gcry_err_code_t rc = GPG_ERR_ENOMEM;

    if (!bctx || !d || !nm1) {
        goto leave;
    }

    if (!BN_sub(nm1, _gcry_mpi_bn(ec->n), BN_value_one())
        || !BN_priv_rand_range_ex(d, nm1, 0, bctx)
        || !BN_add_word(d, 1)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    gcry_mpi_release(ec->d);
    ec->d = _gcry_mpi_new_from_bn(d, 1);
    d = NULL;
    rc = _gcry_ecc_compute_public(ec);

leave:
    BN_clear_free(d);
    BN_free(nm1);
    BN_CTX_free(bctx);
    return rc;
}

/* Generate a Weierstrass key pair with OpenSSL and store d and Q. */
static gcry_err_code_t
weierstrass_keygen(mpi_ec_t ec)
{
    gcry_err_code_t rc = GPG_ERR_INTERNAL;
    BN_CTX *bctx = BN_CTX_new_ex(_gcry_libctx());
    OSSL_PARAM *grp = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    BIGNUM *priv = NULL;
    unsigned char *pub = NULL;
    size_t publen = 0;
    gcry_mpi_t enc = NULL;

    if (!ec->group || !bctx) {
        goto leave;
    }

    if (EC_GROUP_get_curve_name(ec->group) == NID_undef) {
        BN_CTX_free(bctx);
        return explicit_curve_keygen(ec);
    }

    grp = EC_GROUP_to_params(ec->group, _gcry_libctx(), _gcry_propq(), bctx);
    ctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "EC", _gcry_propq());

    if (!grp || !ctx || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_params(ctx, grp) <= 0
        || EVP_PKEY_keygen(ctx, &key) <= 0
        || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &priv)
        || !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                            NULL, 0, &publen)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    pub = _gcry_malloc(publen);

    if (!pub || !EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                                 pub, publen, &publen)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    gcry_mpi_release(ec->d);
    ec->d = _gcry_pk_mpi_from_bn(priv);
    gcry_mpi_set_flag(ec->d, GCRYMPI_FLAG_SECURE);
    enc = gcry_mpi_set_opaque_copy(NULL, pub, (unsigned int)publen * 8);

    if (!ec->Q) {
        ec->Q = gcry_mpi_point_new(0);
    }

    rc = enc ? _gcry_ecc_decode_point(ec->Q, enc, ec) : GPG_ERR_ENOMEM;

leave:
    ERR_clear_error();
    gcry_mpi_release(enc);
    _gcry_free(pub);
    BN_clear_free(priv);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(grp);
    BN_CTX_free(bctx);
    return rc;
}

/* Generate an Ed25519/Ed448/X25519/X448 key pair with OpenSSL. */
static gcry_err_code_t
raw_keygen(mpi_ec_t ec, const char *keytype)
{
    gcry_err_code_t rc;
    EVP_PKEY *key = EVP_PKEY_Q_keygen(_gcry_libctx(), _gcry_propq(), keytype);
    unsigned char priv[64];
    unsigned char pub[64];
    size_t privlen = sizeof priv;
    size_t publen = sizeof pub;
    gcry_mpi_t enc;

    if (!key) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    if (!EVP_PKEY_get_raw_private_key(key, priv, &privlen)
        || !EVP_PKEY_get_raw_public_key(key, pub, &publen)) {
        EVP_PKEY_free(key);
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    EVP_PKEY_free(key);
    gcry_mpi_release(ec->d);

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        /* Store the scalar clamped the way X25519/X448 define it, so that
         * d * G computed exactly is the public key. */
        if (privlen == 32) {
            priv[0] &= 248;
            priv[31] &= 127;
            priv[31] |= 64;
        } else if (privlen == 56) {
            priv[0] &= 252;
            priv[55] |= 128;
        }
    }

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY
        && ec->dialect != GCRY_ECC_DIALECT_SAFECURVE) {
        /* Curve25519 keeps the scalar as a number. */
        unsigned char be[64];
        size_t i;

        for (i = 0; i < privlen; i++) {
            be[i] = priv[privlen - 1 - i];
        }

        ec->d = gcry_mpi_snew(0);
        _gcry_mpi_set_buffer(ec->d, be, (unsigned int)privlen, 0);
        _gcry_wipememory(be, sizeof be);
    } else {
        void *copy = _gcry_malloc_secure(privlen);

        if (!copy) {
            _gcry_wipememory(priv, sizeof priv);
            return GPG_ERR_ENOMEM;
        }

        memcpy(copy, priv, privlen);
        ec->d = gcry_mpi_set_opaque(NULL, copy, (unsigned int)privlen * 8);
    }

    _gcry_wipememory(priv, sizeof priv);
    enc = gcry_mpi_set_opaque_copy(NULL, pub, (unsigned int)publen * 8);

    if (!enc) {
        return GPG_ERR_ENOMEM;
    }

    if (!ec->Q) {
        ec->Q = gcry_mpi_point_new(0);
    }

    rc = _gcry_ecc_decode_point(ec->Q, enc, ec);
    gcry_mpi_release(enc);
    return rc;
}

static gcry_err_code_t
ecc_generate(gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{
    gcry_err_code_t rc;
    mpi_ec_t ec = NULL;
    int flags = 0;
    gcry_sexp_t curve_info = NULL;
    gcry_sexp_t curve_flags = NULL;
    gcry_mpi_t base = NULL;
    gcry_mpi_t public = NULL;

    rc = _gcry_mpi_ec_internal_new(&ec, &flags, genparms, NULL);

    if (rc) {
        goto leave;
    }

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    if ((flags & PUBKEY_FLAG_EDDSA) && ec->model != GCRY_ECC_MODEL_EDWARDS) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    if (is_eddsa(ec, flags)) {
        ec->flags |= PUBKEY_FLAG_EDDSA;
        rc = raw_keygen(ec, ec->nbits == 448 ? "ED448" : "ED25519");
    } else if (ec->model == GCRY_ECC_MODEL_EDWARDS) {
        /* An Edwards curve without the eddsa flag: the reference library
         * generates a plain key pair here; this one is an EdDSA pair whose
         * secret is the seed, encoded without the eddsa marker. */
        rc = raw_keygen(ec, ec->nbits == 448 ? "ED448" : "ED25519");
    } else if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        rc = raw_keygen(ec, ec->nbits == 448 ? "X448" : "X25519");
    } else {
        rc = weierstrass_keygen(ec);
    }

    if (rc) {
        goto leave;
    }

    if (ec->model != GCRY_ECC_MODEL_MONTGOMERY) {
        base = _gcry_mpi_ec_ec2os(ec->G, ec);

        if (!base) {
            rc = GPG_ERR_INTERNAL;
            goto leave;
        }
    }

    if (((ec->dialect == GCRY_ECC_DIALECT_SAFECURVE
          && ec->model == GCRY_ECC_MODEL_EDWARDS)
         || ec->dialect == GCRY_ECC_DIALECT_ED25519
         || ec->model == GCRY_ECC_MODEL_MONTGOMERY)
        && !(flags & PUBKEY_FLAG_NOCOMP)) {
        unsigned char *enc = NULL;
        unsigned int enclen = 0;

        if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
            gcry_mpi_t x = gcry_mpi_new(0);

            if (_gcry_mpi_ec_affine(x, NULL, ec->Q, ec)) {
                rc = GPG_ERR_INTERNAL;
            } else {
                rc = _gcry_ecc_mont_encodepoint(x, ec->nbits,
                                                ec->dialect
                                                != GCRY_ECC_DIALECT_SAFECURVE,
                                                &enc, &enclen);
            }

            gcry_mpi_release(x);
        } else {
            rc = _gcry_ecc_eddsa_encodepoint(ec->Q, ec,
                                             ec->dialect
                                             != GCRY_ECC_DIALECT_SAFECURVE
                                             && !!(flags & PUBKEY_FLAG_COMP),
                                             &enc, &enclen);
        }

        if (rc) {
            goto leave;
        }

        public = gcry_mpi_set_opaque(NULL, enc, enclen * 8);
    } else {
        public = _gcry_mpi_ec_ec2os(ec->Q, ec);

        if (!public) {
            rc = GPG_ERR_INV_PARAMETER;
            goto leave;
        }
    }

    if (ec->name) {
        rc = _gcry_sexp_build(&curve_info, NULL, "(curve %s)", ec->name);

        if (rc) {
            goto leave;
        }
    }

    if ((flags & PUBKEY_FLAG_PARAM) || (flags & PUBKEY_FLAG_EDDSA)
        || (flags & PUBKEY_FLAG_DJB_TWEAK)) {
        const char *s =
            ((flags & PUBKEY_FLAG_PARAM) && (flags & PUBKEY_FLAG_EDDSA))
            ? "(flags param eddsa)"
            : ((flags & PUBKEY_FLAG_PARAM) && (flags & PUBKEY_FLAG_DJB_TWEAK))
            ? "(flags param djb-tweak)"
            : (flags & PUBKEY_FLAG_PARAM) ? "(flags param)"
            : (flags & PUBKEY_FLAG_EDDSA) ? "(flags eddsa)"
            : "(flags djb-tweak)";

        rc = _gcry_sexp_build(&curve_flags, NULL, s);

        if (rc) {
            goto leave;
        }
    }

    if ((flags & PUBKEY_FLAG_PARAM) && ec->name) {
        rc = _gcry_sexp_build(r_skey, NULL,
                              "(key-data"
                              " (public-key"
                              "  (ecc%S%S(p%m)(a%m)(b%m)(g%m)(n%m)(h%u)(q%m)))"
                              " (private-key"
                              "  (ecc%S%S(p%m)(a%m)(b%m)(g%m)(n%m)(h%u)(q%m)"
                              "(d%m))))",
                              curve_info, curve_flags, ec->p, ec->a, ec->b,
                              base, ec->n, ec->h, public, curve_info,
                              curve_flags, ec->p, ec->a, ec->b, base, ec->n,
                              ec->h, public, ec->d);
    } else {
        rc = _gcry_sexp_build(r_skey, NULL,
                              "(key-data"
                              " (public-key"
                              "  (ecc%S%S(q%m)))"
                              " (private-key"
                              "  (ecc%S%S(q%m)(d%m))))",
                              curve_info, curve_flags, public, curve_info,
                              curve_flags, public, ec->d);
    }

leave:
    gcry_mpi_release(public);
    gcry_mpi_release(base);
    gcry_sexp_release(curve_flags);
    gcry_sexp_release(curve_info);
    _gcry_mpi_ec_free(ec);
    return rc;
}

static gcry_err_code_t
ecc_check_secret_key(gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    mpi_ec_t ec = NULL;
    int flags = 0;
    gcry_mpi_point_t Q = NULL;
    gcry_mpi_t x1 = NULL;
    gcry_mpi_t y1 = NULL;
    gcry_mpi_t x2 = NULL;
    gcry_mpi_t y2 = NULL;
    int want_y;

    rc = _gcry_mpi_ec_internal_new(&ec, &flags, keyparms, NULL);

    if (rc) {
        return rc;
    }

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !ec->Q || !ec->d) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    /* Recompute the public key and compare it with the stored one. */
    Q = ec->Q;
    ec->Q = NULL;
    rc = _gcry_ecc_compute_public(ec);

    if (rc) {
        rc = GPG_ERR_BAD_SECKEY;
        goto leave;
    }

    want_y = ec->model != GCRY_ECC_MODEL_MONTGOMERY;
    x1 = gcry_mpi_new(0);
    x2 = gcry_mpi_new(0);

    if (want_y) {
        y1 = gcry_mpi_new(0);
        y2 = gcry_mpi_new(0);
    }

    if (_gcry_mpi_ec_affine(x1, y1, Q, ec)
        || _gcry_mpi_ec_affine(x2, y2, ec->Q, ec)
        || gcry_mpi_cmp(x1, x2) || (want_y && gcry_mpi_cmp(y1, y2))) {
        rc = GPG_ERR_BAD_SECKEY;
    }

leave:
    gcry_mpi_release(x1);
    gcry_mpi_release(y1);
    gcry_mpi_release(x2);
    gcry_mpi_release(y2);
    gcry_mpi_point_release(Q);
    _gcry_mpi_ec_free(ec);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Keygrip                                                             */
/* ------------------------------------------------------------------ */

/* The magnitude of a table constant ("0x..", "-0x..") as bytes. */
static gcry_err_code_t
hex_magnitude(const char *hex, unsigned char **r_buf, size_t *r_len)
{
    BIGNUM *bn = NULL;

    if (*hex == '-') {
        hex++;
    }

    if (hex[0] == '0' && hex[1] == 'x') {
        hex += 2;
    }

    if (BN_hex2bn(&bn, hex) <= 0 || !bn) {
        BN_free(bn);
        ERR_clear_error();
        return GPG_ERR_INTERNAL;
    }

    *r_len = (size_t)BN_num_bytes(bn);
    *r_buf = _gcry_malloc(*r_len ? *r_len : 1);

    if (!*r_buf) {
        BN_free(bn);
        return GPG_ERR_ENOMEM;
    }

    BN_bn2bin(bn, *r_buf);
    BN_free(bn);
    return 0;
}

/* "04 || G.x || G.y" from the table hex strings. */
static gcry_err_code_t
hex_generator(const struct gcry_ecc_curve *curve, unsigned char **r_buf,
              size_t *r_len)
{
    const char *gx = curve->gx;
    const char *gy = curve->gy;
    size_t lx;
    size_t ly;
    size_t i;
    unsigned char *buf;

    if (gx[0] == '0' && gx[1] == 'x') {
        gx += 2;
    }

    if (gy[0] == '0' && gy[1] == 'x') {
        gy += 2;
    }

    lx = strlen(gx);
    ly = strlen(gy);

    if ((lx % 2) || (ly % 2)) {
        return GPG_ERR_INTERNAL;
    }

    *r_len = 1 + lx / 2 + ly / 2;
    buf = _gcry_malloc(*r_len);

    if (!buf) {
        return GPG_ERR_ENOMEM;
    }

    buf[0] = 0x04;

    for (i = 0; i < lx / 2; i++) {
        unsigned int v;

        sscanf(gx + 2 * i, "%2x", &v);
        buf[1 + i] = (unsigned char)v;
    }

    for (i = 0; i < ly / 2; i++) {
        unsigned int v;

        sscanf(gy + 2 * i, "%2x", &v);
        buf[1 + lx / 2 + i] = (unsigned char)v;
    }

    *r_buf = buf;
    return 0;
}

/* Expand the SEC 1 compressed point Q (N bytes, 02 or 03 prefix) of a
 * table CURVE to "04 || x || y".  Only the table constants and BIGNUM
 * arithmetic are used, so no curve context is needed: the keygrip is a
 * pure function of the key material and stays computable in FIPS mode
 * for curves the providers do not offer. */
static gcry_err_code_t
decompress_from_table(const struct gcry_ecc_curve *curve,
                      const unsigned char *q, size_t n,
                      unsigned char **r_buf, size_t *r_len)
{
    gcry_mpi_t p = _gcry_ecc_curve_param(curve, "p");
    gcry_mpi_t a = _gcry_ecc_curve_param(curve, "a");
    gcry_mpi_t b = _gcry_ecc_curve_param(curve, "b");
    BN_CTX *bctx = BN_CTX_new_ex(_gcry_libctx());
    BIGNUM *x = NULL;
    BIGNUM *y = BN_new();
    BIGNUM *t = BN_new();
    unsigned char *buf = NULL;
    size_t pbytes;
    gcry_err_code_t rc = GPG_ERR_ENOMEM;

    if (!p || !a || !b || !bctx || !y || !t) {
        goto leave;
    }

    pbytes = (gcry_mpi_get_nbits(p) + 7) / 8;

    if (n != 1 + pbytes) {
        rc = GPG_ERR_INV_OBJ;
        goto leave;
    }

    x = BN_bin2bn(q + 1, (int)pbytes, NULL);
    buf = _gcry_malloc(1 + 2 * pbytes);

    if (!x || !buf) {
        goto leave;
    }

    /* y^2 = x^3 + a x + b, with the root of the parity the prefix names. */
    if (BN_ucmp(x, _gcry_mpi_bn(p)) >= 0
        || !BN_mod_sqr(t, x, _gcry_mpi_bn(p), bctx)
        || !BN_mod_add(t, t, _gcry_mpi_bn(a), _gcry_mpi_bn(p), bctx)
        || !BN_mod_mul(t, t, x, _gcry_mpi_bn(p), bctx)
        || !BN_mod_add(t, t, _gcry_mpi_bn(b), _gcry_mpi_bn(p), bctx)
        || !BN_mod_sqrt(y, t, _gcry_mpi_bn(p), bctx)) {
        rc = GPG_ERR_INV_OBJ;
        goto leave;
    }

    if (BN_is_odd(y) != (q[0] & 1) && !BN_sub(y, _gcry_mpi_bn(p), y)) {
        rc = GPG_ERR_INTERNAL;
        goto leave;
    }

    buf[0] = 0x04;

    if (BN_bn2binpad(x, buf + 1, (int)pbytes) < 0
        || BN_bn2binpad(y, buf + 1 + pbytes, (int)pbytes) < 0) {
        rc = GPG_ERR_INTERNAL;
        goto leave;
    }

    *r_buf = buf;
    *r_len = 1 + 2 * pbytes;
    buf = NULL;
    rc = 0;

leave:
    ERR_clear_error();
    _gcry_free(buf);
    BN_free(x);
    BN_free(y);
    BN_free(t);
    BN_CTX_free(bctx);
    gcry_mpi_release(p);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    return rc;
}

static gcry_err_code_t
compute_keygrip(EVP_MD_CTX *md, gcry_sexp_t keyparms)
{
#define N_COMPONENTS 6
    static const char names[N_COMPONENTS + 1] = "pabgnq";
    gcry_err_code_t rc;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t values[N_COMPONENTS];
    unsigned char *raw[N_COMPONENTS];
    size_t rawlen[N_COMPONENTS];
    int idx;
    char *curvename = NULL;
    const struct gcry_ecc_curve *curve = NULL;
    int flags = 0;
    enum gcry_ecc_models model = GCRY_ECC_MODEL_WEIERSTRASS;
    enum gcry_ecc_dialects dialect = GCRY_ECC_DIALECT_STANDARD;

    for (idx = 0; idx < N_COMPONENTS; idx++) {
        values[idx] = NULL;
        raw[idx] = NULL;
        rawlen[idx] = 0;
    }

    l1 = gcry_sexp_find_token(keyparms, "flags", 0);

    if (l1) {
        rc = _gcry_pk_util_parse_flaglist(l1, &flags, NULL);
        gcry_sexp_release(l1);
        l1 = NULL;

        if (rc) {
            goto leave;
        }
    }

    if (flags & PUBKEY_FLAG_PARAM) {
        rc = _gcry_sexp_extract_param(keyparms, NULL, "p?a?b?g?n?/q",
                                      &values[0], &values[1], &values[2],
                                      &values[3], &values[4], &values[5],
                                      NULL);
    } else {
        rc = _gcry_sexp_extract_param(keyparms, NULL, "/q", &values[5], NULL);
    }

    if (rc) {
        goto leave;
    }

    l1 = gcry_sexp_find_token(keyparms, "curve", 5);

    if (l1) {
        curvename = gcry_sexp_nth_string(l1, 1);

        if (curvename) {
            curve = _gcry_ecc_curve_find(curvename);

            if (!curve) {
                rc = GPG_ERR_UNKNOWN_CURVE;
                goto leave;
            }

            model = curve->model;
            dialect = curve->dialect;
        }
    }

    if (!curve) {
        model = (flags & PUBKEY_FLAG_EDDSA) ? GCRY_ECC_MODEL_EDWARDS
                : GCRY_ECC_MODEL_WEIERSTRASS;
        dialect = (flags & PUBKEY_FLAG_EDDSA) ? GCRY_ECC_DIALECT_ED25519
                  : GCRY_ECC_DIALECT_STANDARD;
    }

    (void)model;

    /* Domain parameters: the curve's constants win over given values. */
    for (idx = 0; idx < N_COMPONENTS - 1; idx++) {
        if (curve) {
            if (idx == 3) {
                rc = hex_generator(curve, &raw[idx], &rawlen[idx]);
            } else {
                const char *hex = idx == 0 ? curve->p : idx == 1 ? curve->a
                                  : idx == 2 ? curve->b : curve->n;

                rc = hex_magnitude(hex, &raw[idx], &rawlen[idx]);
            }
        } else if (values[idx]) {
            rc = _gcry_pk_mpi_to_bytes(values[idx], &raw[idx], &rawlen[idx]);
        } else {
            rc = GPG_ERR_NO_OBJ;
        }

        if (rc) {
            goto leave;
        }
    }

    if (!values[5]) {
        rc = GPG_ERR_NO_OBJ;
        goto leave;
    }

    /* The public key: compressed EdDSA form, tweak prefix stripped, or
     * uncompressed SEC 1. */
    if ((flags & PUBKEY_FLAG_EDDSA) && dialect == GCRY_ECC_DIALECT_ED25519) {
        unsigned int pbits = (unsigned int)rawlen[0] * 8;
        unsigned int n;

        if (raw[0][0] < 0x80) {
            /* Bit length of p, needed for the encoding size. */
            unsigned char top = raw[0][0];

            while (top && !(top & 0x80)) {
                top = (unsigned char)(top << 1);
                pbits--;
            }
        }

        rc = _gcry_ecc_eddsa_compact(values[5], pbits, &raw[5], &n);
        rawlen[5] = n;
    } else if (flags & PUBKEY_FLAG_DJB_TWEAK) {
        const unsigned char *q;
        unsigned int n;

        q = gcry_mpi_get_opaque(values[5], &n);

        if (!q) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }

        n = (n + 7) / 8;

        if (n > 1 && (n % 2) && q[0] == 0x40) {
            q++;
            n--;
        }

        raw[5] = _gcry_malloc(n ? n : 1);

        if (!raw[5]) {
            rc = GPG_ERR_ENOMEM;
            goto leave;
        }

        memcpy(raw[5], q, n);
        rawlen[5] = n;
    } else {
        const unsigned char *q;
        unsigned int n;

        q = gcry_mpi_get_opaque(values[5], &n);
        n = (n + 7) / 8;

        if (!q || !n) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }

        if (n > 1 && (q[0] == 0x02 || q[0] == 0x03) && curve
            && curve->model == GCRY_ECC_MODEL_WEIERSTRASS) {
            /* Compressed point on a known curve: expand it from the
             * table constants. */
            rc = decompress_from_table(curve, q, n, &raw[5], &rawlen[5]);
        } else if (n > 1 && (q[0] == 0x02 || q[0] == 0x03)) {
            /* Compressed point: expand it with the curve's group. */
            mpi_ec_t ec = NULL;
            int ecflags = flags;
            gcry_mpi_point_t pt;

            rc = _gcry_mpi_ec_internal_new(&ec, &ecflags, keyparms, NULL);

            if (rc) {
                goto leave;
            }

            pt = gcry_mpi_point_new(0);
            rc = _gcry_ecc_decode_point(pt, values[5], ec);

            if (!rc) {
                gcry_mpi_t enc = _gcry_mpi_ec_ec2os(pt, ec);

                if (!enc) {
                    rc = GPG_ERR_INV_OBJ;
                } else {
                    rc = _gcry_pk_mpi_to_bytes(enc, &raw[5], &rawlen[5]);
                    gcry_mpi_release(enc);
                }
            }

            gcry_mpi_point_release(pt);
            _gcry_mpi_ec_free(ec);
        } else {
            raw[5] = _gcry_malloc(n);

            if (!raw[5]) {
                rc = GPG_ERR_ENOMEM;
                goto leave;
            }

            memcpy(raw[5], q, n);
            rawlen[5] = n;
        }
    }

    if (rc) {
        goto leave;
    }

    for (idx = 0; idx < N_COMPONENTS; idx++) {
        char buf[30];

        snprintf(buf, sizeof buf, "(1:%c%u:", names[idx],
                 (unsigned int)rawlen[idx]);

        if (!EVP_DigestUpdate(md, buf, strlen(buf))
            || !EVP_DigestUpdate(md, raw[idx], rawlen[idx])
            || !EVP_DigestUpdate(md, ")", 1)) {
            rc = GPG_ERR_INTERNAL;
            goto leave;
        }
    }

leave:
    _gcry_free(curvename);
    gcry_sexp_release(l1);

    for (idx = 0; idx < N_COMPONENTS; idx++) {
        gcry_mpi_release(values[idx]);
        _gcry_free(raw[idx]);
    }

    return rc;
#undef N_COMPONENTS
}

/* ------------------------------------------------------------------ */
/* Curve queries                                                       */
/* ------------------------------------------------------------------ */

/* Compare a given parameter against a table constant that may be stored
 * as a negative value (meaning p - |value|). */
static int
param_matches(gcry_mpi_t given, const char *hex, gcry_mpi_t p)
{
    BIGNUM *bn = NULL;
    const char *h = hex;
    int negative = 0;
    int match;

    if (*h == '-') {
        negative = 1;
        h++;
    }

    if (h[0] == '0' && h[1] == 'x') {
        h += 2;
    }

    if (BN_hex2bn(&bn, h) <= 0 || !bn) {
        BN_free(bn);
        ERR_clear_error();
        return 0;
    }

    match = BN_cmp(bn, _gcry_mpi_bn(given)) == 0;

    if (!match && negative && p) {
        BIGNUM *t = BN_new();

        match = t && BN_sub(t, _gcry_mpi_bn(p), bn)
                && BN_cmp(t, _gcry_mpi_bn(given)) == 0;
        BN_free(t);
    }

    BN_free(bn);
    return match;
}

static const char *
ecc_get_curve(gcry_sexp_t keyparms, int iterator, unsigned int *r_nbits)
{
    const char *result = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t a = NULL;
    gcry_mpi_t b = NULL;
    gcry_mpi_t n = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_point_t G = NULL;
    gcry_err_code_t rc;
    size_t i;

    if (r_nbits) {
        *r_nbits = 0;
    }

    if (!keyparms) {
        const struct gcry_ecc_curve *curve;

        if (iterator < 0) {
            return NULL;
        }

        curve = _gcry_ecc_curve_by_index((size_t)iterator);

        if (curve && r_nbits) {
            *r_nbits = curve->nbits;
        }

        return curve ? curve->name : NULL;
    }

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pabn", &p, &a, &b, &n,
                                  NULL);

    if (rc == GPG_ERR_NO_OBJ) {
        gcry_sexp_t l1 = gcry_sexp_find_token(keyparms, "curve", 5);
        char *name;
        const struct gcry_ecc_curve *curve;

        if (!l1) {
            return NULL;
        }

        name = gcry_sexp_nth_string(l1, 1);
        gcry_sexp_release(l1);

        if (!name) {
            return NULL;
        }

        curve = usable_curve(name);
        _gcry_free(name);

        if (!curve) {
            return NULL;
        }

        if (r_nbits) {
            *r_nbits = curve->nbits;
        }

        return curve->name;
    }

    if (rc) {
        return NULL;
    }

    rc = _gcry_sexp_extract_param(keyparms, NULL, "/g", &g, NULL);

    if (rc) {
        goto leave;
    }

    G = gcry_mpi_point_new(0);

    if (_gcry_ecc_decode_point(G, g, NULL)) {
        goto leave;
    }

    for (i = 0; i < _gcry_ecc_curve_count(); i++) {
        const struct gcry_ecc_curve *curve = _gcry_ecc_curve_by_index(i);

        if (_gcry_fips_mode() && !curve->fips) {
            continue;
        }

        if (!param_matches(p, curve->p, NULL) || !param_matches(a, curve->a, p)
            || !param_matches(b, curve->b, p)
            || !param_matches(n, curve->n, NULL)
            || !param_matches(G->x, curve->gx, NULL)
            || !param_matches(G->y, curve->gy, NULL)) {
            continue;
        }

        result = curve->name;

        if (r_nbits) {
            *r_nbits = curve->nbits;
        }

        break;
    }

leave:
    gcry_mpi_point_release(G);
    gcry_mpi_release(g);
    gcry_mpi_release(p);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(n);
    return result;
}

static gcry_sexp_t
ecc_get_param_sexp(const char *name)
{
    const struct gcry_ecc_curve *curve = usable_curve(name);
    gcry_mpi_t p;
    gcry_mpi_t a;
    gcry_mpi_t b;
    gcry_mpi_t n;
    gcry_mpi_t gx;
    gcry_mpi_t gy;
    gcry_mpi_t g = NULL;
    gcry_sexp_t result = NULL;

    if (!curve) {
        return NULL;
    }

    p = _gcry_ecc_curve_param(curve, "p");
    a = _gcry_ecc_curve_param(curve, "a");
    b = _gcry_ecc_curve_param(curve, "b");
    n = _gcry_ecc_curve_param(curve, "n");
    gx = _gcry_ecc_curve_param(curve, "g.x");
    gy = _gcry_ecc_curve_param(curve, "g.y");

    if (p && a && b && n && gx && gy) {
        if (!strcmp(curve->name, "Curve25519")) {
            gcry_mpi_sub(gy, p, gy);
        }

        g = _gcry_ecc_ec2os(gx, gy, p);

        if (!g || _gcry_sexp_build(&result, NULL,
                                   "(public-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)"
                                   "(h%u)))", p, a, b, g, n, curve->h)) {
            result = NULL;
        }
    }

    gcry_mpi_release(p);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(n);
    gcry_mpi_release(gx);
    gcry_mpi_release(gy);
    gcry_mpi_release(g);
    return result;
}

/* ------------------------------------------------------------------ */
/* Modern ECC helpers                                                  */
/* ------------------------------------------------------------------ */

unsigned int
gcry_ecc_get_algo_keylen(int curveid)
{
    if (curveid == GCRY_ECC_CURVE25519) {
        return 32;
    }

    if (curveid == GCRY_ECC_CURVE448) {
        return 56;
    }

    return 0;
}

gpg_error_t
gcry_ecc_mul_point(int curveid, unsigned char *result,
                   const unsigned char *scalar, const unsigned char *point)
{
    const char *keytype;
    const char *curvename;
    size_t len;
    EVP_PKEY *priv = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    gcry_err_code_t rc = 0;
    size_t outlen;

    if (curveid == GCRY_ECC_CURVE25519) {
        keytype = "X25519";
        curvename = "Curve25519";
        len = 32;
    } else if (curveid == GCRY_ECC_CURVE448) {
        keytype = "X448";
        curvename = "X448";
        len = 56;
    } else {
        return GCRY_ERR(GPG_ERR_UNKNOWN_CURVE);
    }

    if (!result || !scalar) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    /* The curve table decides what FIPS mode allows, as for the keys of
     * gcry_pk_*; the FIPS provider has no X25519/X448 anyway. */
    if (!usable_curve(curvename)) {
        return GCRY_ERR(GPG_ERR_NOT_SUPPORTED);
    }

    priv = EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(), keytype,
                                           _gcry_propq(), scalar, len);

    if (!priv) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_DATA);
        goto leave;
    }

    outlen = len;

    if (!point) {
        if (!EVP_PKEY_get_raw_public_key(priv, result, &outlen)) {
            rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        goto leave;
    }

    peer = EVP_PKEY_new_raw_public_key_ex(_gcry_libctx(), keytype,
                                          _gcry_propq(), point, len);
    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), priv, _gcry_propq());

    if (!peer || !ctx || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer_ex(ctx, peer, 0) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_DATA);
    } else if (EVP_PKEY_derive(ctx, result, &outlen) <= 0) {
        /* OpenSSL refuses the all zero shared secret of a low order
         * point; the function itself is defined to return it. */
        ERR_clear_error();
        memset(result, 0, len);
    }

leave:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return GCRY_ERR(rc);
}

const struct gcry_pk_spec _gcry_pubkey_spec_ecc = {
    GCRY_PK_ECC,
    1,
    GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
    "ECC",
    ecc_names,
    "pabgnhq",
    "pabgnhqd",
    "se",
    "rs",
    "pabgnhq",
    ecc_generate,
    ecc_check_secret_key,
    ecc_encrypt_raw,
    ecc_decrypt_raw,
    ecc_sign,
    ecc_verify,
    ecc_get_nbits,
    compute_keygrip,
    ecc_get_curve,
    ecc_get_param_sexp
};
