/*
 * pk-rsa.c - RSA on top of OpenSSL's EVP_PKEY interface.
 *
 * Libgcrypt keeps p < q and u = p^-1 mod q; OpenSSL wants the CRT values
 * for its own (p, q) order, so the factors are swapped when a key object
 * is built, which makes Libgcrypt's u exactly OpenSSL's "coefficient".
 */
#include "gcrypt-int.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

static const char *const rsa_names[] = {
    "rsa", "openpgp-rsa", "oid.1.2.840.113549.1.1.1", NULL
};

static unsigned int
rsa_get_nbits(gcry_sexp_t parms)
{
    gcry_sexp_t l1 = gcry_sexp_find_token(parms, "n", 1);
    gcry_mpi_t n;
    unsigned int nbits;

    if (!l1) {
        return 0;
    }

    n = gcry_sexp_nth_mpi(l1, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(l1);
    nbits = n ? gcry_mpi_get_nbits(n) : 0;
    gcry_mpi_release(n);
    return nbits;
}

/* Build an EVP_PKEY from the key parameters. */
static gcry_err_code_t
rsa_evp_key(gcry_sexp_t parms, int want_private, EVP_PKEY **r_key,
            gcry_mpi_t *r_n)
{
    gcry_err_code_t rc;
    gcry_mpi_t n = NULL;
    gcry_mpi_t e = NULL;
    gcry_mpi_t d = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t u = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BN_CTX *bctx = NULL;
    BIGNUM *dp = NULL;
    BIGNUM *dq = NULL;
    BIGNUM *coeff = NULL;
    BIGNUM *tmp = NULL;

    *r_key = NULL;

    if (r_n) {
        *r_n = NULL;
    }

    if (want_private) {
        rc = _gcry_sexp_extract_param(parms, NULL, "nedp?q?u?", &n, &e, &d,
                                      &p, &q, &u, NULL);
    } else {
        rc = _gcry_sexp_extract_param(parms, NULL, "ne", &n, &e, NULL);
    }

    if (rc) {
        return rc;
    }

    bld = OSSL_PARAM_BLD_new();
    bctx = BN_CTX_new_ex(_gcry_libctx());

    if (!bld || !bctx
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, _gcry_mpi_bn(n))
        || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E,
                                   _gcry_mpi_bn(e))) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (want_private) {
        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D,
                                    _gcry_mpi_bn(d))) {
            rc = GPG_ERR_ENOMEM;
            goto leave;
        }

        if (p && q) {
            /* OpenSSL factor1 := q, factor2 := p. */
            dp = BN_new();
            dq = BN_new();
            coeff = BN_new();
            tmp = BN_new();

            if (!dp || !dq || !coeff || !tmp
                || !BN_sub(tmp, _gcry_mpi_bn(q), BN_value_one())
                || !BN_mod(dp, _gcry_mpi_bn(d), tmp, bctx)
                || !BN_sub(tmp, _gcry_mpi_bn(p), BN_value_one())
                || !BN_mod(dq, _gcry_mpi_bn(d), tmp, bctx)) {
                rc = GPG_ERR_INTERNAL;
                goto leave;
            }

            if (u) {
                if (!BN_copy(coeff, _gcry_mpi_bn(u))) {
                    rc = GPG_ERR_ENOMEM;
                    goto leave;
                }
            } else if (!BN_mod_inverse(coeff, _gcry_mpi_bn(p),
                                       _gcry_mpi_bn(q), bctx)) {
                rc = GPG_ERR_BAD_SECKEY;
                goto leave;
            }

            if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1,
                                        _gcry_mpi_bn(q))
                || !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2,
                                           _gcry_mpi_bn(p))
                || !OSSL_PARAM_BLD_push_BN(bld,
                                           OSSL_PKEY_PARAM_RSA_EXPONENT1, dp)
                || !OSSL_PARAM_BLD_push_BN(bld,
                                           OSSL_PKEY_PARAM_RSA_EXPONENT2, dq)
                || !OSSL_PARAM_BLD_push_BN(bld,
                                           OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                           coeff)) {
                rc = GPG_ERR_ENOMEM;
                goto leave;
            }
        }
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "RSA", _gcry_propq());

    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, r_key, want_private ? EVP_PKEY_KEYPAIR
                             : EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        rc = _gcry_err_from_openssl(want_private ? GPG_ERR_BAD_SECKEY
                                    : GPG_ERR_BAD_PUBKEY);
        *r_key = NULL;
        goto leave;
    }

    if (r_n) {
        *r_n = n;
        n = NULL;
    }

    rc = 0;

leave:
    ERR_clear_error();
    BN_free(dp);
    BN_free(dq);
    BN_free(coeff);
    BN_free(tmp);
    BN_CTX_free(bctx);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(d);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);
    return rc;
}

/* The digest to sign: either given directly or computed from the message
 * (prehash flag).  The buffer is allocated. */
static gcry_err_code_t
signing_digest(struct pk_data *pd, unsigned char **r_buf, size_t *r_len)
{
    if (!pd->value) {
        return GPG_ERR_INV_DATA;
    }

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

    return _gcry_pk_md_hash(pd->hash_algo, pd->value, pd->valuelen, *r_buf,
                            *r_len);
}

static EVP_MD *
fetch_md(int algo)
{
    const char *name = _gcry_pk_md_openssl_name(algo);
    EVP_MD *md;

    if (!name) {
        return NULL;
    }

    md = EVP_MD_fetch(_gcry_libctx(), name, _gcry_propq());

    if (!md) {
        ERR_clear_error();
    }

    return md;
}

/* Configure padding and digests of CTX according to PD.  SIGNING selects
 * the signature variants of the encodings. */
static gcry_err_code_t
apply_encoding(EVP_PKEY_CTX *ctx, struct pk_data *pd, int signing,
               EVP_MD **r_md)
{
    EVP_MD *md = NULL;
    int ok;

    *r_md = NULL;

    switch (pd->encoding) {
    case PUBKEY_ENC_RAW:
        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) > 0;
        break;

    case PUBKEY_ENC_PKCS1:
        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0;

        if (ok && signing) {
            md = fetch_md(pd->hash_algo);
            ok = md && EVP_PKEY_CTX_set_signature_md(ctx, md) > 0;

            if (!md) {
                return GPG_ERR_DIGEST_ALGO;
            }
        }

        break;

    case PUBKEY_ENC_PKCS1_RAW:
        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0;
        break;

    case PUBKEY_ENC_PSS:
        md = fetch_md(pd->hash_algo);

        if (!md) {
            return GPG_ERR_DIGEST_ALGO;
        }

        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) > 0
             && EVP_PKEY_CTX_set_signature_md(ctx, md) > 0
             && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) > 0
             && EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, (int)pd->saltlen) > 0;
        break;

    case PUBKEY_ENC_OAEP:
        md = fetch_md(pd->hash_algo);

        if (!md) {
            return GPG_ERR_DIGEST_ALGO;
        }

        ok = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0
             && EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) > 0
             && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) > 0;

        if (ok && pd->labellen) {
            void *label = OPENSSL_malloc(pd->labellen);

            if (!label) {
                ok = 0;
            } else {
                memcpy(label, pd->label, pd->labellen);
                ok = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label,
                                                      (int)pd->labellen) > 0;

                if (!ok) {
                    OPENSSL_free(label);
                }
            }
        }

        break;

    default:
        return GPG_ERR_INV_FLAG;
    }

    if (!ok) {
        EVP_MD_free(md);
        return _gcry_err_from_openssl(GPG_ERR_INV_FLAG);
    }

    *r_md = md;
    return 0;
}

/* The input bytes for a raw (textbook) RSA operation: the numeric value
 * left padded to the modulus size. */
static gcry_err_code_t
raw_input(struct pk_data *pd, size_t k, unsigned char **r_buf)
{
    if (!pd->mpi || mpi_is_opaque(pd->mpi)) {
        return GPG_ERR_INV_DATA;
    }

    *r_buf = _gcry_malloc(k);

    if (!*r_buf) {
        return _gcry_err_code_from_syserror();
    }

    if (_gcry_pk_mpi_to_fixed(pd->mpi, *r_buf, k)) {
        _gcry_free(*r_buf);
        *r_buf = NULL;
        return GPG_ERR_INV_DATA;
    }

    return 0;
}

static gcry_err_code_t
rsa_encrypt(gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    unsigned int nbits = rsa_get_nbits(keyparms);
    size_t k = (nbits + 7) / 8;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *in = NULL;
    size_t inlen = 0;
    unsigned char *out = NULL;
    size_t outlen = k;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_ENCRYPT, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_RAW) {
        rc = raw_input(&pd, k, &in);
        inlen = k;
    } else if (pd.encoding == PUBKEY_ENC_PKCS1
               || pd.encoding == PUBKEY_ENC_OAEP) {
        if (!pd.value || !pd.valuelen) {
            rc = GPG_ERR_INV_DATA;
        } else {
            in = pd.value;
            inlen = pd.valuelen;
            pd.value = NULL;
        }
    } else {
        rc = GPG_ERR_CONFLICT;
    }

    if (rc) {
        goto leave;
    }

    rc = rsa_evp_key(keyparms, 0, &key, NULL);

    if (rc) {
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());
    out = _gcry_malloc(k);

    if (!ctx || !out) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = apply_encoding(ctx, &pd, 0, &md);

    if (rc) {
        goto leave;
    }

    if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_DATA);
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_FIXEDLEN) {
        rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(rsa(a%b)))",
                              (int)outlen, out);
    } else {
        gcry_mpi_t ciph = NULL;

        rc = _gcry_mpi_scan(&ciph, GCRYMPI_FMT_USG, out, outlen, NULL);

        if (!rc) {
            rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(rsa(a%m)))", ciph);
        }

        gcry_mpi_release(ciph);
    }

leave:
    EVP_MD_free(md);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    _gcry_free(in);
    _gcry_free(out);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
rsa_decrypt(gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t data = NULL;
    gcry_mpi_t n = NULL;
    unsigned int nbits = rsa_get_nbits(keyparms);
    size_t k = (nbits + 7) / 8;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *in = NULL;
    unsigned char *out = NULL;
    size_t outlen = k;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_DECRYPT, nbits);
    rc = _gcry_pk_util_preparse_encval(s_data, rsa_names, &l1, &pd);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL, "a", &data, NULL);

    if (rc) {
        goto leave;
    }

    if (mpi_is_opaque(data)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = rsa_evp_key(keyparms, 1, &key, &n);

    if (rc) {
        goto leave;
    }

    /* Reduce the input first so that oversized values are handled like
     * the reference implementation does. */
    gcry_mpi_mod(data, data, n);
    in = _gcry_malloc(k);
    out = _gcry_malloc_secure(k);
    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!in || !out || !ctx) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (_gcry_pk_mpi_to_fixed(data, in, k)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_UNKNOWN) {
        pd.encoding = PUBKEY_ENC_RAW;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = apply_encoding(ctx, &pd, 0, &md);

    if (rc) {
        goto leave;
    }

    if (EVP_PKEY_decrypt(ctx, out, &outlen, in, k) <= 0) {
        ERR_clear_error();
        rc = pd.encoding == PUBKEY_ENC_RAW ? GPG_ERR_INV_DATA
             : GPG_ERR_ENCODING_PROBLEM;
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_RAW) {
        gcry_mpi_t plain = NULL;

        rc = _gcry_mpi_scan(&plain, GCRYMPI_FMT_USG, out, outlen, NULL);

        if (!rc) {
            rc = _gcry_sexp_build(r_plain, NULL,
                                  (pd.flags & PUBKEY_FLAG_LEGACYRESULT)
                                  ? "%m" : "(value %m)", plain);
        }

        gcry_mpi_release(plain);
    } else {
        rc = _gcry_sexp_build(r_plain, NULL, "(value %b)", (int)outlen, out);
    }

leave:
    EVP_MD_free(md);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    if (out) {
        _gcry_wipememory(out, k);
    }

    _gcry_free(in);
    _gcry_free(out);
    gcry_mpi_release(data);
    gcry_mpi_release(n);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

/* The bytes handed to EVP_PKEY_sign/verify for the configured encoding. */
static gcry_err_code_t
signature_input(struct pk_data *pd, size_t k, unsigned char **r_buf,
                size_t *r_len)
{
    switch (pd->encoding) {
    case PUBKEY_ENC_RAW:
        *r_len = k;
        return raw_input(pd, k, r_buf);

    case PUBKEY_ENC_PKCS1:
    case PUBKEY_ENC_PSS:
        return signing_digest(pd, r_buf, r_len);

    case PUBKEY_ENC_PKCS1_RAW:
        if (!pd->value || !pd->valuelen) {
            return GPG_ERR_INV_DATA;
        }

        *r_buf = pd->value;
        *r_len = pd->valuelen;
        pd->value = NULL;
        return 0;

    default:
        return GPG_ERR_CONFLICT;
    }
}

static gcry_err_code_t
rsa_sign(gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    unsigned int nbits = rsa_get_nbits(keyparms);
    size_t k = (nbits + 7) / 8;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *in = NULL;
    size_t inlen = 0;
    unsigned char *sig = NULL;
    size_t siglen = k;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_SIGN, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    rc = signature_input(&pd, k, &in, &inlen);

    if (rc) {
        goto leave;
    }

    rc = rsa_evp_key(keyparms, 1, &key, NULL);

    if (rc) {
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());
    sig = _gcry_malloc(k);

    if (!ctx || !sig) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = apply_encoding(ctx, &pd, 1, &md);

    if (rc) {
        goto leave;
    }

    if (EVP_PKEY_sign(ctx, sig, &siglen, in, inlen) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_DATA);
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_FIXEDLEN) {
        rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(rsa(s%b)))",
                              (int)siglen, sig);
    } else {
        gcry_mpi_t s = NULL;

        rc = _gcry_mpi_scan(&s, GCRYMPI_FMT_USG, sig, siglen, NULL);

        if (!rc) {
            rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(rsa(s%M)))", s);
        }

        gcry_mpi_release(s);
    }

leave:
    EVP_MD_free(md);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    _gcry_free(in);
    _gcry_free(sig);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
rsa_verify(gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t sig = NULL;
    gcry_mpi_t n = NULL;
    unsigned int nbits = rsa_get_nbits(keyparms);
    size_t k = (nbits + 7) / 8;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char *in = NULL;
    size_t inlen = 0;
    unsigned char *sigbuf = NULL;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_VERIFY, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    rc = _gcry_pk_util_preparse_sigval(s_sig, rsa_names, &l1, NULL);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL, "s", &sig, NULL);

    if (rc) {
        goto leave;
    }

    rc = rsa_evp_key(keyparms, 0, &key, &n);

    if (rc) {
        goto leave;
    }

    if (mpi_is_opaque(sig) || gcry_mpi_is_neg(sig) || gcry_mpi_cmp(sig, n) >= 0) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    rc = signature_input(&pd, k, &in, &inlen);

    if (rc) {
        goto leave;
    }

    sigbuf = _gcry_malloc(k);
    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!sigbuf || !ctx) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (_gcry_pk_mpi_to_fixed(sig, sigbuf, k)) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = apply_encoding(ctx, &pd, 1, &md);

    if (rc) {
        goto leave;
    }

    if (EVP_PKEY_verify(ctx, sigbuf, k, in, inlen) != 1) {
        ERR_clear_error();
        rc = GPG_ERR_BAD_SIGNATURE;
    }

leave:
    EVP_MD_free(md);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    _gcry_free(in);
    _gcry_free(sigbuf);
    gcry_mpi_release(sig);
    gcry_mpi_release(n);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
rsa_check_secret_key(gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    gcry_mpi_t n = NULL;
    gcry_mpi_t e = NULL;
    gcry_mpi_t d = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t u = NULL;
    gcry_mpi_t t1;
    gcry_mpi_t t2;
    gcry_mpi_t phi;

    rc = _gcry_sexp_extract_param(keyparms, NULL, "nedpqu", &n, &e, &d, &p,
                                  &q, &u, NULL);

    if (rc) {
        return rc;
    }

    t1 = gcry_mpi_new(0);
    t2 = gcry_mpi_new(0);
    phi = gcry_mpi_new(0);

    /* n == p*q */
    gcry_mpi_mul(t1, p, q);

    if (gcry_mpi_cmp(t1, n)) {
        rc = GPG_ERR_BAD_SECKEY;
    }

    /* u*p == 1 mod q */
    if (!rc) {
        gcry_mpi_mulm(t1, u, p, q);

        if (gcry_mpi_cmp_ui(t1, 1)) {
            rc = GPG_ERR_BAD_SECKEY;
        }
    }

    /* e*d == 1 mod lcm(p-1, q-1) */
    if (!rc) {
        gcry_mpi_sub_ui(t1, p, 1);
        gcry_mpi_sub_ui(t2, q, 1);
        gcry_mpi_mul(phi, t1, t2);
        gcry_mpi_gcd(t1, t1, t2);
        gcry_mpi_div(phi, NULL, phi, t1, 0);
        gcry_mpi_mulm(t1, e, d, phi);

        if (gcry_mpi_cmp_ui(t1, 1)) {
            rc = GPG_ERR_BAD_SECKEY;
        }
    }

    gcry_mpi_release(t1);
    gcry_mpi_release(t2);
    gcry_mpi_release(phi);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_mpi_release(d);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(u);
    return rc;
}

static gcry_err_code_t
rsa_generate(gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{
    gcry_err_code_t rc;
    unsigned int nbits;
    unsigned long evalue;
    gcry_sexp_t l1;
    int flags = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    BIGNUM *e = NULL;
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_e = NULL;
    BIGNUM *bn_d = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_q = NULL;
    BIGNUM *bn_u = NULL;
    BN_CTX *bctx = NULL;
    gcry_mpi_t m_n = NULL;
    gcry_mpi_t m_e = NULL;
    gcry_mpi_t m_d = NULL;
    gcry_mpi_t m_p = NULL;
    gcry_mpi_t m_q = NULL;
    gcry_mpi_t m_u = NULL;

    rc = _gcry_pk_util_get_nbits(genparms, &nbits);

    if (rc) {
        return rc;
    }

    rc = _gcry_pk_util_get_rsa_use_e(genparms, &evalue);

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

    if (nbits < 1024 || (nbits % 2)) {
        return GPG_ERR_INV_VALUE;
    }

    if (evalue == 0 || evalue == 1) {
        evalue = 65537; /* Upstream picks the default for these too. */
    }

    e = BN_new();
    ctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "RSA", _gcry_propq());
    bctx = BN_CTX_new_ex(_gcry_libctx());

    if (!e || !ctx || !bctx || !BN_set_word(e, evalue)) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)nbits) <= 0
        || EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) <= 0
        || EVP_PKEY_keygen(ctx, &key) <= 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INV_VALUE);
        goto leave;
    }

    if (!EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &bn_n)
        || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &bn_e)
        || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &bn_d)
        || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn_p)
        || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn_q)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    /* Libgcrypt convention: p < q and u = p^-1 mod q. */
    if (BN_cmp(bn_p, bn_q) > 0) {
        BIGNUM *t = bn_p;

        bn_p = bn_q;
        bn_q = t;
    }

    bn_u = BN_new();

    if (!bn_u || !BN_mod_inverse(bn_u, bn_p, bn_q, bctx)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    m_n = _gcry_pk_mpi_from_bn(bn_n);
    m_e = _gcry_pk_mpi_from_bn(bn_e);
    m_d = _gcry_pk_mpi_from_bn(bn_d);
    m_p = _gcry_pk_mpi_from_bn(bn_p);
    m_q = _gcry_pk_mpi_from_bn(bn_q);
    m_u = _gcry_pk_mpi_from_bn(bn_u);
    rc = _gcry_sexp_build(r_skey, NULL,
                          "(key-data"
                          " (public-key"
                          "  (rsa(n%m)(e%m)))"
                          " (private-key"
                          "  (rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m))))",
                          m_n, m_e, m_n, m_e, m_d, m_p, m_q, m_u);

leave:
    gcry_mpi_release(m_n);
    gcry_mpi_release(m_e);
    gcry_mpi_release(m_d);
    gcry_mpi_release(m_p);
    gcry_mpi_release(m_q);
    gcry_mpi_release(m_u);
    BN_free(e);
    BN_free(bn_n);
    BN_free(bn_e);
    BN_clear_free(bn_d);
    BN_clear_free(bn_p);
    BN_clear_free(bn_q);
    BN_clear_free(bn_u);
    BN_CTX_free(bctx);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* The RSA keygrip is simply the SHA-1 of the modulus as it appears in the
 * S-expression, without the "(1:n...)" framing other algorithms use. */
static gcry_err_code_t
rsa_compute_keygrip(EVP_MD_CTX *md, gcry_sexp_t keyparms)
{
    gcry_sexp_t l1 = gcry_sexp_find_token(keyparms, "n", 1);
    const char *data;
    size_t datalen;
    int ok;

    if (!l1) {
        return GPG_ERR_NO_OBJ;
    }

    data = gcry_sexp_nth_data(l1, 1, &datalen);

    if (!data) {
        gcry_sexp_release(l1);
        return GPG_ERR_NO_OBJ;
    }

    ok = EVP_DigestUpdate(md, data, datalen);
    gcry_sexp_release(l1);
    return ok ? 0 : GPG_ERR_INTERNAL;
}

const struct gcry_pk_spec _gcry_pubkey_spec_rsa = {
    GCRY_PK_RSA,
    1,
    GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
    "RSA",
    rsa_names,
    "ne",
    "nedpqu",
    "a",
    "s",
    "n",
    rsa_generate,
    rsa_check_secret_key,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    rsa_get_nbits,
    rsa_compute_keygrip,
    NULL,
    NULL
};
