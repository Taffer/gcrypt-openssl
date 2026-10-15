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

/* ------------------------------------------------------------------ */
/* The RSA primitive                                                   */
/* ------------------------------------------------------------------ */
/*
 * All operations run OpenSSL's RSA primitive without padding on frames
 * of exactly K bytes; the PKCS#1 encodings are applied by pk-util.c so
 * that the gcrypt specific details (random-override, every digest, the
 * reference library's length rules and error codes) are honoured.
 */

/* OUT = IN^e mod n (public) or IN^d mod n (private, blinded by OpenSSL).
 * IN must be K bytes and smaller than n. */
static gcry_err_code_t
rsa_raw_op(EVP_PKEY *key, int private, const unsigned char *in,
           unsigned char *out, size_t k)
{
    EVP_PKEY_CTX *ctx;
    size_t outlen = k;
    int ok;

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());

    if (!ctx) {
        return GPG_ERR_ENOMEM;
    }

    if (private) {
        ok = EVP_PKEY_decrypt_init(ctx) > 0
             && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) > 0
             && EVP_PKEY_decrypt(ctx, out, &outlen, in, k) > 0;
    } else {
        ok = EVP_PKEY_encrypt_init(ctx) > 0
             && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) > 0
             && EVP_PKEY_encrypt(ctx, out, &outlen, in, k) > 0;
    }

    EVP_PKEY_CTX_free(ctx);

    if (!ok) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    if (outlen < k) {
        /* Right align a short result; the primitive is a number. */
        memmove(out + (k - outlen), out, outlen);
        memset(out, 0, k - outlen);
    }

    return 0;
}

/* The K byte frame for the number A reduced modulo N, as the reference
 * library's modular exponentiation would see it. */
static gcry_err_code_t
reduced_frame(gcry_mpi_t a, gcry_mpi_t n, unsigned char *out, size_t k)
{
    BN_CTX *bctx = BN_CTX_new_ex(_gcry_libctx());
    BIGNUM *r = BN_new();
    gcry_err_code_t rc = 0;

    if (!bctx || !r || !BN_nnmod(r, _gcry_mpi_bn(a), _gcry_mpi_bn(n), bctx)
        || BN_bn2binpad(r, out, (int)k) < 0) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    BN_free(r);
    BN_CTX_free(bctx);
    return rc;
}

/* Is the K byte big endian FRAME smaller than N? */
static int
frame_below_n(const unsigned char *frame, size_t k, gcry_mpi_t n)
{
    BIGNUM *f = BN_bin2bn(frame, (int)k, NULL);
    int res = f && BN_ucmp(f, _gcry_mpi_bn(n)) < 0;

    BN_free(f);
    return res;
}

static gcry_err_code_t
rsa_encrypt(gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    unsigned int nbits = rsa_get_nbits(keyparms);
    size_t k = (nbits + 7) / 8;
    EVP_PKEY *key = NULL;
    gcry_mpi_t n = NULL;
    unsigned char *frame = NULL;
    size_t framelen = 0;
    unsigned char *out = NULL;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_ENCRYPT, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding != PUBKEY_ENC_RAW && pd.encoding != PUBKEY_ENC_PKCS1
        && pd.encoding != PUBKEY_ENC_OAEP) {
        rc = GPG_ERR_CONFLICT;
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_RAW
        && (!pd.mpi || mpi_is_opaque(pd.mpi))) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    if (pd.encoding != PUBKEY_ENC_RAW) {
        rc = _gcry_pk_data_to_frame(&pd, nbits, &frame, &framelen);

        if (rc) {
            goto leave;
        }
    }

    rc = rsa_evp_key(keyparms, 0, &key, &n);

    if (rc) {
        goto leave;
    }

    out = _gcry_malloc(k);

    if (!out) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_RAW) {
        frame = _gcry_malloc(k);

        if (!frame) {
            rc = GPG_ERR_ENOMEM;
            goto leave;
        }

        rc = reduced_frame(pd.mpi, n, frame, k);

        if (rc) {
            goto leave;
        }
    }

    rc = rsa_raw_op(key, 0, frame, out, k);

    if (rc) {
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_FIXEDLEN) {
        rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(rsa(a%b)))", (int)k,
                              out);
    } else {
        gcry_mpi_t ciph = NULL;

        rc = _gcry_mpi_scan(&ciph, GCRYMPI_FMT_USG, out, k, NULL);

        if (!rc) {
            rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(rsa(a%m)))", ciph);
        }

        gcry_mpi_release(ciph);
    }

leave:
    EVP_PKEY_free(key);
    gcry_mpi_release(n);
    _gcry_free(frame);
    _gcry_free(out);
    _gcry_pk_data_free(&pd);
    return rc;
}

/* PKCS#1 v1.5 decryption of the K byte ciphertext IN. */
static gcry_err_code_t
rsa_pkcs1_decrypt(EVP_PKEY *key, const unsigned char *in, size_t k,
                  unsigned char **r_value, size_t *r_valuelen)
{
    EVP_PKEY_CTX *ctx;
    unsigned char *out;
    size_t outlen = k;
    int ok;

    *r_value = NULL;
    *r_valuelen = 0;
    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), key, _gcry_propq());
    out = _gcry_malloc_secure(k);

    if (!ctx || !out) {
        EVP_PKEY_CTX_free(ctx);
        _gcry_free(out);
        return GPG_ERR_ENOMEM;
    }

    ok = EVP_PKEY_decrypt_init(ctx) > 0
         && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) > 0
         && EVP_PKEY_decrypt(ctx, out, &outlen, in, k) > 0;
    EVP_PKEY_CTX_free(ctx);

    if (!ok) {
        _gcry_free(out);
        return _gcry_err_from_openssl(GPG_ERR_ENCODING_PROBLEM);
    }

    *r_value = out;
    *r_valuelen = outlen;
    return 0;
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
    unsigned char *in = NULL;
    unsigned char *out = NULL;
    unsigned char *value = NULL;
    size_t valuelen = 0;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_DECRYPT, nbits);
    rc = _gcry_pk_util_preparse_encval(s_data, rsa_names, &l1, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding != PUBKEY_ENC_UNKNOWN && pd.encoding != PUBKEY_ENC_RAW
        && pd.encoding != PUBKEY_ENC_PKCS1
        && pd.encoding != PUBKEY_ENC_OAEP) {
        rc = GPG_ERR_CONFLICT;
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

    in = _gcry_malloc(k);
    out = _gcry_malloc_secure(k);

    if (!in || !out) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    rc = reduced_frame(data, n, in, k);

    if (rc) {
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_PKCS1) {
        /* OpenSSL's PKCS#1 v1.5 check with implicit rejection: a bad
         * padding yields a deterministic synthetic plaintext instead of an
         * error, which is also what the reference library does. */
        rc = rsa_pkcs1_decrypt(key, in, k, &value, &valuelen);

        if (!rc) {
            rc = _gcry_sexp_build(r_plain, NULL, "(value %b)", (int)valuelen,
                                  value);
        }

        goto leave;
    }

    rc = rsa_raw_op(key, 1, in, out, k);

    if (rc) {
        goto leave;
    }

    switch (pd.encoding) {

    case PUBKEY_ENC_OAEP:
        rc = _gcry_pk_oaep_decode(out, k, pd.hash_algo, pd.label, pd.labellen,
                                  &value, &valuelen);

        if (!rc) {
            rc = _gcry_sexp_build(r_plain, NULL, "(value %b)", (int)valuelen,
                                  value);
        }

        break;

    default: {
        gcry_mpi_t plain = NULL;

        rc = _gcry_mpi_scan(&plain, GCRYMPI_FMT_USG, out, k, NULL);

        if (!rc) {
            rc = _gcry_sexp_build(r_plain, NULL,
                                  (pd.flags & PUBKEY_FLAG_LEGACYRESULT) ? "%m"
                                  : "(value %m)", plain);
        }

        gcry_mpi_release(plain);
        break;
    }
    }

leave:

    if (value) {
        _gcry_wipememory(value, valuelen);
    }

    if (out) {
        _gcry_wipememory(out, k);
    }

    _gcry_free(value);
    _gcry_free(in);
    _gcry_free(out);
    EVP_PKEY_free(key);
    gcry_mpi_release(data);
    gcry_mpi_release(n);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
rsa_sign(gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    unsigned int nbits = rsa_get_nbits(keyparms);
    size_t k = (nbits + 7) / 8;
    EVP_PKEY *key = NULL;
    gcry_mpi_t n = NULL;
    unsigned char *frame = NULL;
    size_t framelen = 0;
    unsigned char *sig = NULL;
    unsigned char *check = NULL;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_SIGN, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_OAEP) {
        rc = GPG_ERR_CONFLICT;
        goto leave;
    }

    rc = _gcry_pk_data_to_frame(&pd, nbits, &frame, &framelen);

    if (rc == GPG_ERR_TOO_LARGE) {
        rc = GPG_ERR_BAD_SIGNATURE; /* Raw data not below the modulus. */
    }

    if (rc) {
        goto leave;
    }

    rc = rsa_evp_key(keyparms, 1, &key, &n);

    if (rc) {
        goto leave;
    }

    if (!frame_below_n(frame, k, n)) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    sig = _gcry_malloc(k);
    check = _gcry_malloc(k);

    if (!sig || !check) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    rc = rsa_raw_op(key, 1, frame, sig, k);

    if (rc) {
        goto leave;
    }

    /* Verify the fresh signature, as the reference library does, which
     * also catches a faulty CRT computation. */
    rc = rsa_raw_op(key, 0, sig, check, k);

    if (!rc && memcmp(check, frame, k)) {
        rc = GPG_ERR_BAD_SIGNATURE;
    }

    if (rc) {
        goto leave;
    }

    if (pd.flags & PUBKEY_FLAG_FIXEDLEN) {
        rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(rsa(s%b)))", (int)k, sig);
    } else {
        gcry_mpi_t s = NULL;

        rc = _gcry_mpi_scan(&s, GCRYMPI_FMT_USG, sig, k, NULL);

        if (!rc) {
            rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(rsa(s%M)))", s);
        }

        gcry_mpi_release(s);
    }

leave:
    EVP_PKEY_free(key);
    gcry_mpi_release(n);
    _gcry_free(frame);
    _gcry_free(sig);
    _gcry_free(check);
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
    unsigned char *frame = NULL;
    size_t framelen = 0;
    unsigned char *sigbuf = NULL;
    unsigned char *em = NULL;

    if (!nbits) {
        return GPG_ERR_INV_OBJ;
    }

    _gcry_pk_data_init(&pd, PUBKEY_OP_VERIFY, nbits);
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_OAEP) {
        rc = GPG_ERR_CONFLICT;
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

    if (pd.encoding != PUBKEY_ENC_PSS) {
        /* The expected frame; its encoding errors come before the key. */
        rc = _gcry_pk_data_to_frame(&pd, nbits, &frame, &framelen);

        if (rc == GPG_ERR_TOO_LARGE) {
            rc = GPG_ERR_BAD_SIGNATURE;
        }

        if (rc) {
            goto leave;
        }
    }

    rc = rsa_evp_key(keyparms, 0, &key, &n);

    if (rc) {
        goto leave;
    }

    if (mpi_is_opaque(sig) || gcry_mpi_is_neg(sig)
        || gcry_mpi_cmp(sig, n) >= 0) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    sigbuf = _gcry_malloc(k);
    em = _gcry_malloc(k);

    if (!sigbuf || !em) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    if (_gcry_pk_mpi_to_fixed(sig, sigbuf, k)) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    rc = rsa_raw_op(key, 0, sigbuf, em, k);

    if (rc) {
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_PSS) {
        if (!pd.value) {
            rc = GPG_ERR_INV_DATA;
        } else {
            rc = _gcry_pk_pss_verify(nbits, pd.hash_algo, pd.saltlen, pd.value,
                                     pd.valuelen, pd.value_is_hash, em, k);
        }
    } else if (memcmp(em, frame, k)) {
        rc = GPG_ERR_BAD_SIGNATURE;
    }

leave:
    EVP_PKEY_free(key);
    _gcry_free(frame);
    _gcry_free(sigbuf);
    _gcry_free(em);
    gcry_mpi_release(sig);
    gcry_mpi_release(n);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

/* The reference library only checks that n is the product of p and q. */
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
    gcry_mpi_t t;

    rc = _gcry_sexp_extract_param(keyparms, NULL, "nedpqu", &n, &e, &d, &p,
                                  &q, &u, NULL);

    if (rc) {
        return rc;
    }

    t = gcry_mpi_new(0);
    gcry_mpi_mul(t, p, q);

    if (gcry_mpi_cmp(t, n)) {
        rc = GPG_ERR_BAD_SECKEY;
    }

    gcry_mpi_release(t);
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

    /* The reference library rounds an odd size up and has no lower limit
     * outside FIPS mode; OpenSSL refuses to generate below 512 bits. */
    if (nbits & 1) {
        nbits++;
    }

    if (nbits < 512) {
        return GPG_ERR_INV_VALUE;
    }

    if (_gcry_fips_mode() && (nbits <= 1024 || (nbits & 0x1ff))) {
        return GPG_ERR_INV_VALUE;
    }

    /* The public exponent rules of the reference library: 0 selects 41,
     * 1 selects 65537, an even value is made odd. */
    if (evalue == 0) {
        evalue = 41;
    } else if (evalue == 1) {
        evalue = 65537;
    } else {
        evalue |= 1;
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
