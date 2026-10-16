/*
 * kem.c - Key encapsulation mechanisms.
 *
 * ML-KEM (FIPS 203) and the X25519/X448 DHKEMs of RFC 9180 are provided
 * by OpenSSL's EVP_PKEY encapsulation API.  The DHKEMs over the NIST
 * curves are composed here from EC_POINT Diffie-Hellman and HKDF, because
 * OpenSSL's EC KEM lives in the default provider only while ECDH and HKDF
 * are also in the FIPS provider.  The "raw" ECC KEMs are plain
 * Diffie-Hellman on X25519/X448 (via EVP_PKEY) or on the Weierstrass
 * curves of the curve table (via EC_POINT arithmetic), with an ephemeral
 * public key as the ciphertext.
 *
 * In FIPS mode only the curves the table approves for it are served:
 * the FIPS provider has no X25519/X448 at all, and brainpool and secp256k1
 * are not approved.
 *
 * Byte formats follow the reference implementation:
 *   ML-KEM:       ek/dk/ct as in FIPS 203 (dk is the expanded form).
 *   RAW X25519/X448: raw little-endian scalars and u-coordinates.
 *   RAW Weierstrass: seckey is the big-endian scalar padded to the field
 *                 size; pubkey, ciphertext and shared secret are
 *                 uncompressed SEC1 points (0x04 || x || y).
 *   DHKEM:        enc and shared secret as in RFC 9180.
 */
#include "gcrypt-int.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#define MLKEM_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN

struct kem_info {
    int algo;
    const char *ossl_name;   /* EVP_PKEY algorithm name (ML-KEM, X25519,
                              * X448, EC) or NULL for table curves. */
    const char *curve;       /* gcrypt curve name for ECC based KEMs. */
    size_t pubkey_len;
    size_t seckey_len;
    size_t cipher_len;
    size_t shared_len;
    int kind;
};

enum {
    KIND_UNSUPPORTED,
    KIND_MLKEM,
    KIND_RAW_MONT,
    KIND_RAW_WEIER,
    KIND_DHKEM_MONT,
    KIND_DHKEM_WEIER
};

/* DHKEM over the NIST curves has no length constants in the public header;
 * the values follow RFC 9180 (Nenc, Nsk, Nsecret). */
static const struct kem_info kem_infos[] = {
    {
        GCRY_KEM_SNTRUP761, NULL, NULL, GCRY_KEM_SNTRUP761_PUBKEY_LEN,
        GCRY_KEM_SNTRUP761_SECKEY_LEN, GCRY_KEM_SNTRUP761_CIPHER_LEN,
        GCRY_KEM_SNTRUP761_SHARED_LEN, KIND_UNSUPPORTED
    },
    {
        GCRY_KEM_CM6688128F, NULL, NULL, GCRY_KEM_CM6688128F_PUBKEY_LEN,
        GCRY_KEM_CM6688128F_SECKEY_LEN, GCRY_KEM_CM6688128F_CIPHER_LEN,
        GCRY_KEM_CM6688128F_SHARED_LEN, KIND_UNSUPPORTED
    },
    {
        GCRY_KEM_MLKEM512, "ML-KEM-512", NULL, GCRY_KEM_MLKEM512_PUBKEY_LEN,
        GCRY_KEM_MLKEM512_SECKEY_LEN, GCRY_KEM_MLKEM512_CIPHER_LEN,
        GCRY_KEM_MLKEM512_SHARED_LEN, KIND_MLKEM
    },
    {
        GCRY_KEM_MLKEM768, "ML-KEM-768", NULL, GCRY_KEM_MLKEM768_PUBKEY_LEN,
        GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN,
        GCRY_KEM_MLKEM768_SHARED_LEN, KIND_MLKEM
    },
    {
        GCRY_KEM_MLKEM1024, "ML-KEM-1024", NULL,
        GCRY_KEM_MLKEM1024_PUBKEY_LEN, GCRY_KEM_MLKEM1024_SECKEY_LEN,
        GCRY_KEM_MLKEM1024_CIPHER_LEN, GCRY_KEM_MLKEM1024_SHARED_LEN,
        KIND_MLKEM
    },
    {
        GCRY_KEM_RAW_X25519, "X25519", "Curve25519",
        GCRY_KEM_ECC_X25519_PUBKEY_LEN, GCRY_KEM_ECC_X25519_SECKEY_LEN,
        GCRY_KEM_ECC_X25519_CIPHER_LEN, GCRY_KEM_RAW_X25519_SHARED_LEN,
        KIND_RAW_MONT
    },
    {
        GCRY_KEM_RAW_X448, "X448", "X448", GCRY_KEM_ECC_X448_PUBKEY_LEN,
        GCRY_KEM_ECC_X448_SECKEY_LEN, GCRY_KEM_ECC_X448_CIPHER_LEN,
        GCRY_KEM_RAW_X448_SHARED_LEN, KIND_RAW_MONT
    },
    {
        GCRY_KEM_RAW_BP256, NULL, "brainpoolP256r1",
        GCRY_KEM_ECC_BP256_PUBKEY_LEN, GCRY_KEM_ECC_BP256_SECKEY_LEN,
        GCRY_KEM_ECC_BP256_CIPHER_LEN, GCRY_KEM_RAW_BP256_SHARED_LEN,
        KIND_RAW_WEIER
    },
    {
        GCRY_KEM_RAW_BP384, NULL, "brainpoolP384r1",
        GCRY_KEM_ECC_BP384_PUBKEY_LEN, GCRY_KEM_ECC_BP384_SECKEY_LEN,
        GCRY_KEM_ECC_BP384_CIPHER_LEN, GCRY_KEM_RAW_BP384_SHARED_LEN,
        KIND_RAW_WEIER
    },
    {
        GCRY_KEM_RAW_BP512, NULL, "brainpoolP512r1", 1 + 2 * 64, 64,
        1 + 2 * 64, 1 + 2 * 64, KIND_RAW_WEIER
    },
    {
        GCRY_KEM_RAW_P256R1, NULL, "NIST P-256", 1 + 2 * 32, 32, 1 + 2 * 32,
        1 + 2 * 32, KIND_RAW_WEIER
    },
    {
        GCRY_KEM_RAW_P384R1, NULL, "NIST P-384", 1 + 2 * 48, 48, 1 + 2 * 48,
        1 + 2 * 48, KIND_RAW_WEIER
    },
    {
        GCRY_KEM_RAW_P521R1, NULL, "NIST P-521", 1 + 2 * 66, 66, 1 + 2 * 66,
        1 + 2 * 66, KIND_RAW_WEIER
    },
    {
        GCRY_KEM_RAW_P256K1, NULL, "secp256k1", 1 + 2 * 32, 32, 1 + 2 * 32,
        1 + 2 * 32, KIND_RAW_WEIER
    },
    {
        GCRY_KEM_DHKEM25519, "X25519", "Curve25519",
        GCRY_KEM_DHKEM25519_PUBKEY_LEN, GCRY_KEM_DHKEM25519_SECKEY_LEN,
        GCRY_KEM_DHKEM25519_CIPHER_LEN, GCRY_KEM_DHKEM25519_SHARED_LEN,
        KIND_DHKEM_MONT
    },
    {
        GCRY_KEM_DHKEM448, "X448", "X448", GCRY_KEM_DHKEM448_PUBKEY_LEN,
        GCRY_KEM_DHKEM448_SECKEY_LEN, GCRY_KEM_DHKEM448_CIPHER_LEN,
        GCRY_KEM_DHKEM448_SHARED_LEN, KIND_DHKEM_MONT
    },
    {
        GCRY_KEM_DHKEMP256R1, "EC", "NIST P-256", 1 + 2 * 32, 32, 1 + 2 * 32,
        32, KIND_DHKEM_WEIER
    },
    {
        GCRY_KEM_DHKEMP384R1, "EC", "NIST P-384", 1 + 2 * 48, 48, 1 + 2 * 48,
        48, KIND_DHKEM_WEIER
    },
    {
        GCRY_KEM_DHKEMP521R1, "EC", "NIST P-521", 1 + 2 * 66, 66, 1 + 2 * 66,
        64, KIND_DHKEM_WEIER
    },
};

static const struct kem_info *
find_info(int algo)
{
    size_t i;

    for (i = 0; i < DIM(kem_infos); i++) {
        if (kem_infos[i].algo == algo) {
            return &kem_infos[i];
        }
    }

    return NULL;
}

/* Whether the curve of an ECC KEM may be used right now: in FIPS mode
 * only the curves the table approves for it. */
static gcry_err_code_t
check_curve_allowed(const struct kem_info *info)
{
    const struct gcry_ecc_curve *curve;

    if (!info->curve || !_gcry_fips_mode()) {
        return 0;
    }

    curve = _gcry_ecc_curve_find(info->curve);

    if (!curve) {
        return GPG_ERR_UNKNOWN_CURVE;
    }

    return curve->fips ? 0 : GPG_ERR_NOT_SUPPORTED;
}

static gcry_err_code_t
ossl_error(gcry_err_code_t fallback)
{
    return _gcry_err_from_openssl(fallback);
}

/* OSSL_PARAM constructors take non-const pointers although the data is only
 * read; strip the qualifier without a cast the compiler objects to. */
static void *
unconst(const void *p)
{
    union {
        const void *c;
        void *v;
    } u;

    u.c = p;
    return u.v;
}

/* ------------------------------------------------------------------ */
/* ML-KEM                                                              */
/* ------------------------------------------------------------------ */

/* Build an EVP_PKEY from one octet string parameter. */
static gcry_err_code_t
pkey_from_octets(const char *name, const char *param, int selection,
                 const unsigned char *data, size_t len, EVP_PKEY **r_pkey)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    gcry_err_code_t rc = 0;

    *r_pkey = NULL;
    params[0] = OSSL_PARAM_construct_octet_string(param, unconst(data), len);
    params[1] = OSSL_PARAM_construct_end();
    ctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), name, _gcry_propq());

    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0
        || EVP_PKEY_fromdata(ctx, r_pkey, selection, params) <= 0
        || !*r_pkey) {
        rc = ossl_error(GPG_ERR_INV_DATA);
    }

    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static gcry_err_code_t
pkey_get_octets(EVP_PKEY *pkey, const char *param, unsigned char *buf,
                size_t len)
{
    size_t outlen = 0;

    if (!EVP_PKEY_get_octet_string_param(pkey, param, buf, len, &outlen)) {
        return ossl_error(GPG_ERR_INTERNAL);
    }

    if (outlen != len) {
        return GPG_ERR_INV_LENGTH;
    }

    return 0;
}

static gcry_err_code_t
mlkem_genkey(const struct kem_info *info, unsigned char *pubkey,
             unsigned char *seckey, const unsigned char *seed)
{
    EVP_PKEY *pkey = NULL;
    gcry_err_code_t rc;

    if (seed) {
        rc = pkey_from_octets(info->ossl_name, OSSL_PKEY_PARAM_ML_KEM_SEED,
                              EVP_PKEY_KEYPAIR, seed, 2 * MLKEM_RANDOM_LEN,
                              &pkey);

        if (rc) {
            return rc;
        }
    } else {
        pkey = EVP_PKEY_Q_keygen(_gcry_libctx(), _gcry_propq(),
                                 info->ossl_name);

        if (!pkey) {
            return ossl_error(GPG_ERR_INTERNAL);
        }
    }

    rc = pkey_get_octets(pkey, OSSL_PKEY_PARAM_PUB_KEY, pubkey,
                         info->pubkey_len);

    if (!rc) {
        rc = pkey_get_octets(pkey, OSSL_PKEY_PARAM_PRIV_KEY, seckey,
                             info->seckey_len);
    }

    EVP_PKEY_free(pkey);
    return rc;
}

/* Common encapsulation on an EVP_PKEY.  PARAMS may be NULL. */
static gcry_err_code_t
do_encapsulate(EVP_PKEY *pkey, const OSSL_PARAM *params,
               unsigned char *ciphertext, size_t cipher_len,
               unsigned char *shared, size_t shared_len)
{
    EVP_PKEY_CTX *ctx;
    size_t ctl = cipher_len;
    size_t ssl = shared_len;
    gcry_err_code_t rc = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), pkey, _gcry_propq());

    if (!ctx || EVP_PKEY_encapsulate_init(ctx, params) <= 0
        || EVP_PKEY_encapsulate(ctx, ciphertext, &ctl, shared, &ssl) <= 0) {
        rc = ossl_error(GPG_ERR_GENERAL);
    } else if (ctl != cipher_len || ssl != shared_len) {
        rc = GPG_ERR_INV_LENGTH;
    }

    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static gcry_err_code_t
do_decapsulate(EVP_PKEY *pkey, const OSSL_PARAM *params,
               const unsigned char *ciphertext, size_t cipher_len,
               unsigned char *shared, size_t shared_len)
{
    EVP_PKEY_CTX *ctx;
    size_t ssl = shared_len;
    gcry_err_code_t rc = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), pkey, _gcry_propq());

    if (!ctx || EVP_PKEY_decapsulate_init(ctx, params) <= 0
        || EVP_PKEY_decapsulate(ctx, shared, &ssl, ciphertext,
                                cipher_len) <= 0) {
        rc = ossl_error(GPG_ERR_GENERAL);
    } else if (ssl != shared_len) {
        rc = GPG_ERR_INV_LENGTH;
    }

    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static gcry_err_code_t
mlkem_encap(const struct kem_info *info, const unsigned char *pubkey,
            unsigned char *ciphertext, unsigned char *shared,
            const unsigned char *m)
{
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    gcry_err_code_t rc;

    rc = pkey_from_octets(info->ossl_name, OSSL_PKEY_PARAM_PUB_KEY,
                          EVP_PKEY_PUBLIC_KEY, pubkey, info->pubkey_len,
                          &pkey);

    if (rc) {
        return rc;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
                                                  unconst(m), MLKEM_RANDOM_LEN);
    params[1] = OSSL_PARAM_construct_end();
    rc = do_encapsulate(pkey, m ? params : NULL, ciphertext, info->cipher_len,
                        shared, info->shared_len);
    EVP_PKEY_free(pkey);
    return rc;
}

static gcry_err_code_t
mlkem_decap(const struct kem_info *info, const unsigned char *seckey,
            const unsigned char *ciphertext, unsigned char *shared)
{
    EVP_PKEY *pkey = NULL;
    gcry_err_code_t rc;

    rc = pkey_from_octets(info->ossl_name, OSSL_PKEY_PARAM_PRIV_KEY,
                          EVP_PKEY_KEYPAIR, seckey, info->seckey_len, &pkey);

    if (rc) {
        return rc;
    }

    rc = do_decapsulate(pkey, NULL, ciphertext, info->cipher_len, shared,
                        info->shared_len);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Montgomery curves (X25519, X448)                                    */
/* ------------------------------------------------------------------ */

/* Clear and set the bits the reference implementation fixes in a freshly
 * generated scalar, so that keys are interchangeable with it. */
static void
mont_clamp(unsigned char *seckey, size_t len)
{
    if (len == 32) {
        seckey[0] &= 0xf8;
        seckey[31] &= 0x7f;
        seckey[31] |= 0x40;
    } else {
        seckey[0] &= 0xfc;
        seckey[55] |= 0x80;
    }
}

static gcry_err_code_t
mont_keypair(const struct kem_info *info, unsigned char *pubkey,
             unsigned char *seckey)
{
    EVP_PKEY *pkey;
    size_t outlen = info->pubkey_len;
    gcry_err_code_t rc = check_curve_allowed(info);

    if (rc) {
        return rc;
    }

    if (RAND_priv_bytes_ex(_gcry_libctx(), seckey, info->seckey_len, 0) <= 0) {
        return ossl_error(GPG_ERR_INTERNAL);
    }

    mont_clamp(seckey, info->seckey_len);
    pkey = EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(), info->ossl_name,
                                           _gcry_propq(), seckey,
                                           info->seckey_len);

    if (!pkey || !EVP_PKEY_get_raw_public_key(pkey, pubkey, &outlen)
        || outlen != info->pubkey_len) {
        rc = ossl_error(GPG_ERR_INTERNAL);
    }

    EVP_PKEY_free(pkey);
    return rc;
}

/* shared = scalar * point on X25519/X448.  Small order inputs yield an
 * all-zero result which OpenSSL rejects; report it as invalid data like
 * the reference implementation does. */
static gcry_err_code_t
mont_mul(const struct kem_info *info, unsigned char *shared,
         const unsigned char *scalar, const unsigned char *point)
{
    EVP_PKEY *priv = NULL;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen = info->shared_len;
    gcry_err_code_t rc = check_curve_allowed(info);

    if (rc) {
        return rc;
    }

    priv = EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(), info->ossl_name,
                                           _gcry_propq(), scalar,
                                           info->seckey_len);
    peer = EVP_PKEY_new_raw_public_key_ex(_gcry_libctx(), info->ossl_name,
                                          _gcry_propq(), point,
                                          info->pubkey_len);

    if (!priv || !peer) {
        rc = ossl_error(GPG_ERR_INV_DATA);
        goto leave;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), priv, _gcry_propq());

    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0
        || EVP_PKEY_derive_set_peer(ctx, peer) <= 0) {
        rc = ossl_error(GPG_ERR_INTERNAL);
        goto leave;
    }

    if (EVP_PKEY_derive(ctx, shared, &outlen) <= 0) {
        rc = ossl_error(GPG_ERR_INV_DATA);
        goto leave;
    }

    if (outlen != info->shared_len) {
        rc = GPG_ERR_INV_LENGTH;
    }

leave:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(peer);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Weierstrass curves                                                  */
/* ------------------------------------------------------------------ */

struct weier {
    EC_GROUP *group;
    BN_CTX *ctx;
    size_t nbytes;
};

static gcry_err_code_t
weier_open(const struct kem_info *info, struct weier *w)
{
    const struct gcry_ecc_curve *curve = _gcry_ecc_curve_find(info->curve);
    gcry_err_code_t rc = check_curve_allowed(info);

    memset(w, 0, sizeof * w);

    if (rc) {
        return rc;
    }

    if (!curve) {
        return GPG_ERR_UNKNOWN_CURVE;
    }

    w->group = _gcry_ecc_curve_group(curve);
    w->ctx = BN_CTX_new_ex(_gcry_libctx());

    if (!w->group || !w->ctx) {
        EC_GROUP_free(w->group);
        BN_CTX_free(w->ctx);
        ERR_clear_error();
        return GPG_ERR_INTERNAL;
    }

    w->nbytes = ((size_t)EC_GROUP_get_degree(w->group) + 7) / 8;
    return 0;
}

static void
weier_close(struct weier *w)
{
    EC_GROUP_free(w->group);
    BN_CTX_free(w->ctx);
}

/* Encode POINT as 0x04 || x || y into BUF of LEN bytes. */
static gcry_err_code_t
weier_point_out(const struct weier *w, const EC_POINT *point,
                unsigned char *buf, size_t len)
{
    size_t n;

    if (EC_POINT_is_at_infinity(w->group, point)) {
        return GPG_ERR_INV_DATA;
    }

    n = EC_POINT_point2oct(w->group, point, POINT_CONVERSION_UNCOMPRESSED,
                           buf, len, w->ctx);

    if (n != len) {
        ERR_clear_error();
        return n ? GPG_ERR_INV_LENGTH : GPG_ERR_INTERNAL;
    }

    return 0;
}

static gcry_err_code_t
weier_keypair(const struct kem_info *info, unsigned char *pubkey,
              unsigned char *seckey)
{
    struct weier w;
    BIGNUM *k = NULL;
    BIGNUM *y = NULL;
    BIGNUM *negy = NULL;
    BIGNUM *p = NULL;
    EC_POINT *q = NULL;
    const BIGNUM *order;
    gcry_err_code_t rc;

    rc = weier_open(info, &w);

    if (rc) {
        return rc;
    }

    order = EC_GROUP_get0_order(w.group);
    k = BN_secure_new();
    y = BN_new();
    negy = BN_new();
    p = BN_new();
    q = EC_POINT_new(w.group);

    if (!k || !y || !negy || !p || !q
        || !BN_priv_rand_range_ex(k, order, 0, w.ctx)
        || !EC_POINT_mul(w.group, q, k, NULL, NULL, w.ctx)
        || !EC_POINT_get_affine_coordinates(w.group, q, NULL, y, w.ctx)
        || !EC_GROUP_get_curve(w.group, p, NULL, NULL, w.ctx)
        || !BN_sub(negy, p, y)) {
        rc = ossl_error(GPG_ERR_INTERNAL);
        goto leave;
    }

    /* Like the reference implementation, prefer the key whose public point
     * has the smaller y coordinate; the mirrored scalar is n - k. */
    if (BN_cmp(negy, y) < 0) {
        if (!BN_sub(k, order, k) || !EC_POINT_invert(w.group, q, w.ctx)) {
            rc = ossl_error(GPG_ERR_INTERNAL);
            goto leave;
        }
    }

    if (BN_bn2binpad(k, seckey, (int)info->seckey_len) < 0) {
        rc = GPG_ERR_INTERNAL;
        goto leave;
    }

    rc = weier_point_out(&w, q, pubkey, info->pubkey_len);

leave:
    BN_clear_free(k);
    BN_free(y);
    BN_free(negy);
    BN_free(p);
    EC_POINT_free(q);
    weier_close(&w);
    return rc;
}

/* result = scalar * point, or scalar * G when POINT is NULL, all in the
 * byte formats described above; RESULT is an uncompressed point of
 * info->pubkey_len bytes. */
static gcry_err_code_t
weier_mul(const struct kem_info *info, unsigned char *result,
          const unsigned char *scalar, const unsigned char *point)
{
    struct weier w;
    BIGNUM *k = NULL;
    EC_POINT *pt = NULL;
    EC_POINT *r = NULL;
    gcry_err_code_t rc;

    rc = weier_open(info, &w);

    if (rc) {
        return rc;
    }

    k = BN_secure_new();
    pt = EC_POINT_new(w.group);
    r = EC_POINT_new(w.group);

    if (!k || !pt || !r
        || !BN_bin2bn(scalar, (int)info->seckey_len, k)) {
        rc = ossl_error(GPG_ERR_INTERNAL);
        goto leave;
    }

    if (point) {
        if (!EC_POINT_oct2point(w.group, pt, point, info->pubkey_len, w.ctx)
            || EC_POINT_is_on_curve(w.group, pt, w.ctx) != 1) {
            ERR_clear_error();
            rc = GPG_ERR_INV_DATA;
            goto leave;
        }

        if (!EC_POINT_mul(w.group, r, NULL, pt, k, w.ctx)) {
            rc = ossl_error(GPG_ERR_INTERNAL);
            goto leave;
        }
    } else if (!EC_POINT_mul(w.group, r, k, NULL, NULL, w.ctx)) {
        rc = ossl_error(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = weier_point_out(&w, r, result, info->pubkey_len);

leave:
    BN_clear_free(k);
    EC_POINT_free(pt);
    EC_POINT_free(r);
    weier_close(&w);
    return rc;
}

/* ------------------------------------------------------------------ */
/* DHKEM (RFC 9180)                                                    */
/* ------------------------------------------------------------------ */

static const OSSL_PARAM *
dhkem_params(OSSL_PARAM params[2])
{
    static char operation[] = OSSL_KEM_PARAM_OPERATION_DHKEM;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                                 operation, 0);
    params[1] = OSSL_PARAM_construct_end();
    return params;
}

/* Build the recipient's public or private X25519/X448 EVP_PKEY from the
 * raw bytes. */
static gcry_err_code_t
dhkem_pkey(const struct kem_info *info, const unsigned char *data, int priv,
           EVP_PKEY **r_pkey)
{
    gcry_err_code_t rc = check_curve_allowed(info);

    *r_pkey = NULL;

    if (rc) {
        return rc;
    }

    *r_pkey = priv
              ? EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(),
                                                info->ossl_name, _gcry_propq(), data,
                                                info->seckey_len)
              : EVP_PKEY_new_raw_public_key_ex(_gcry_libctx(),
                                               info->ossl_name, _gcry_propq(), data,
                                               info->pubkey_len);

    if (!*r_pkey) {
        return ossl_error(GPG_ERR_INV_DATA);
    }

    return 0;
}

static gcry_err_code_t
dhkem_encap(const struct kem_info *info, const unsigned char *pubkey,
            unsigned char *ciphertext, unsigned char *shared,
            size_t shared_len)
{
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    gcry_err_code_t rc;

    rc = dhkem_pkey(info, pubkey, 0, &pkey);

    if (rc) {
        return rc;
    }

    rc = do_encapsulate(pkey, dhkem_params(params), ciphertext,
                        info->cipher_len, shared, shared_len);
    EVP_PKEY_free(pkey);
    return rc;
}

static gcry_err_code_t
dhkem_decap(const struct kem_info *info, const unsigned char *seckey,
            const unsigned char *ciphertext, unsigned char *shared,
            size_t shared_len)
{
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    gcry_err_code_t rc;

    rc = dhkem_pkey(info, seckey, 1, &pkey);

    if (rc) {
        return rc;
    }

    rc = do_decapsulate(pkey, dhkem_params(params), ciphertext,
                        info->cipher_len, shared, shared_len);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ---- DHKEM over the NIST curves: ECDH + HKDF, RFC 9180 section 4.1 ---- */

/* Hash name and suite_id ("KEM" || I2OSP(kem_id, 2)) of a NIST curve
 * DHKEM, RFC 9180 section 7.1. */
static void
dhkem_suite(const struct kem_info *info, const char **r_digest,
            unsigned char suite_id[5])
{
    unsigned int kem_id;

    if (info->algo == GCRY_KEM_DHKEMP256R1) {
        kem_id = 0x0010;
        *r_digest = "SHA256";
    } else if (info->algo == GCRY_KEM_DHKEMP384R1) {
        kem_id = 0x0011;
        *r_digest = "SHA384";
    } else {
        kem_id = 0x0012;
        *r_digest = "SHA512";
    }

    memcpy(suite_id, "KEM", 3);
    suite_id[3] = (unsigned char)(kem_id >> 8);
    suite_id[4] = (unsigned char)kem_id;
}

/* One HKDF stage with OpenSSL's KDF: MODE is EVP_KDF_HKDF_MODE_EXTRACT_ONLY
 * (KEY is the IKM, the salt is empty, OUT receives the PRK) or
 * EVP_KDF_HKDF_MODE_EXPAND_ONLY (KEY is the PRK, INFO the context). */
static gcry_err_code_t
hkdf_stage(const char *digest, int mode, const unsigned char *key,
           size_t keylen, const unsigned char *info, size_t infolen,
           unsigned char *out, size_t outlen)
{
    EVP_KDF *kdf = EVP_KDF_fetch(_gcry_libctx(), "HKDF", _gcry_propq());
    EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
    OSSL_PARAM params[5];
    size_t n = 0;
    gcry_err_code_t rc = 0;

    EVP_KDF_free(kdf);

    if (!kctx) {
        return ossl_error(GPG_ERR_NOT_SUPPORTED);
    }

    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                   unconst(digest), 0);
    params[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                    unconst(key), keylen);

    if (mode == EVP_KDF_HKDF_MODE_EXPAND_ONLY) {
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                        unconst(info), infolen);
    }

    params[n] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, out, outlen, params) <= 0) {
        rc = ossl_error(GPG_ERR_INTERNAL);
    }

    EVP_KDF_CTX_free(kctx);
    return rc;
}

/* RFC 9180 ExtractAndExpand(dh, kem_context):
 *   eae_prk = LabeledExtract("", "eae_prk", dh)
 *   shared  = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
 * where the labeled forms prefix "HPKE-v1" || suite_id || label (and, for
 * the expansion, I2OSP(Nsecret, 2)) to the input. */
static gcry_err_code_t
dhkem_extract_expand(const struct kem_info *info, const unsigned char *dh,
                     size_t dhlen, const unsigned char *kem_context,
                     size_t ctxlen, unsigned char *shared, size_t shared_len)
{
    const char *digest;
    unsigned char suite_id[5];
    unsigned char ikm[7 + 5 + 7 + 66];
    unsigned char label[2 + 7 + 5 + 13 + 2 * (1 + 2 * 66)];
    unsigned char prk[64];
    size_t prklen = info->shared_len; /* Nh == Nsecret for these suites. */
    size_t n = 0;
    gcry_err_code_t rc;

    dhkem_suite(info, &digest, suite_id);

    memcpy(ikm + n, "HPKE-v1", 7);
    n += 7;
    memcpy(ikm + n, suite_id, 5);
    n += 5;
    memcpy(ikm + n, "eae_prk", 7);
    n += 7;
    memcpy(ikm + n, dh, dhlen);
    n += dhlen;
    rc = hkdf_stage(digest, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, ikm, n, NULL, 0,
                    prk, prklen);

    if (rc) {
        goto leave;
    }

    n = 0;
    label[n++] = (unsigned char)(shared_len >> 8);
    label[n++] = (unsigned char)shared_len;
    memcpy(label + n, "HPKE-v1", 7);
    n += 7;
    memcpy(label + n, suite_id, 5);
    n += 5;
    memcpy(label + n, "shared_secret", 13);
    n += 13;
    memcpy(label + n, kem_context, ctxlen);
    n += ctxlen;
    rc = hkdf_stage(digest, EVP_KDF_HKDF_MODE_EXPAND_ONLY, prk, prklen, label,
                    n, shared, shared_len);

leave:
    _gcry_wipememory(ikm, sizeof ikm);
    _gcry_wipememory(prk, sizeof prk);
    return rc;
}

/* Encap(pkR): an ephemeral key pair, dh = skE * pkR (its x coordinate),
 * enc = pkE, kem_context = enc || pkR. */
static gcry_err_code_t
weier_dhkem_encap(const struct kem_info *info, const unsigned char *pubkey,
                  unsigned char *enc, unsigned char *shared,
                  size_t shared_len)
{
    unsigned char sk_e[66];
    unsigned char dh[1 + 2 * 66];
    unsigned char kem_context[2 * (1 + 2 * 66)];
    gcry_err_code_t rc;

    rc = weier_keypair(info, enc, sk_e);

    if (!rc) {
        rc = weier_mul(info, dh, sk_e, pubkey);
    }

    if (!rc) {
        memcpy(kem_context, enc, info->pubkey_len);
        memcpy(kem_context + info->pubkey_len, pubkey, info->pubkey_len);
        rc = dhkem_extract_expand(info, dh + 1, info->seckey_len, kem_context,
                                  2 * info->pubkey_len, shared, shared_len);
    }

    _gcry_wipememory(sk_e, sizeof sk_e);
    _gcry_wipememory(dh, sizeof dh);
    return rc;
}

/* Decap(enc, skR): dh = skR * enc, kem_context = enc || pk(skR). */
static gcry_err_code_t
weier_dhkem_decap(const struct kem_info *info, const unsigned char *seckey,
                  const unsigned char *enc, unsigned char *shared,
                  size_t shared_len)
{
    unsigned char dh[1 + 2 * 66];
    unsigned char kem_context[2 * (1 + 2 * 66)];
    gcry_err_code_t rc;

    rc = weier_mul(info, dh, seckey, enc);

    if (!rc) {
        rc = weier_mul(info, kem_context + info->pubkey_len, seckey, NULL);
    }

    if (!rc) {
        memcpy(kem_context, enc, info->pubkey_len);
        rc = dhkem_extract_expand(info, dh + 1, info->seckey_len, kem_context,
                                  2 * info->pubkey_len, shared, shared_len);
    }

    _gcry_wipememory(dh, sizeof dh);
    return rc;
}

/* The X448 DHKEM secret is 64 bytes (RFC 9180), yet the public header's
 * GCRY_KEM_DHKEM448_SHARED_LEN says 56.  Accept both: a 56 byte buffer
 * receives the first 56 bytes of the RFC secret, which is what the
 * reference implementation stores there. */
static gcry_err_code_t
dhkem_shared_adjust(const struct kem_info *info, size_t shared_len,
                    size_t *r_real_len)
{
    if (info->algo == GCRY_KEM_DHKEM448) {
        if (shared_len != 56 && shared_len != 64) {
            return GPG_ERR_INV_ARG;
        }

        *r_real_len = 64;
        return 0;
    }

    if (shared_len != info->shared_len) {
        return GPG_ERR_INV_ARG;
    }

    *r_real_len = info->shared_len;
    return 0;
}

static gcry_err_code_t
dhkem_run(const struct kem_info *info, int encap, const unsigned char *key,
          unsigned char *ciphertext, const unsigned char *in_ciphertext,
          unsigned char *shared, size_t shared_len)
{
    unsigned char tmp[64];
    size_t real_len;
    gcry_err_code_t rc = dhkem_shared_adjust(info, shared_len, &real_len);

    if (rc) {
        return rc;
    }

    if (info->kind == KIND_DHKEM_WEIER) {
        rc = encap ? weier_dhkem_encap(info, key, ciphertext, tmp, real_len)
             : weier_dhkem_decap(info, key, in_ciphertext, tmp, real_len);
    } else if (encap) {
        rc = dhkem_encap(info, key, ciphertext, tmp, real_len);
    } else {
        rc = dhkem_decap(info, key, in_ciphertext, tmp, real_len);
    }

    if (!rc) {
        memcpy(shared, tmp, shared_len);
    }

    _gcry_wipememory(tmp, sizeof tmp);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
kem_genkey(int algo, void *pubkey, size_t pubkey_len, void *seckey,
           size_t seckey_len, const void *optional, size_t optional_len)
{
    const struct kem_info *info = find_info(algo);

    _gcry_global_init();

    if (!info) {
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }

    if (info->kind == KIND_UNSUPPORTED) {
        return GPG_ERR_UNSUPPORTED_ALGORITHM;
    }

    if (!pubkey || !seckey || pubkey_len != info->pubkey_len
        || seckey_len != info->seckey_len) {
        return GPG_ERR_INV_ARG;
    }

    switch (info->kind) {
    case KIND_MLKEM:
        if (optional && optional_len != 2 * MLKEM_RANDOM_LEN) {
            return GPG_ERR_INV_ARG;
        }

        if (!optional && optional_len) {
            return GPG_ERR_INV_ARG;
        }

        return mlkem_genkey(info, pubkey, seckey, optional);

    case KIND_RAW_MONT:
    case KIND_DHKEM_MONT:
        if (optional || optional_len) {
            return GPG_ERR_INV_ARG;
        }

        return mont_keypair(info, pubkey, seckey);

    case KIND_RAW_WEIER:
    case KIND_DHKEM_WEIER:
        if (optional || optional_len) {
            return GPG_ERR_INV_ARG;
        }

        return weier_keypair(info, pubkey, seckey);

    default:
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_error_t
gcry_kem_genkey(int algo, void *pubkey, size_t pubkey_len, void *seckey,
                size_t seckey_len, const void *optional, size_t optional_len)
{
    return GCRY_ERR(kem_genkey(algo, pubkey, pubkey_len, seckey, seckey_len,
                               optional, optional_len));
}

gcry_error_t
gcry_kem_keypair(int algo, void *pubkey, size_t pubkey_len, void *seckey,
                 size_t seckey_len)
{
    return GCRY_ERR(kem_genkey(algo, pubkey, pubkey_len, seckey, seckey_len,
                               NULL, 0));
}

static gcry_err_code_t
kem_encap(int algo, const void *pubkey, size_t pubkey_len, void *ciphertext,
          size_t ciphertext_len, void *shared, size_t shared_len,
          const void *optional, size_t optional_len)
{
    const struct kem_info *info = find_info(algo);

    _gcry_global_init();

    if (!info) {
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }

    if (info->kind == KIND_UNSUPPORTED) {
        return GPG_ERR_UNSUPPORTED_ALGORITHM;
    }

    if (!pubkey || !ciphertext || !shared) {
        return GPG_ERR_INV_ARG;
    }

    switch (info->kind) {
    case KIND_MLKEM:
        if (pubkey_len != info->pubkey_len
            || ciphertext_len != info->cipher_len
            || shared_len != info->shared_len) {
            return GPG_ERR_INV_ARG;
        }

        if (optional && optional_len != MLKEM_RANDOM_LEN) {
            return GPG_ERR_INV_ARG;
        }

        if (!optional && optional_len) {
            return GPG_ERR_INV_ARG;
        }

        return mlkem_encap(info, pubkey, ciphertext, shared, optional);

    case KIND_RAW_MONT:
    case KIND_RAW_WEIER: {
        unsigned char eph_seckey[66];
        gcry_err_code_t rc;

        if (optional || optional_len) {
            return GPG_ERR_INV_ARG;
        }

        if (ciphertext_len != pubkey_len) {
            return GPG_ERR_INV_VALUE;
        }

        if (pubkey_len != info->pubkey_len || shared_len != info->shared_len) {
            return GPG_ERR_INV_ARG;
        }

        /* The ciphertext is an ephemeral public key. */
        if (info->kind == KIND_RAW_MONT) {
            rc = mont_keypair(info, ciphertext, eph_seckey);

            if (!rc) {
                rc = mont_mul(info, shared, eph_seckey, pubkey);
            }
        } else {
            rc = weier_keypair(info, ciphertext, eph_seckey);

            if (!rc) {
                rc = weier_mul(info, shared, eph_seckey, pubkey);
            }
        }

        _gcry_wipememory(eph_seckey, sizeof eph_seckey);
        return rc;
    }

    case KIND_DHKEM_MONT:
    case KIND_DHKEM_WEIER:
        if (optional || optional_len) {
            return GPG_ERR_INV_ARG;
        }

        if (pubkey_len != info->pubkey_len
            || ciphertext_len != info->cipher_len) {
            return GPG_ERR_INV_ARG;
        }

        return dhkem_run(info, 1, pubkey, ciphertext, NULL, shared,
                         shared_len);

    default:
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_error_t
gcry_kem_encap(int algo, const void *pubkey, size_t pubkey_len,
               void *ciphertext, size_t ciphertext_len, void *shared,
               size_t shared_len, const void *optional, size_t optional_len)
{
    return GCRY_ERR(kem_encap(algo, pubkey, pubkey_len, ciphertext,
                              ciphertext_len, shared, shared_len, optional,
                              optional_len));
}

static gcry_err_code_t
kem_decap(int algo, const void *seckey, size_t seckey_len,
          const void *ciphertext, size_t ciphertext_len, void *shared,
          size_t shared_len, const void *optional, size_t optional_len)
{
    const struct kem_info *info = find_info(algo);

    _gcry_global_init();

    if (!info) {
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }

    if (info->kind == KIND_UNSUPPORTED) {
        return GPG_ERR_UNSUPPORTED_ALGORITHM;
    }

    if (!seckey || !ciphertext || !shared) {
        return GPG_ERR_INV_ARG;
    }

    switch (info->kind) {
    case KIND_MLKEM:
        if (seckey_len != info->seckey_len
            || ciphertext_len != info->cipher_len
            || shared_len != info->shared_len) {
            return GPG_ERR_INV_ARG;
        }

        if (optional || optional_len) {
            return GPG_ERR_INV_ARG;
        }

        return mlkem_decap(info, seckey, ciphertext, shared);

    case KIND_RAW_MONT:
    case KIND_RAW_WEIER:
        if (optional || optional_len) {
            return GPG_ERR_INV_ARG;
        }

        if (seckey_len != info->seckey_len
            || ciphertext_len != info->cipher_len
            || shared_len != info->shared_len) {
            return GPG_ERR_INV_ARG;
        }

        if (info->kind == KIND_RAW_MONT) {
            return mont_mul(info, shared, seckey, ciphertext);
        }

        return weier_mul(info, shared, seckey, ciphertext);

    case KIND_DHKEM_MONT:
    case KIND_DHKEM_WEIER:

        /* OPTIONAL may carry the recipient's public key to save its
         * recomputation; OpenSSL derives it from the secret key anyway, so
         * only its length is validated. */
        if (optional && optional_len != info->pubkey_len) {
            return GPG_ERR_INV_ARG;
        }

        if (!optional && optional_len) {
            return GPG_ERR_INV_ARG;
        }

        if (seckey_len != info->seckey_len
            || ciphertext_len != info->cipher_len) {
            return GPG_ERR_INV_ARG;
        }

        return dhkem_run(info, 0, seckey, NULL, ciphertext, shared,
                         shared_len);

    default:
        return GPG_ERR_UNKNOWN_ALGORITHM;
    }
}

gcry_error_t
gcry_kem_decap(int algo, const void *seckey, size_t seckey_len,
               const void *ciphertext, size_t ciphertext_len, void *shared,
               size_t shared_len, const void *optional, size_t optional_len)
{
    return GCRY_ERR(kem_decap(algo, seckey, seckey_len, ciphertext,
                              ciphertext_len, shared, shared_len, optional,
                              optional_len));
}
