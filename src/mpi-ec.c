/*
 * mpi-ec.c - Elliptic curve contexts and point arithmetic.
 *
 * A context describes a curve (from the table in ecc-curves.c or from
 * explicit parameters) plus an optional key pair.  Weierstrass curves are
 * backed by an OpenSSL EC_GROUP and all point arithmetic goes through
 * EC_POINT_*.  For the Edwards and Montgomery curves OpenSSL offers no
 * generic point arithmetic, so only the operations OpenSSL can express
 * (public key derivation, X25519/X448 scalar multiplication) are
 * provided; the rest report GPG_ERR_NOT_IMPLEMENTED.
 *
 * Points follow Libgcrypt's conventions: Weierstrass points are Jacobian
 * (x = X/Z^2, y = Y/Z^3), Edwards and Montgomery points are projective
 * (x = X/Z, y = Y/Z), and Z = 0 is the point at infinity.
 */
#include "gcrypt-int.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static BN_CTX *
new_bnctx(void)
{
    return BN_CTX_new_ex(_gcry_libctx());
}

static void
reverse_buffer(unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len / 2; i++) {
        unsigned char t = buf[i];

        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = t;
    }
}

/* Encoded length of a point coordinate / EdDSA key for a curve. */
static unsigned int
eddsa_len(unsigned int nbits)
{
    return (nbits % 8) == 0 ? nbits / 8 + 1 : (nbits + 7) / 8;
}

static const char *
edwards_keytype(mpi_ec_t ec)
{
    return ec->nbits == 448 ? "ED448" : "ED25519";
}

static const char *
mont_keytype(mpi_ec_t ec)
{
    return ec->nbits == 448 ? "X448" : "X25519";
}

static int
is_eddsa_ctx(mpi_ec_t ec)
{
    return (ec->dialect == GCRY_ECC_DIALECT_ED25519
            && (ec->flags & PUBKEY_FLAG_EDDSA))
           || (ec->model == GCRY_ECC_MODEL_EDWARDS
               && ec->dialect == GCRY_ECC_DIALECT_SAFECURVE);
}

/* ------------------------------------------------------------------ */
/* Point encodings                                                     */
/* ------------------------------------------------------------------ */

/* "04 || X || Y" as an opaque MPI; coordinates are padded to the size of
 * the field prime P. */
gcry_mpi_t
_gcry_ecc_ec2os(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p)
{
    size_t pbytes = (gcry_mpi_get_nbits(p) + 7) / 8;
    unsigned char *buf = _gcry_xmalloc(1 + 2 * pbytes);

    buf[0] = 0x04;

    if (_gcry_pk_mpi_to_fixed(x, buf + 1, pbytes)
        || _gcry_pk_mpi_to_fixed(y, buf + 1 + pbytes, pbytes)) {
        _gcry_free(buf);
        return NULL;
    }

    return gcry_mpi_set_opaque(NULL, buf, (unsigned int)(8 * (1 + 2 * pbytes)));
}

gcry_mpi_t
_gcry_mpi_ec_ec2os(gcry_mpi_point_t point, mpi_ec_t ec)
{
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);
    gcry_mpi_t result = NULL;

    if (!_gcry_mpi_ec_affine(x, y, point, ec)) {
        result = _gcry_ecc_ec2os(x, y, ec->p);
    }

    gcry_mpi_release(x);
    gcry_mpi_release(y);
    return result;
}

/* EdDSA compressed encoding: little endian Y with the parity of X in the
 * top bit, optionally with Libgcrypt's 0x40 prefix. */
gcry_err_code_t
_gcry_ecc_eddsa_encode_x_y(gcry_mpi_t x, gcry_mpi_t y, unsigned int nbits,
                           int with_prefix, unsigned char **r_buf,
                           unsigned int *r_len)
{
    unsigned int len = eddsa_len(nbits);
    unsigned int off = with_prefix ? 1u : 0u;
    unsigned char *buf;

    if (BN_num_bytes(_gcry_mpi_bn(y)) > (int)len) {
        return GPG_ERR_INV_OBJ;
    }

    buf = _gcry_malloc(len + off);

    if (!buf) {
        return _gcry_err_code_from_syserror();
    }

    memset(buf, 0, len + off);
    BN_bn2bin(_gcry_mpi_bn(y), buf + off + (len - (unsigned int)BN_num_bytes(
                                                _gcry_mpi_bn(y))));
    reverse_buffer(buf + off, len);

    if (BN_is_odd(_gcry_mpi_bn(x))) {
        buf[off + len - 1] |= 0x80;
    }

    if (off) {
        buf[0] = 0x40;
    }

    *r_buf = buf;
    *r_len = len + off;
    return 0;
}

gcry_err_code_t
_gcry_ecc_eddsa_encodepoint(gcry_mpi_point_t point, mpi_ec_t ec,
                            int with_prefix, unsigned char **r_buf,
                            unsigned int *r_len)
{
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);
    gcry_err_code_t rc;

    if (_gcry_mpi_ec_affine(x, y, point, ec)) {
        rc = GPG_ERR_INTERNAL;
    } else {
        rc = _gcry_ecc_eddsa_encode_x_y(x, y, ec->nbits, with_prefix, r_buf,
                                        r_len);
    }

    gcry_mpi_release(x);
    gcry_mpi_release(y);
    return rc;
}

/* Turn any accepted encoding of an EdDSA public key ("04||X||Y",
 * "40||compressed", or compressed) into the plain compressed form. */
gcry_err_code_t
_gcry_ecc_eddsa_compact(gcry_mpi_t value, unsigned int nbits,
                        unsigned char **r_buf, unsigned int *r_len)
{
    const unsigned char *buf;
    unsigned int rawlen;
    unsigned int len = eddsa_len(nbits);
    unsigned char *out;

    if (!mpi_is_opaque(value)) {
        return GPG_ERR_INV_OBJ;
    }

    buf = gcry_mpi_get_opaque(value, &rawlen);

    if (!buf) {
        return GPG_ERR_INV_OBJ;
    }

    rawlen = (rawlen + 7) / 8;

    if (rawlen > 1 && (rawlen % 2) && buf[0] == 0x04) {
        gcry_mpi_t x = NULL;
        gcry_mpi_t y = NULL;
        gcry_err_code_t rc;
        unsigned int half = (rawlen - 1) / 2;

        rc = _gcry_mpi_scan(&x, GCRYMPI_FMT_USG, buf + 1, half, NULL);

        if (!rc) {
            rc = _gcry_mpi_scan(&y, GCRYMPI_FMT_USG, buf + 1 + half, half,
                                NULL);
        }

        if (!rc) {
            rc = _gcry_ecc_eddsa_encode_x_y(x, y, nbits, 0, r_buf, r_len);
        }

        gcry_mpi_release(x);
        gcry_mpi_release(y);
        return rc;
    }

    if (rawlen == len + 1 && buf[0] == 0x40) {
        buf++;
        rawlen--;
    }

    if (rawlen != len) {
        return GPG_ERR_INV_OBJ;
    }

    out = _gcry_malloc(len);

    if (!out) {
        return _gcry_err_code_from_syserror();
    }

    memcpy(out, buf, len);
    *r_buf = out;
    *r_len = len;
    return 0;
}

/* Montgomery u-coordinate encoding: little endian, optional 0x40 prefix. */
gcry_err_code_t
_gcry_ecc_mont_encodepoint(gcry_mpi_t x, unsigned int nbits, int with_prefix,
                           unsigned char **r_buf, unsigned int *r_len)
{
    unsigned int nbytes = (nbits + 7) / 8;
    unsigned int off = with_prefix ? 1u : 0u;
    unsigned char *buf = _gcry_malloc(nbytes + off);

    if (!buf) {
        return _gcry_err_code_from_syserror();
    }

    memset(buf, 0, nbytes + off);

    if (_gcry_pk_mpi_to_fixed(x, buf + off, nbytes)) {
        _gcry_free(buf);
        return GPG_ERR_INV_OBJ;
    }

    reverse_buffer(buf + off, nbytes);

    if (off) {
        buf[0] = 0x40;
    }

    *r_buf = buf;
    *r_len = nbytes + off;
    return 0;
}

/* Decode an encoded Montgomery point into its little endian u coordinate
 * (NBYTES bytes).  Accepts the opaque "40||u", "00||u" and plain forms as
 * well as a numeric MPI whose little endian bytes are the encoding. */
gcry_err_code_t
_gcry_ecc_mont_decode_u(gcry_mpi_t value, unsigned int nbits,
                        unsigned char *out)
{
    unsigned int nbytes = (nbits + 7) / 8;

    memset(out, 0, nbytes);

    if (mpi_is_opaque(value)) {
        const unsigned char *buf;
        unsigned int rawlen;

        buf = gcry_mpi_get_opaque(value, &rawlen);

        if (!buf) {
            return GPG_ERR_INV_OBJ;
        }

        rawlen = (rawlen + 7) / 8;

        if (rawlen == nbytes + 1 && (buf[0] == 0x00 || buf[0] == 0x40)) {
            rawlen--;
            buf++;
        } else if (rawlen > nbytes) {
            return GPG_ERR_INV_OBJ;
        }

        /* A short payload is the top of a big endian number whose low
         * bytes are zero, exactly as the reference implementation sees
         * it; in little endian that means the payload sits at the end. */
        memcpy(out + (nbytes - rawlen), buf, rawlen);
    } else {
        unsigned int len;
        int sign;
        unsigned char *tmp = _gcry_mpi_get_buffer(value, nbytes, &len, &sign);

        if (!tmp) {
            return _gcry_err_code_from_syserror();
        }

        if (len > nbytes + 8) {
            _gcry_free(tmp);
            return GPG_ERR_INV_OBJ;
        }

        memcpy(out, tmp, nbytes);
        _gcry_free(tmp);
    }

    if (nbits % 8) {
        out[nbytes - 1] &= (unsigned char)((1u << (nbits % 8)) - 1);
    }

    return 0;
}

/* The EdDSA secret seed of EC as a fresh buffer. */
gcry_err_code_t
_gcry_ecc_eddsa_seed(mpi_ec_t ec, unsigned char **r_seed, size_t *r_len)
{
    unsigned int len = eddsa_len(ec->nbits);
    unsigned char *seed;

    if (!ec->d) {
        return GPG_ERR_NO_SECKEY;
    }

    seed = _gcry_malloc_secure(len);

    if (!seed) {
        return _gcry_err_code_from_syserror();
    }

    if (mpi_is_opaque(ec->d)) {
        const unsigned char *buf;
        unsigned int n;

        buf = gcry_mpi_get_opaque(ec->d, &n);
        n = (n + 7) / 8;

        if (!buf) {
            _gcry_free(seed);
            return GPG_ERR_INV_OBJ;
        }

        if (n == len) {
            memcpy(seed, buf, len);
        } else if (n < len) {
            memset(seed, 0, len - n);
            memcpy(seed + (len - n), buf, n);
        } else if (n == len + 1) {
            memcpy(seed, buf + 1, len);
        } else {
            _gcry_free(seed);
            return GPG_ERR_INV_OBJ;
        }
    } else if (_gcry_pk_mpi_to_fixed(ec->d, seed, len)) {
        _gcry_free(seed);
        return GPG_ERR_INV_OBJ;
    }

    *r_seed = seed;
    *r_len = len;
    return 0;
}

/* The little endian scalar for X25519/X448 derived from D. */
gcry_err_code_t
_gcry_ecc_mont_scalar(gcry_mpi_t d, unsigned int nbits,
                      unsigned char **r_buf, size_t *r_len)
{
    unsigned int nbytes = (nbits + 7) / 8;
    unsigned char *buf;

    if (!d) {
        return GPG_ERR_NO_SECKEY;
    }

    buf = _gcry_malloc_secure(nbytes);

    if (!buf) {
        return _gcry_err_code_from_syserror();
    }

    if (mpi_is_opaque(d)) {
        const unsigned char *p;
        unsigned int n;

        p = gcry_mpi_get_opaque(d, &n);
        n = (n + 7) / 8;

        if (!p || n != nbytes) {
            _gcry_free(buf);
            return GPG_ERR_INV_OBJ;
        }

        memcpy(buf, p, nbytes);
    } else {
        unsigned int len;
        unsigned char *tmp = _gcry_mpi_get_buffer(d, nbytes, &len, NULL);

        if (!tmp) {
            _gcry_free(buf);
            return _gcry_err_code_from_syserror();
        }

        if (len > nbytes) {
            _gcry_free(tmp);
            _gcry_free(buf);
            return GPG_ERR_INV_OBJ;
        }

        memcpy(buf, tmp, nbytes);
        _gcry_free(tmp);
    }

    *r_buf = buf;
    *r_len = nbytes;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Weierstrass points <-> EC_POINT                                     */
/* ------------------------------------------------------------------ */

static void
point_set_infinity(gcry_mpi_point_t pt)
{
    gcry_mpi_set_ui(pt->x, 1);
    gcry_mpi_set_ui(pt->y, 1);
    gcry_mpi_set_ui(pt->z, 0);
}

/* Convert a Jacobian point into an EC_POINT.  Fails if the coordinates
 * are not on the curve. */
static gcry_err_code_t
point_to_ec(mpi_ec_t ec, gcry_mpi_point_t pt, EC_POINT *P, BN_CTX *bctx)
{
    const BIGNUM *p = _gcry_mpi_bn(ec->p);
    const BIGNUM *z = _gcry_mpi_bn(pt->z);
    BIGNUM *x;
    BIGNUM *y;
    BIGNUM *zi;
    BIGNUM *t;
    int ok;

    if (BN_is_zero(z)) {
        return EC_POINT_set_to_infinity(ec->group, P) ? 0 : GPG_ERR_INTERNAL;
    }

    if (BN_is_one(z)) {
        if (!EC_POINT_set_affine_coordinates(ec->group, P, _gcry_mpi_bn(pt->x),
                                             _gcry_mpi_bn(pt->y), bctx)) {
            ERR_clear_error();
            return GPG_ERR_INV_OBJ;
        }

        return 0;
    }

    BN_CTX_start(bctx);
    x = BN_CTX_get(bctx);
    y = BN_CTX_get(bctx);
    zi = BN_CTX_get(bctx);
    t = BN_CTX_get(bctx);
    ok = t && BN_mod_inverse(zi, z, p, bctx)
         && BN_mod_sqr(t, zi, p, bctx)
         && BN_mod_mul(x, _gcry_mpi_bn(pt->x), t, p, bctx)
         && BN_mod_mul(t, t, zi, p, bctx)
         && BN_mod_mul(y, _gcry_mpi_bn(pt->y), t, p, bctx)
         && EC_POINT_set_affine_coordinates(ec->group, P, x, y, bctx);
    BN_CTX_end(bctx);

    if (!ok) {
        ERR_clear_error();
        return GPG_ERR_INV_OBJ;
    }

    return 0;
}

static gcry_err_code_t
ec_to_point(mpi_ec_t ec, const EC_POINT *P, gcry_mpi_point_t pt, BN_CTX *bctx)
{
    if (EC_POINT_is_at_infinity(ec->group, P)) {
        point_set_infinity(pt);
        return 0;
    }

    if (!EC_POINT_get_affine_coordinates(ec->group, P, _gcry_mpi_bn(pt->x),
                                         _gcry_mpi_bn(pt->y), bctx)) {
        ERR_clear_error();
        return GPG_ERR_INTERNAL;
    }

    gcry_mpi_set_ui(pt->z, 1);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Edwards helpers (encoding level arithmetic)                         */
/* ------------------------------------------------------------------ */

/* Recover the X coordinate of an Edwards point from Y and the parity bit
 * SIGN, following RFC 8032 sections 5.1.3 and 5.2.3. */
static gcry_err_code_t
eddsa_recover_x(gcry_mpi_t x_out, gcry_mpi_t y, int sign, mpi_ec_t ec)
{
    BN_CTX *bctx = new_bnctx();
    const BIGNUM *p;
    const BIGNUM *d;
    BIGNUM *u;
    BIGNUM *v;
    BIGNUM *x;
    BIGNUM *t;
    BIGNUM *e;
    gcry_err_code_t rc = GPG_ERR_INV_OBJ;
    int ok;

    if (!bctx) {
        return GPG_ERR_ENOMEM;
    }

    p = _gcry_mpi_bn(ec->p);
    d = _gcry_mpi_bn(ec->b);
    BN_CTX_start(bctx);
    u = BN_CTX_get(bctx);
    v = BN_CTX_get(bctx);
    x = BN_CTX_get(bctx);
    t = BN_CTX_get(bctx);
    e = BN_CTX_get(bctx);

    if (!e) {
        goto leave;
    }

    /* u = y^2 - 1 ; v = d*y^2 + 1 (Ed25519, a = -1) or d*y^2 - 1 (Ed448). */
    ok = BN_mod_sqr(u, _gcry_mpi_bn(y), p, bctx)
         && BN_mod_mul(v, d, u, p, bctx)
         && BN_mod_sub(u, u, BN_value_one(), p, bctx);

    if (!ok) {
        goto leave;
    }

    if (ec->dialect == GCRY_ECC_DIALECT_ED25519) {
        /* x = u v^3 (u v^7)^((p-5)/8) */
        ok = BN_mod_add(v, v, BN_value_one(), p, bctx)
             && BN_mod_sqr(t, v, p, bctx)            /* v^2 */
             && BN_mod_mul(x, t, v, p, bctx)         /* v^3 */
             && BN_mod_sqr(t, t, p, bctx)            /* v^4 */
             && BN_mod_mul(t, t, x, p, bctx)         /* v^7 */
             && BN_mod_mul(t, t, u, p, bctx)         /* u v^7 */
             && BN_copy(e, p) && BN_sub_word(e, 5) && BN_rshift(e, e, 3)
             && BN_mod_exp(t, t, e, p, bctx)
             && BN_mod_mul(x, x, u, p, bctx)         /* u v^3 */
             && BN_mod_mul(x, x, t, p, bctx);

        if (!ok) {
            goto leave;
        }

        /* Check v x^2 == u, else try x * 2^((p-1)/4). */
        ok = BN_mod_sqr(t, x, p, bctx) && BN_mod_mul(t, t, v, p, bctx);

        if (!ok) {
            goto leave;
        }

        if (BN_cmp(t, u) != 0) {
            BIGNUM *two = BN_CTX_get(bctx);

            ok = two && BN_set_word(two, 2) && BN_copy(e, p)
                 && BN_sub_word(e, 1) && BN_rshift(e, e, 2)
                 && BN_mod_exp(e, two, e, p, bctx)
                 && BN_mod_mul(x, x, e, p, bctx)
                 && BN_mod_sqr(t, x, p, bctx) && BN_mod_mul(t, t, v, p, bctx);

            if (!ok || BN_cmp(t, u) != 0) {
                goto leave;
            }
        }
    } else {
        /* Ed448: x = u^3 v (u^5 v^3)^((p-3)/4) */
        ok = BN_mod_sub(v, v, BN_value_one(), p, bctx)
             && BN_mod_sqr(t, u, p, bctx)            /* u^2 */
             && BN_mod_mul(x, t, u, p, bctx)         /* u^3 */
             && BN_mod_mul(x, x, v, p, bctx)         /* u^3 v */
             && BN_mod_mul(t, t, x, p, bctx)         /* u^5 v */
             && BN_mod_sqr(e, v, p, bctx)            /* v^2 */
             && BN_mod_mul(t, t, e, p, bctx)         /* u^5 v^3 */
             && BN_copy(e, p) && BN_sub_word(e, 3) && BN_rshift(e, e, 2)
             && BN_mod_exp(t, t, e, p, bctx)
             && BN_mod_mul(x, x, t, p, bctx)
             && BN_mod_sqr(t, x, p, bctx) && BN_mod_mul(t, t, v, p, bctx);

        if (!ok || BN_cmp(t, u) != 0) {
            goto leave;
        }
    }

    if (BN_is_zero(x) && sign) {
        goto leave;
    }

    if ((BN_is_odd(x) != 0) != (sign != 0)) {
        if (!BN_sub(x, p, x)) {
            goto leave;
        }
    }

    if (!BN_copy(_gcry_mpi_bn(x_out), x)) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    rc = 0;

leave:
    ERR_clear_error();
    BN_CTX_end(bctx);
    BN_CTX_free(bctx);
    return rc;
}

/* Decode an EdDSA public key encoding into RESULT. */
static gcry_err_code_t
eddsa_decodepoint(gcry_mpi_t pk, mpi_ec_t ec, gcry_mpi_point_t result)
{
    unsigned int len = eddsa_len(ec->nbits);
    unsigned char *raw;
    unsigned int rawlen;
    int sign;
    gcry_err_code_t rc;

    if (mpi_is_opaque(pk)) {
        const unsigned char *buf = gcry_mpi_get_opaque(pk, &rawlen);

        if (!buf) {
            return GPG_ERR_INV_OBJ;
        }

        rawlen = (rawlen + 7) / 8;

        if (!(rawlen == len || rawlen == len + 1 || rawlen == len * 2 + 1)) {
            return GPG_ERR_INV_OBJ;
        }

        if (rawlen > 1 && (rawlen == len + 1 || rawlen == len * 2 + 1)) {
            if (buf[0] == 0x04) {
                gcry_mpi_t x = NULL;
                gcry_mpi_t y = NULL;
                unsigned int half = (rawlen - 1) / 2;

                rc = _gcry_mpi_scan(&x, GCRYMPI_FMT_USG, buf + 1, half, NULL);

                if (!rc) {
                    rc = _gcry_mpi_scan(&y, GCRYMPI_FMT_USG, buf + 1 + half,
                                        half, NULL);
                }

                if (rc) {
                    gcry_mpi_release(x);
                    return rc;
                }

                gcry_mpi_snatch(result->x, x);
                gcry_mpi_snatch(result->y, y);
                gcry_mpi_set_ui(result->z, 1);
                return 0;
            }

            if (buf[0] == 0x40) {
                rawlen--;
                buf++;
            }
        }

        raw = _gcry_malloc(rawlen);

        if (!raw) {
            return _gcry_err_code_from_syserror();
        }

        memcpy(raw, buf, rawlen);
        reverse_buffer(raw, rawlen);
    } else {
        raw = _gcry_mpi_get_buffer(pk, (ec->nbits + 7) / 8, &rawlen, NULL);

        if (!raw) {
            return _gcry_err_code_from_syserror();
        }

        /* The buffer is little endian here.  A number carrying the
         * prefixed native encoding has the 0x40 marker in its top byte,
         * which is the last one: drop it. */
        if (rawlen == len + 1 && raw[len] == 0x40) {
            rawlen = len;
        }
    }

    if (rawlen) {
        sign = !!(raw[0] & 0x80);
        raw[0] &= 0x7f;
    } else {
        sign = 0;
    }

    _gcry_mpi_set_buffer(result->y, raw, rawlen, 0);
    _gcry_free(raw);
    rc = eddsa_recover_x(result->x, result->y, sign, ec);
    gcry_mpi_set_ui(result->z, 1);
    return rc;
}

/* Decode a SEC 1 encoded point ("04||X||Y", or compressed when the group
 * is available). */
static gcry_err_code_t
sec_decodepoint(gcry_mpi_t value, mpi_ec_t ec, gcry_mpi_point_t result)
{
    const unsigned char *buf;
    unsigned char *tmp = NULL;
    size_t n;
    gcry_err_code_t rc = 0;

    if (mpi_is_opaque(value)) {
        unsigned int nbits;

        buf = gcry_mpi_get_opaque(value, &nbits);

        if (!buf) {
            return GPG_ERR_INV_OBJ;
        }

        n = (nbits + 7) / 8;
    } else {
        rc = _gcry_pk_mpi_to_bytes(value, &tmp, &n);

        if (rc) {
            return rc;
        }

        buf = tmp;
    }

    if (n < 1) {
        rc = GPG_ERR_INV_OBJ;
    } else if (buf[0] == 0x04) {
        gcry_mpi_t x = NULL;
        gcry_mpi_t y = NULL;

        if (((n - 1) % 2)) {
            rc = GPG_ERR_INV_OBJ;
        } else {
            size_t half = (n - 1) / 2;

            rc = _gcry_mpi_scan(&x, GCRYMPI_FMT_USG, buf + 1, half, NULL);

            if (!rc) {
                rc = _gcry_mpi_scan(&y, GCRYMPI_FMT_USG, buf + 1 + half, half,
                                    NULL);
            }

            if (!rc) {
                gcry_mpi_snatch(result->x, x);
                gcry_mpi_snatch(result->y, y);
                gcry_mpi_set_ui(result->z, 1);
                x = y = NULL;
            }

            gcry_mpi_release(x);
            gcry_mpi_release(y);
        }
    } else if (buf[0] == 0x02 || buf[0] == 0x03) {
        if (!ec || !ec->group) {
            rc = GPG_ERR_NOT_IMPLEMENTED;
        } else {
            BN_CTX *bctx = new_bnctx();
            EC_POINT *P = EC_POINT_new(ec->group);

            if (!bctx || !P
                || !EC_POINT_oct2point(ec->group, P, buf, n, bctx)) {
                ERR_clear_error();
                rc = GPG_ERR_INV_OBJ;
            } else {
                rc = ec_to_point(ec, P, result, bctx);
            }

            EC_POINT_free(P);
            BN_CTX_free(bctx);
        }
    } else {
        rc = GPG_ERR_INV_OBJ;
    }

    _gcry_free(tmp);
    return rc;
}

/* Decode a Montgomery point: only the u coordinate is meaningful. */
static gcry_err_code_t
mont_decodepoint(gcry_mpi_t value, mpi_ec_t ec, gcry_mpi_point_t result)
{
    unsigned int nbytes = (ec->nbits + 7) / 8;
    unsigned char *u = _gcry_malloc(nbytes);
    gcry_err_code_t rc;

    if (!u) {
        return _gcry_err_code_from_syserror();
    }

    rc = _gcry_ecc_mont_decode_u(value, ec->nbits, u);

    if (!rc) {
        reverse_buffer(u, nbytes);
        _gcry_mpi_set_buffer(result->x, u, nbytes, 0);
        gcry_mpi_set_ui(result->y, 0);
        gcry_mpi_set_ui(result->z, 1);
    }

    _gcry_free(u);
    return rc;
}

gcry_err_code_t
_gcry_ecc_decode_point(gcry_mpi_point_t result, gcry_mpi_t value,
                       mpi_ec_t ec)
{
    if (ec && (ec->dialect == GCRY_ECC_DIALECT_ED25519
               || (ec->model == GCRY_ECC_MODEL_EDWARDS
                   && ec->dialect == GCRY_ECC_DIALECT_SAFECURVE))) {
        return eddsa_decodepoint(value, ec, result);
    }

    if (ec && ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        return mont_decodepoint(value, ec, result);
    }

    return sec_decodepoint(value, ec, result);
}

/* ------------------------------------------------------------------ */
/* Context construction                                                */
/* ------------------------------------------------------------------ */

void
_gcry_mpi_ec_free(mpi_ec_t ec)
{
    if (!ec) {
        return;
    }

    EC_GROUP_free(ec->group);
    EC_GROUP_free(ec->mont_group);
    gcry_mpi_release(ec->p);
    gcry_mpi_release(ec->a);
    gcry_mpi_release(ec->b);
    gcry_mpi_release(ec->n);
    gcry_mpi_release(ec->d);
    gcry_mpi_point_release(ec->G);
    gcry_mpi_point_release(ec->Q);
    _gcry_free(ec);
}

static gcry_err_code_t
mpi_from_keyparam(gcry_mpi_t *r_a, gcry_sexp_t keyparam, const char *name,
                  int opaque)
{
    gcry_sexp_t l1 = gcry_sexp_find_token(keyparam, name, 0);
    gcry_err_code_t rc = 0;

    *r_a = NULL;

    if (l1) {
        *r_a = gcry_sexp_nth_mpi(l1, 1, opaque ? GCRYMPI_FMT_OPAQUE
                                 : GCRYMPI_FMT_USG);
        gcry_sexp_release(l1);

        if (!*r_a) {
            rc = GPG_ERR_INV_OBJ;
        }
    }

    return rc;
}

static gcry_err_code_t
point_from_keyparam(gcry_mpi_point_t *r_pt, gcry_sexp_t keyparam,
                    const char *name, mpi_ec_t ec)
{
    gcry_mpi_t a = NULL;
    gcry_err_code_t rc;

    *r_pt = NULL;
    rc = mpi_from_keyparam(&a, keyparam, name, 1);

    if (rc || !a) {
        return rc;
    }

    *r_pt = gcry_mpi_point_new(0);
    rc = _gcry_ecc_decode_point(*r_pt, a, ec);
    gcry_mpi_release(a);

    if (rc) {
        gcry_mpi_point_release(*r_pt);
        *r_pt = NULL;
    }

    return rc;
}

/* Fill the curve parameters of EC from the table entry CURVE, keeping any
 * explicitly given value. */
static void
fill_in_curve(mpi_ec_t ec, const struct gcry_ecc_curve *curve)
{
    ec->curve = curve;
    ec->model = curve->model;
    ec->dialect = curve->dialect;
    ec->nbits = curve->nbits;

    if (!ec->p) {
        ec->p = _gcry_ecc_curve_param(curve, "p");
    }

    if (!ec->a) {
        ec->a = _gcry_ecc_curve_param(curve, "a");
    }

    if (!ec->b) {
        ec->b = _gcry_ecc_curve_param(curve, "b");
    }

    if (!ec->n) {
        ec->n = _gcry_ecc_curve_param(curve, "n");
    }

    if (!ec->G) {
        gcry_mpi_t gx = _gcry_ecc_curve_param(curve, "g.x");
        gcry_mpi_t gy = _gcry_ecc_curve_param(curve, "g.y");

        if (gx && gy && !strcmp(curve->name, "Curve25519")) {
            /* The table keeps the historical G.y for keygrip stability;
             * the real base point has p - that value. */
            gcry_mpi_sub(gy, ec->p, gy);
        }

        ec->G = gcry_mpi_point_snatch_set(NULL, gx, gy,
                                          gcry_mpi_set_ui(NULL, 1));
    }

    ec->h = curve->h;

    if (!ec->name) {
        ec->name = curve->name;
    }
}

/* Build the EC_GROUP for a Weierstrass context. */
static gcry_err_code_t
setup_group(mpi_ec_t ec)
{
    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS || ec->group) {
        return 0;
    }

    if (ec->curve) {
        ec->group = _gcry_ecc_curve_group(ec->curve);
    }

    if (!ec->group) {
        BN_CTX *bctx = new_bnctx();
        EC_POINT *g = NULL;
        BIGNUM *h = BN_new();
        gcry_err_code_t rc = GPG_ERR_INV_CURVE;

        if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n || !bctx || !h) {
            goto leave;
        }

        ec->group = EC_GROUP_new_curve_GFp(_gcry_mpi_bn(ec->p),
                                           _gcry_mpi_bn(ec->a),
                                           _gcry_mpi_bn(ec->b), bctx);

        if (!ec->group) {
            goto leave;
        }

        g = EC_POINT_new(ec->group);

        if (!g || !BN_set_word(h, ec->h)
            || !EC_POINT_set_affine_coordinates(ec->group, g,
                                                _gcry_mpi_bn(ec->G->x), _gcry_mpi_bn(ec->G->y), bctx)
            || !EC_GROUP_set_generator(ec->group, g, _gcry_mpi_bn(ec->n),
                                       h)) {
            EC_GROUP_free(ec->group);
            ec->group = NULL;
            goto leave;
        }

        EC_GROUP_set_asn1_flag(ec->group, OPENSSL_EC_EXPLICIT_CURVE);

        if (!ec->curve) {
            ec->curve = _gcry_ecc_curve_from_group(ec->group);

            if (ec->curve && ec->curve->nid != NID_undef) {
                EC_GROUP *named = _gcry_ecc_curve_group(ec->curve);

                if (named) {
                    EC_GROUP_free(ec->group);
                    ec->group = named;
                }
            }
        }

        rc = 0;
leave:
        ERR_clear_error();
        EC_POINT_free(g);
        BN_free(h);
        BN_CTX_free(bctx);
        return rc;
    }

    return 0;
}

gcry_err_code_t
_gcry_mpi_ec_internal_new(mpi_ec_t *r_ec, int *r_flags, gcry_sexp_t keyparam,
                          const char *curvename)
{
    gcry_err_code_t rc;
    mpi_ec_t ec;
    unsigned int nbits = 0;
    gcry_sexp_t l1 = NULL;
    char *name = NULL;
    int flags = r_flags ? *r_flags : 0;

    *r_ec = NULL;
    rc = _gcry_pk_util_get_nbits(keyparam, &nbits);

    if (rc) {
        return rc;
    }

    ec = _gcry_calloc(1, sizeof * ec);

    if (!ec) {
        return _gcry_err_code_from_syserror();
    }

    ec->model = GCRY_ECC_MODEL_WEIERSTRASS;
    ec->dialect = GCRY_ECC_DIALECT_STANDARD;
    ec->h = 1;

    if (keyparam) {
        l1 = gcry_sexp_find_token(keyparam, "flags", 0);

        if (l1) {
            int f = 0;

            rc = _gcry_pk_util_parse_flaglist(l1, &f, NULL);
            gcry_sexp_release(l1);
            l1 = NULL;

            if (rc) {
                goto leave;
            }

            flags |= f;
        }

        l1 = gcry_sexp_find_token(keyparam, "curve", 5);

        /* Explicit parameters are used when there is no curve name or
         * when the "param" flag asks for them. */
        if (!l1 || (flags & PUBKEY_FLAG_PARAM)) {
            gcry_mpi_t cofactor = NULL;

            if (!(rc = mpi_from_keyparam(&ec->p, keyparam, "p", 0))
                && !(rc = mpi_from_keyparam(&ec->a, keyparam, "a", 0))
                && !(rc = mpi_from_keyparam(&ec->b, keyparam, "b", 0))
                && !(rc = point_from_keyparam(&ec->G, keyparam, "g", NULL))
                && !(rc = mpi_from_keyparam(&ec->n, keyparam, "n", 0))) {
                rc = mpi_from_keyparam(&cofactor, keyparam, "h", 0);
            }

            if (rc) {
                goto leave;
            }

            if (cofactor) {
                gcry_mpi_get_ui(&ec->h, cofactor);
                gcry_mpi_release(cofactor);
            }
        }
    }

    if (l1) {
        name = gcry_sexp_nth_string(l1, 1);
        gcry_sexp_release(l1);
        l1 = NULL;

        if (!name) {
            rc = GPG_ERR_INV_OBJ;
            goto leave;
        }
    }

    if (name || curvename || nbits) {
        const struct gcry_ecc_curve *curve;

        if (name || curvename) {
            curve = _gcry_ecc_curve_find(name ? name : curvename);
        } else {
            curve = _gcry_ecc_curve_by_nbits(nbits);
        }

        if (!curve) {
            rc = GPG_ERR_UNKNOWN_CURVE;
            goto leave;
        }

        if (_gcry_fips_mode() && !curve->fips) {
            rc = GPG_ERR_NOT_SUPPORTED;
            goto leave;
        }

        fill_in_curve(ec, curve);
    } else if (ec->p) {
        ec->nbits = gcry_mpi_get_nbits(ec->p);
    } else {
        rc = GPG_ERR_INV_ARG; /* Neither a curve name nor parameters. */
        goto leave;
    }

    ec->flags = flags;
    rc = setup_group(ec);

    if (rc) {
        goto leave;
    }

    if (keyparam) {
        int is_opaque_bytes = is_eddsa_ctx(ec)
                              || ec->dialect == GCRY_ECC_DIALECT_SAFECURVE;

        rc = point_from_keyparam(&ec->Q, keyparam, "q", ec);

        if (rc) {
            goto leave;
        }

        rc = mpi_from_keyparam(&ec->d, keyparam, "d", is_opaque_bytes);

        if (rc) {
            goto leave;
        }

        if (ec->d && is_opaque_bytes) {
            unsigned int n = gcry_mpi_get_nbits(ec->d);
            unsigned int len = (ec->nbits + 7) / 8;

            if ((ec->nbits % 8) == 0 && ec->model == GCRY_ECC_MODEL_EDWARDS) {
                len++;
            }

            if ((n + 7) / 8 != len) {
                if (ec->dialect == GCRY_ECC_DIALECT_ED25519) {
                    unsigned char *seed;
                    size_t seedlen;

                    rc = _gcry_ecc_eddsa_seed(ec, &seed, &seedlen);

                    if (rc) {
                        goto leave;
                    }

                    gcry_mpi_set_opaque(ec->d, seed, (unsigned int)seedlen * 8);
                } else {
                    rc = GPG_ERR_INV_OBJ;
                    goto leave;
                }
            }
        }
    }

    if (r_flags) {
        *r_flags = flags;
    }

leave:
    _gcry_free(name);
    gcry_sexp_release(l1);

    if (rc) {
        _gcry_mpi_ec_free(ec);
    } else {
        *r_ec = ec;
    }

    return rc;
}

/* ------------------------------------------------------------------ */
/* Arithmetic                                                          */
/* ------------------------------------------------------------------ */

int
_gcry_mpi_ec_affine(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_point_t point,
                    mpi_ec_t ec)
{
    BN_CTX *bctx;
    const BIGNUM *p;
    const BIGNUM *z;
    BIGNUM *zi;
    BIGNUM *t;
    int ok = 1;

    if (!point || BN_is_zero(_gcry_mpi_bn(point->z))) {
        return -1;
    }

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        /* The reference library hands out X without dividing by Z and
         * has no Y coordinate for these curves. */
        if (y) {
            log_error("getting the Y coordinate of a Montgomery point "
                      "is not supported\n");
            return -1;
        }

        if (x) {
            gcry_mpi_set(x, point->x);
        }

        return 0;
    }

    z = _gcry_mpi_bn(point->z);

    if (BN_is_one(z)) {
        if (x) {
            gcry_mpi_set(x, point->x);
        }

        if (y) {
            if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
                log_error("getting the Y coordinate of a Montgomery point "
                          "is not supported\n");
                return -1;
            }

            gcry_mpi_set(y, point->y);
        }

        return 0;
    }

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY && y) {
        log_error("getting the Y coordinate of a Montgomery point "
                  "is not supported\n");
        return -1;
    }

    bctx = new_bnctx();

    if (!bctx) {
        return -1;
    }

    /* Make sure the outputs are plain numbers before writing into them. */
    if (x) {
        gcry_mpi_set_ui(x, 0);
    }

    if (y) {
        gcry_mpi_set_ui(y, 0);
    }

    p = _gcry_mpi_bn(ec->p);
    BN_CTX_start(bctx);
    zi = BN_CTX_get(bctx);
    t = BN_CTX_get(bctx);
    ok = t && BN_mod_inverse(zi, z, p, bctx);

    if (ok && ec->model == GCRY_ECC_MODEL_WEIERSTRASS) {
        ok = BN_mod_sqr(t, zi, p, bctx);                   /* z^-2 */

        if (ok && x) {
            ok = BN_mod_mul(_gcry_mpi_bn(x), _gcry_mpi_bn(point->x), t, p,
                            bctx);
        }

        if (ok && y) {
            ok = BN_mod_mul(t, t, zi, p, bctx)             /* z^-3 */
                 && BN_mod_mul(_gcry_mpi_bn(y), _gcry_mpi_bn(point->y), t, p,
                               bctx);
        }
    } else if (ok) {
        if (x) {
            ok = BN_mod_mul(_gcry_mpi_bn(x), _gcry_mpi_bn(point->x), zi, p,
                            bctx);
        }

        if (ok && y) {
            ok = BN_mod_mul(_gcry_mpi_bn(y), _gcry_mpi_bn(point->y), zi, p,
                            bctx);
        }
    }

    BN_CTX_end(bctx);
    BN_CTX_free(bctx);

    if (!ok) {
        ERR_clear_error();
        return -1;
    }

    return 0;
}

/*
 * Scalar multiplication on a Montgomery curve.
 *
 * OpenSSL has no point arithmetic for Montgomery curves (its X25519 and
 * X448 functions clamp the scalar, which gcry_mpi_ec_mul must not do).
 * The curve v^2 = u^3 + A u^2 + u is isomorphic to the short Weierstrass
 * curve y^2 = x^3 + a x + b with x = u + A/3, y = v, a = (3 - A^2)/3 and
 * b = (2A^3 - 9A)/27, so points are moved there, multiplied with
 * EC_POINT_mul and moved back.  Only u is kept for Montgomery points;
 * v is recovered as a square root, which fails for points on the
 * quadratic twist (those are not handled).
 */

/* A as a BIGNUM: the curve table stores (A - 2) / 4. */
static BIGNUM *
mont_A(mpi_ec_t ec, BN_CTX *bctx)
{
    BIGNUM *A = BN_CTX_get(bctx);

    if (!A || !BN_copy(A, _gcry_mpi_bn(ec->a)) || !BN_mul_word(A, 4)
        || !BN_add_word(A, 2)) {
        return NULL;
    }

    return A;
}

/* A/3 mod p, the x shift of the isomorphism. */
static BIGNUM *
mont_shift(mpi_ec_t ec, const BIGNUM *A, BN_CTX *bctx)
{
    const BIGNUM *p = _gcry_mpi_bn(ec->p);
    BIGNUM *three = BN_CTX_get(bctx);
    BIGNUM *inv3 = BN_CTX_get(bctx);
    BIGNUM *shift = BN_CTX_get(bctx);

    if (!shift || !BN_set_word(three, 3) || !BN_mod_inverse(inv3, three, p, bctx)
        || !BN_mod_mul(shift, A, inv3, p, bctx)) {
        return NULL;
    }

    return shift;
}

/* v for the u coordinate U: a square root of u^3 + A u^2 + u. */
static BIGNUM *
mont_v(mpi_ec_t ec, const BIGNUM *A, const BIGNUM *u, BN_CTX *bctx)
{
    const BIGNUM *p = _gcry_mpi_bn(ec->p);
    BIGNUM *t = BN_CTX_get(bctx);
    BIGNUM *r = BN_CTX_get(bctx);
    BIGNUM *v = BN_CTX_get(bctx);

    if (!v || !BN_mod_sqr(t, u, p, bctx)                 /* u^2 */
        || !BN_mod_mul(r, t, u, p, bctx)                 /* u^3 */
        || !BN_mod_mul(t, t, A, p, bctx)                 /* A u^2 */
        || !BN_mod_add(r, r, t, p, bctx) || !BN_mod_add(r, r, u, p, bctx)) {
        return NULL;
    }

    return BN_mod_sqrt(v, r, p, bctx) ? v : NULL;
}

static gcry_err_code_t
mont_setup(mpi_ec_t ec, BN_CTX *bctx)
{
    const BIGNUM *p;
    BIGNUM *A;
    BIGNUM *shift;
    BIGNUM *t;
    BIGNUM *a;
    BIGNUM *b;
    BIGNUM *w;
    BIGNUM *inv27;
    BIGNUM *h;
    BIGNUM *gx;
    BIGNUM *gv;
    EC_POINT *G = NULL;
    gcry_err_code_t rc = GPG_ERR_INTERNAL;

    if (ec->mont_group) {
        return 0;
    }

    if (!ec->p || !ec->a || !ec->b || !ec->n || !ec->G
        || !BN_is_one(_gcry_mpi_bn(ec->b))) {
        return GPG_ERR_NOT_IMPLEMENTED;
    }

    p = _gcry_mpi_bn(ec->p);
    BN_CTX_start(bctx);
    A = mont_A(ec, bctx);
    shift = A ? mont_shift(ec, A, bctx) : NULL;
    t = BN_CTX_get(bctx);
    a = BN_CTX_get(bctx);
    b = BN_CTX_get(bctx);
    w = BN_CTX_get(bctx);
    inv27 = BN_CTX_get(bctx);
    h = BN_CTX_get(bctx);
    gx = BN_CTX_get(bctx);

    if (!shift || !gx) {
        goto leave;
    }

    /* a = (3 - A^2) / 3 = 1 - A * shift;  b = A (2 A^2 - 9) / 27 */
    if (!BN_mod_mul(t, A, shift, p, bctx) || !BN_set_word(a, 1)
        || !BN_mod_sub(a, a, t, p, bctx) || !BN_mod_sqr(t, A, p, bctx)
        || !BN_mod_add(t, t, t, p, bctx) || !BN_set_word(w, 9)
        || !BN_mod_sub(t, t, w, p, bctx) || !BN_mod_mul(t, t, A, p, bctx)
        || !BN_set_word(w, 27) || !BN_mod_inverse(inv27, w, p, bctx)
        || !BN_mod_mul(b, t, inv27, p, bctx)) {
        goto leave;
    }

    ec->mont_group = EC_GROUP_new_curve_GFp(p, a, b, bctx);

    if (!ec->mont_group) {
        goto leave;
    }

    /* The generator, with the group order and cofactor. */
    gv = mont_v(ec, A, _gcry_mpi_bn(ec->G->x), bctx);
    G = EC_POINT_new(ec->mont_group);

    if (!gv || !G || !BN_mod_add(gx, _gcry_mpi_bn(ec->G->x), shift, p, bctx)
        || !EC_POINT_set_affine_coordinates(ec->mont_group, G, gx, gv, bctx)
        || !BN_set_word(h, ec->h)
        || !EC_GROUP_set_generator(ec->mont_group, G, _gcry_mpi_bn(ec->n),
                                   h)) {
        EC_GROUP_free(ec->mont_group);
        ec->mont_group = NULL;
        goto leave;
    }

    rc = 0;

leave:
    ERR_clear_error();
    EC_POINT_free(G);
    BN_CTX_end(bctx);
    return rc;
}

/*
 * Fast path: when the scalar already has the clamped form X25519/X448
 * produce and the point is affine, OpenSSL's X25519/X448 compute exactly
 * the u coordinate of [n]P, so the isomorphism path is not needed.
 * Returns 1 and fills W on success, 0 when the generic path must be used
 * (unclamped scalar, odd input, or a low order point for which OpenSSL
 * refuses to produce the all-zero result).
 */
static int
mont_mul_fast(gcry_mpi_point_t w, const BIGNUM *n, gcry_mpi_point_t u,
              mpi_ec_t ec)
{
    unsigned int nbytes = (ec->nbits + 7) / 8;
    unsigned char scalar[56];
    unsigned char ubuf[56];
    unsigned char out[56];
    size_t outlen = nbytes;
    const BIGNUM *ux;
    EVP_PKEY *priv = NULL;
    EVP_PKEY *pub = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ok = 0;

    if ((ec->nbits != 255 && ec->nbits != 448) || BN_is_negative(n)
        || gcry_mpi_cmp_ui(u->z, 1) || mpi_is_opaque(u->x)
        || BN_bn2lebinpad(n, scalar, (int)nbytes) < 0) {
        return 0;
    }

    if (nbytes == 32) {
        if ((scalar[0] & 7) || (scalar[31] & 0x80) || !(scalar[31] & 0x40)) {
            return 0;
        }
    } else if ((scalar[0] & 3) || !(scalar[55] & 0x80)) {
        return 0;
    }

    /* Only a reduced u coordinate: X25519/X448 would mask or reduce
     * anything larger, which the generic path does not. */
    ux = _gcry_mpi_bn(u->x);

    if (BN_is_negative(ux) || BN_ucmp(ux, _gcry_mpi_bn(ec->p)) >= 0
        || BN_bn2lebinpad(ux, ubuf, (int)nbytes) < 0) {
        return 0;
    }

    priv = EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(), mont_keytype(ec),
                                           _gcry_propq(), scalar, nbytes);
    pub = EVP_PKEY_new_raw_public_key_ex(_gcry_libctx(), mont_keytype(ec),
                                         _gcry_propq(), ubuf, nbytes);
    ctx = priv ? EVP_PKEY_CTX_new_from_pkey(_gcry_libctx(), priv,
                                            _gcry_propq())
          : NULL;

    if (priv && pub && ctx && EVP_PKEY_derive_init(ctx) > 0
        && EVP_PKEY_derive_set_peer_ex(ctx, pub, 0) > 0
        && EVP_PKEY_derive(ctx, out, &outlen) > 0 && outlen == nbytes) {
        reverse_buffer(out, nbytes);
        _gcry_mpi_set_buffer(w->x, out, nbytes, 0);
        gcry_mpi_set_ui(w->y, 0);
        gcry_mpi_set_ui(w->z, 1);
        ok = 1;
    }

    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    _gcry_wipememory(scalar, sizeof scalar);
    return ok;
}

static gcry_err_code_t
mont_mul(gcry_mpi_point_t w, gcry_mpi_t n, gcry_mpi_point_t u, mpi_ec_t ec)
{
    BN_CTX *bctx = new_bnctx();
    const BIGNUM *p;
    BIGNUM *A;
    BIGNUM *shift;
    BIGNUM *ux;
    BIGNUM *v;
    BIGNUM *x;
    EC_POINT *P = NULL;
    EC_POINT *R = NULL;
    gcry_mpi_t nnum = NULL;
    gcry_err_code_t rc;

    if (!bctx) {
        return GPG_ERR_ENOMEM;
    }

    /* An opaque scalar is the little endian byte string of X25519/X448
     * secret keys; read it as a number. */
    if (mpi_is_opaque(n)) {
        unsigned char *scalar;
        size_t scalarlen;

        rc = _gcry_ecc_mont_scalar(n, ec->nbits, &scalar, &scalarlen);

        if (rc) {
            BN_CTX_free(bctx);
            return rc;
        }

        reverse_buffer(scalar, scalarlen);
        nnum = gcry_mpi_snew(0);
        _gcry_mpi_set_buffer(nnum, scalar, (unsigned int)scalarlen, 0);
        _gcry_wipememory(scalar, scalarlen);
        _gcry_free(scalar);
        n = nnum;
    }

    if (mont_mul_fast(w, _gcry_mpi_bn(n), u, ec)) {
        gcry_mpi_release(nnum);
        BN_CTX_free(bctx);
        return 0;
    }

    rc = mont_setup(ec, bctx);

    if (rc) {
        gcry_mpi_release(nnum);
        BN_CTX_free(bctx);
        return rc;
    }

    p = _gcry_mpi_bn(ec->p);
    BN_CTX_start(bctx);
    A = mont_A(ec, bctx);
    shift = A ? mont_shift(ec, A, bctx) : NULL;
    ux = BN_CTX_get(bctx);
    x = BN_CTX_get(bctx);
    rc = GPG_ERR_INTERNAL;

    if (!shift || !x || !BN_nnmod(ux, _gcry_mpi_bn(u->x), p, bctx)) {
        goto leave;
    }

    v = mont_v(ec, A, ux, bctx);

    if (!v) {
        rc = GPG_ERR_INV_DATA; /* Not a point of the curve (twist). */
        goto leave;
    }

    P = EC_POINT_new(ec->mont_group);
    R = EC_POINT_new(ec->mont_group);

    if (!P || !R || !BN_mod_add(x, ux, shift, p, bctx)
        || !EC_POINT_set_affine_coordinates(ec->mont_group, P, x, v, bctx)
        || !EC_POINT_mul(ec->mont_group, R, NULL, P, _gcry_mpi_bn(n), bctx)) {
        goto leave;
    }

    if (EC_POINT_is_at_infinity(ec->mont_group, R)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    if (!EC_POINT_get_affine_coordinates(ec->mont_group, R, x, NULL, bctx)
        || !BN_mod_sub(x, x, shift, p, bctx)) {
        goto leave;
    }

    {
        unsigned char buf[80];
        unsigned int nbytes = (ec->nbits + 7) / 8;

        if (nbytes > sizeof buf || BN_bn2binpad(x, buf, (int)nbytes) < 0) {
            goto leave;
        }

        _gcry_mpi_set_buffer(w->x, buf, nbytes, 0);
    }

    gcry_mpi_set_ui(w->y, 0);
    gcry_mpi_set_ui(w->z, 1);
    rc = 0;

leave:
    ERR_clear_error();
    EC_POINT_free(P);
    EC_POINT_free(R);
    BN_CTX_end(bctx);
    BN_CTX_free(bctx);
    gcry_mpi_release(nnum);
    return rc;
}

gcry_err_code_t
_gcry_mpi_ec_mul(gcry_mpi_point_t w, gcry_mpi_t n, gcry_mpi_point_t u,
                 mpi_ec_t ec)
{
    BN_CTX *bctx;
    EC_POINT *P;
    EC_POINT *R;
    gcry_err_code_t rc;

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        return mont_mul(w, n, u, ec);
    }

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS || !ec->group) {
        return GPG_ERR_NOT_IMPLEMENTED;
    }

    /* What the reference library's double-and-add yields for the corner
     * cases: a zero scalar gives (0, 0, 0), the point at infinity stays
     * itself for the scalar one and becomes (0, p, 1) otherwise. */
    if (BN_is_zero(_gcry_mpi_bn(n))) {
        gcry_mpi_set_ui(w->x, 0);
        gcry_mpi_set_ui(w->y, 0);
        gcry_mpi_set_ui(w->z, 0);
        return 0;
    }

    if (BN_is_zero(_gcry_mpi_bn(u->z))) {
        if (BN_is_one(_gcry_mpi_bn(n))) {
            gcry_mpi_set(w->x, u->x);
            gcry_mpi_set(w->y, u->y);
            gcry_mpi_set(w->z, u->z);
        } else {
            gcry_mpi_set_ui(w->x, 0);
            gcry_mpi_set(w->y, ec->p);
            gcry_mpi_set_ui(w->z, 1);
        }

        return 0;
    }

    bctx = new_bnctx();
    P = EC_POINT_new(ec->group);
    R = EC_POINT_new(ec->group);

    if (!bctx || !P || !R) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    rc = point_to_ec(ec, u, P, bctx);

    if (rc) {
        goto leave;
    }

    if (!EC_POINT_mul(ec->group, R, NULL, P, _gcry_mpi_bn(n), bctx)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = ec_to_point(ec, R, w, bctx);

leave:
    EC_POINT_free(P);
    EC_POINT_free(R);
    BN_CTX_free(bctx);
    return rc;
}

/* W = U + V (SUB: W = U - V; DUP: W = 2U, V unused). */
static gcry_err_code_t
weierstrass_addsub(gcry_mpi_point_t w, gcry_mpi_point_t u,
                   gcry_mpi_point_t v, mpi_ec_t ec, int op)
{
    BN_CTX *bctx;
    EC_POINT *P = NULL;
    EC_POINT *Qp = NULL;
    EC_POINT *R = NULL;
    gcry_err_code_t rc;
    int ok;

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS || !ec->group) {
        return GPG_ERR_NOT_IMPLEMENTED;
    }

    bctx = new_bnctx();
    P = EC_POINT_new(ec->group);
    R = EC_POINT_new(ec->group);

    if (op != 'd') {
        Qp = EC_POINT_new(ec->group);
    }

    if (!bctx || !P || !R || (op != 'd' && !Qp)) {
        rc = GPG_ERR_ENOMEM;
        goto leave;
    }

    rc = point_to_ec(ec, u, P, bctx);

    if (!rc && op != 'd') {
        rc = point_to_ec(ec, v, Qp, bctx);
    }

    if (rc) {
        goto leave;
    }

    if (op == 'd') {
        ok = EC_POINT_dbl(ec->group, R, P, bctx);
    } else if (op == 's') {
        ok = EC_POINT_invert(ec->group, Qp, bctx)
             && EC_POINT_add(ec->group, R, P, Qp, bctx);
    } else {
        ok = EC_POINT_add(ec->group, R, P, Qp, bctx);
    }

    if (!ok) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    rc = ec_to_point(ec, R, w, bctx);

leave:
    EC_POINT_free(P);
    EC_POINT_free(Qp);
    EC_POINT_free(R);
    BN_CTX_free(bctx);
    return rc;
}

static void
report_unsupported(const char *what, mpi_ec_t ec, gcry_mpi_point_t w)
{
    log_error("%s is not implemented for %s curves\n", what,
              ec->model == GCRY_ECC_MODEL_EDWARDS ? "Edwards" : "Montgomery");
    point_set_infinity(w);
}

int
_gcry_mpi_ec_on_curve(gcry_mpi_point_t point, mpi_ec_t ec)
{
    BN_CTX *bctx;
    const BIGNUM *p = _gcry_mpi_bn(ec->p);
    gcry_mpi_t x;
    gcry_mpi_t y;
    int res = 0;

    if (BN_ucmp(_gcry_mpi_bn(point->x), p) >= 0
        || BN_ucmp(_gcry_mpi_bn(point->y), p) >= 0
        || BN_ucmp(_gcry_mpi_bn(point->z), p) >= 0
        || BN_is_zero(_gcry_mpi_bn(point->z))) {
        return 0;
    }

    if (ec->model == GCRY_ECC_MODEL_WEIERSTRASS) {
        EC_POINT *P;

        if (!ec->group) {
            return 0;
        }

        bctx = new_bnctx();
        P = EC_POINT_new(ec->group);

        if (bctx && P && !point_to_ec(ec, point, P, bctx)) {
            res = EC_POINT_is_on_curve(ec->group, P, bctx) == 1;
        }

        ERR_clear_error();
        EC_POINT_free(P);
        BN_CTX_free(bctx);
        return res;
    }

    bctx = new_bnctx();
    x = gcry_mpi_new(0);
    y = gcry_mpi_new(0);

    if (bctx && !_gcry_mpi_ec_affine(x, ec->model == GCRY_ECC_MODEL_EDWARDS
                                     ? y : NULL, point, ec)) {
        BIGNUM *w;
        BIGNUM *t;
        BIGNUM *e;
        int ok;

        BN_CTX_start(bctx);
        w = BN_CTX_get(bctx);
        t = BN_CTX_get(bctx);
        e = BN_CTX_get(bctx);

        if (e && ec->model == GCRY_ECC_MODEL_EDWARDS) {
            /* a x^2 + y^2 == 1 + d x^2 y^2 */
            ok = BN_mod_sqr(t, _gcry_mpi_bn(x), p, bctx)
                 && BN_mod_sqr(e, _gcry_mpi_bn(y), p, bctx)
                 && BN_mod_mul(w, _gcry_mpi_bn(ec->a), t, p, bctx)
                 && BN_mod_add(w, w, e, p, bctx)
                 && BN_mod_mul(t, t, e, p, bctx)
                 && BN_mod_mul(t, t, _gcry_mpi_bn(ec->b), p, bctx)
                 && BN_mod_sub(w, w, t, p, bctx);
            res = ok && BN_is_one(w);
        } else if (e) {
            /* Euler's criterion on B (x^3 + A x^2 + x).  The table keeps
             * (A - 2) / 4 for Montgomery curves, so A = 4a + 2. */
            ok = BN_copy(e, _gcry_mpi_bn(ec->a)) && BN_mul_word(e, 4)
                 && BN_add_word(e, 2)
                 && BN_mod_sqr(t, _gcry_mpi_bn(x), p, bctx)          /* x^2 */
                 && BN_mod_mul(w, e, _gcry_mpi_bn(x), p, bctx)       /* A x */
                 && BN_mod_add(w, w, t, p, bctx)                     /* + x^2 */
                 && BN_mod_add(w, w, BN_value_one(), p, bctx)        /* + 1 */
                 && BN_mod_mul(w, w, _gcry_mpi_bn(x), p, bctx)       /* * x */
                 && BN_mod_mul(w, w, _gcry_mpi_bn(ec->b), p, bctx)
                 && BN_copy(e, p) && BN_sub_word(e, 1) && BN_rshift1(e, e)
                 && BN_mod_exp(w, w, e, p, bctx);
            res = ok && BN_is_one(w);
        }

        BN_CTX_end(bctx);
    }

    ERR_clear_error();
    gcry_mpi_release(x);
    gcry_mpi_release(y);
    BN_CTX_free(bctx);
    return res;
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

/* Set Q from a raw public key as OpenSSL returns it. */
static gcry_err_code_t
set_q_from_raw(mpi_ec_t ec, const unsigned char *pub, size_t publen)
{
    gcry_mpi_t enc = gcry_mpi_set_opaque_copy(NULL, pub, (unsigned int)publen * 8);
    gcry_err_code_t rc;

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

/* Compute Q = public key of D and store it in EC. */
gcry_err_code_t
_gcry_ecc_compute_public(mpi_ec_t ec)
{
    gcry_err_code_t rc;

    if (!ec->d || !ec->G || !ec->p || !ec->a) {
        return GPG_ERR_NO_SECKEY;
    }

    if (ec->model == GCRY_ECC_MODEL_WEIERSTRASS) {
        gcry_mpi_point_t Q = gcry_mpi_point_new(0);

        rc = _gcry_mpi_ec_mul(Q, ec->d, ec->G, ec);

        if (rc) {
            gcry_mpi_point_release(Q);
            return rc;
        }

        gcry_mpi_point_release(ec->Q);
        ec->Q = Q;
        return 0;
    }

    if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        /* Exact scalar multiplication: the secret is used as stored, the
         * caller (or the key generator) is responsible for clamping.  An
         * opaque secret holds the little endian byte string. */
        gcry_mpi_point_t Q = gcry_mpi_point_new(0);

        rc = _gcry_mpi_ec_mul(Q, ec->d, ec->G, ec);

        if (rc) {
            gcry_mpi_point_release(Q);
            return rc;
        }

        gcry_mpi_point_release(ec->Q);
        ec->Q = Q;
        return 0;
    }

    if (is_eddsa_ctx(ec)) {
        EVP_PKEY *key = _gcry_ecc_evp_key(ec, 1, &rc);
        unsigned char pub[64];
        size_t publen = sizeof pub;

        if (!key) {
            return rc;
        }

        if (!EVP_PKEY_get_raw_public_key(key, pub, &publen)) {
            EVP_PKEY_free(key);
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        EVP_PKEY_free(key);
        return set_q_from_raw(ec, pub, publen);
    }

    return GPG_ERR_NOT_IMPLEMENTED;
}

/* Build an OpenSSL key object for EC. */
EVP_PKEY *
_gcry_ecc_evp_key(mpi_ec_t ec, int want_private, gcry_err_code_t *r_rc)
{
    EVP_PKEY *key = NULL;
    gcry_err_code_t rc = 0;

    if (want_private && !ec->d) {
        *r_rc = GPG_ERR_NO_SECKEY;
        return NULL;
    }

    if (ec->model == GCRY_ECC_MODEL_WEIERSTRASS) {
        BN_CTX *bctx = new_bnctx();
        OSSL_PARAM *grp = NULL;
        OSSL_PARAM *keyp = NULL;
        OSSL_PARAM *merged = NULL;
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        EVP_PKEY_CTX *pctx = NULL;
        EC_POINT *P = NULL;
        unsigned char *pub = NULL;
        size_t publen = 0;
        int selection = want_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;

        if (!ec->group || !bctx || !bld) {
            rc = GPG_ERR_ENOMEM;
            goto wleave;
        }

        /* OpenSSL's EVP layer only handles named curves. */
        if (EC_GROUP_get_curve_name(ec->group) == NID_undef) {
            rc = GPG_ERR_NOT_SUPPORTED;
            goto wleave;
        }

        if (!ec->Q && ec->d) {
            rc = _gcry_ecc_compute_public(ec);

            if (rc) {
                goto wleave;
            }
        }

        if (!ec->Q && !want_private) {
            rc = GPG_ERR_NO_PUBKEY;
            goto wleave;
        }

        grp = EC_GROUP_to_params(ec->group, _gcry_libctx(), _gcry_propq(),
                                 bctx);

        if (!grp) {
            rc = _gcry_err_from_openssl(GPG_ERR_INV_CURVE);
            goto wleave;
        }

        if (ec->Q) {
            P = EC_POINT_new(ec->group);

            if (!P || (rc = point_to_ec(ec, ec->Q, P, bctx)) != 0) {
                rc = rc ? rc : GPG_ERR_ENOMEM;
                goto wleave;
            }

            publen = EC_POINT_point2oct(ec->group, P,
                                        POINT_CONVERSION_UNCOMPRESSED, NULL, 0,
                                        bctx);
            pub = _gcry_malloc(publen ? publen : 1);

            if (!publen || !pub
                || !EC_POINT_point2oct(ec->group, P,
                                       POINT_CONVERSION_UNCOMPRESSED, pub,
                                       publen, bctx)
                || !OSSL_PARAM_BLD_push_octet_string(bld,
                                                     OSSL_PKEY_PARAM_PUB_KEY, pub, publen)) {
                rc = GPG_ERR_INTERNAL;
                goto wleave;
            }
        }

        if (want_private
            && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                       _gcry_mpi_bn(ec->d))) {
            rc = GPG_ERR_INTERNAL;
            goto wleave;
        }

        keyp = OSSL_PARAM_BLD_to_param(bld);
        merged = keyp ? OSSL_PARAM_merge(grp, keyp) : NULL;
        pctx = EVP_PKEY_CTX_new_from_name(_gcry_libctx(), "EC", _gcry_propq());

        if (!merged || !pctx || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &key, selection, merged) <= 0) {
            rc = _gcry_err_from_openssl(GPG_ERR_BAD_PUBKEY);
            key = NULL;
        }

wleave:
        ERR_clear_error();
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(merged);
        OSSL_PARAM_free(keyp);
        OSSL_PARAM_free(grp);
        OSSL_PARAM_BLD_free(bld);
        EC_POINT_free(P);
        _gcry_free(pub);
        BN_CTX_free(bctx);
    } else if (ec->model == GCRY_ECC_MODEL_EDWARDS) {
        if (!is_eddsa_ctx(ec)) {
            rc = GPG_ERR_NOT_IMPLEMENTED;
        } else if (want_private) {
            unsigned char *seed;
            size_t seedlen;

            rc = _gcry_ecc_eddsa_seed(ec, &seed, &seedlen);

            if (!rc) {
                key = EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(),
                                                      edwards_keytype(ec), _gcry_propq(), seed, seedlen);
                _gcry_wipememory(seed, seedlen);
                _gcry_free(seed);

                if (!key) {
                    rc = _gcry_err_from_openssl(GPG_ERR_BAD_SECKEY);
                }
            }
        } else {
            unsigned char *pub = NULL;
            unsigned int publen = 0;

            if (!ec->Q) {
                rc = GPG_ERR_NO_PUBKEY;
            } else {
                rc = _gcry_ecc_eddsa_encodepoint(ec->Q, ec, 0, &pub, &publen);
            }

            if (!rc) {
                key = EVP_PKEY_new_raw_public_key_ex(_gcry_libctx(),
                                                     edwards_keytype(ec), _gcry_propq(), pub, publen);
                _gcry_free(pub);

                if (!key) {
                    rc = _gcry_err_from_openssl(GPG_ERR_BAD_PUBKEY);
                }
            }
        }
    } else {
        unsigned int nbytes = (ec->nbits + 7) / 8;

        if (want_private) {
            unsigned char *scalar;
            size_t scalarlen;

            rc = _gcry_ecc_mont_scalar(ec->d, ec->nbits, &scalar, &scalarlen);

            if (!rc) {
                key = EVP_PKEY_new_raw_private_key_ex(_gcry_libctx(),
                                                      mont_keytype(ec), _gcry_propq(), scalar, scalarlen);
                _gcry_wipememory(scalar, scalarlen);
                _gcry_free(scalar);

                if (!key) {
                    rc = _gcry_err_from_openssl(GPG_ERR_BAD_SECKEY);
                }
            }
        } else if (!ec->Q) {
            rc = GPG_ERR_NO_PUBKEY;
        } else {
            unsigned char *u = _gcry_malloc(nbytes);

            if (!u) {
                rc = GPG_ERR_ENOMEM;
            } else {
                gcry_mpi_t ux = gcry_mpi_new(0);

                if (_gcry_mpi_ec_affine(ux, NULL, ec->Q, ec)
                    || _gcry_ecc_mont_decode_u(ux, ec->nbits, u)) {
                    rc = GPG_ERR_INV_OBJ;
                } else {
                    key = EVP_PKEY_new_raw_public_key_ex(_gcry_libctx(),
                                                         mont_keytype(ec), _gcry_propq(), u, nbytes);

                    if (!key) {
                        rc = _gcry_err_from_openssl(GPG_ERR_BAD_PUBKEY);
                    }
                }

                gcry_mpi_release(ux);
                _gcry_free(u);
            }
        }
    }

    *r_rc = key ? 0 : (rc ? rc : GPG_ERR_INTERNAL);
    return key;
}

/* Encoded public key of EC as an opaque MPI, in the encoding the curve
 * model uses in S-expressions. */
static gcry_mpi_t
encoded_q(mpi_ec_t ec)
{
    unsigned char *enc = NULL;
    unsigned int enclen = 0;
    gcry_err_code_t rc;

    if (!ec->Q) {
        return NULL;
    }

    if (ec->dialect == GCRY_ECC_DIALECT_ED25519
        || (ec->model == GCRY_ECC_MODEL_EDWARDS
            && ec->dialect == GCRY_ECC_DIALECT_SAFECURVE)) {
        rc = _gcry_ecc_eddsa_encodepoint(ec->Q, ec, 0, &enc, &enclen);
    } else if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
        gcry_mpi_t x = gcry_mpi_new(0);

        if (_gcry_mpi_ec_affine(x, NULL, ec->Q, ec)) {
            rc = GPG_ERR_INV_OBJ;
        } else {
            rc = _gcry_ecc_mont_encodepoint(x, ec->nbits,
                                            ec->dialect
                                            != GCRY_ECC_DIALECT_SAFECURVE,
                                            &enc, &enclen);
        }

        gcry_mpi_release(x);
    } else {
        return _gcry_mpi_ec_ec2os(ec->Q, ec);
    }

    if (rc) {
        return NULL;
    }

    return gcry_mpi_set_opaque(NULL, enc, enclen * 8);
}

gcry_err_code_t
_gcry_pk_ecc_get_sexp(gcry_sexp_t *r_sexp, int mode, mpi_ec_t ec)
{
    gcry_err_code_t rc;
    gcry_mpi_t mpi_G = NULL;
    gcry_mpi_t mpi_Q = NULL;

    if (!ec->p || !ec->a || !ec->b || !ec->G || !ec->n) {
        return GPG_ERR_BAD_CRYPT_CTX;
    }

    if (mode == GCRY_PK_GET_SECKEY && !ec->d) {
        return GPG_ERR_NO_SECKEY;
    }

    if (!ec->Q && ec->d) {
        rc = _gcry_ecc_compute_public(ec);

        if (rc) {
            return rc;
        }
    }

    mpi_G = _gcry_mpi_ec_ec2os(ec->G, ec);

    if (!mpi_G) {
        return GPG_ERR_BROKEN_PUBKEY;
    }

    if (!ec->Q) {
        rc = GPG_ERR_BAD_CRYPT_CTX;
        goto leave;
    }

    mpi_Q = encoded_q(ec);

    if (!mpi_Q) {
        rc = GPG_ERR_BROKEN_PUBKEY;
        goto leave;
    }

    if (ec->d && (!mode || mode == GCRY_PK_GET_SECKEY)) {
        rc = _gcry_sexp_build(r_sexp, NULL,
                              "(private-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)"
                              "(h%u)(q%m)(d%m)))",
                              ec->p, ec->a, ec->b, mpi_G, ec->n, ec->h, mpi_Q,
                              ec->d);
    } else {
        rc = _gcry_sexp_build(r_sexp, NULL,
                              "(public-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)"
                              "(h%u)(q%m)))",
                              ec->p, ec->a, ec->b, mpi_G, ec->n, ec->h,
                              mpi_Q);
    }

leave:
    gcry_mpi_release(mpi_G);
    gcry_mpi_release(mpi_Q);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

static void
ec_ctx_deinit(void *payload)
{
    mpi_ec_t *slot = payload;

    _gcry_mpi_ec_free(*slot);
    *slot = NULL;
}

mpi_ec_t
_gcry_ctx_get_ec(gcry_ctx_t ctx)
{
    mpi_ec_t *slot = _gcry_ctx_find_pointer(ctx, GCRY_CTX_TYPE_EC);

    return slot ? *slot : NULL;
}

/* The EC context behind CTX for the void arithmetic functions, which
 * have no way to report an error.  A missing operand (OPERANDS_OK is
 * zero) or a missing or foreign context is fatal: silently leaving the
 * result untouched would corrupt the caller's computation.  FUNC names
 * the calling function for the message. */
static mpi_ec_t
arith_context(const char *func, gcry_ctx_t ctx, int operands_ok)
{
    mpi_ec_t ec = operands_ok && ctx ? _gcry_ctx_get_ec(ctx) : NULL;

    if (!ec) {
        char msg[64];

        snprintf(msg, sizeof msg, "%s: %s", func,
                 operands_ok && ctx ? "not an EC context" : "NULL argument");
        _gcry_fatal_error(GPG_ERR_INV_ARG, msg);
    }

    return ec;
}

gpg_error_t
gcry_mpi_ec_new(gcry_ctx_t *r_ctx, gcry_sexp_t keyparam,
                const char *curvename)
{
    mpi_ec_t ec = NULL;
    gcry_ctx_t ctx;
    int flags = 0;
    gcry_err_code_t rc;

    if (!r_ctx) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *r_ctx = NULL;
    rc = _gcry_mpi_ec_internal_new(&ec, &flags, keyparam, curvename);

    if (rc) {
        return GCRY_ERR(rc);
    }

    ctx = _gcry_ctx_alloc(GCRY_CTX_TYPE_EC, sizeof(mpi_ec_t), ec_ctx_deinit);

    if (!ctx) {
        _gcry_mpi_ec_free(ec);
        return GCRY_ERR(GPG_ERR_ENOMEM);
    }

    *(mpi_ec_t *)_gcry_ctx_get_pointer(ctx, GCRY_CTX_TYPE_EC) = ec;
    *r_ctx = ctx;
    return 0;
}

gcry_mpi_t
gcry_mpi_ec_get_mpi(const char *name, gcry_ctx_t ctx, int copy)
{
    mpi_ec_t ec = _gcry_ctx_get_ec(ctx);
    gcry_mpi_t v = NULL;

    if (!ec || !name || !*name) {
        return NULL;
    }

    if (!strcmp(name, "p")) {
        v = ec->p;
    } else if (!strcmp(name, "a")) {
        v = ec->a;
    } else if (!strcmp(name, "b")) {
        v = ec->b;
    } else if (!strcmp(name, "n")) {
        v = ec->n;
    } else if (!strcmp(name, "d")) {
        v = ec->d;
    } else if (!strcmp(name, "g.x")) {
        v = ec->G ? ec->G->x : NULL;
    } else if (!strcmp(name, "g.y")) {
        v = ec->G ? ec->G->y : NULL;
    } else if (!strcmp(name, "q.x") || !strcmp(name, "q.y")) {
        if (!ec->Q && ec->d) {
            _gcry_ecc_compute_public(ec);
        }

        v = ec->Q ? (name[2] == 'x' ? ec->Q->x : ec->Q->y) : NULL;
    } else if (!strcmp(name, "h")) {
        if (!copy && ec->h >= 1 && ec->h <= 8
            && (ec->h == 1 || ec->h == 2 || ec->h == 3 || ec->h == 4
                || ec->h == 8)) {
            return _gcry_mpi_get_const((int)ec->h);
        }

        return gcry_mpi_set_ui(NULL, ec->h);
    } else if (!strcmp(name, "g")) {
        return ec->G ? _gcry_mpi_ec_ec2os(ec->G, ec) : NULL;
    } else if (*name == 'q' && (!name[1] || name[1] == '@')) {
        if (!ec->Q && ec->d) {
            _gcry_ecc_compute_public(ec);
        }

        if (!ec->Q) {
            return NULL;
        }

        if (name[1] != '@') {
            if (ec->model == GCRY_ECC_MODEL_MONTGOMERY) {
                return encoded_q(ec);
            }

            return _gcry_mpi_ec_ec2os(ec->Q, ec);
        }

        if (!strcmp(name + 2, "eddsa") && ec->model == GCRY_ECC_MODEL_EDWARDS) {
            unsigned char *enc;
            unsigned int enclen;

            if (!_gcry_ecc_eddsa_encodepoint(ec->Q, ec, 0, &enc, &enclen)) {
                return gcry_mpi_set_opaque(NULL, enc, enclen * 8);
            }
        }

        return NULL;
    }

    if (!v) {
        return NULL;
    }

    return copy ? gcry_mpi_copy(v) : v;
}

gcry_mpi_point_t
gcry_mpi_ec_get_point(const char *name, gcry_ctx_t ctx, int copy)
{
    mpi_ec_t ec = _gcry_ctx_get_ec(ctx);

    (void)copy;

    if (!ec || !name) {
        return NULL;
    }

    if (!strcmp(name, "g") && ec->G) {
        return gcry_mpi_point_copy(ec->G);
    }

    if (!strcmp(name, "q")) {
        if (!ec->Q && ec->d) {
            _gcry_ecc_compute_public(ec);
        }

        if (ec->Q) {
            return gcry_mpi_point_copy(ec->Q);
        }
    }

    return NULL;
}

gpg_error_t
gcry_mpi_ec_set_mpi(const char *name, gcry_mpi_t newvalue, gcry_ctx_t ctx)
{
    mpi_ec_t ec = _gcry_ctx_get_ec(ctx);
    gcry_err_code_t rc = 0;

    if (!ec || !name) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (!*name) {
        ;
    } else if (!strcmp(name, "p") || !strcmp(name, "a") || !strcmp(name, "b")
               || !strcmp(name, "n")) {
        gcry_mpi_t *slot = !strcmp(name, "p") ? &ec->p
                           : !strcmp(name, "a") ? &ec->a
                           : !strcmp(name, "b") ? &ec->b : &ec->n;

        /* The curve parameters are numbers the rest of the context
         * dereferences; they can be replaced but not removed. */
        if (!newvalue || mpi_is_opaque(newvalue)) {
            return GCRY_ERR(GPG_ERR_INV_ARG);
        }

        gcry_mpi_release(*slot);
        *slot = gcry_mpi_copy(newvalue);

        /* The curve changed: drop the OpenSSL group so that it is rebuilt
         * from the explicit parameters next time. */
        EC_GROUP_free(ec->group);
        ec->group = NULL;
        ec->curve = NULL;
        ec->name = NULL;
        rc = setup_group(ec);
    } else if (!strcmp(name, "h")) {
        if (newvalue) {
            gcry_mpi_get_ui(&ec->h, newvalue);
        }
    } else if (*name == 'q' && (!name[1] || name[1] == '@')) {
        if (newvalue) {
            if (!ec->Q) {
                ec->Q = gcry_mpi_point_new(0);
            }

            rc = _gcry_ecc_decode_point(ec->Q, newvalue, ec);
        }

        if (rc || !newvalue) {
            gcry_mpi_point_release(ec->Q);
            ec->Q = NULL;
        }
    } else if (!strcmp(name, "d")) {
        if (newvalue && mpi_is_opaque(newvalue)) {
            return GCRY_ERR(GPG_ERR_INV_ARG); /* A secret scalar is a number. */
        }

        gcry_mpi_release(ec->d);
        ec->d = gcry_mpi_copy(newvalue);

        if (ec->d) {
            gcry_mpi_point_release(ec->Q);
            ec->Q = NULL;
        }
    } else {
        rc = GPG_ERR_UNKNOWN_NAME;
    }

    return GCRY_ERR(rc);
}

gpg_error_t
gcry_mpi_ec_set_point(const char *name, gcry_mpi_point_t newvalue,
                      gcry_ctx_t ctx)
{
    mpi_ec_t ec = _gcry_ctx_get_ec(ctx);

    if (!ec || !name) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (!strcmp(name, "g")) {
        gcry_mpi_point_release(ec->G);
        ec->G = gcry_mpi_point_copy(newvalue);
    } else if (!strcmp(name, "q")) {
        gcry_mpi_point_release(ec->Q);
        ec->Q = gcry_mpi_point_copy(newvalue);
    } else {
        return GCRY_ERR(GPG_ERR_UNKNOWN_NAME);
    }

    return 0;
}

gpg_error_t
gcry_mpi_ec_decode_point(gcry_mpi_point_t result, gcry_mpi_t value,
                         gcry_ctx_t ctx)
{
    mpi_ec_t ec = ctx ? _gcry_ctx_get_ec(ctx) : NULL;

    if (!result || !value) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(_gcry_ecc_decode_point(result, value, ec));
}

int
gcry_mpi_ec_get_affine(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_point_t point,
                       gcry_ctx_t ctx)
{
    mpi_ec_t ec = _gcry_ctx_get_ec(ctx);

    if (!ec) {
        return -1;
    }

    return _gcry_mpi_ec_affine(x, y, point, ec);
}

void
gcry_mpi_ec_dup(gcry_mpi_point_t w, gcry_mpi_point_t u, gcry_ctx_t ctx)
{
    mpi_ec_t ec = arith_context("gcry_mpi_ec_dup", ctx, w && u);

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS) {
        report_unsupported("point doubling", ec, w);
        return;
    }

    if (weierstrass_addsub(w, u, NULL, ec, 'd')) {
        point_set_infinity(w);
    }
}

void
gcry_mpi_ec_add(gcry_mpi_point_t w, gcry_mpi_point_t u, gcry_mpi_point_t v,
                gcry_ctx_t ctx)
{
    mpi_ec_t ec = arith_context("gcry_mpi_ec_add", ctx, w && u && v);

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS) {
        report_unsupported("point addition", ec, w);
        return;
    }

    if (weierstrass_addsub(w, u, v, ec, 'a')) {
        point_set_infinity(w);
    }
}

void
gcry_mpi_ec_sub(gcry_mpi_point_t w, gcry_mpi_point_t u, gcry_mpi_point_t v,
                gcry_ctx_t ctx)
{
    mpi_ec_t ec = arith_context("gcry_mpi_ec_sub", ctx, w && u && v);

    if (ec->model != GCRY_ECC_MODEL_WEIERSTRASS) {
        report_unsupported("point subtraction", ec, w);
        return;
    }

    if (weierstrass_addsub(w, u, v, ec, 's')) {
        point_set_infinity(w);
    }
}

void
gcry_mpi_ec_mul(gcry_mpi_point_t w, gcry_mpi_t n, gcry_mpi_point_t u,
                gcry_ctx_t ctx)
{
    mpi_ec_t ec = arith_context("gcry_mpi_ec_mul", ctx, w && n && u);

    if (mpi_is_opaque(n)) {
        _gcry_fatal_error(GPG_ERR_INV_ARG, "gcry_mpi_ec_mul: opaque scalar");
    }

    if (ec->model == GCRY_ECC_MODEL_EDWARDS) {
        report_unsupported("scalar multiplication", ec, w);
        return;
    }

    if (_gcry_mpi_ec_mul(w, n, u, ec)) {
        point_set_infinity(w);
    }
}

int
gcry_mpi_ec_curve_point(gcry_mpi_point_t w, gcry_ctx_t ctx)
{
    mpi_ec_t ec = _gcry_ctx_get_ec(ctx);

    if (!ec || !w) {
        return 0;
    }

    return _gcry_mpi_ec_on_curve(w, ec);
}

void
_gcry_log_printpnt(const char *text, gcry_mpi_point_t point, gcry_ctx_t ctx)
{
    mpi_ec_t ec = ctx ? _gcry_ctx_get_ec(ctx) : NULL;

    if (text && *text) {
        _gcry_log(GCRY_LOG_DEBUG, "%s:\n", text);
    }

    if (!point) {
        _gcry_log(GCRY_LOG_DEBUG, "  (null)\n");
        return;
    }

    if (ec) {
        gcry_mpi_t x = gcry_mpi_new(0);
        gcry_mpi_t y = gcry_mpi_new(0);

        if (!_gcry_mpi_ec_affine(x, ec->model == GCRY_ECC_MODEL_MONTGOMERY
                                 ? NULL : y, point, ec)) {
            gcry_log_debugmpi("  x", x);

            if (ec->model != GCRY_ECC_MODEL_MONTGOMERY) {
                gcry_log_debugmpi("  y", y);
            }

            gcry_mpi_release(x);
            gcry_mpi_release(y);
            return;
        }

        gcry_mpi_release(x);
        gcry_mpi_release(y);
    }

    gcry_log_debugmpi("  x", point->x);
    gcry_log_debugmpi("  y", point->y);
    gcry_log_debugmpi("  z", point->z);
}
