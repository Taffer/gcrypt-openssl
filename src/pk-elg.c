/*
 * pk-elg.c - ElGamal.
 *
 * OpenSSL has no ElGamal implementation.  The textbook scheme is a thin
 * composition of modular exponentiations, so it is expressed here directly
 * on BIGNUMs (via the MPI layer): this file is the one place in the
 * library that does more than hand data to an OpenSSL primitive.  Prime
 * generation and the random numbers still come from OpenSSL.
 */
#include "gcrypt-int.h"

#include <stdlib.h>
#include <string.h>

static const char *const elg_names[] = {
    "elg", "openpgp-elg", "openpgp-elg-sig", NULL
};

static unsigned int
elg_get_nbits(gcry_sexp_t parms)
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

/* A random k with 0 < k < p-1, and gcd(k, p-1) = 1 when COPRIME. */
static gcry_err_code_t
gen_k(gcry_mpi_t p, int coprime, gcry_mpi_t *r_k)
{
    gcry_mpi_t k = gcry_mpi_snew(0);
    gcry_mpi_t p_1 = gcry_mpi_new(0);
    gcry_mpi_t g = gcry_mpi_new(0);
    BN_CTX *bctx = BN_CTX_new_ex(_gcry_libctx());
    gcry_err_code_t rc = 0;

    gcry_mpi_sub_ui(p_1, p, 1);

    for (;;) {
        if (!bctx || !BN_priv_rand_range_ex(_gcry_mpi_bn(k), _gcry_mpi_bn(p_1),
                                            0, bctx)) {
            rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
            break;
        }

        if (gcry_mpi_cmp_ui(k, 0) <= 0) {
            continue;
        }

        if (!coprime || gcry_mpi_gcd(g, k, p_1)) {
            break;
        }
    }

    BN_CTX_free(bctx);
    gcry_mpi_release(p_1);
    gcry_mpi_release(g);

    if (rc) {
        gcry_mpi_release(k);
        k = NULL;
    }

    *r_k = k;
    return rc;
}

static gcry_err_code_t
elg_encrypt(gcry_sexp_t *r_ciph, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_mpi_t p = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t k = NULL;
    gcry_mpi_t a = NULL;
    gcry_mpi_t b = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_ENCRYPT, elg_get_nbits(keyparms));
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding != PUBKEY_ENC_RAW) {
        rc = GPG_ERR_NOT_IMPLEMENTED; /* No PKCS#1/OAEP for ElGamal here. */
        goto leave;
    }

    if (!pd.mpi || mpi_is_opaque(pd.mpi)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pgy", &p, &g, &y, NULL);

    if (rc) {
        goto leave;
    }

    rc = gen_k(p, 0, &k);

    if (rc) {
        goto leave;
    }

    a = gcry_mpi_new(0);
    b = gcry_mpi_new(0);
    gcry_mpi_powm(a, g, k, p);
    gcry_mpi_powm(b, y, k, p);
    gcry_mpi_mulm(b, b, pd.mpi, p);
    rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(elg(a%m)(b%m)))", a, b);

leave:
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(k);
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
elg_decrypt(gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t data_a = NULL;
    gcry_mpi_t data_b = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t plain = NULL;
    gcry_mpi_t t = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_DECRYPT, elg_get_nbits(keyparms));
    rc = _gcry_pk_util_preparse_encval(s_data, elg_names, &l1, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding != PUBKEY_ENC_UNKNOWN && pd.encoding != PUBKEY_ENC_RAW) {
        rc = GPG_ERR_NOT_IMPLEMENTED;
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL, "ab", &data_a, &data_b, NULL);

    if (rc) {
        goto leave;
    }

    if (mpi_is_opaque(data_a) || mpi_is_opaque(data_b)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pgyx", &p, &g, &y, &x,
                                  NULL);

    if (rc) {
        goto leave;
    }

    plain = gcry_mpi_snew(0);
    t = gcry_mpi_snew(0);
    gcry_mpi_powm(t, data_a, x, p);

    if (!gcry_mpi_invm(t, t, p)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    gcry_mpi_mulm(plain, data_b, t, p);
    rc = _gcry_sexp_build(r_plain, NULL,
                          (pd.flags & PUBKEY_FLAG_LEGACYRESULT) ? "%m"
                          : "(value %m)", plain);

leave:
    gcry_mpi_release(plain);
    gcry_mpi_release(t);
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    gcry_mpi_release(data_a);
    gcry_mpi_release(data_b);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
elg_sign(gcry_sexp_t *r_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_mpi_t p = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t k = NULL;
    gcry_mpi_t a = NULL;
    gcry_mpi_t b = NULL;
    gcry_mpi_t t = NULL;
    gcry_mpi_t inv = NULL;
    gcry_mpi_t p_1 = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_SIGN, elg_get_nbits(keyparms));
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (!pd.mpi || mpi_is_opaque(pd.mpi)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pgyx", &p, &g, &y, &x,
                                  NULL);

    if (rc) {
        goto leave;
    }

    rc = gen_k(p, 1, &k);

    if (rc) {
        goto leave;
    }

    a = gcry_mpi_new(0);
    b = gcry_mpi_new(0);
    t = gcry_mpi_snew(0);
    inv = gcry_mpi_snew(0);
    p_1 = gcry_mpi_new(0);
    gcry_mpi_sub_ui(p_1, p, 1);
    gcry_mpi_powm(a, g, k, p);          /* a = g^k mod p */
    gcry_mpi_mul(t, x, a);
    gcry_mpi_subm(t, pd.mpi, t, p_1);   /* t = m - x*a mod (p-1) */
    gcry_mpi_invm(inv, k, p_1);
    gcry_mpi_mulm(b, t, inv, p_1);      /* b = t * k^-1 mod (p-1) */
    rc = _gcry_sexp_build(r_sig, NULL, "(sig-val(elg(r%M)(s%M)))", a, b);

leave:
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(t);
    gcry_mpi_release(inv);
    gcry_mpi_release(p_1);
    gcry_mpi_release(k);
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
elg_verify(gcry_sexp_t s_sig, gcry_sexp_t s_data, gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    struct pk_data pd;
    gcry_sexp_t l1 = NULL;
    gcry_mpi_t sig_a = NULL;
    gcry_mpi_t sig_b = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t t1 = NULL;
    gcry_mpi_t t2 = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_VERIFY, elg_get_nbits(keyparms));
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (!pd.mpi || mpi_is_opaque(pd.mpi)) {
        rc = GPG_ERR_INV_DATA;
        goto leave;
    }

    rc = _gcry_pk_util_preparse_sigval(s_sig, elg_names, &l1, NULL);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_extract_param(l1, NULL, "rs", &sig_a, &sig_b, NULL);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pgy", &p, &g, &y, NULL);

    if (rc) {
        goto leave;
    }

    if (gcry_mpi_cmp_ui(sig_a, 0) <= 0 || gcry_mpi_cmp(sig_a, p) >= 0) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    /* y^a * a^b == g^m (mod p) */
    t1 = gcry_mpi_new(0);
    t2 = gcry_mpi_new(0);
    gcry_mpi_powm(t1, y, sig_a, p);
    gcry_mpi_powm(t2, sig_a, sig_b, p);
    gcry_mpi_mulm(t1, t1, t2, p);
    gcry_mpi_powm(t2, g, pd.mpi, p);

    if (gcry_mpi_cmp(t1, t2)) {
        rc = GPG_ERR_BAD_SIGNATURE;
    }

leave:
    gcry_mpi_release(t1);
    gcry_mpi_release(t2);
    gcry_mpi_release(p);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(sig_a);
    gcry_mpi_release(sig_b);
    gcry_sexp_release(l1);
    _gcry_pk_data_free(&pd);
    return rc;
}

static gcry_err_code_t
elg_check_secret_key(gcry_sexp_t keyparms)
{
    gcry_err_code_t rc;
    gcry_mpi_t p = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t t;

    rc = _gcry_sexp_extract_param(keyparms, NULL, "pgyx", &p, &g, &y, &x,
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
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    return rc;
}

/* Wiener's table: size of the exponent that gives security matching a
 * modulus of the given size. */
static unsigned int
wiener_map(unsigned int n)
{
    static const struct {
        unsigned int p_n;
        unsigned int q_n;
    } t[] = {
        { 512, 119 }, { 768, 145 }, { 1024, 165 }, { 1280, 183 },
        { 1536, 198 }, { 1792, 212 }, { 2048, 225 }, { 2304, 237 },
        { 2560, 249 }, { 2816, 259 }, { 3072, 269 }, { 3328, 279 },
        { 3584, 288 }, { 3840, 296 }, { 4096, 305 }, { 4352, 313 },
        { 4608, 320 }, { 4864, 328 }, { 5120, 335 }, { 5376, 342 },
        { 5632, 349 }, { 5888, 355 }, { 6144, 362 }, { 6400, 368 },
        { 6656, 374 }, { 6912, 380 }, { 7168, 386 }, { 7424, 391 },
        { 7680, 397 }, { 7936, 402 }, { 8192, 408 }, { 9472, 433 },
        { 10752, 456 }, { 12032, 477 }, { 13312, 496 }, { 14592, 515 },
        { 15872, 532 }, { 17152, 548 }, { 18432, 564 }, { 19712, 579 },
        { 20992, 593 }, { 0, 0 }
    };
    size_t i;

    for (i = 0; t[i].p_n; i++) {
        if (n <= t[i].p_n) {
            return t[i].q_n;
        }
    }

    return 3 * n / 8;
}

static gcry_err_code_t
elg_generate(gcry_sexp_t genparms, gcry_sexp_t *r_skey)
{
    gcry_err_code_t rc;
    unsigned int nbits;
    unsigned int qbits;
    unsigned int xbits;
    gcry_sexp_t l1;
    gcry_mpi_t xvalue = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t q = NULL;
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t t = NULL;
    gcry_mpi_t p_1 = NULL;
    gcry_sexp_t misc_info = NULL;
    BN_CTX *bctx = NULL;
    unsigned long gval;

    rc = _gcry_pk_util_get_nbits(genparms, &nbits);

    if (rc) {
        return rc;
    }

    if (nbits < 512 || nbits > 16384) {
        return GPG_ERR_INV_VALUE;
    }

    l1 = gcry_sexp_find_token(genparms, "xvalue", 0);

    if (l1) {
        xvalue = gcry_sexp_nth_mpi(l1, 1, 0);
        gcry_sexp_release(l1);

        if (!xvalue) {
            return GPG_ERR_BAD_MPI;
        }
    }

    bctx = BN_CTX_new_ex(_gcry_libctx());
    p = gcry_mpi_new(0);
    q = gcry_mpi_new(0);
    g = gcry_mpi_new(0);
    y = gcry_mpi_new(0);
    t = gcry_mpi_new(0);
    p_1 = gcry_mpi_new(0);

    /* A safe prime p = 2q + 1, so that the factors of (p-1)/2 are known. */
    if (!bctx || !BN_generate_prime_ex2(_gcry_mpi_bn(p), (int)nbits, 1, NULL,
                                        NULL, NULL, bctx)) {
        rc = _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        goto leave;
    }

    gcry_mpi_sub_ui(p_1, p, 1);
    gcry_mpi_rshift(q, p_1, 1);

    /* The smallest generator of the whole group: g^2 != 1 and g^q != 1. */
    for (gval = 2;; gval++) {
        gcry_mpi_set_ui(g, gval);
        gcry_mpi_mulm(t, g, g, p);

        if (!gcry_mpi_cmp_ui(t, 1)) {
            continue;
        }

        gcry_mpi_powm(t, g, q, p);

        if (gcry_mpi_cmp_ui(t, 1)) {
            break;
        }
    }

    if (xvalue) {
        if (gcry_mpi_cmp_ui(xvalue, 0) <= 0 || gcry_mpi_cmp(xvalue, p_1) >= 0) {
            rc = GPG_ERR_INV_VALUE;
            goto leave;
        }

        x = gcry_mpi_copy(xvalue);
        gcry_mpi_set_flag(x, GCRYMPI_FLAG_SECURE);
    } else {
        qbits = wiener_map(nbits);

        if (qbits & 1) {
            qbits++;
        }

        xbits = qbits * 3 / 2;

        if (xbits >= nbits) {
            xbits = nbits - 1;
        }

        x = gcry_mpi_snew(0);

        do {
            gcry_mpi_randomize(x, xbits, GCRY_VERY_STRONG_RANDOM);
            gcry_mpi_clear_highbit(x, xbits + 1);
        } while (!(gcry_mpi_cmp_ui(x, 0) > 0 && gcry_mpi_cmp(x, p_1) < 0));
    }

    gcry_mpi_powm(y, g, x, p);
    rc = _gcry_sexp_build(&misc_info, NULL, "(misc-key-info(pm1-factors%m))",
                          q);

    if (rc) {
        goto leave;
    }

    rc = _gcry_sexp_build(r_skey, NULL,
                          "(key-data"
                          " (public-key"
                          "  (elg(p%m)(g%m)(y%m)))"
                          " (private-key"
                          "  (elg(p%m)(g%m)(y%m)(x%m)))"
                          " %S)",
                          p, g, y, p, g, y, x, misc_info);

leave:
    gcry_sexp_release(misc_info);
    gcry_mpi_release(xvalue);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    gcry_mpi_release(t);
    gcry_mpi_release(p_1);
    BN_CTX_free(bctx);
    return rc;
}

const struct gcry_pk_spec _gcry_pubkey_spec_elg = {
    GCRY_PK_ELG,
    0,
    GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR,
    "ELG",
    elg_names,
    "pgy",
    "pgyx",
    "ab",
    "rs",
    "pgy",
    elg_generate,
    elg_check_secret_key,
    elg_encrypt,
    elg_decrypt,
    elg_sign,
    elg_verify,
    elg_get_nbits,
    NULL,
    NULL,
    NULL
};
