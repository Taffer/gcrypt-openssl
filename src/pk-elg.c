/*
 * pk-elg.c - ElGamal.
 *
 * OpenSSL has no ElGamal implementation.  The textbook scheme is a thin
 * composition of modular exponentiations, so it is expressed here directly
 * on BIGNUMs (via the MPI layer): this file is the one place in the
 * library that does more than hand data to an OpenSSL primitive.  Prime
 * generation and the random numbers still come from OpenSSL, and the
 * PKCS#1 encodings are the shared ones from pk-util.c.
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
    gcry_mpi_t k;
    gcry_mpi_t p_1;
    gcry_mpi_t g;
    BN_CTX *bctx;
    gcry_err_code_t rc = 0;
    unsigned int tries;

    *r_k = NULL;

    /* For p < 3 there is no such k at all (the reference library loops
     * forever on p = 2); for any larger p, k = 1 is one, so the search
     * below terminates quickly and its bound is only a safeguard. */
    if (mpi_is_opaque(p) || gcry_mpi_cmp_ui(p, 3) < 0) {
        return GPG_ERR_INV_VALUE;
    }

    k = gcry_mpi_snew(0);
    p_1 = gcry_mpi_new(0);
    g = gcry_mpi_new(0);
    bctx = BN_CTX_new_ex(_gcry_libctx());
    gcry_mpi_sub_ui(p_1, p, 1);

    for (tries = 0;; tries++) {
        if (tries >= 10000) {
            rc = GPG_ERR_INV_VALUE;
            break;
        }

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

/* The number ElGamal operates on: the value itself for raw data, else
 * the PKCS#1 frame for the key size read as a big endian number. */
static gcry_err_code_t
data_to_mpi(struct pk_data *pd, gcry_mpi_t *r_m)
{
    unsigned char *frame = NULL;
    size_t framelen = 0;
    gcry_err_code_t rc;

    *r_m = NULL;

    if (pd->encoding == PUBKEY_ENC_RAW) {
        if (!pd->mpi || mpi_is_opaque(pd->mpi)) {
            return GPG_ERR_INV_DATA;
        }

        *r_m = gcry_mpi_copy(pd->mpi);
        return *r_m ? 0 : GPG_ERR_ENOMEM;
    }

    rc = _gcry_pk_data_to_frame(pd, pd->nbits, &frame, &framelen);

    if (rc) {
        return rc;
    }

    rc = _gcry_mpi_scan(r_m, GCRYMPI_FMT_USG, frame, framelen, NULL);
    _gcry_wipememory(frame, framelen); /* The padded plaintext. */
    _gcry_free(frame);
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
    gcry_mpi_t m = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_ENCRYPT, elg_get_nbits(keyparms));
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding != PUBKEY_ENC_RAW && pd.encoding != PUBKEY_ENC_PKCS1
        && pd.encoding != PUBKEY_ENC_OAEP) {
        rc = GPG_ERR_CONFLICT;
        goto leave;
    }

    rc = data_to_mpi(&pd, &m);

    if (rc) {
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
    gcry_mpi_mulm(b, b, m, p);
    rc = _gcry_sexp_build(r_ciph, NULL, "(enc-val(elg(a%m)(b%m)))", a, b);

leave:
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(k);
    gcry_mpi_release(m);
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

    if (pd.encoding != PUBKEY_ENC_UNKNOWN && pd.encoding != PUBKEY_ENC_RAW
        && pd.encoding != PUBKEY_ENC_PKCS1
        && pd.encoding != PUBKEY_ENC_OAEP) {
        rc = GPG_ERR_CONFLICT;
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

    if (pd.encoding == PUBKEY_ENC_PKCS1 || pd.encoding == PUBKEY_ENC_OAEP) {
        /* The PKCS#1 frame for the key size, decoded like RSA does it. */
        size_t k = (pd.nbits + 7) / 8;
        unsigned char *frame = _gcry_malloc_secure(k);
        unsigned char *value = NULL;
        size_t valuelen = 0;

        if (!frame) {
            rc = GPG_ERR_ENOMEM;
            goto leave;
        }

        if (_gcry_pk_mpi_to_fixed(plain, frame, k)) {
            rc = GPG_ERR_ENCODING_PROBLEM;
        } else if (pd.encoding == PUBKEY_ENC_PKCS1) {
            rc = _gcry_pk_pkcs1_decode_for_enc(frame, k, &value, &valuelen);
        } else {
            rc = _gcry_pk_oaep_decode(frame, k, pd.hash_algo, pd.label,
                                      pd.labellen, &value, &valuelen);
        }

        if (!rc) {
            rc = _gcry_sexp_build(r_plain, NULL, "(value %b)", (int)valuelen,
                                  value);
        }

        if (value) {
            _gcry_wipememory(value, valuelen);
        }

        _gcry_wipememory(frame, k);
        _gcry_free(value);
        _gcry_free(frame);
    } else {
        rc = _gcry_sexp_build(r_plain, NULL,
                              (pd.flags & PUBKEY_FLAG_LEGACYRESULT) ? "%m"
                              : "(value %m)", plain);
    }

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
    gcry_mpi_t m = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_SIGN, elg_get_nbits(keyparms));
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    rc = data_to_mpi(&pd, &m);

    if (rc) {
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
    gcry_mpi_subm(t, m, t, p_1);        /* t = m - x*a mod (p-1) */
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
    gcry_mpi_release(m);
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
    gcry_mpi_t m = NULL;

    _gcry_pk_data_init(&pd, PUBKEY_OP_VERIFY, elg_get_nbits(keyparms));
    rc = _gcry_pk_data_parse(s_data, &pd);

    if (rc) {
        goto leave;
    }

    if (pd.encoding == PUBKEY_ENC_PSS) {
        rc = GPG_ERR_INV_DATA; /* PSS needs a recoverable frame. */
        goto leave;
    }

    rc = data_to_mpi(&pd, &m);

    if (rc) {
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

    /* 0 < a < p and 0 < b < p - 1: b is an exponent modulo p - 1, so a
     * value outside that range is a non-canonical signature (the reference
     * library only checks a). */
    t1 = gcry_mpi_new(0);
    t2 = gcry_mpi_new(0);
    gcry_mpi_sub_ui(t1, p, 1);

    if (gcry_mpi_cmp_ui(sig_a, 0) <= 0 || gcry_mpi_cmp(sig_a, p) >= 0
        || gcry_mpi_cmp_ui(sig_b, 0) <= 0 || gcry_mpi_cmp(sig_b, t1) >= 0) {
        rc = GPG_ERR_BAD_SIGNATURE;
        goto leave;
    }

    /* y^a * a^b == g^m (mod p) */
    gcry_mpi_powm(t1, y, sig_a, p);
    gcry_mpi_powm(t2, sig_a, sig_b, p);
    gcry_mpi_mulm(t1, t1, t2, p);
    gcry_mpi_powm(t2, g, m, p);

    if (gcry_mpi_cmp(t1, t2)) {
        rc = GPG_ERR_BAD_SIGNATURE;
    }

leave:
    gcry_mpi_release(m);
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
        { 3584, 288 }, { 3840, 296 }, { 4096, 305 }, { 4608, 320 },
        { 5120, 334 }, { 5632, 347 }, { 6144, 359 }, { 6656, 371 },
        { 7168, 382 }, { 7680, 392 }, { 8192, 402 }, { 9728, 439 },
        { 10240, 451 }, { 10752, 462 }, { 11264, 473 }, { 11776, 483 },
        { 12288, 493 }, { 13312, 512 }, { 13824, 521 }, { 14336, 530 },
        { 14848, 539 }, { 15360, 548 }, { 15872, 556 }, { 16384, 564 },
        { 16896, 572 }, { 17408, 580 }, { 17920, 587 }, { 18432, 595 },
        { 18944, 602 }, { 19456, 609 }, { 19968, 616 }, { 20480, 623 },
        { 20992, 630 }, { 21504, 637 }, { 22016, 643 }, { 22528, 650 },
        { 23040, 656 }, { 23552, 662 }, { 24064, 668 }, { 24576, 674 },
        { 25088, 680 }, { 25600, 686 }, { 26112, 692 }, { 26624, 698 },
        { 27136, 703 }, { 27648, 709 }, { 28160, 714 }, { 28672, 720 },
        { 29184, 725 }, { 29696, 731 }, { 30208, 736 }, { 30720, 741 },
        { 31232, 746 }, { 31744, 752 }, { 32256, 757 }, { 32768, 762 },
        { 0, 0 }
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
    gcry_mpi_t g = NULL;
    gcry_mpi_t y = NULL;
    gcry_mpi_t x = NULL;
    gcry_mpi_t p_1 = NULL;
    gcry_mpi_t *factors = NULL;
    size_t nfactors = 0;
    gcry_sexp_t misc_info = NULL;

    rc = _gcry_pk_util_get_nbits(genparms, &nbits);

    if (rc) {
        return rc;
    }

    /* The reference library accepts any size; the Wiener table (and the
     * prime generator) needs the exponent group to fit into the modulus. */
    if (nbits > 16384 || wiener_map(nbits) + 2 >= nbits) {
        return GPG_ERR_INV_VALUE;
    }

    l1 = gcry_sexp_find_token(genparms, "xvalue", 0);

    if (l1) {
        xvalue = gcry_sexp_nth_mpi(l1, 1, GCRYMPI_FMT_USG);
        gcry_sexp_release(l1);

        if (!xvalue) {
            return GPG_ERR_BAD_MPI;
        }
    }

    y = gcry_mpi_new(0);
    p_1 = gcry_mpi_new(0);

    /* The group size follows Wiener's table, as in the reference
     * implementation: p - 1 = 2 * q * f_1 ... f_n with q of QBITS bits and
     * the f_i known, so that a generator of the whole group can be found
     * from the factorisation. */
    qbits = wiener_map(nbits);

    if (qbits & 1) {
        qbits++;
    }

    rc = gcry_err_code(gcry_prime_generate(&p, nbits, qbits, &factors, NULL,
                                           NULL, GCRY_VERY_STRONG_RANDOM, 0));

    if (rc) {
        goto leave;
    }

    rc = gcry_err_code(gcry_prime_group_generator(&g, p, factors, NULL));

    if (rc) {
        goto leave;
    }

    gcry_mpi_sub_ui(p_1, p, 1);

    for (nfactors = 0; factors[nfactors]; nfactors++) {
        ;
    }

    if (xvalue) {
        unsigned int xb = gcry_mpi_get_nbits(xvalue);

        /* A caller supplied secret must have at least 64 bits. */
        if (xb < 64 || xb >= nbits || gcry_mpi_cmp_ui(xvalue, 0) <= 0
            || gcry_mpi_cmp(xvalue, p_1) >= 0) {
            rc = GPG_ERR_INV_VALUE;
            goto leave;
        }

        x = gcry_mpi_copy(xvalue);
        gcry_mpi_set_flag(x, GCRYMPI_FLAG_SECURE);
    } else {
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

    /* misc-key-info lists every factor of p - 1: "(pm1-factors%m%m...)". */
    {
        const char *prefix = "(misc-key-info(pm1-factors";
        size_t fmtlen = strlen(prefix) + 2 * nfactors + 3;
        char *fmt = _gcry_malloc(fmtlen);
        void **args = _gcry_calloc(nfactors + 1, sizeof * args);
        size_t i;

        if (!fmt || !args) {
            _gcry_free(fmt);
            _gcry_free(args);
            rc = _gcry_err_code_from_syserror();
            goto leave;
        }

        strcpy(fmt, prefix);

        for (i = 0; i < nfactors; i++) {
            strcat(fmt, "%m");
            args[i] = &factors[i]; /* %m takes a pointer to the MPI. */
        }

        strcat(fmt, "))");
        rc = gcry_err_code(gcry_sexp_build_array(&misc_info, NULL, fmt,
                                                 args));
        _gcry_free(fmt);
        _gcry_free(args);

        if (rc) {
            goto leave;
        }
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
    gcry_mpi_release(g);
    gcry_mpi_release(y);
    gcry_mpi_release(x);
    gcry_mpi_release(p_1);
    gcry_prime_release_factors(factors);
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
