/*
 * pk.c - Public key algorithm dispatcher: the gcry_pk_* API.
 */
#include "gcrypt-int.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const struct gcry_pk_spec *const pubkey_list[] = {
    &_gcry_pubkey_spec_ecc,
    &_gcry_pubkey_spec_rsa,
    &_gcry_pubkey_spec_dsa,
    &_gcry_pubkey_spec_elg,
    NULL
};

/* Algorithms disabled through gcry_pk_ctl(GCRYCTL_DISABLE_ALGO). */
static int disabled_algos[DIM(pubkey_list)];

static int
map_algo(int algo)
{
    switch (algo) {
    case GCRY_PK_RSA_E:
    case GCRY_PK_RSA_S:
        return GCRY_PK_RSA;

    case GCRY_PK_ELG_E:
        return GCRY_PK_ELG;

    case GCRY_PK_ECDSA:
    case GCRY_PK_EDDSA:
    case GCRY_PK_ECDH:
        return GCRY_PK_ECC;

    default:
        return algo;
    }
}

static const struct gcry_pk_spec *
spec_from_algo(int algo)
{
    int idx;

    algo = map_algo(algo);

    for (idx = 0; pubkey_list[idx]; idx++) {
        if (pubkey_list[idx]->algo == algo) {
            return pubkey_list[idx];
        }
    }

    return NULL;
}

static const struct gcry_pk_spec *
spec_from_name(const char *name)
{
    int idx;
    const char *const *aliases;

    for (idx = 0; pubkey_list[idx]; idx++) {
        const struct gcry_pk_spec *spec = pubkey_list[idx];

        if (!strcasecmp(name, spec->name)) {
            return spec;
        }

        for (aliases = spec->aliases; *aliases; aliases++) {
            if (!strcasecmp(name, *aliases)) {
                return spec;
            }
        }
    }

    return NULL;
}

static int
spec_disabled(const struct gcry_pk_spec *spec)
{
    int idx;

    for (idx = 0; pubkey_list[idx]; idx++) {
        if (pubkey_list[idx] == spec) {
            return disabled_algos[idx];
        }
    }

    return 0;
}

/* Reject disabled algorithms and, in FIPS mode, non-approved ones. */
static gcry_err_code_t
check_spec_usable(const struct gcry_pk_spec *spec)
{
    if (spec_disabled(spec)) {
        return GPG_ERR_PUBKEY_ALGO;
    }

    if (!spec->fips && _gcry_fips_mode()) {
        return GPG_ERR_PUBKEY_ALGO;
    }

    return 0;
}

/* Find the "(public-key (algo ...))" or "(private-key (algo ...))" part of
 * SEXP.  On success the parameter list "(algo ...)" is stored at R_PARMS. */
static gcry_err_code_t
spec_from_sexp(gcry_sexp_t sexp, int want_private,
               const struct gcry_pk_spec **r_spec, gcry_sexp_t *r_parms)
{
    gcry_sexp_t list;
    gcry_sexp_t l2;
    char *name;
    const struct gcry_pk_spec *spec;

    *r_spec = NULL;

    if (r_parms) {
        *r_parms = NULL;
    }

    list = gcry_sexp_find_token(sexp, want_private ? "private-key"
                                : "public-key", 0);

    if (!list && !want_private) {
        list = gcry_sexp_find_token(sexp, "private-key", 0);
    }

    if (!list) {
        return GPG_ERR_INV_OBJ;
    }

    l2 = gcry_sexp_cadr(list);
    gcry_sexp_release(list);
    list = l2;
    name = gcry_sexp_nth_string(list, 0);

    if (!name) {
        gcry_sexp_release(list);
        return GPG_ERR_INV_OBJ;
    }

    spec = spec_from_name(name);
    _gcry_free(name);

    if (!spec) {
        gcry_sexp_release(list);
        return GPG_ERR_PUBKEY_ALGO;
    }

    *r_spec = spec;

    if (r_parms) {
        *r_parms = list;
    } else {
        gcry_sexp_release(list);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Names and info                                                      */
/* ------------------------------------------------------------------ */

int
gcry_pk_map_name(const char *name)
{
    const struct gcry_pk_spec *spec;

    if (!name) {
        return 0;
    }

    spec = spec_from_name(name);

    if (!spec || check_spec_usable(spec)) {
        return 0;
    }

    return spec->algo;
}

const char *
gcry_pk_algo_name(int algorithm)
{
    const struct gcry_pk_spec *spec = spec_from_algo(algorithm);

    return spec ? spec->name : "?";
}

gcry_error_t
gcry_pk_algo_info(int algo, int what, void *buffer, size_t *nbytes)
{
    gcry_err_code_t rc = 0;
    const struct gcry_pk_spec *spec = spec_from_algo(algo);

    switch (what) {
    case GCRYCTL_TEST_ALGO: {
        unsigned int use = nbytes ? (unsigned int) * nbytes : 0;

        if (buffer) {
            rc = GPG_ERR_INV_ARG;
        } else if (!spec || check_spec_usable(spec)) {
            rc = GPG_ERR_PUBKEY_ALGO;
        } else if (((use & GCRY_PK_USAGE_SIGN)
                    && !(spec->use & GCRY_PK_USAGE_SIGN))
                   || ((use & GCRY_PK_USAGE_ENCR)
                       && !(spec->use & GCRY_PK_USAGE_ENCR))) {
            rc = GPG_ERR_PUBKEY_ALGO; /* Wrong usage. */
        }

        break;
    }

    case GCRYCTL_GET_ALGO_USAGE:
        if (!nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            *nbytes = spec ? spec->use : 0;
        }

        break;

    case GCRYCTL_GET_ALGO_NPKEY:
    case GCRYCTL_GET_ALGO_NSKEY:
    case GCRYCTL_GET_ALGO_NSIGN:
    case GCRYCTL_GET_ALGO_NENCR:
        if (!nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else if (!spec) {
            *nbytes = 0;
        } else {
            const char *elems = what == GCRYCTL_GET_ALGO_NPKEY
                                ? spec->elements_pkey
                                : what == GCRYCTL_GET_ALGO_NSKEY
                                ? spec->elements_skey
                                : what == GCRYCTL_GET_ALGO_NSIGN
                                ? spec->elements_sig : spec->elements_enc;

            *nbytes = strlen(elems);
        }

        break;

    default:
        rc = GPG_ERR_INV_OP;
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_ctl(int cmd, void *buffer, size_t buflen)
{
    gcry_err_code_t rc = 0;

    switch (cmd) {
    case GCRYCTL_DISABLE_ALGO:
        if (!buffer || buflen != sizeof(int)) {
            rc = GPG_ERR_INV_ARG;
        } else {
            const struct gcry_pk_spec *spec = spec_from_algo(*(int *)buffer);
            int idx;

            for (idx = 0; pubkey_list[idx]; idx++) {
                if (pubkey_list[idx] == spec) {
                    disabled_algos[idx] = 1;
                }
            }
        }

        break;

    default:
        rc = GPG_ERR_INV_OP;
    }

    return GCRY_ERR(rc);
}

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

gcry_error_t
gcry_pk_encrypt(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t pkey)
{
    gcry_err_code_t rc;
    const struct gcry_pk_spec *spec;
    gcry_sexp_t keyparms = NULL;

    if (!result) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *result = NULL;
    rc = spec_from_sexp(pkey, 0, &spec, &keyparms);

    if (!rc) {
        rc = check_spec_usable(spec);
    }

    if (!rc) {
        rc = spec->encrypt ? spec->encrypt(result, data, keyparms)
             : GPG_ERR_NOT_IMPLEMENTED;
    }

    gcry_sexp_release(keyparms);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_decrypt(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey)
{
    gcry_err_code_t rc;
    const struct gcry_pk_spec *spec;
    gcry_sexp_t keyparms = NULL;

    if (!result) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *result = NULL;
    rc = spec_from_sexp(skey, 1, &spec, &keyparms);

    if (!rc) {
        rc = check_spec_usable(spec);
    }

    if (!rc) {
        rc = spec->decrypt ? spec->decrypt(result, data, keyparms)
             : GPG_ERR_NOT_IMPLEMENTED;
    }

    gcry_sexp_release(keyparms);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_sign(gcry_sexp_t *result, gcry_sexp_t data, gcry_sexp_t skey)
{
    gcry_err_code_t rc;
    const struct gcry_pk_spec *spec;
    gcry_sexp_t keyparms = NULL;

    if (!result) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *result = NULL;
    rc = spec_from_sexp(skey, 1, &spec, &keyparms);

    if (!rc) {
        rc = check_spec_usable(spec);
    }

    if (!rc) {
        rc = spec->sign ? spec->sign(result, data, keyparms)
             : GPG_ERR_NOT_IMPLEMENTED;
    }

    gcry_sexp_release(keyparms);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_verify(gcry_sexp_t sigval, gcry_sexp_t data, gcry_sexp_t pkey)
{
    gcry_err_code_t rc;
    const struct gcry_pk_spec *spec;
    gcry_sexp_t keyparms = NULL;

    rc = spec_from_sexp(pkey, 0, &spec, &keyparms);

    if (!rc) {
        rc = check_spec_usable(spec);
    }

    if (!rc) {
        rc = spec->verify ? spec->verify(sigval, data, keyparms)
             : GPG_ERR_NOT_IMPLEMENTED;
    }

    gcry_sexp_release(keyparms);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_testkey(gcry_sexp_t key)
{
    gcry_err_code_t rc;
    const struct gcry_pk_spec *spec;
    gcry_sexp_t keyparms = NULL;

    rc = spec_from_sexp(key, 1, &spec, &keyparms);

    if (!rc) {
        rc = check_spec_usable(spec);
    }

    if (!rc) {
        rc = spec->check_secret_key ? spec->check_secret_key(keyparms)
             : GPG_ERR_NOT_IMPLEMENTED;
    }

    gcry_sexp_release(keyparms);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_genkey(gcry_sexp_t *r_key, gcry_sexp_t s_parms)
{
    const struct gcry_pk_spec *spec;
    gcry_sexp_t list;
    gcry_sexp_t l2;
    char *name;
    gcry_err_code_t rc;

    if (!r_key) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *r_key = NULL;
    list = gcry_sexp_find_token(s_parms, "genkey", 0);

    if (!list) {
        return GCRY_ERR(GPG_ERR_INV_OBJ);
    }

    l2 = gcry_sexp_cadr(list);
    gcry_sexp_release(list);
    list = l2;

    if (!list) {
        return GCRY_ERR(GPG_ERR_NO_OBJ);
    }

    name = gcry_sexp_nth_string(list, 0);

    if (!name) {
        gcry_sexp_release(list);
        return GCRY_ERR(GPG_ERR_INV_OBJ);
    }

    spec = spec_from_name(name);
    _gcry_free(name);

    if (!spec || check_spec_usable(spec)) {
        rc = GPG_ERR_PUBKEY_ALGO;
    } else if (spec->generate) {
        rc = spec->generate(list, r_key);
    } else {
        rc = GPG_ERR_NOT_IMPLEMENTED;
    }

    gcry_sexp_release(list);
    return GCRY_ERR(rc);
}

unsigned int
gcry_pk_get_nbits(gcry_sexp_t key)
{
    const struct gcry_pk_spec *spec;
    gcry_sexp_t parms;
    unsigned int nbits;

    if (spec_from_sexp(key, 0, &spec, &parms)) {
        return 0;
    }

    nbits = check_spec_usable(spec) ? 0 : spec->get_nbits(parms);
    gcry_sexp_release(parms);
    return nbits;
}

/* ------------------------------------------------------------------ */
/* Keygrip                                                             */
/* ------------------------------------------------------------------ */

/* The generic keygrip: SHA-1 over "(1:X<len>:<data>)" for each element,
 * using the data bytes exactly as they appear in the S-expression. */
static gcry_err_code_t
generic_keygrip(EVP_MD_CTX *md, const char *elems, gcry_sexp_t list)
{
    const char *s;

    for (s = elems; *s; s++) {
        gcry_sexp_t l2 = gcry_sexp_find_token(list, s, 1);
        const char *data;
        size_t datalen;
        char buf[30];
        int ok;

        if (!l2) {
            return GPG_ERR_NO_OBJ;
        }

        data = gcry_sexp_nth_data(l2, 1, &datalen);

        if (!data) {
            gcry_sexp_release(l2);
            return GPG_ERR_INV_OBJ;
        }

        snprintf(buf, sizeof buf, "(1:%c%u:", *s, (unsigned int)datalen);
        ok = EVP_DigestUpdate(md, buf, strlen(buf))
             && EVP_DigestUpdate(md, data, datalen)
             && EVP_DigestUpdate(md, ")", 1);
        gcry_sexp_release(l2);

        if (!ok) {
            return GPG_ERR_INTERNAL;
        }
    }

    return 0;
}

unsigned char *
gcry_pk_get_keygrip(gcry_sexp_t key, unsigned char *array)
{
    gcry_sexp_t list = NULL;
    gcry_sexp_t l2;
    const struct gcry_pk_spec *spec;
    char *name = NULL;
    EVP_MD *sha1 = NULL;
    EVP_MD_CTX *md = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    int okay = 0;

    list = gcry_sexp_find_token(key, "public-key", 0);

    if (!list) {
        list = gcry_sexp_find_token(key, "private-key", 0);
    }

    if (!list) {
        list = gcry_sexp_find_token(key, "protected-private-key", 0);
    }

    if (!list) {
        list = gcry_sexp_find_token(key, "shadowed-private-key", 0);
    }

    if (!list) {
        return NULL;
    }

    l2 = gcry_sexp_cadr(list);
    gcry_sexp_release(list);
    list = l2;
    name = gcry_sexp_nth_string(list, 0);

    if (!name) {
        goto fail;
    }

    spec = spec_from_name(name);

    if (!spec || !spec->elements_grip) {
        goto fail;
    }

    sha1 = EVP_MD_fetch(_gcry_libctx(), "SHA1", _gcry_propq());
    md = EVP_MD_CTX_new();

    if (!sha1 || !md || !EVP_DigestInit_ex2(md, sha1, NULL)) {
        goto fail;
    }

    if (spec->comp_keygrip) {
        if (spec->comp_keygrip(md, list)) {
            goto fail;
        }
    } else if (generic_keygrip(md, spec->elements_grip, list)) {
        goto fail;
    }

    if (!EVP_DigestFinal_ex(md, digest, &dlen) || dlen != 20) {
        goto fail;
    }

    if (!array) {
        array = _gcry_malloc(20);

        if (!array) {
            goto fail;
        }
    }

    memcpy(array, digest, 20);
    okay = 1;

fail:
    ERR_clear_error();
    _gcry_free(name);
    EVP_MD_CTX_free(md);
    EVP_MD_free(sha1);
    gcry_sexp_release(list);
    return okay ? array : NULL;
}

/* ------------------------------------------------------------------ */
/* Curves                                                              */
/* ------------------------------------------------------------------ */

const char *
gcry_pk_get_curve(gcry_sexp_t key, int iterator, unsigned int *r_nbits)
{
    const char *result = NULL;
    const struct gcry_pk_spec *spec;
    gcry_sexp_t keyparms = NULL;

    if (r_nbits) {
        *r_nbits = 0;
    }

    if (key) {
        iterator = 0;

        if (spec_from_sexp(key, 0, &spec, &keyparms)) {
            return NULL;
        }
    } else {
        spec = spec_from_name("ecc");

        if (!spec) {
            return NULL;
        }
    }

    if (!check_spec_usable(spec) && spec->get_curve) {
        result = spec->get_curve(keyparms, iterator, r_nbits);
    }

    gcry_sexp_release(keyparms);
    return result;
}

gcry_sexp_t
gcry_pk_get_param(int algo, const char *name)
{
    const struct gcry_pk_spec *spec;

    if (!name || map_algo(algo) != GCRY_PK_ECC) {
        return NULL;
    }

    spec = spec_from_name("ecc");

    if (!spec || !spec->get_curve_param) {
        return NULL;
    }

    return spec->get_curve_param(name);
}

gcry_error_t
gcry_pubkey_get_sexp(gcry_sexp_t *r_sexp, int mode, gcry_ctx_t ctx)
{
    mpi_ec_t ec;

    if (!r_sexp) {
        return GCRY_ERR(GPG_ERR_INV_VALUE);
    }

    *r_sexp = NULL;

    switch (mode) {
    case 0:
    case GCRY_PK_GET_PUBKEY:
    case GCRY_PK_GET_SECKEY:
        break;

    default:
        return GCRY_ERR(GPG_ERR_INV_VALUE);
    }

    if (!ctx) {
        return GCRY_ERR(GPG_ERR_NO_CRYPT_CTX);
    }

    ec = _gcry_ctx_get_ec(ctx);

    if (!ec) {
        return GCRY_ERR(GPG_ERR_WRONG_CRYPT_CTX);
    }

    return GCRY_ERR(_gcry_pk_ecc_get_sexp(r_sexp, mode, ec));
}

/* ------------------------------------------------------------------ */
/* Hash-and-sign with input data contexts                              */
/* ------------------------------------------------------------------ */

/* Payload of a GCRY_CTX_TYPE_RANDOM_OVERRIDE context.  Several of them
 * form a chain through NEXT, newest first. */
struct pk_single_data {
    gcry_ctx_t next;
    size_t len;
    unsigned char *data;
};

static void
single_data_deinit(void *payload)
{
    struct pk_single_data *psd = payload;

    gcry_ctx_release(psd->next);
    _gcry_free(psd->data);
}

gcry_error_t
gcry_pk_random_override_new(gcry_ctx_t *r_ctx, const unsigned char *p,
                            size_t len)
{
    gcry_ctx_t ctx;
    struct pk_single_data *psd;

    if (!r_ctx || !p) {
        return GCRY_ERR(GPG_ERR_EINVAL);
    }

    ctx = _gcry_ctx_alloc(GCRY_CTX_TYPE_RANDOM_OVERRIDE, sizeof * psd,
                          single_data_deinit);

    if (!ctx) {
        return GCRY_ERR(_gcry_err_code_from_syserror());
    }

    psd = _gcry_ctx_get_pointer(ctx, GCRY_CTX_TYPE_RANDOM_OVERRIDE);
    psd->data = _gcry_malloc(len ? len : 1);

    if (!psd->data) {
        gcry_ctx_release(ctx);
        return GCRY_ERR(GPG_ERR_ENOMEM);
    }

    memcpy(psd->data, p, len);
    psd->len = len;
    psd->next = *r_ctx;
    *r_ctx = ctx;
    return 0;
}

#define MAX_CONTEXTS 2

/* Build the "(data ...)" S-expression from TMPL.  With HD, the digest
 * from a copy of the hash handle fills "%s %b" (or "%b" when the template
 * names the hash algorithm itself); without HD the bytes come from the
 * input data contexts. */
static gcry_err_code_t
prepare_datasexp(const char *tmpl, gcry_md_hd_t hd, gcry_ctx_t ctx,
                 gcry_sexp_t *r_data)
{
    gcry_err_code_t rc;
    const char *s;
    const char *digest_name = NULL;
    const unsigned char *digest;
    int digest_size;
    int algo;
    gcry_md_hd_t copy = NULL;

    if (!hd) {
        const unsigned char *data[MAX_CONTEXTS];
        int data_size[MAX_CONTEXTS];
        void *argv[MAX_CONTEXTS * 2];
        int i = 0;

        while (ctx) {
            struct pk_single_data *psd;

            if (i >= MAX_CONTEXTS * 2) {
                return GPG_ERR_EINVAL;
            }

            psd = _gcry_ctx_find_pointer(ctx, GCRY_CTX_TYPE_RANDOM_OVERRIDE);

            if (!psd) {
                return GPG_ERR_EINVAL;
            }

            data[i / 2] = psd->data;
            data_size[i / 2] = (int)psd->len;
            argv[i] = &data_size[i / 2];
            argv[i + 1] = &data[i / 2];
            i += 2;
            ctx = psd->next;
        }

        if (!i) {
            return GPG_ERR_EINVAL;
        }

        return gcry_err_code(gcry_sexp_build_array(r_data, NULL, tmpl, argv));
    }

    rc = gcry_err_code(gcry_md_copy(&copy, hd));

    if (rc) {
        return rc;
    }

    s = strstr(tmpl, "(hash ");

    if (!s) {
        gcry_md_close(copy);
        return GPG_ERR_DIGEST_ALGO;
    }

    s += 6;

    if (!strncmp(s, "%s", 2)) {
        algo = gcry_md_get_algo(copy);
        digest_name = gcry_md_algo_name(algo);
        digest_size = (int)gcry_md_get_algo_dlen(algo);
        digest = gcry_md_read(copy, 0);
    } else {
        const char *p;
        char *supplied;

        for (p = s; *p && *p != ' '; p++) {
            ;
        }

        supplied = _gcry_malloc((size_t)(p - s) + 1);

        if (!supplied) {
            gcry_md_close(copy);
            return _gcry_err_code_from_syserror();
        }

        memcpy(supplied, s, (size_t)(p - s));
        supplied[p - s] = 0;
        algo = gcry_md_map_name(supplied);
        _gcry_free(supplied);

        if (!algo) {
            gcry_md_close(copy);
            return GPG_ERR_DIGEST_ALGO;
        }

        digest_size = (int)gcry_md_get_algo_dlen(algo);
        digest = gcry_md_read(copy, algo);
    }

    if (!digest) {
        gcry_md_close(copy);
        return GPG_ERR_NOT_IMPLEMENTED;
    }

    if (!ctx) {
        if (!digest_name) {
            rc = _gcry_sexp_build(r_data, NULL, tmpl, digest_size, digest);
        } else {
            rc = _gcry_sexp_build(r_data, NULL, tmpl, digest_name,
                                  digest_size, digest);
        }
    } else {
        struct pk_single_data *psd =
            _gcry_ctx_find_pointer(ctx, GCRY_CTX_TYPE_RANDOM_OVERRIDE);

        if (!psd) {
            rc = GPG_ERR_EINVAL;
        } else if (!digest_name) {
            rc = _gcry_sexp_build(r_data, NULL, tmpl, digest_size, digest,
                                  (int)psd->len, psd->data);
        } else {
            rc = _gcry_sexp_build(r_data, NULL, tmpl, digest_name,
                                  digest_size, digest, (int)psd->len,
                                  psd->data);
        }
    }

    gcry_md_close(copy);
    return rc;
}

gcry_error_t
gcry_pk_hash_sign(gcry_sexp_t *result, const char *data_tmpl,
                  gcry_sexp_t skey, gcry_md_hd_t hd, gcry_ctx_t ctx)
{
    gcry_err_code_t rc;
    gcry_sexp_t s_data = NULL;

    if (!result || !data_tmpl) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    *result = NULL;
    rc = prepare_datasexp(data_tmpl, hd, ctx, &s_data);

    if (rc) {
        return GCRY_ERR(rc);
    }

    rc = gcry_err_code(gcry_pk_sign(result, s_data, skey));
    gcry_sexp_release(s_data);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_pk_hash_verify(gcry_sexp_t sigval, const char *data_tmpl,
                    gcry_sexp_t pkey, gcry_md_hd_t hd, gcry_ctx_t ctx)
{
    gcry_err_code_t rc;
    gcry_sexp_t s_data = NULL;

    if (!data_tmpl) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    rc = prepare_datasexp(data_tmpl, hd, ctx, &s_data);

    if (rc) {
        return GCRY_ERR(rc);
    }

    rc = gcry_err_code(gcry_pk_verify(sigval, s_data, pkey));
    gcry_sexp_release(s_data);
    return GCRY_ERR(rc);
}
