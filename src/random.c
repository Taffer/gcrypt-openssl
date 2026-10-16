/*
 * random.c - Random numbers.
 *
 * All randomness comes from OpenSSL's DRBGs in the library context.  The
 * "very strong" and "strong" levels use the private DRBG (key material),
 * the weak level and nonces use the public one.
 */
#include "gcrypt-int.h"

#include <openssl/rand.h>

gcry_err_code_t
_gcry_random_bytes_into(void *buffer, size_t length,
                        enum gcry_random_level level)
{
    int ok;

    if (!length) {
        return 0;
    }

    if (!buffer) {
        return GPG_ERR_INV_ARG;
    }

    /* FIPS mode required without a FIPS provider: no generator may be
     * used (none could be fetched anyway); say so rather than failing
     * with a bare "random number generator failed". */
    if (_gcry_fips_error_state()) {
        return GPG_ERR_NOT_OPERATIONAL;
    }

    if (level == GCRY_WEAK_RANDOM) {
        ok = RAND_bytes_ex(_gcry_libctx(), buffer, length, 0);
    } else {
        ok = RAND_priv_bytes_ex(_gcry_libctx(), buffer, length, 0);
    }

    if (ok <= 0) {
        return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
    }

    return 0;
}

static void
do_randomize(void *buffer, size_t length, enum gcry_random_level level)
{
    gcry_err_code_t rc = _gcry_random_bytes_into(buffer, length, level);

    if (rc) {
        _gcry_fatal_error((int)rc, "random number generator failed");
    }
}

void
gcry_randomize(void *buffer, size_t length, enum gcry_random_level level)
{
    if (!buffer && length) {
        _gcry_fatal_error(GPG_ERR_INV_ARG, "gcry_randomize: NULL argument");
    }

    do_randomize(buffer, length, level);
}

/* Mix the caller's bytes into DRBG as additional input of a reseed; the
 * generator draws fresh entropy from its source at the same time, so the
 * result can only get better, never worse. */
static void
reseed_with(EVP_RAND_CTX *drbg, const void *buffer, size_t length)
{
    if (drbg && !EVP_RAND_reseed(drbg, 0, NULL, 0, buffer, length)) {
        ERR_clear_error();
    }
}

gcry_error_t
gcry_random_add_bytes(const void *buffer, size_t length, int quality)
{
    OSSL_LIB_CTX *libctx;

    if (!buffer) {
        return GCRY_ERR(GPG_ERR_INV_ARG); /* As the reference, even for 0. */
    }

    if (_gcry_fips_mode()) {
        return 0; /* The FIPS DRBG must not be fed from outside. */
    }

    if (quality == -1) {
        quality = 35;
    } else if (quality > 100) {
        quality = 100;
    } else if (quality < 0) {
        quality = 0;
    }

    if (!length || quality < 10) {
        return 0;
    }

    /* The generators in use are those of the library's own context, not
     * OpenSSL's global one, so that is where the bytes have to go: into
     * the primary DRBG that seeds the others, and into the public one
     * directly, which is cheap. */
    libctx = _gcry_libctx();
    reseed_with(RAND_get0_primary(libctx), buffer, length);
    reseed_with(RAND_get0_public(libctx), buffer, length);
    ERR_clear_error();
    return 0;
}

void *
gcry_random_bytes(size_t nbytes, enum gcry_random_level level)
{
    void *buffer = _gcry_xmalloc(nbytes);

    do_randomize(buffer, nbytes, level);
    return buffer;
}

void *
gcry_random_bytes_secure(size_t nbytes, enum gcry_random_level level)
{
    void *buffer = _gcry_xmalloc_secure(nbytes);

    do_randomize(buffer, nbytes, level);
    return buffer;
}

void
gcry_create_nonce(void *buffer, size_t length)
{
    if (!buffer && length) {
        _gcry_fatal_error(GPG_ERR_INV_ARG, "gcry_create_nonce: NULL argument");
    }

    do_randomize(buffer, length, GCRY_WEAK_RANDOM);
}
