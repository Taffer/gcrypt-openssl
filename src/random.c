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
    do_randomize(buffer, length, level);
}

gcry_error_t
gcry_random_add_bytes(const void *buffer, size_t length, int quality)
{
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

    if (!buffer) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (!length || quality < 10) {
        return 0;
    }

    RAND_add(buffer, (int)(length > 0x7fffffffu ? 0x7fffffffu : length),
             (double)length * (double)quality / 100.0);
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
    do_randomize(buffer, length, GCRY_WEAK_RANDOM);
}
