/*
 * gcrypt-openssl: library entry points that don't belong anywhere else yet.
 */
#include <gcrypt-openssl/gcrypt_openssl.h>

#include <openssl/crypto.h>

#include "internal.h"

const char *
gcrypt_openssl_version(void)
{
    return GCRYPT_OPENSSL_VERSION_STRING;
}

const char *
gcrypt_openssl_backend_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}
