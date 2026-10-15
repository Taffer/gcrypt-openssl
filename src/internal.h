/*
 * gcrypt-openssl: private declarations shared between translation units.
 *
 * Nothing in this header is part of the public API or ABI.
 */
#ifndef GCRYPT_OPENSSL_INTERNAL_H
#define GCRYPT_OPENSSL_INTERNAL_H

#define GCRYPT_OPENSSL_STRINGIFY_(x) #x
#define GCRYPT_OPENSSL_STRINGIFY(x)  GCRYPT_OPENSSL_STRINGIFY_(x)

#define GCRYPT_OPENSSL_VERSION_STRING                        \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_MAJOR) "." \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_MINOR) "." \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_PATCH)

#endif /* GCRYPT_OPENSSL_INTERNAL_H */
