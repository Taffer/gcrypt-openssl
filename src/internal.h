/*
 * gcrypt-openssl: private declarations shared between translation units.
 *
 * Nothing in this header is part of the public API or ABI.
 */
#ifndef GCRYPT_OPENSSL_INTERNAL_H
#define GCRYPT_OPENSSL_INTERNAL_H

#include <openssl/opensslv.h>

/*
 * The build system already asks for OpenSSL 4, but a stale include path can
 * still pick up older headers. Fail loudly rather than compile against an
 * API we do not target.
 */
#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 4
    #error "gcrypt-openssl requires OpenSSL 4.0 or newer"
#endif

#define GCRYPT_OPENSSL_STRINGIFY_(x) #x
#define GCRYPT_OPENSSL_STRINGIFY(x)  GCRYPT_OPENSSL_STRINGIFY_(x)

/* clang-format off */
#define GCRYPT_OPENSSL_VERSION_STRING                          \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_MAJOR) "." \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_MINOR) "." \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_PATCH)
/* clang-format on */

#endif /* GCRYPT_OPENSSL_INTERNAL_H */
