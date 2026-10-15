/*
 * gcrypt-openssl: the gcrypt API, implemented using OpenSSL.
 *
 * Public header. Everything declared here is part of the library's ABI.
 */
#ifndef GCRYPT_OPENSSL_H
#define GCRYPT_OPENSSL_H

#include <gcrypt-openssl/export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return the library version as a NUL-terminated "MAJOR.MINOR.PATCH" string.
 * The returned pointer refers to static storage and must not be freed.
 */
GCRYPT_OPENSSL_EXPORT const char *gcrypt_openssl_version(void);

/*
 * Return the version of the OpenSSL library this build is running against,
 * as reported by OpenSSL itself. The returned pointer refers to static
 * storage and must not be freed.
 */
GCRYPT_OPENSSL_EXPORT const char *gcrypt_openssl_backend_version(void);

#ifdef __cplusplus
}
#endif

#endif /* GCRYPT_OPENSSL_H */
