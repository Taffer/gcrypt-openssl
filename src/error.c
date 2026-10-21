/*
 * error.c - Error code and error source descriptions, errno mapping.
 *
 * The public gcry_* error helpers wrap libgpg-error, exactly as the
 * reference library's do, so error values and their descriptions are the
 * ones every other GnuPG component uses.
 */
#include "gcrypt-int.h"

gcry_err_code_t
gcry_err_code_from_errno(int err)
{
    return gpg_err_code_from_errno(err);
}

int
gcry_err_code_to_errno(gcry_err_code_t code)
{
    return gpg_err_code_to_errno(code);
}

gcry_error_t
gcry_err_make_from_errno(gcry_err_source_t source, int err)
{
    return gpg_err_make_from_errno(source, err);
}

gcry_error_t
gcry_error_from_errno(int err)
{
    return gcry_err_make_from_errno(GPG_ERR_SOURCE_GCRYPT, err);
}

const char *
gcry_strerror(gcry_error_t err)
{
    return gpg_strerror(err);
}

const char *
gcry_strsource(gcry_error_t err)
{
    return gpg_strsource(err);
}

gcry_err_code_t
_gcry_err_code_from_syserror(void)
{
    return gpg_err_code_from_syserror();
}

/* Drain OpenSSL's error queue and derive a Libgcrypt error code.  Memory
 * failures are reported as such; anything else maps to FALLBACK.  With
 * verbose logging enabled the OpenSSL diagnostics are logged. */
gcry_err_code_t
_gcry_err_from_openssl(gcry_err_code_t fallback)
{
    gcry_err_code_t rc = fallback;
    unsigned long e;

    while ((e = ERR_get_error()) != 0) {
        if (ERR_GET_REASON(e) == ERR_R_MALLOC_FAILURE) {
            rc = GPG_ERR_ENOMEM;
        }

        if (_gcry_log_verbosity() > 1) {
            char buf[256];

            ERR_error_string_n(e, buf, sizeof buf);
            log_debug("openssl: %s\n", buf);
        }
    }

    return rc;
}
