/*
 * error.c - Error code and error source descriptions, errno mapping.
 *
 * The numeric values and description strings come from the libgpg-error
 * data tables (see err-tables.h) so that error values are interchangeable
 * with a real libgpg-error.
 */
#include "gcrypt-int.h"

#include <errno.h>
#include <string.h>

#include "err-tables.h"

static const char *
lookup_code_desc(unsigned int code)
{
    size_t lo = 0;
    size_t hi = DIM(errcode_descs);

    /* The table is sorted by code; binary search. */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;

        if (errcode_descs[mid].code == code) {
            return errcode_descs[mid].desc;
        }

        if (errcode_descs[mid].code < code) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    return NULL;
}

gcry_err_code_t
gcry_err_code_from_errno(int err)
{
    size_t i;

    if (!err) {
        return GPG_ERR_NO_ERROR;
    }

    for (i = 0; i < DIM(errno_maps); i++) {
        if (errno_maps[i].err == err) {
            return (gcry_err_code_t)(GPG_ERR_SYSTEM_ERROR
                                     | errno_maps[i].idx);
        }
    }

    return GPG_ERR_UNKNOWN_ERRNO;
}

int
gcry_err_code_to_errno(gcry_err_code_t code)
{
    unsigned int idx;
    size_t i;

    if (!((unsigned int)code & GPG_ERR_SYSTEM_ERROR)) {
        return 0;
    }

    idx = (unsigned int)code & (GPG_ERR_SYSTEM_ERROR - 1);

    for (i = 0; i < DIM(errno_maps); i++) {
        if (errno_maps[i].idx == idx) {
            return errno_maps[i].err;
        }
    }

    return 0;
}

gcry_error_t
gcry_err_make_from_errno(gcry_err_source_t source, int err)
{
    return gcry_err_make(source, gcry_err_code_from_errno(err));
}

gcry_error_t
gcry_error_from_errno(int err)
{
    return gcry_err_make_from_errno(GPG_ERR_SOURCE_GCRYPT, err);
}

const char *
gcry_strerror(gcry_error_t err)
{
    gcry_err_code_t code = gcry_err_code(err);
    const char *desc;

    if ((unsigned int)code & GPG_ERR_SYSTEM_ERROR) {
        int e = gcry_err_code_to_errno(code);

        if (e) {
            return strerror(e);
        }

        return "Unknown system error";
    }

    desc = lookup_code_desc((unsigned int)code);
    return desc ? desc : "Unknown error code";
}

const char *
gcry_strsource(gcry_error_t err)
{
    unsigned int src = (unsigned int)gcry_err_source(err);
    size_t i;

    for (i = 0; i < DIM(errsrc_descs); i++) {
        if (errsrc_descs[i].src == src) {
            return errsrc_descs[i].desc;
        }
    }

    return "Unknown source";
}

gcry_err_code_t
_gcry_err_code_from_syserror(void)
{
    int err = errno;

    if (!err) {
        return GPG_ERR_MISSING_ERRNO;
    }

    return gcry_err_code_from_errno(err);
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
