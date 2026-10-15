/*
 * mpi-ec.c - Elliptic curve contexts and point arithmetic.
 *
 * The curve operations (gcry_mpi_ec_*) are implemented on top of OpenSSL's
 * EC_GROUP/EC_POINT API; see the public key module for the users.
 */
#include "gcrypt-int.h"

void
_gcry_log_printpnt(const char *text, gcry_mpi_point_t point, gcry_ctx_t ctx)
{
    (void)ctx;

    if (text && *text) {
        _gcry_log(GCRY_LOG_DEBUG, "%s:\n", text);
    }

    if (!point) {
        _gcry_log(GCRY_LOG_DEBUG, "  (null)\n");
        return;
    }

    gcry_log_debugmpi("  x", point->x);
    gcry_log_debugmpi("  y", point->y);
    gcry_log_debugmpi("  z", point->z);
}
