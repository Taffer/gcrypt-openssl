/*
 * md-stub.c - TEMPORARY STUB, removed at merge.
 *
 * gcry_pk_hash_sign/verify use a few gcry_md_* functions when a hash
 * handle is passed.  The message digest module is developed separately;
 * until it is merged these stubs keep the shared library linking.  They
 * report "not implemented" so the hash-handle paths fail cleanly.
 */
#include "gcrypt-int.h"

gcry_error_t
gcry_md_copy(gcry_md_hd_t *bhd, gcry_md_hd_t ahd)
{
    (void)ahd;
    *bhd = NULL;
    return GCRY_ERR(GPG_ERR_NOT_IMPLEMENTED);
}

void
gcry_md_close(gcry_md_hd_t hd)
{
    (void)hd;
}

int
gcry_md_get_algo(gcry_md_hd_t hd)
{
    (void)hd;
    return 0;
}

const char *
gcry_md_algo_name(int algo)
{
    return _gcry_pk_md_gcry_name(algo);
}

unsigned int
gcry_md_get_algo_dlen(int algo)
{
    return _gcry_pk_md_dlen(algo);
}

unsigned char *
gcry_md_read(gcry_md_hd_t hd, int algo)
{
    (void)hd;
    (void)algo;
    return NULL;
}

int
gcry_md_map_name(const char *name)
{
    if (!name) {
        return 0;
    }

    return _gcry_pk_util_hash_algo_from_name(name, strlen(name));
}
