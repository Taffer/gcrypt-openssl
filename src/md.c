/*
 * md.c - Message digests (gcry_md_*).
 *
 * Every hash function is provided by OpenSSL's EVP_MD interface; the HMAC
 * flavour of a handle uses EVP_MAC "HMAC" and keyed BLAKE2 uses the
 * BLAKE2BMAC/BLAKE2SMAC algorithms.  The only algorithms computed here are
 * the three CRC checksums, which are not cryptographic.
 */
#include "gcrypt-int.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

/* ------------------------------------------------------------------ */
/* Algorithm table                                                     */
/* ------------------------------------------------------------------ */

#define MD_F_FIPS 1u     /* Approved algorithm. */
#define MD_F_XOF 2u      /* Extendable output function. */
#define MD_F_CRC 4u      /* Implemented here, not by OpenSSL. */
#define MD_F_BLAKE2B 8u  /* BLAKE2b family (size parameter). */
#define MD_F_BLAKE2S 16u /* BLAKE2s family (size parameter). */
#define MD_F_CSHAKE 32u  /* cSHAKE: supports customisation. */

struct md_spec {
    int algo;
    const char *name;
    const char *ossl;          /* OpenSSL algorithm name, NULL if none. */
    unsigned int mdlen;
    unsigned int flags;
    const unsigned char *asn;  /* DER DigestInfo prefix. */
    unsigned int asnlen;
    const char *const *oids;   /* NULL terminated list. */
};

/* DER encodings of DigestInfo prefixes (AlgorithmIdentifier with NULL
 * parameters followed by the OCTET STRING header). */
static const unsigned char asn_md5[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x02, 0x05, 0x05, 0x00, 0x04, 0x10
};
static const unsigned char asn_md4[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x02, 0x04, 0x05, 0x00, 0x04, 0x10
};
static const unsigned char asn_sha1[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
    0x00, 0x04, 0x14
};
static const unsigned char asn_rmd160[] = {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x14
};
static const unsigned char asn_sha224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};
static const unsigned char asn_sha256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char asn_sha384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const unsigned char asn_sha512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};
static const unsigned char asn_sha512_224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c
};
static const unsigned char asn_sha512_256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char asn_sha3_224[] = {
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c
};
static const unsigned char asn_sha3_256[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char asn_sha3_384[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30
};
static const unsigned char asn_sha3_512[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40
};
static const unsigned char asn_shake128[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x0b, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char asn_shake256[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x0c, 0x05, 0x00, 0x04, 0x40
};
static const unsigned char asn_sm3[] = {
    0x30, 0x2f, 0x30, 0x0b, 0x06, 0x07, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x83,
    0x11, 0x05, 0x00, 0x04, 0x20
};
/* The reference implementation has no real DigestInfo for BLAKE2 and
 * returns a one byte placeholder. */
static const unsigned char asn_blake2[] = { 0x30 };

static const char *const oids_md5[] = {
    "1.2.840.113549.1.1.4", "1.2.840.113549.2.5", NULL
};
static const char *const oids_sha1[] = {
    "1.2.840.113549.1.1.5", "1.2.840.10040.4.3", "1.3.14.3.2.26",
    "1.3.14.3.2.29", "1.2.840.10045.4.1", NULL
};
static const char *const oids_rmd160[] = {
    "1.3.36.3.3.1.2", "1.3.36.3.2.1", NULL
};
static const char *const oids_tiger1[] = { "1.3.6.1.4.1.11591.12.2", NULL };
static const char *const oids_sha224[] = {
    "2.16.840.1.101.3.4.2.4", "1.2.840.10045.4.3.1", NULL
};
static const char *const oids_sha256[] = {
    "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", "1.2.840.10045.4.3.2",
    NULL
};
static const char *const oids_sha384[] = {
    "2.16.840.1.101.3.4.2.2", "1.2.840.113549.1.1.12", "1.2.840.10045.4.3.3",
    NULL
};
static const char *const oids_sha512[] = {
    "2.16.840.1.101.3.4.2.3", "1.2.840.113549.1.1.13", "1.2.840.10045.4.3.4",
    NULL
};
static const char *const oids_sha512_224[] = { "2.16.840.1.101.3.4.2.5", NULL };
static const char *const oids_sha512_256[] = { "2.16.840.1.101.3.4.2.6", NULL };
static const char *const oids_md4[] = { "1.2.840.113549.2.4", NULL };
static const char *const oids_sm3[] = { "1.2.156.10197.401", NULL };
static const char *const oids_sha3_224[] = {
    "2.16.840.1.101.3.4.2.7", "2.16.840.1.101.3.4.3.13",
    "2.16.840.1.101.3.4.3.9", NULL
};
static const char *const oids_sha3_256[] = {
    "2.16.840.1.101.3.4.2.8", "2.16.840.1.101.3.4.3.14",
    "2.16.840.1.101.3.4.3.10", NULL
};
static const char *const oids_sha3_384[] = {
    "2.16.840.1.101.3.4.2.9", "2.16.840.1.101.3.4.3.15",
    "2.16.840.1.101.3.4.3.11", NULL
};
static const char *const oids_sha3_512[] = {
    "2.16.840.1.101.3.4.2.10", "2.16.840.1.101.3.4.3.16",
    "2.16.840.1.101.3.4.3.12", NULL
};
static const char *const oids_shake128[] = {
    "2.16.840.1.101.3.4.2.11", "1.3.6.1.5.5.7.6.30", "1.3.6.1.5.5.7.6.32", NULL
};
static const char *const oids_shake256[] = {
    "2.16.840.1.101.3.4.2.12", "1.3.6.1.5.5.7.6.31", "1.3.6.1.5.5.7.6.33", NULL
};
static const char *const oids_blake2b_512[] = { "1.3.6.1.4.1.1722.12.2.1.16", NULL };
static const char *const oids_blake2b_384[] = { "1.3.6.1.4.1.1722.12.2.1.12", NULL };
static const char *const oids_blake2b_256[] = { "1.3.6.1.4.1.1722.12.2.1.8", NULL };
static const char *const oids_blake2b_160[] = { "1.3.6.1.4.1.1722.12.2.1.5", NULL };
static const char *const oids_blake2s_256[] = { "1.3.6.1.4.1.1722.12.2.2.8", NULL };
static const char *const oids_blake2s_224[] = { "1.3.6.1.4.1.1722.12.2.2.7", NULL };
static const char *const oids_blake2s_160[] = { "1.3.6.1.4.1.1722.12.2.2.5", NULL };
static const char *const oids_blake2s_128[] = { "1.3.6.1.4.1.1722.12.2.2.4", NULL };

#define ASN(a) a, (unsigned int)sizeof(a)

static const struct md_spec md_specs[] = {
    { GCRY_MD_MD5, "MD5", "MD5", 16, 0, ASN(asn_md5), oids_md5 },
    { GCRY_MD_SHA1, "SHA1", "SHA1", 20, MD_F_FIPS, ASN(asn_sha1), oids_sha1 },
    { GCRY_MD_RMD160, "RIPEMD160", "RIPEMD160", 20, 0, ASN(asn_rmd160), oids_rmd160 },
    { GCRY_MD_MD2, "MD2", "MD2", 16, 0, NULL, 0, NULL },
    { GCRY_MD_TIGER, "TIGER192", NULL, 24, 0, NULL, 0, NULL },
    { GCRY_MD_HAVAL, "HAVAL", NULL, 20, 0, NULL, 0, NULL },
    { GCRY_MD_SHA256, "SHA256", "SHA256", 32, MD_F_FIPS, ASN(asn_sha256), oids_sha256 },
    { GCRY_MD_SHA384, "SHA384", "SHA384", 48, MD_F_FIPS, ASN(asn_sha384), oids_sha384 },
    { GCRY_MD_SHA512, "SHA512", "SHA512", 64, MD_F_FIPS, ASN(asn_sha512), oids_sha512 },
    { GCRY_MD_SHA224, "SHA224", "SHA224", 28, MD_F_FIPS, ASN(asn_sha224), oids_sha224 },
    { GCRY_MD_MD4, "MD4", "MD4", 16, 0, ASN(asn_md4), oids_md4 },
    { GCRY_MD_CRC32, "CRC32", NULL, 4, MD_F_CRC, NULL, 0, NULL },
    { GCRY_MD_CRC32_RFC1510, "CRC32RFC1510", NULL, 4, MD_F_CRC, NULL, 0, NULL },
    { GCRY_MD_CRC24_RFC2440, "CRC24RFC2440", NULL, 3, MD_F_CRC, NULL, 0, NULL },
    { GCRY_MD_WHIRLPOOL, "WHIRLPOOL", "WHIRLPOOL", 64, 0, NULL, 0, NULL },
    { GCRY_MD_TIGER1, "TIGER", NULL, 24, 0, NULL, 0, oids_tiger1 },
    { GCRY_MD_TIGER2, "TIGER2", NULL, 24, 0, NULL, 0, NULL },
    { GCRY_MD_GOSTR3411_94, "GOSTR3411_94", NULL, 32, 0, NULL, 0, NULL },
    { GCRY_MD_STRIBOG256, "STRIBOG256", NULL, 32, 0, NULL, 0, NULL },
    { GCRY_MD_STRIBOG512, "STRIBOG512", NULL, 64, 0, NULL, 0, NULL },
    { GCRY_MD_GOSTR3411_CP, "GOSTR3411_CP", NULL, 32, 0, NULL, 0, NULL },
    { GCRY_MD_SHA3_224, "SHA3-224", "SHA3-224", 28, MD_F_FIPS, ASN(asn_sha3_224), oids_sha3_224 },
    { GCRY_MD_SHA3_256, "SHA3-256", "SHA3-256", 32, MD_F_FIPS, ASN(asn_sha3_256), oids_sha3_256 },
    { GCRY_MD_SHA3_384, "SHA3-384", "SHA3-384", 48, MD_F_FIPS, ASN(asn_sha3_384), oids_sha3_384 },
    { GCRY_MD_SHA3_512, "SHA3-512", "SHA3-512", 64, MD_F_FIPS, ASN(asn_sha3_512), oids_sha3_512 },
    { GCRY_MD_SHAKE128, "SHAKE128", "SHAKE128", 32, MD_F_FIPS | MD_F_XOF, ASN(asn_shake128), oids_shake128 },
    { GCRY_MD_SHAKE256, "SHAKE256", "SHAKE256", 64, MD_F_FIPS | MD_F_XOF, ASN(asn_shake256), oids_shake256 },
    { GCRY_MD_BLAKE2B_512, "BLAKE2B_512", "BLAKE2B512", 64, MD_F_BLAKE2B, ASN(asn_blake2), oids_blake2b_512 },
    { GCRY_MD_BLAKE2B_384, "BLAKE2B_384", "BLAKE2B512", 48, MD_F_BLAKE2B, ASN(asn_blake2), oids_blake2b_384 },
    { GCRY_MD_BLAKE2B_256, "BLAKE2B_256", "BLAKE2B512", 32, MD_F_BLAKE2B, ASN(asn_blake2), oids_blake2b_256 },
    { GCRY_MD_BLAKE2B_160, "BLAKE2B_160", "BLAKE2B512", 20, MD_F_BLAKE2B, ASN(asn_blake2), oids_blake2b_160 },
    { GCRY_MD_BLAKE2S_256, "BLAKE2S_256", "BLAKE2S256", 32, MD_F_BLAKE2S, ASN(asn_blake2), oids_blake2s_256 },
    { GCRY_MD_BLAKE2S_224, "BLAKE2S_224", "BLAKE2S256", 28, MD_F_BLAKE2S, ASN(asn_blake2), oids_blake2s_224 },
    { GCRY_MD_BLAKE2S_160, "BLAKE2S_160", "BLAKE2S256", 20, MD_F_BLAKE2S, ASN(asn_blake2), oids_blake2s_160 },
    { GCRY_MD_BLAKE2S_128, "BLAKE2S_128", "BLAKE2S256", 16, MD_F_BLAKE2S, ASN(asn_blake2), oids_blake2s_128 },
    { GCRY_MD_SM3, "SM3", "SM3", 32, 0, ASN(asn_sm3), oids_sm3 },
    { GCRY_MD_SHA512_256, "SHA512_256", "SHA512-256", 32, MD_F_FIPS, ASN(asn_sha512_256), oids_sha512_256 },
    { GCRY_MD_SHA512_224, "SHA512_224", "SHA512-224", 28, MD_F_FIPS, ASN(asn_sha512_224), oids_sha512_224 },
    { GCRY_MD_CSHAKE128, "CSHAKE128", "CSHAKE128", 32, MD_F_FIPS | MD_F_XOF | MD_F_CSHAKE, NULL, 0, NULL },
    { GCRY_MD_CSHAKE256, "CSHAKE256", "CSHAKE256", 64, MD_F_FIPS | MD_F_XOF | MD_F_CSHAKE, NULL, 0, NULL },
};

static const struct md_spec *
spec_from_algo(int algo)
{
    size_t i;

    for (i = 0; i < DIM(md_specs); i++) {
        if (md_specs[i].algo == algo) {
            return &md_specs[i];
        }
    }

    return NULL;
}

static const struct md_spec *
spec_from_name(const char *name)
{
    size_t i;

    for (i = 0; i < DIM(md_specs); i++) {
        if (!strcasecmp(name, md_specs[i].name)) {
            return &md_specs[i];
        }
    }

    return NULL;
}

static const struct md_spec *
spec_from_oid(const char *oid)
{
    size_t i;
    size_t j;

    if (!strncasecmp(oid, "oid.", 4)) {
        oid += 4;
    }

    for (i = 0; i < DIM(md_specs); i++) {
        if (!md_specs[i].oids) {
            continue;
        }

        for (j = 0; md_specs[i].oids[j]; j++) {
            if (!strcasecmp(oid, md_specs[i].oids[j])) {
                return &md_specs[i];
            }
        }
    }

    return NULL;
}

/* The OpenSSL name of the digest behind ALGO, or NULL if OpenSSL has no
 * such digest (or it is a CRC). */
const char *
_gcry_md_openssl_name(int algo)
{
    const struct md_spec *spec = spec_from_algo(algo);

    return spec ? spec->ossl : NULL;
}

/* For the truncated BLAKE2 variants: the "size" parameter that must be set
 * on the OpenSSL digest context; 0 if no parameter is needed. */
unsigned int
_gcry_md_reduced_size(int algo)
{
    const struct md_spec *spec = spec_from_algo(algo);

    if (!spec || !(spec->flags & (MD_F_BLAKE2B | MD_F_BLAKE2S))) {
        return 0;
    }

    if ((spec->flags & MD_F_BLAKE2B) && spec->mdlen == 64) {
        return 0;
    }

    if ((spec->flags & MD_F_BLAKE2S) && spec->mdlen == 32) {
        return 0;
    }

    return spec->mdlen;
}

/* Fetched EVP_MD objects, one slot per table entry.  EVP_MD_fetch walks
 * OpenSSL's method store by name, which is far more expensive than the
 * digest setup it precedes, so each algorithm is fetched once and the
 * object is kept for the lifetime of the process: the private library
 * context it belongs to is never torn down either. */
static EVP_MD *md_cache[DIM(md_specs)];
static pthread_mutex_t md_cache_lock = PTHREAD_MUTEX_INITIALIZER;

/* A reference to the digest behind ALGO, or NULL if OpenSSL has none.  The
 * caller releases it with EVP_MD_free. */
EVP_MD *
_gcry_md_fetch(int algo)
{
    const struct md_spec *spec = spec_from_algo(algo);
    OSSL_LIB_CTX *libctx;
    const char *propq;
    EVP_MD *md;
    size_t idx;

    if (!spec || !spec->ossl) {
        return NULL;
    }

    /* Finish global initialisation before taking the lock: it may use
     * this function itself. */
    libctx = _gcry_libctx();
    propq = _gcry_propq();
    idx = (size_t)(spec - md_specs);

    pthread_mutex_lock(&md_cache_lock);
    md = md_cache[idx];

    if (!md) {
        md = EVP_MD_fetch(libctx, spec->ossl, propq);

        if (!md) {
            ERR_clear_error();
        }

        md_cache[idx] = md;
    }

    if (md && !EVP_MD_up_ref(md)) {
        ERR_clear_error();
        md = NULL;
    }

    pthread_mutex_unlock(&md_cache_lock);
    return md;
}

/* GPG_ERR_DIGEST_ALGO unless ALGO can actually be used. */
static gcry_err_code_t
check_digest_algo(int algo)
{
    const struct md_spec *spec = spec_from_algo(algo);
    EVP_MD *md;

    if (!spec) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (spec->flags & MD_F_CRC) {
        return 0;
    }

    md = _gcry_md_fetch(algo);

    if (!md) {
        return GPG_ERR_DIGEST_ALGO;
    }

    EVP_MD_free(md);
    return 0;
}

/* ------------------------------------------------------------------ */
/* CRC checksums                                                       */
/* ------------------------------------------------------------------ */

/* CRC tables, built on first use.  CRC-32 (ISO 3309, reflected polynomial
 * 0xEDB88320) is computed eight bytes at a time with the "slicing by 8"
 * tables; CRC-24 (OpenPGP, RFC 4880, polynomial 0x1864CFB, MSB first) with
 * a single byte table.  Shared by GCRY_MD_CRC32 and the RFC 1510 variant,
 * which differ only in their initial value and final inversion. */
static uint32_t crc32_table[8][256];
static uint32_t crc24_table[256];
static pthread_once_t crc_tables_once = PTHREAD_ONCE_INIT;

static void
crc_tables_init(void)
{
    unsigned int i;
    unsigned int k;

    for (i = 0; i < 256; i++) {
        uint32_t c = i;

        for (k = 0; k < 8; k++) {
            c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
        }

        crc32_table[0][i] = c;
    }

    for (i = 0; i < 256; i++) {
        uint32_t c = crc32_table[0][i];

        for (k = 1; k < 8; k++) {
            c = crc32_table[0][c & 0xffu] ^ (c >> 8);
            crc32_table[k][i] = c;
        }
    }

    for (i = 0; i < 256; i++) {
        uint32_t c = (uint32_t)i << 16;

        for (k = 0; k < 8; k++) {
            c <<= 1;

            if (c & 0x1000000u) {
                c ^= 0x1864cfbu;
            }
        }

        crc24_table[i] = c & 0xffffffu;
    }
}

static uint32_t
crc32_update(uint32_t crc, const unsigned char *buf, size_t len)
{
    pthread_once(&crc_tables_once, crc_tables_init);

    /* Align to eight bytes so the wide loop reads naturally aligned words
     * (through memcpy, so no alignment is actually assumed). */
    while (len && ((uintptr_t)buf & 7u)) {
        crc = crc32_table[0][(crc ^ *buf++) & 0xffu] ^ (crc >> 8);
        len--;
    }

    while (len >= 8) {
        uint32_t lo;
        uint32_t hi;

        memcpy(&lo, buf, 4);
        memcpy(&hi, buf + 4, 4);
        lo ^= crc;
        crc = crc32_table[7][lo & 0xffu]
              ^ crc32_table[6][(lo >> 8) & 0xffu]
              ^ crc32_table[5][(lo >> 16) & 0xffu]
              ^ crc32_table[4][lo >> 24]
              ^ crc32_table[3][hi & 0xffu]
              ^ crc32_table[2][(hi >> 8) & 0xffu]
              ^ crc32_table[1][(hi >> 16) & 0xffu]
              ^ crc32_table[0][hi >> 24];
        buf += 8;
        len -= 8;
    }

    while (len--) {
        crc = crc32_table[0][(crc ^ *buf++) & 0xffu] ^ (crc >> 8);
    }

    return crc;
}

static uint32_t
crc24_update(uint32_t crc, const unsigned char *buf, size_t len)
{
    pthread_once(&crc_tables_once, crc_tables_init);

    while (len--) {
        crc = (crc << 8) ^ crc24_table[((crc >> 16) ^ *buf++) & 0xffu];
    }

    return crc & 0xffffffu;
}

/* ------------------------------------------------------------------ */
/* Handle structures                                                   */
/* ------------------------------------------------------------------ */

struct md_entry {
    struct md_entry *next;
    const struct md_spec *spec;
    EVP_MD *md;
    EVP_MD_CTX *mdctx;        /* Plain digest. */
    EVP_MAC *mac;
    EVP_MAC_CTX *macctx;      /* HMAC or keyed BLAKE2. */
    int keyed;                /* MAC context is in use. */
    unsigned char *cust_n;    /* cSHAKE function name. */
    size_t cust_nlen;
    unsigned char *cust_s;    /* cSHAKE customisation string. */
    size_t cust_slen;
    uint32_t crc;
    unsigned char digest[64];
    int have_digest;
};

struct gcry_md_context {
    size_t actual_handle_size;
    unsigned int secure : 1;
    unsigned int hmac : 1;
    unsigned int finalized : 1;
    unsigned int bugemu1 : 1;
    struct md_entry *list;
    unsigned char *key;       /* HMAC key. */
    size_t keylen;
    FILE *debug;
};

union md_align {
    long l;
    double d;
    void *p;
};

static void *
md_alloc(const struct gcry_md_context *ctx, size_t n)
{
    return ctx->secure ? _gcry_malloc_secure(n) : _gcry_malloc(n);
}

/* Copy of a cSHAKE customisation string with a terminating NUL, which
 * OpenSSL expects even though it is also told the length. */
static unsigned char *
md_dup_string(const struct gcry_md_context *ctx, const void *s, size_t n)
{
    unsigned char *p = md_alloc(ctx, n + 1);

    if (p) {
        memcpy(p, s, n);
        p[n] = 0;
    }

    return p;
}

/* ------------------------------------------------------------------ */
/* Per algorithm state                                                 */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
entry_init_digest(struct md_entry *e)
{
    OSSL_PARAM params[3];
    size_t np = 0;
    size_t size = e->spec->mdlen;

    if (!e->mdctx) {
        e->mdctx = EVP_MD_CTX_new();

        if (!e->mdctx) {
            return GPG_ERR_ENOMEM;
        }
    }

    if (_gcry_md_reduced_size(e->spec->algo)) {
        params[np++] = OSSL_PARAM_construct_size_t(OSSL_DIGEST_PARAM_SIZE,
                                                   &size);
    }

    /* OpenSSL takes the cSHAKE function name and customisation string as
     * UTF-8 string parameters with an explicit length. */
    if ((e->spec->flags & MD_F_CSHAKE) && (e->cust_nlen || e->cust_slen)) {
        if (e->cust_nlen) {
            params[np++] = OSSL_PARAM_construct_utf8_string(
                               OSSL_DIGEST_PARAM_FUNCTION_NAME,
                               (char *)e->cust_n, e->cust_nlen);
        }

        if (e->cust_slen) {
            params[np++] = OSSL_PARAM_construct_utf8_string(
                               OSSL_DIGEST_PARAM_CUSTOMIZATION,
                               (char *)e->cust_s, e->cust_slen);
        }
    }

    params[np] = OSSL_PARAM_construct_end();

    if (!EVP_DigestInit_ex2(e->mdctx, e->md, np ? params : NULL)) {
        return _gcry_err_from_openssl(GPG_ERR_DIGEST_ALGO);
    }

    return 0;
}

/* (Re)initialise the HMAC context of E with KEY. */
static gcry_err_code_t
entry_init_hmac(struct md_entry *e, const unsigned char *key, size_t keylen)
{
    OSSL_PARAM params[2];

    if (!e->mac) {
        e->mac = EVP_MAC_fetch(_gcry_libctx(), "HMAC", _gcry_propq());

        if (!e->mac) {
            return _gcry_err_from_openssl(GPG_ERR_DIGEST_ALGO);
        }
    }

    if (!e->macctx) {
        e->macctx = EVP_MAC_CTX_new(e->mac);

        if (!e->macctx) {
            return GPG_ERR_ENOMEM;
        }
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)(uintptr_t)e->spec->ossl, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(e->macctx, key ? key : (const unsigned char *)"",
                      keylen, params)) {
        return _gcry_err_from_openssl(GPG_ERR_DIGEST_ALGO);
    }

    e->keyed = 1;
    return 0;
}

/* Keyed BLAKE2 (the digest's own key input, not HMAC). */
static gcry_err_code_t
entry_init_keyed_blake2(struct md_entry *e, const unsigned char *key,
                        size_t keylen)
{
    OSSL_PARAM params[2];
    size_t size = e->spec->mdlen;
    const char *macname = (e->spec->flags & MD_F_BLAKE2B) ? "BLAKE2BMAC"
                          : "BLAKE2SMAC";

    if (!e->mac) {
        e->mac = EVP_MAC_fetch(_gcry_libctx(), macname, _gcry_propq());

        if (!e->mac) {
            return _gcry_err_from_openssl(GPG_ERR_DIGEST_ALGO);
        }
    }

    if (!e->macctx) {
        e->macctx = EVP_MAC_CTX_new(e->mac);

        if (!e->macctx) {
            return GPG_ERR_ENOMEM;
        }
    }

    params[0] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(e->macctx, key, keylen, params)) {
        return _gcry_err_from_openssl(GPG_ERR_INV_KEYLEN);
    }

    e->keyed = 1;
    return 0;
}

/* Back to the state right after enabling (and, if any, keying). */
static gcry_err_code_t
entry_reset(struct gcry_md_context *ctx, struct md_entry *e)
{
    e->have_digest = 0;
    memset(e->digest, 0, sizeof e->digest);

    if (e->spec->flags & MD_F_CRC) {
        switch (e->spec->algo) {
        case GCRY_MD_CRC32:
            e->crc = 0xffffffffu;
            break;

        case GCRY_MD_CRC32_RFC1510:
            e->crc = 0;
            break;

        default:
            e->crc = 0xb704ceu;
            break;
        }

        return 0;
    }

    if (ctx->hmac) {
        return entry_init_hmac(e, ctx->key, ctx->keylen);
    }

    if (e->keyed) {
        /* Keyed BLAKE2: EVP_MAC_init with a NULL key reuses the key. */
        if (!EVP_MAC_init(e->macctx, NULL, 0, NULL)) {
            return _gcry_err_from_openssl(GPG_ERR_INTERNAL);
        }

        return 0;
    }

    return entry_init_digest(e);
}

static void
entry_write(struct md_entry *e, const unsigned char *buf, size_t len)
{
    if (!len) {
        return;
    }

    if (e->spec->flags & MD_F_CRC) {
        if (e->spec->algo == GCRY_MD_CRC24_RFC2440) {
            e->crc = crc24_update(e->crc, buf, len);
        } else {
            e->crc = crc32_update(e->crc, buf, len);
        }

        return;
    }

    if (e->keyed) {
        if (!EVP_MAC_update(e->macctx, buf, len)) {
            ERR_clear_error();
        }

        return;
    }

    if (!EVP_DigestUpdate(e->mdctx, buf, len)) {
        ERR_clear_error();
    }
}

static void
entry_final(struct md_entry *e)
{
    if (e->have_digest) {
        return;
    }

    if (e->spec->flags & MD_F_CRC) {
        uint32_t v = e->crc;

        if (e->spec->algo == GCRY_MD_CRC32) {
            v ^= 0xffffffffu;
        }

        if (e->spec->algo == GCRY_MD_CRC24_RFC2440) {
            e->digest[0] = (unsigned char)(v >> 16);
            e->digest[1] = (unsigned char)(v >> 8);
            e->digest[2] = (unsigned char)v;
        } else {
            e->digest[0] = (unsigned char)(v >> 24);
            e->digest[1] = (unsigned char)(v >> 16);
            e->digest[2] = (unsigned char)(v >> 8);
            e->digest[3] = (unsigned char)v;
        }

        e->have_digest = 1;
        return;
    }

    if (e->keyed) {
        size_t outl = 0;

        if (!EVP_MAC_final(e->macctx, e->digest, &outl, sizeof e->digest)) {
            ERR_clear_error();
        }

        e->have_digest = 1;
        return;
    }

    if (e->spec->flags & MD_F_XOF) {
        /* Nothing to do: output is squeezed on demand. */
        return;
    }

    {
        unsigned int outl = 0;

        if (!EVP_DigestFinal_ex(e->mdctx, e->digest, &outl)) {
            ERR_clear_error();
        }
    }

    e->have_digest = 1;
}

static void
entry_free(struct gcry_md_context *ctx, struct md_entry *e)
{
    EVP_MD_CTX_free(e->mdctx);
    EVP_MD_free(e->md);
    EVP_MAC_CTX_free(e->macctx);
    EVP_MAC_free(e->mac);
    _gcry_free(e->cust_n);
    _gcry_free(e->cust_s);
    _gcry_wipememory(e, sizeof * e);
    (void)ctx;
    _gcry_free(e);
}

static struct md_entry *
entry_dup(struct gcry_md_context *ctx, const struct md_entry *src)
{
    struct md_entry *e = md_alloc(ctx, sizeof * e);

    if (!e) {
        return NULL;
    }

    memset(e, 0, sizeof * e);
    e->spec = src->spec;
    e->crc = src->crc;
    e->have_digest = src->have_digest;
    e->keyed = src->keyed;
    memcpy(e->digest, src->digest, sizeof e->digest);

    if (src->md) {
        if (!EVP_MD_up_ref(src->md)) {
            goto fail;
        }

        e->md = src->md;
    }

    if (src->mac) {
        if (!EVP_MAC_up_ref(src->mac)) {
            goto fail;
        }

        e->mac = src->mac;
    }

    if (src->mdctx) {
        e->mdctx = EVP_MD_CTX_dup(src->mdctx);

        if (!e->mdctx) {
            goto fail;
        }
    }

    if (src->macctx) {
        e->macctx = EVP_MAC_CTX_dup(src->macctx);

        if (!e->macctx) {
            goto fail;
        }
    }

    if (src->cust_nlen) {
        e->cust_n = md_dup_string(ctx, src->cust_n, src->cust_nlen);

        if (!e->cust_n) {
            goto fail;
        }

        e->cust_nlen = src->cust_nlen;
    }

    if (src->cust_slen) {
        e->cust_s = md_dup_string(ctx, src->cust_s, src->cust_slen);

        if (!e->cust_s) {
            goto fail;
        }

        e->cust_slen = src->cust_slen;
    }

    return e;

fail:
    ERR_clear_error();
    entry_free(ctx, e);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Handle management                                                   */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
md_enable(gcry_md_hd_t hd, int algo)
{
    struct gcry_md_context *ctx = hd->ctx;
    const struct md_spec *spec;
    struct md_entry *e;
    gcry_err_code_t rc;

    for (e = ctx->list; e; e = e->next) {
        if (e->spec->algo == algo) {
            return 0; /* Already enabled. */
        }
    }

    spec = spec_from_algo(algo);

    if (!spec) {
        log_debug("md_enable: algorithm %d not available\n", algo);
        return GPG_ERR_DIGEST_ALGO;
    }

    if (ctx->hmac && (spec->flags & (MD_F_XOF | MD_F_CRC))) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (ctx->hmac && _gcry_md_reduced_size(algo)) {
        /* OpenSSL's HMAC cannot be parameterised with a truncated BLAKE2
         * output length. */
        return GPG_ERR_DIGEST_ALGO;
    }

    e = md_alloc(ctx, sizeof * e);

    if (!e) {
        return _gcry_err_code_from_syserror();
    }

    memset(e, 0, sizeof * e);
    e->spec = spec;

    if (!(spec->flags & MD_F_CRC)) {
        e->md = _gcry_md_fetch(algo);

        if (!e->md) {
            _gcry_free(e);
            return GPG_ERR_DIGEST_ALGO;
        }
    }

    rc = entry_reset(ctx, e);

    if (rc) {
        entry_free(ctx, e);
        return rc;
    }

    e->next = ctx->list;
    ctx->list = e;
    return 0;
}

static gcry_err_code_t
md_open(gcry_md_hd_t *r_hd, int algo, unsigned int flags)
{
    int secure = !!(flags & GCRY_MD_FLAG_SECURE);
    size_t bufsize = secure ? 512 : 1024;
    size_t n;
    gcry_md_hd_t hd;
    struct gcry_md_context *ctx;
    gcry_err_code_t rc;

    *r_hd = NULL;

    if (flags & ~(unsigned int)(GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC
                                | GCRY_MD_FLAG_BUGEMU1)) {
        return GPG_ERR_INV_ARG;
    }

    /* The caller visible part (pointer, buffer control, buffer) is followed
     * by the private context; the buffer is sized so that the context is
     * properly aligned. */
    n = offsetof(struct gcry_md_handle, buf) + bufsize;
    n = (n + sizeof(union md_align) - 1) / sizeof(union md_align)
        * sizeof(union md_align);

    hd = secure ? _gcry_malloc_secure(n + sizeof * ctx)
         : _gcry_malloc(n + sizeof * ctx);

    if (!hd) {
        return _gcry_err_code_from_syserror();
    }

    ctx = (struct gcry_md_context *)(void *)((unsigned char *)hd + n);
    memset(ctx, 0, sizeof * ctx);
    hd->ctx = ctx;
    hd->bufsize = (int)(n - offsetof(struct gcry_md_handle, buf));
    hd->bufpos = 0;
    ctx->actual_handle_size = n + sizeof * ctx;
    ctx->secure = secure ? 1u : 0u;
    ctx->hmac = (flags & GCRY_MD_FLAG_HMAC) ? 1u : 0u;
    ctx->bugemu1 = (flags & GCRY_MD_FLAG_BUGEMU1) ? 1u : 0u;

    if (algo) {
        rc = md_enable(hd, algo);

        if (rc) {
            _gcry_free(hd);
            return rc;
        }
    }

    *r_hd = hd;
    return 0;
}

static void
md_stop_debug(gcry_md_hd_t hd)
{
    if (hd->ctx->debug) {
        fflush(hd->ctx->debug);
        fclose(hd->ctx->debug);
        hd->ctx->debug = NULL;
    }
}

static void
md_start_debug(gcry_md_hd_t hd, const char *suffix)
{
    static int idx;
    char buf[50];

    if (!hd || !suffix) {
        return;
    }

    if (hd->ctx->debug) {
        log_debug("Oops: md debug already started\n");
        return;
    }

    idx++;
    snprintf(buf, sizeof buf, "dbgmd-%05d.%.10s", idx, suffix);
    hd->ctx->debug = fopen(buf, "w");

    if (!hd->ctx->debug) {
        log_debug("md debug: can't open %s\n", buf);
    }
}

static void
md_close(gcry_md_hd_t hd)
{
    struct gcry_md_context *ctx;
    struct md_entry *e;
    struct md_entry *next;

    if (!hd) {
        return;
    }

    ctx = hd->ctx;
    md_stop_debug(hd);

    for (e = ctx->list; e; e = next) {
        next = e->next;
        entry_free(ctx, e);
    }

    if (ctx->key) {
        _gcry_wipememory(ctx->key, ctx->keylen);
        _gcry_free(ctx->key);
    }

    /* Only the part of the buffer that was written holds caller data. */
    _gcry_wipememory(hd, offsetof(struct gcry_md_handle, buf)
                     + (size_t)hd->bufpos);
    _gcry_wipememory(ctx, sizeof * ctx);
    _gcry_free(hd);
}

static void
md_write(gcry_md_hd_t hd, const void *inbuf, size_t inlen)
{
    struct gcry_md_context *ctx = hd->ctx;
    struct md_entry *e;

    if (ctx->debug) {
        if (hd->bufpos
            && fwrite(hd->buf, (size_t)hd->bufpos, 1, ctx->debug) != 1) {
            BUG();
        }

        if (inlen && fwrite(inbuf, inlen, 1, ctx->debug) != 1) {
            BUG();
        }
    }

    for (e = ctx->list; e; e = e->next) {
        if (hd->bufpos) {
            entry_write(e, hd->buf, (size_t)hd->bufpos);
        }

        if (inlen) {
            entry_write(e, inbuf, inlen);
        }
    }

    hd->bufpos = 0;
}

static void
md_final(gcry_md_hd_t hd)
{
    struct md_entry *e;

    if (hd->ctx->finalized) {
        return;
    }

    if (hd->bufpos) {
        md_write(hd, NULL, 0);
    }

    for (e = hd->ctx->list; e; e = e->next) {
        entry_final(e);
    }

    hd->ctx->finalized = 1;
}

static struct md_entry *
find_entry(gcry_md_hd_t hd, int algo, const char *what)
{
    struct md_entry *e = hd->ctx->list;

    if (!algo) {
        if (e && e->next) {
            log_debug("more than one algorithm in %s(0)\n", what);
        }

        return e;
    }

    for (; e; e = e->next) {
        if (e->spec->algo == algo) {
            return e;
        }
    }

    return NULL;
}

static void
md_reset(gcry_md_hd_t hd)
{
    struct md_entry *e;

    hd->bufpos = 0;
    hd->ctx->finalized = 0;

    for (e = hd->ctx->list; e; e = e->next) {
        if (entry_reset(hd->ctx, e)) {
            log_error("md_reset: re-initialisation of %s failed\n",
                      e->spec->name);
        }
    }
}

static gcry_err_code_t
md_copy(gcry_md_hd_t ahd, gcry_md_hd_t *r_bhd)
{
    struct gcry_md_context *a = ahd->ctx;
    struct gcry_md_context *b;
    gcry_md_hd_t bhd;
    size_t n;
    struct md_entry *ae;
    struct md_entry **tail;

    *r_bhd = NULL;

    if (ahd->bufpos) {
        md_write(ahd, NULL, 0);
    }

    n = (size_t)((unsigned char *)a - (unsigned char *)ahd);
    bhd = a->secure ? _gcry_malloc_secure(n + sizeof * b)
          : _gcry_malloc(n + sizeof * b);

    if (!bhd) {
        return _gcry_err_code_from_syserror();
    }

    b = (struct gcry_md_context *)(void *)((unsigned char *)bhd + n);
    bhd->ctx = b;
    bhd->bufsize = ahd->bufsize;
    bhd->bufpos = 0;
    memcpy(b, a, sizeof * b);
    b->list = NULL;
    b->debug = NULL;
    b->key = NULL;
    b->keylen = 0;

    if (a->key) {
        b->key = md_alloc(b, a->keylen ? a->keylen : 1);

        if (!b->key) {
            md_close(bhd);
            return GPG_ERR_ENOMEM;
        }

        memcpy(b->key, a->key, a->keylen);
        b->keylen = a->keylen;
    }

    tail = &b->list;

    for (ae = a->list; ae; ae = ae->next) {
        struct md_entry *be = entry_dup(b, ae);

        if (!be) {
            md_close(bhd);
            return GPG_ERR_ENOMEM;
        }

        *tail = be;
        tail = &be->next;
    }

    if (a->debug) {
        md_start_debug(bhd, "unknown");
    }

    *r_bhd = bhd;
    return 0;
}

static gcry_err_code_t
md_setkey(gcry_md_hd_t hd, const void *key, size_t keylen)
{
    struct gcry_md_context *ctx = hd->ctx;
    struct md_entry *e;
    gcry_err_code_t rc = 0;
    int touched = 0;

    if (!ctx->list) {
        return GPG_ERR_DIGEST_ALGO;
    }

    if (ctx->hmac) {
        unsigned char *copy;

        if (keylen && !key) {
            return GPG_ERR_INV_ARG;
        }

        copy = md_alloc(ctx, keylen ? keylen : 1);

        if (!copy) {
            return _gcry_err_code_from_syserror();
        }

        if (keylen) {
            memcpy(copy, key, keylen);
        }

        if (ctx->key) {
            _gcry_wipememory(ctx->key, ctx->keylen);
            _gcry_free(ctx->key);
        }

        ctx->key = copy;
        ctx->keylen = keylen;
        md_reset(hd);
        return 0;
    }

    /* Plain handles: only keyed BLAKE2 accepts a key.  The algorithm is
     * checked before the arguments, as the reference library does. */
    for (e = ctx->list; e; e = e->next) {
        if (e->spec->flags & MD_F_BLAKE2B) {
            if (keylen > 64) {
                rc = GPG_ERR_INV_KEYLEN;
                break;
            }
        } else if (e->spec->flags & MD_F_BLAKE2S) {
            if (keylen > 32) {
                rc = GPG_ERR_INV_KEYLEN;
                break;
            }
        } else {
            rc = GPG_ERR_DIGEST_ALGO;
            break;
        }

        if (keylen && !key) {
            rc = GPG_ERR_INV_ARG;
            break;
        }

        touched = 1;
        rc = entry_init_keyed_blake2(e, key, keylen);

        if (rc) {
            break;
        }
    }

    if (rc) {
        if (touched) {
            md_reset(hd);
        }

        return rc;
    }

    hd->bufpos = 0;
    ctx->finalized = 0;
    return 0;
}

static gcry_err_code_t
md_customize(gcry_md_hd_t hd, const void *buffer, size_t buflen)
{
    struct gcry_md_context *ctx = hd->ctx;
    struct md_entry *e;
    gcry_err_code_t rc = 0;
    int touched = 0;

    if (!ctx->list) {
        return GPG_ERR_DIGEST_ALGO;
    }

    for (e = ctx->list; e; e = e->next) {
        const struct gcry_cshake_customization *c = buffer;

        if (!(e->spec->flags & MD_F_CSHAKE)) {
            rc = GPG_ERR_DIGEST_ALGO;
            break;
        }

        if (!buffer || buflen != sizeof * c) {
            rc = GPG_ERR_INV_ARG;
            break;
        }

        touched = 1;
        _gcry_free(e->cust_n);
        _gcry_free(e->cust_s);
        e->cust_n = NULL;
        e->cust_s = NULL;
        e->cust_nlen = 0;
        e->cust_slen = 0;

        if (c->n_len) {
            e->cust_n = md_dup_string(ctx, c->n, c->n_len);

            if (!e->cust_n) {
                rc = GPG_ERR_ENOMEM;
                break;
            }

            e->cust_nlen = c->n_len;
        }

        if (c->s_len) {
            e->cust_s = md_dup_string(ctx, c->s, c->s_len);

            if (!e->cust_s) {
                rc = GPG_ERR_ENOMEM;
                break;
            }

            e->cust_slen = c->s_len;
        }

        rc = entry_reset(ctx, e);

        if (rc) {
            /* OpenSSL only knows the NIST-defined function names, so a
             * customisation it rejects cannot be provided.  Drop it so the
             * handle keeps working as before the call. */
            _gcry_free(e->cust_n);
            _gcry_free(e->cust_s);
            e->cust_n = NULL;
            e->cust_s = NULL;
            e->cust_nlen = 0;
            e->cust_slen = 0;
            rc = GPG_ERR_NOT_SUPPORTED;
            break;
        }
    }

    if (rc && touched) {
        md_reset(hd);
    }

    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

gcry_error_t
gcry_md_open(gcry_md_hd_t *h, int algo, unsigned int flags)
{
    gcry_err_code_t rc;

    if (!h) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    _gcry_global_init();
    rc = md_open(h, algo, flags);
    return GCRY_ERR(rc);
}

void
gcry_md_close(gcry_md_hd_t hd)
{
    md_close(hd);
}

gcry_error_t
gcry_md_enable(gcry_md_hd_t hd, int algo)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(md_enable(hd, algo));
}

gcry_error_t
gcry_md_copy(gcry_md_hd_t *bhd, gcry_md_hd_t ahd)
{
    if (!bhd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (!ahd) {
        *bhd = NULL;
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(md_copy(ahd, bhd));
}

void
gcry_md_reset(gcry_md_hd_t hd)
{
    if (hd) {
        md_reset(hd);
    }
}

gcry_error_t
gcry_md_ctl(gcry_md_hd_t hd, int cmd, void *buffer, size_t buflen)
{
    gcry_err_code_t rc = 0;

    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    switch (cmd) {
    case GCRYCTL_FINALIZE:
        md_final(hd);
        break;

    case GCRYCTL_START_DUMP:
        md_start_debug(hd, buffer);
        break;

    case GCRYCTL_STOP_DUMP:
        md_stop_debug(hd);
        break;

    case GCRYCTL_MD_CUSTOMIZE:
        rc = md_customize(hd, buffer, buflen);
        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

void
gcry_md_write(gcry_md_hd_t hd, const void *buffer, size_t length)
{
    if (!hd) {
        return;
    }

    md_write(hd, buffer, length);
}

unsigned char *
gcry_md_read(gcry_md_hd_t hd, int algo)
{
    struct md_entry *e;

    if (!hd) {
        _gcry_fatal_error(GPG_ERR_INV_ARG, "gcry_md_read with NULL handle");
    }

    md_final(hd);
    e = find_entry(hd, algo, "md_read");

    if (!e) {
        _gcry_fatal_error(GPG_ERR_DIGEST_ALGO,
                          "requested algo not in md context");
    }

    if ((e->spec->flags & MD_F_XOF) && !e->have_digest) {
        /* Fixed-length output of an XOF: the first mdlen bytes. */
        if (!EVP_DigestSqueeze(e->mdctx, e->digest, e->spec->mdlen)) {
            ERR_clear_error();
        }

        e->have_digest = 1;
    }

    return e->digest;
}

gpg_error_t
gcry_md_extract(gcry_md_hd_t hd, int algo, void *buffer, size_t length)
{
    struct md_entry *e;

    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    md_final(hd);
    e = find_entry(hd, algo, "md_extract");

    if (!e || !(e->spec->flags & MD_F_XOF)) {
        return GCRY_ERR(GPG_ERR_DIGEST_ALGO);
    }

    if (length && !EVP_DigestSqueeze(e->mdctx, buffer, length)) {
        return GCRY_ERR(_gcry_err_from_openssl(GPG_ERR_INTERNAL));
    }

    return 0;
}

void
gcry_md_hash_buffer(int algo, void *digest, const void *buffer,
                    size_t length)
{
    gcry_md_hd_t hd;
    gcry_err_code_t rc;

    _gcry_global_init();

    if (!spec_from_algo(algo)) {
        log_debug("md_hash_buffer: algorithm %d not available\n", algo);
        return;
    }

    rc = md_open(&hd, algo, 0);

    if (rc) {
        /* The reference library cannot fail here because every algorithm
         * in its table is built in.  An algorithm OpenSSL lacks must not
         * abort the caller: report it and hand back a zeroed digest. */
        log_error("gcry_md_hash_buffer: %s not available: %s\n",
                  gcry_md_algo_name(algo), gcry_strerror(GCRY_ERR(rc)));
        memset(digest, 0, gcry_md_get_algo_dlen(algo));
        return;
    }

    md_write(hd, buffer, length);
    md_final(hd);
    memcpy(digest, gcry_md_read(hd, algo), gcry_md_get_algo_dlen(algo));
    md_close(hd);
}

gpg_error_t
gcry_md_hash_buffers_ext(int algo, unsigned int flags, void *digest,
                         int digestlen, const gcry_buffer_t *iov, int iovcnt)
{
    const struct md_spec *spec;
    int hmac;
    gcry_md_hd_t hd;
    gcry_err_code_t rc;

    _gcry_global_init();

    if (!iov || iovcnt < 0) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    if (flags & ~(unsigned int)GCRY_MD_FLAG_HMAC) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    hmac = !!(flags & GCRY_MD_FLAG_HMAC);

    if (hmac && iovcnt < 1) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    spec = spec_from_algo(algo);

    if (!spec) {
        log_debug("md_hash_buffers: algorithm %d not available\n", algo);
        return GCRY_ERR(GPG_ERR_DIGEST_ALGO);
    }

    if (!(spec->flags & MD_F_XOF) && digestlen != -1
        && (unsigned int)digestlen != spec->mdlen) {
        return GCRY_ERR(GPG_ERR_DIGEST_ALGO);
    }

    if (digestlen == -1) {
        digestlen = (int)spec->mdlen;
    }

    rc = md_open(&hd, algo, hmac ? GCRY_MD_FLAG_HMAC : 0u);

    if (rc) {
        return GCRY_ERR(rc);
    }

    if (hmac) {
        rc = md_setkey(hd, (const char *)iov[0].data + iov[0].off,
                       iov[0].len);

        if (rc) {
            md_close(hd);
            return GCRY_ERR(rc);
        }

        iov++;
        iovcnt--;
    }

    for (; iovcnt; iov++, iovcnt--) {
        md_write(hd, (const char *)iov[0].data + iov[0].off, iov[0].len);
    }

    md_final(hd);

    if ((unsigned int)digestlen == spec->mdlen) {
        memcpy(digest, gcry_md_read(hd, algo), spec->mdlen);
    } else if (digestlen > 0) {
        rc = gcry_err_code(gcry_md_extract(hd, algo, digest,
                                           (size_t)digestlen));
    }

    md_close(hd);
    return GCRY_ERR(rc);
}

gpg_error_t
gcry_md_hash_buffers(int algo, unsigned int flags, void *digest,
                     const gcry_buffer_t *iov, int iovcnt)
{
    return gcry_md_hash_buffers_ext(algo, flags, digest, -1, iov, iovcnt);
}

int
gcry_md_get_algo(gcry_md_hd_t hd)
{
    struct md_entry *e;

    if (!hd) {
        return 0;
    }

    e = hd->ctx->list;

    if (e && e->next) {
        log_error("WARNING: more than one algorithm in md_get_algo()\n");
    }

    return e ? e->spec->algo : 0;
}

unsigned int
gcry_md_get_algo_dlen(int algo)
{
    const struct md_spec *spec = spec_from_algo(algo);

    return spec ? spec->mdlen : 0;
}

gcry_error_t
gcry_md_info(gcry_md_hd_t h, int what, void *buffer, size_t *nbytes)
{
    gcry_err_code_t rc = 0;

    if (!h) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    switch (what) {
    case GCRYCTL_IS_SECURE:
        if (!nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            *nbytes = h->ctx->secure;
        }

        break;

    case GCRYCTL_IS_ALGO_ENABLED:
        if (!buffer || !nbytes || *nbytes != sizeof(int)) {
            rc = GPG_ERR_INV_ARG;
        } else {
            int algo;
            struct md_entry *e;

            memcpy(&algo, buffer, sizeof algo);
            *nbytes = 0;

            for (e = h->ctx->list; e; e = e->next) {
                if (e->spec->algo == algo) {
                    *nbytes = 1;
                    break;
                }
            }
        }

        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

int
gcry_md_is_enabled(gcry_md_hd_t a, int algo)
{
    size_t value = sizeof algo;

    if (gcry_md_info(a, GCRYCTL_IS_ALGO_ENABLED, &algo, &value)) {
        value = 0;
    }

    return value != 0;
}

int
gcry_md_is_secure(gcry_md_hd_t a)
{
    size_t value;

    if (gcry_md_info(a, GCRYCTL_IS_SECURE, NULL, &value)) {
        value = 1; /* Assume secure memory on error. */
    }

    return value != 0;
}

gcry_error_t
gcry_md_algo_info(int algo, int what, void *buffer, size_t *nbytes)
{
    gcry_err_code_t rc;

    _gcry_global_init();

    switch (what) {
    case GCRYCTL_TEST_ALGO:
        if (buffer || nbytes) {
            rc = GPG_ERR_INV_ARG;
        } else {
            rc = check_digest_algo(algo);
        }

        break;

    case GCRYCTL_GET_ASNOID:
        rc = check_digest_algo(algo);

        if (!rc) {
            const struct md_spec *spec = spec_from_algo(algo);
            size_t asnlen = spec->asnlen;

            if (buffer && nbytes && *nbytes >= asnlen) {
                if (asnlen) {
                    memcpy(buffer, spec->asn, asnlen);
                }

                *nbytes = asnlen;
            } else if (!buffer && nbytes) {
                *nbytes = asnlen;
            } else if (buffer) {
                rc = GPG_ERR_TOO_SHORT;
            } else {
                rc = GPG_ERR_INV_ARG;
            }
        }

        break;

    case GCRYCTL_SELFTEST:
        /* OpenSSL runs its own known answer tests; just report whether
         * the algorithm is usable. */
        rc = check_digest_algo(algo);
        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return GCRY_ERR(rc);
}

const char *
gcry_md_algo_name(int algo)
{
    const struct md_spec *spec = spec_from_algo(algo);

    return spec ? spec->name : "?";
}

int
gcry_md_map_name(const char *name)
{
    const struct md_spec *spec;

    if (!name) {
        return 0;
    }

    spec = spec_from_oid(name);

    if (!spec) {
        spec = spec_from_name(name);
    }

    return spec ? spec->algo : 0;
}

gcry_error_t
gcry_md_setkey(gcry_md_hd_t hd, const void *key, size_t keylen)
{
    if (!hd) {
        return GCRY_ERR(GPG_ERR_INV_ARG);
    }

    return GCRY_ERR(md_setkey(hd, key, keylen));
}

void
gcry_md_debug(gcry_md_hd_t hd, const char *suffix)
{
    if (!hd) {
        return;
    }

    if (suffix) {
        md_start_debug(hd, suffix);
    } else {
        md_stop_debug(hd);
    }
}
