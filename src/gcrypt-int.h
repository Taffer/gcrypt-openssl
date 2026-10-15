/*
 * gcrypt-int.h - Private declarations shared by the library sources.
 *
 * Nothing in here is part of the public API or ABI.  Public functions are
 * declared in <gcrypt.h>; this header adds the internal helpers, the
 * definitions of the opaque public structures, and the OpenSSL plumbing.
 */
#ifndef GCRYPT_INT_H
#define GCRYPT_INT_H

#define _GCRYPT_IN_LIBGCRYPT 1
#define GCRY_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_GCRYPT

#include <gcrypt.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/provider.h>

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR < 4
    #error "gcrypt-openssl requires OpenSSL 4.0 or newer"
#endif

#define GCRYPT_OPENSSL_STRINGIFY_(x) #x
#define GCRYPT_OPENSSL_STRINGIFY(x) GCRYPT_OPENSSL_STRINGIFY_(x)

/* clang-format off */
#define GCRYPT_OPENSSL_VERSION_STRING                          \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_MAJOR) "." \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_MINOR) "." \
    GCRYPT_OPENSSL_STRINGIFY(GCRYPT_OPENSSL_VERSION_PATCH)
/* clang-format on */

#define DIM(v) (sizeof(v) / sizeof((v)[0]))

#if defined(__GNUC__)
    #define GCRY_NORETURN __attribute__((__noreturn__))
#else
    #define GCRY_NORETURN
#endif

/* Every error leaving the library carries the GCRYPT source. */
#define GCRY_ERR(code) gcry_err_make(GPG_ERR_SOURCE_GCRYPT, (code))

/* ---- global.c ---------------------------------------------------- */

void _gcry_global_init(void);
OSSL_LIB_CTX *_gcry_libctx(void);
const char *_gcry_propq(void);
int _gcry_fips_mode(void);
unsigned int _gcry_get_debug_flags(void);
int _gcry_get_rng_type(void);

/* Generic context object (gcry_ctx_t). */
enum gcry_ctx_types {
    GCRY_CTX_TYPE_EC = 1,
    GCRY_CTX_TYPE_RANDOM_OVERRIDE = 2
};

gcry_ctx_t _gcry_ctx_alloc(int type, size_t length,
                           void (*deinit)(void *));
void *_gcry_ctx_get_pointer(gcry_ctx_t ctx, int type);
void *_gcry_ctx_find_pointer(gcry_ctx_t ctx, int type);

/* ---- memory.c ---------------------------------------------------- */

void *_gcry_malloc(size_t n);
void *_gcry_malloc_secure(size_t n);
void *_gcry_calloc(size_t n, size_t m);
void *_gcry_calloc_secure(size_t n, size_t m);
void *_gcry_realloc(void *a, size_t n);
char *_gcry_strdup(const char *string);
void *_gcry_xmalloc(size_t n);
void *_gcry_xcalloc(size_t n, size_t m);
void *_gcry_xmalloc_secure(size_t n);
void *_gcry_xcalloc_secure(size_t n, size_t m);
void *_gcry_xrealloc(void *a, size_t n);
char *_gcry_xstrdup(const char *string);
void _gcry_free(void *a);
int _gcry_is_secure(const void *a);
void _gcry_wipememory(void *ptr, size_t len);

void _gcry_secmem_init(size_t n);
void _gcry_secmem_term(void);
void _gcry_secmem_disable(void);
int _gcry_secmem_is_disabled(void);

/* ---- error.c ----------------------------------------------------- */

gcry_err_code_t _gcry_err_code_from_syserror(void);
gcry_err_code_t _gcry_err_from_openssl(gcry_err_code_t fallback);

/* ---- misc.c ------------------------------------------------------ */

void _gcry_log(int level, const char *fmt, ...) _GCRY_GCC_ATTR_PRINTF(2, 3);
void _gcry_logv(int level, const char *fmt, va_list ap);
void _gcry_log_printhex(const char *text, const void *buffer, size_t length);
void _gcry_set_log_verbosity(int level);
int _gcry_log_verbosity(void);
void _gcry_fatal_error(int rc, const char *text) GCRY_NORETURN;
void _gcry_bug(const char *file, int line, const char *func) GCRY_NORETURN;
void _gcry_progress(const char *what, int printchar, int current, int total);

#define BUG() _gcry_bug(__FILE__, __LINE__, __func__)
#define log_info(...) _gcry_log(GCRY_LOG_INFO, __VA_ARGS__)
#define log_error(...) _gcry_log(GCRY_LOG_ERROR, __VA_ARGS__)
#define log_debug(...) _gcry_log(GCRY_LOG_DEBUG, __VA_ARGS__)

/* ---- sexp.c ------------------------------------------------------ */

struct gcry_sexp {
    unsigned char d[1];
};

gcry_err_code_t _gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff,
                                 const char *format, ...);
gcry_err_code_t _gcry_sexp_vbuild(gcry_sexp_t *retsexp, size_t *erroff,
                                  const char *format, va_list arg_ptr);
gcry_err_code_t _gcry_sexp_sscan(gcry_sexp_t *retsexp, size_t *erroff,
                                 const char *buffer, size_t length);
gcry_err_code_t _gcry_sexp_new(gcry_sexp_t *retsexp, const void *buffer,
                               size_t length, int autodetect);
gcry_err_code_t _gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path,
                                         const char *list, ...);
gcry_err_code_t _gcry_sexp_vextract_param(gcry_sexp_t sexp,
                                          const char *path,
                                          const char *list, va_list arg_ptr);
void *_gcry_hex2buffer(const char *string, size_t *r_length);

/* ---- mpi.c ------------------------------------------------------- */

struct gcry_mpi {
    BIGNUM *bn;             /* Always allocated, even for opaque values. */
    unsigned int flags;     /* GCRYMPI_FLAG_* bits. */
    unsigned char *opaque;  /* Payload when GCRYMPI_FLAG_OPAQUE is set. */
    unsigned int opaque_nbits;
};

struct gcry_mpi_point {
    gcry_mpi_t x;
    gcry_mpi_t y;
    gcry_mpi_t z;
};

#define mpi_is_opaque(a) (!!((a)->flags & GCRYMPI_FLAG_OPAQUE))
#define mpi_is_secure(a) (!!((a)->flags & GCRYMPI_FLAG_SECURE))
#define mpi_is_immutable(a) (!!((a)->flags & GCRYMPI_FLAG_IMMUTABLE))

gcry_mpi_t _gcry_mpi_alloc(int secure);
gcry_mpi_t _gcry_mpi_new_from_bn(BIGNUM *bn, int secure);
BIGNUM *_gcry_mpi_bn(gcry_mpi_t a);
gcry_err_code_t _gcry_mpi_scan(gcry_mpi_t *ret_mpi,
                               enum gcry_mpi_format format,
                               const void *buffer, size_t buflen,
                               size_t *nscanned);
gcry_err_code_t _gcry_mpi_print(enum gcry_mpi_format format,
                                unsigned char *buffer, size_t buflen,
                                size_t *nwritten, const gcry_mpi_t a);
gcry_err_code_t _gcry_mpi_aprint(enum gcry_mpi_format format,
                                 unsigned char **buffer, size_t *nwritten,
                                 const gcry_mpi_t a);
unsigned char *_gcry_mpi_get_buffer(gcry_mpi_t a, unsigned int fill_le,
                                    unsigned int *nbytes, int *sign);
void _gcry_mpi_set_buffer(gcry_mpi_t a, const void *buffer,
                          unsigned int nbytes, int sign);
void _gcry_mpi_immutable_failed(void);

/* ---- ecc-curves.c ------------------------------------------------ */

#include <openssl/ec.h>

enum gcry_ecc_models {
    GCRY_ECC_MODEL_WEIERSTRASS = 0,
    GCRY_ECC_MODEL_MONTGOMERY,
    GCRY_ECC_MODEL_EDWARDS
};

enum gcry_ecc_dialects {
    GCRY_ECC_DIALECT_STANDARD = 0,
    GCRY_ECC_DIALECT_ED25519,
    GCRY_ECC_DIALECT_SAFECURVE
};

struct gcry_ecc_curve {
    const char *name;        /* Canonical gcrypt name, e.g. "NIST P-256". */
    unsigned int nbits;      /* Size of the field in bits. */
    int fips;                /* Allowed in FIPS mode. */
    enum gcry_ecc_models model;
    enum gcry_ecc_dialects dialect;
    int nid;                 /* OpenSSL NID, or NID_undef. */
    const char *keytype;     /* OpenSSL EVP_PKEY type name for non-Weierstrass
                              * curves ("X25519", "ED25519", ...), else NULL. */
    const char *p;           /* Domain parameters as hex strings. */
    const char *a;
    const char *b;
    const char *n;
    const char *gx;
    const char *gy;
    unsigned int h;          /* Cofactor. */
};

size_t _gcry_ecc_curve_count(void);
const struct gcry_ecc_curve *_gcry_ecc_curve_by_index(size_t idx);
const struct gcry_ecc_curve *_gcry_ecc_curve_find(const char *name);
const struct gcry_ecc_curve *_gcry_ecc_curve_by_nbits(unsigned int nbits);
const struct gcry_ecc_curve *_gcry_ecc_curve_from_group(const EC_GROUP *g);
gcry_mpi_t _gcry_ecc_curve_param(const struct gcry_ecc_curve *curve,
                                 const char *name);
EC_GROUP *_gcry_ecc_curve_group(const struct gcry_ecc_curve *curve);

/* ---- md.c -------------------------------------------------------- */

/* OpenSSL digest name for a GCRY_MD_* algorithm, NULL if none. */
const char *_gcry_md_openssl_name(int algo);
/* Fetched EVP_MD for ALGO (caller frees), NULL if unavailable. */
EVP_MD *_gcry_md_fetch(int algo);
/* Output size parameter needed for the truncated BLAKE2 variants, else 0. */
unsigned int _gcry_md_reduced_size(int algo);

/* ---- mpi-ec.c ---------------------------------------------------- */

void _gcry_log_printpnt(const char *text, gcry_mpi_point_t point,
                        gcry_ctx_t ctx);

#endif /* GCRYPT_INT_H */
