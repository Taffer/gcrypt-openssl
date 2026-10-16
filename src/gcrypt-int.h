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
/* FIPS mode was required but no FIPS provider could be activated: the
 * library is not operational.  Algorithm entry points should refuse with
 * GPG_ERR_NOT_OPERATIONAL while this is true. */
int _gcry_fips_error_state(void);
unsigned int _gcry_get_debug_flags(void);
int _gcry_get_rng_type(void);
unsigned int _gcry_fips_reject_flags(void);
int _gcry_fips_md_approved(int algo);

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
/* Size of the mappings added when the secure pools are full; 0 restores
 * the default. */
void _gcry_secmem_set_auto_expand(size_t chunksize);

#define GCRY_SECMEM_FLAG_NO_WARNING (1u << 0)
#define GCRY_SECMEM_FLAG_SUSPEND_WARNING (1u << 1)
void _gcry_secmem_set_flags(unsigned int flags);
unsigned int _gcry_secmem_get_flags(void);

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
gcry_err_code_t _gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path,
                                         const char *list, ...);
gcry_err_code_t _gcry_sexp_vextract_param(gcry_sexp_t sexp,
                                          const char *path,
                                          const char *list, va_list arg_ptr);

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

/* ---- mac.c ------------------------------------------------------- */

/* GCRY_MD_* digest behind an HMAC algorithm id, 0 if not an HMAC. */
int _gcry_mac_hmac_digest_algo(int macalgo);

/* ---- random.c ---------------------------------------------------- */

gcry_err_code_t _gcry_random_bytes_into(void *buffer, size_t length,
                                        enum gcry_random_level level);

/* ---- pk-util.c --------------------------------------------------- */

/* Flags collected from "(flags ...)" lists of keys and data. */
#define PUBKEY_FLAG_NO_BLINDING (1 << 0)
#define PUBKEY_FLAG_RFC6979 (1 << 1)
#define PUBKEY_FLAG_FIXEDLEN (1 << 2)
#define PUBKEY_FLAG_LEGACYRESULT (1 << 3)
#define PUBKEY_FLAG_RAW_FLAG (1 << 4)
#define PUBKEY_FLAG_TRANSIENT_KEY (1 << 5)
#define PUBKEY_FLAG_USE_X931 (1 << 6)
#define PUBKEY_FLAG_USE_FIPS186 (1 << 7)
#define PUBKEY_FLAG_USE_FIPS186_2 (1 << 8)
#define PUBKEY_FLAG_PARAM (1 << 9)
#define PUBKEY_FLAG_COMP (1 << 10)
#define PUBKEY_FLAG_NOCOMP (1 << 11)
#define PUBKEY_FLAG_EDDSA (1 << 12)
#define PUBKEY_FLAG_GOST (1 << 13)
#define PUBKEY_FLAG_NO_KEYTEST (1 << 14)
#define PUBKEY_FLAG_DJB_TWEAK (1 << 15)
#define PUBKEY_FLAG_SM2 (1 << 16)
#define PUBKEY_FLAG_PREHASH (1 << 17)
#define PUBKEY_FLAG_NO_PREFIX (1 << 19)

enum pk_encoding {
    PUBKEY_ENC_RAW,
    PUBKEY_ENC_PKCS1,
    PUBKEY_ENC_PKCS1_RAW,
    PUBKEY_ENC_OAEP,
    PUBKEY_ENC_PSS,
    PUBKEY_ENC_UNKNOWN
};

enum pk_operation {
    PUBKEY_OP_ENCRYPT,
    PUBKEY_OP_DECRYPT,
    PUBKEY_OP_SIGN,
    PUBKEY_OP_VERIFY
};

/* The parsed form of a "(data ...)" S-expression. */
struct pk_data {
    enum pk_operation op;
    unsigned int nbits;        /* Key size, for the encodings that need it. */
    enum pk_encoding encoding;
    int flags;                 /* PUBKEY_FLAG_* (data and key flags). */
    int hash_algo;             /* GCRY_MD_* or 0. */
    unsigned char *value;      /* Digest or message bytes, or NULL. */
    size_t valuelen;
    int value_is_hash;         /* VALUE came from a (hash ...) element. */
    gcry_mpi_t mpi;            /* Numeric value for raw operations. */
    unsigned char *label;
    size_t labellen;
    unsigned int saltlen;      /* PSS salt length. */
    unsigned char *rnd;        /* random-override, ignored but parsed. */
    size_t rndlen;
};

void _gcry_pk_data_init(struct pk_data *pd, enum pk_operation op,
                        unsigned int nbits);
void _gcry_pk_data_free(struct pk_data *pd);
gcry_err_code_t _gcry_pk_data_parse(gcry_sexp_t input, struct pk_data *pd);
gcry_err_code_t _gcry_pk_util_parse_flaglist(gcry_sexp_t list, int *r_flags,
                                             enum pk_encoding *r_encoding);
gcry_err_code_t _gcry_pk_util_get_nbits(gcry_sexp_t list,
                                        unsigned int *r_nbits);
gcry_err_code_t _gcry_pk_util_get_rsa_use_e(gcry_sexp_t list,
                                            unsigned long *r_e);
gcry_err_code_t _gcry_pk_util_preparse_sigval(gcry_sexp_t s_sig,
                                              const char *const *algo_names,
                                              gcry_sexp_t *r_parms,
                                              int *r_eccflags);
gcry_err_code_t _gcry_pk_util_preparse_encval(gcry_sexp_t sexp,
                                              const char *const *algo_names,
                                              gcry_sexp_t *r_parms,
                                              struct pk_data *pd);
int _gcry_pk_util_hash_algo_from_name(const char *s, size_t n);

/* Digest helpers for the public key code.  They talk to OpenSSL directly
 * so that this module does not depend on the md module. */
const char *_gcry_pk_md_openssl_name(int algo);
unsigned int _gcry_pk_md_dlen(int algo);
gcry_err_code_t _gcry_pk_md_hash(int algo, const void *data, size_t len,
                                 unsigned char *out, size_t outlen);

/* Byte string helpers. */
gcry_err_code_t _gcry_pk_mpi_to_fixed(gcry_mpi_t a, unsigned char *buf,
                                      size_t len);
gcry_err_code_t _gcry_pk_mpi_to_bytes(gcry_mpi_t a, unsigned char **r_buf,
                                      size_t *r_len);
gcry_err_code_t _gcry_pk_bn_to_fixed(const BIGNUM *bn, unsigned char *buf,
                                     size_t len);
gcry_mpi_t _gcry_pk_mpi_from_bn(const BIGNUM *bn);
gcry_err_code_t _gcry_pk_rs_from_der(const unsigned char *der, size_t derlen,
                                     int is_ecdsa, gcry_mpi_t *r_r,
                                     gcry_mpi_t *r_s);
gcry_err_code_t _gcry_pk_rs_to_der(gcry_mpi_t r, gcry_mpi_t s, int is_ecdsa,
                                   unsigned char **r_der, size_t *r_derlen);

/* PKCS#1 encodings on byte strings (frames of (nbits+7)/8 bytes). */
gcry_err_code_t _gcry_pk_pkcs1_encode_for_enc(unsigned int nbits,
                                              const unsigned char *value,
                                              size_t valuelen,
                                              const unsigned char *rnd,
                                              size_t rndlen,
                                              unsigned char **r_frame,
                                              size_t *r_framelen);
gcry_err_code_t _gcry_pk_pkcs1_decode_for_enc(const unsigned char *frame,
                                              size_t nframe,
                                              unsigned char **r_value,
                                              size_t *r_valuelen);
gcry_err_code_t _gcry_pk_pkcs1_encode_for_sig(unsigned int nbits, int algo,
                                              const unsigned char *digest,
                                              size_t digestlen,
                                              unsigned char **r_frame,
                                              size_t *r_framelen);
gcry_err_code_t _gcry_pk_pkcs1_encode_raw_for_sig(unsigned int nbits,
                                                  const unsigned char *value,
                                                  size_t valuelen,
                                                  unsigned char **r_frame,
                                                  size_t *r_framelen);
gcry_err_code_t _gcry_pk_oaep_encode(unsigned int nbits, int algo,
                                     const unsigned char *value,
                                     size_t valuelen,
                                     const unsigned char *label,
                                     size_t labellen, const unsigned char *rnd,
                                     size_t rndlen, unsigned char **r_frame,
                                     size_t *r_framelen);
gcry_err_code_t _gcry_pk_oaep_decode(const unsigned char *frame, size_t nframe,
                                     int algo, const unsigned char *label,
                                     size_t labellen, unsigned char **r_value,
                                     size_t *r_valuelen);
gcry_err_code_t _gcry_pk_pss_encode(unsigned int nbits, int algo,
                                    unsigned int saltlen,
                                    const unsigned char *rnd, size_t rndlen,
                                    const unsigned char *value,
                                    size_t valuelen, int hashed_already,
                                    unsigned char **r_frame,
                                    size_t *r_framelen);
gcry_err_code_t _gcry_pk_pss_verify(unsigned int nbits, int algo,
                                    unsigned int saltlen,
                                    const unsigned char *value,
                                    size_t valuelen, int hashed_already,
                                    const unsigned char *em, size_t emlen);
gcry_err_code_t _gcry_pk_data_to_frame(struct pk_data *pd, unsigned int nbits,
                                       unsigned char **r_frame,
                                       size_t *r_framelen);

/* ---- pk.c -------------------------------------------------------- */

struct gcry_pk_spec {
    int algo;
    int fips;                  /* Allowed in FIPS mode. */
    unsigned int use;          /* GCRY_PK_USAGE_* bits. */
    const char *name;
    const char *const *aliases;
    const char *elements_pkey;
    const char *elements_skey;
    const char *elements_enc;
    const char *elements_sig;
    const char *elements_grip; /* NULL if no keygrip. */
    gcry_err_code_t (*generate)(gcry_sexp_t genparms, gcry_sexp_t *r_skey);
    gcry_err_code_t (*check_secret_key)(gcry_sexp_t keyparms);
    gcry_err_code_t (*encrypt)(gcry_sexp_t *r_ciph, gcry_sexp_t s_data,
                               gcry_sexp_t keyparms);
    gcry_err_code_t (*decrypt)(gcry_sexp_t *r_plain, gcry_sexp_t s_data,
                               gcry_sexp_t keyparms);
    gcry_err_code_t (*sign)(gcry_sexp_t *r_sig, gcry_sexp_t s_data,
                            gcry_sexp_t keyparms);
    gcry_err_code_t (*verify)(gcry_sexp_t s_sig, gcry_sexp_t s_data,
                              gcry_sexp_t keyparms);
    unsigned int (*get_nbits)(gcry_sexp_t keyparms);
    /* Algorithm specific keygrip: feed the parameters into MD. */
    gcry_err_code_t (*comp_keygrip)(EVP_MD_CTX *md, gcry_sexp_t keyparms);
    const char *(*get_curve)(gcry_sexp_t keyparms, int iterator,
                             unsigned int *r_nbits);
    gcry_sexp_t (*get_curve_param)(const char *name);
};

extern const struct gcry_pk_spec _gcry_pubkey_spec_rsa;
extern const struct gcry_pk_spec _gcry_pubkey_spec_dsa;
extern const struct gcry_pk_spec _gcry_pubkey_spec_elg;
extern const struct gcry_pk_spec _gcry_pubkey_spec_ecc;

/* ---- mpi-ec.c ---------------------------------------------------- */

/* An elliptic curve context: curve description plus an optional key. */
struct gcry_mpi_ec_ctx {
    enum gcry_ecc_models model;
    enum gcry_ecc_dialects dialect;
    int flags;                 /* PUBKEY_FLAG_EDDSA, _DJB_TWEAK, ... */
    unsigned int nbits;
    const struct gcry_ecc_curve *curve; /* NULL for unknown curves. */
    const char *name;          /* Curve name or NULL. */
    EC_GROUP *group;           /* Weierstrass curves only. */
    EC_GROUP *mont_group;      /* Montgomery curves: the isomorphic
                                * Weierstrass group used for arithmetic. */
    gcry_mpi_t p;
    gcry_mpi_t a;
    gcry_mpi_t b;
    gcry_mpi_point_t G;
    gcry_mpi_t n;
    unsigned int h;
    gcry_mpi_point_t Q;        /* Public key, may be NULL. */
    gcry_mpi_t d;              /* Secret key, may be NULL. */
};
typedef struct gcry_mpi_ec_ctx *mpi_ec_t;

gcry_err_code_t _gcry_mpi_ec_internal_new(mpi_ec_t *r_ec, int *r_flags,
                                          gcry_sexp_t keyparam,
                                          const char *curvename);
void _gcry_mpi_ec_free(mpi_ec_t ec);
int _gcry_mpi_ec_affine(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_point_t point,
                        mpi_ec_t ec);
gcry_err_code_t _gcry_mpi_ec_mul(gcry_mpi_point_t w, gcry_mpi_t n,
                                 gcry_mpi_point_t u, mpi_ec_t ec);
int _gcry_mpi_ec_on_curve(gcry_mpi_point_t point, mpi_ec_t ec);
gcry_err_code_t _gcry_ecc_decode_point(gcry_mpi_point_t result,
                                       gcry_mpi_t value, mpi_ec_t ec);
gcry_err_code_t _gcry_ecc_compute_public(mpi_ec_t ec);
gcry_mpi_t _gcry_ecc_ec2os(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t p);
gcry_mpi_t _gcry_mpi_ec_ec2os(gcry_mpi_point_t point, mpi_ec_t ec);
gcry_err_code_t _gcry_ecc_eddsa_encode_x_y(gcry_mpi_t x, gcry_mpi_t y,
                                           unsigned int nbits, int with_prefix,
                                           unsigned char **r_buf,
                                           unsigned int *r_len);
gcry_err_code_t _gcry_ecc_eddsa_encodepoint(gcry_mpi_point_t point,
                                            mpi_ec_t ec, int with_prefix,
                                            unsigned char **r_buf,
                                            unsigned int *r_len);
gcry_err_code_t _gcry_ecc_eddsa_compact(gcry_mpi_t value, unsigned int nbits,
                                        unsigned char **r_buf,
                                        unsigned int *r_len);
gcry_err_code_t _gcry_ecc_mont_encodepoint(gcry_mpi_t x, unsigned int nbits,
                                           int with_prefix,
                                           unsigned char **r_buf,
                                           unsigned int *r_len);
gcry_err_code_t _gcry_ecc_mont_decode_u(gcry_mpi_t value, unsigned int nbits,
                                        unsigned char *out);
gcry_err_code_t _gcry_ecc_eddsa_seed(mpi_ec_t ec, unsigned char **r_seed,
                                     size_t *r_len);
gcry_err_code_t _gcry_ecc_mont_scalar(gcry_mpi_t d, unsigned int nbits,
                                      unsigned char **r_buf, size_t *r_len);
EVP_PKEY *_gcry_ecc_evp_key(mpi_ec_t ec, int want_private,
                            gcry_err_code_t *r_rc);
gcry_err_code_t _gcry_pk_ecc_get_sexp(gcry_sexp_t *r_sexp, int mode,
                                      mpi_ec_t ec);
mpi_ec_t _gcry_ctx_get_ec(gcry_ctx_t ctx);

#endif /* GCRYPT_INT_H */
