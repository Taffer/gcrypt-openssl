/*
 * gcrypt.h - Public interface of gcrypt-openssl.
 *
 * This header is an API/ABI compatible replacement for the header shipped
 * with Libgcrypt 1.12, written against that header's interface.  Like the
 * original it takes its error types, codes and inline error helpers from
 * libgpg-error's <gpg-error.h>, so error values are interchangeable with
 * programs and libraries built against the reference library.
 *
 * This file is in the public domain.
 */
#ifndef _GCRYPT_H
#define _GCRYPT_H

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <gpg-error.h>

#if defined _WIN32 || defined __WIN32__
    #ifndef __GNUC__
        #include <basetsd.h>
        typedef SSIZE_T ssize_t;
        typedef int pid_t;
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

/* The Libgcrypt API level this library implements.  gcry_check_version()
 * reports the same string so that existing version checks keep working. */
#define GCRYPT_VERSION "1.12.4"
#define GCRYPT_VERSION_NUMBER 0x010c04

/* ------------------------------------------------------------------ */
/* Compiler attribute helpers                                          */
/* ------------------------------------------------------------------ */

#ifdef __GNUC__
#define _GCRY_GCC_VERSION \
        (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if _GCRY_GCC_VERSION >= 30100
#define _GCRY_GCC_ATTR_DEPRECATED __attribute__((__deprecated__))
#endif
#if _GCRY_GCC_VERSION >= 29600
#define _GCRY_GCC_ATTR_PURE __attribute__((__pure__))
#endif
#if _GCRY_GCC_VERSION >= 30200
#define _GCRY_GCC_ATTR_MALLOC __attribute__((__malloc__))
#endif
#define _GCRY_GCC_ATTR_PRINTF(f, a) __attribute__((format(printf, f, a)))
#if _GCRY_GCC_VERSION >= 40000
#define _GCRY_GCC_ATTR_SENTINEL(a) __attribute__((sentinel(a)))
#endif
#if defined __has_attribute
#if __has_attribute(__nonstring__)
#define _GCRY_GCC_ATTR_NONSTRING __attribute__((__nonstring__))
#endif
#endif
#endif

#ifndef _GCRY_GCC_ATTR_DEPRECATED
#define _GCRY_GCC_ATTR_DEPRECATED
#endif
#ifndef _GCRY_GCC_ATTR_PURE
#define _GCRY_GCC_ATTR_PURE
#endif
#ifndef _GCRY_GCC_ATTR_MALLOC
#define _GCRY_GCC_ATTR_MALLOC
#endif
#ifndef _GCRY_GCC_ATTR_PRINTF
#define _GCRY_GCC_ATTR_PRINTF(f, a)
#endif
#ifndef _GCRY_GCC_ATTR_SENTINEL
#define _GCRY_GCC_ATTR_SENTINEL(a)
#endif
#ifndef _GCRY_GCC_ATTR_NONSTRING
#define _GCRY_GCC_ATTR_NONSTRING
#endif

#ifdef _GCRYPT_IN_LIBGCRYPT
#define _GCRY_ATTR_INTERNAL
#ifndef GCRYPT_NO_MPI_MACROS
#define GCRYPT_NO_MPI_MACROS 1
#endif
#else
#define _GCRY_ATTR_INTERNAL _GCRY_GCC_ATTR_DEPRECATED
#endif

/* ------------------------------------------------------------------ */
/* Error handling                                                      */
/* ------------------------------------------------------------------ */

typedef gpg_error_t gcry_error_t;
typedef gpg_err_code_t gcry_err_code_t;
typedef gpg_err_source_t gcry_err_source_t;

static GPG_ERR_INLINE gcry_error_t
gcry_err_make(gcry_err_source_t source, gcry_err_code_t code)
{
    return gpg_err_make(source, code);
}

#ifndef GCRY_ERR_SOURCE_DEFAULT
#define GCRY_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_USER_1
#endif

static GPG_ERR_INLINE gcry_error_t
gcry_error(gcry_err_code_t code)
{
    return gcry_err_make(GCRY_ERR_SOURCE_DEFAULT, code);
}

static GPG_ERR_INLINE gcry_err_code_t
gcry_err_code(gcry_error_t err)
{
    return gpg_err_code(err);
}

static GPG_ERR_INLINE gcry_err_source_t
gcry_err_source(gcry_error_t err)
{
    return gpg_err_source(err);
}

const char *gcry_strerror(gcry_error_t err);
const char *gcry_strsource(gcry_error_t err);
gcry_err_code_t gcry_err_code_from_errno(int err);
int gcry_err_code_to_errno(gcry_err_code_t code);
gcry_error_t gcry_err_make_from_errno(gcry_err_source_t source, int err);
gcry_error_t gcry_error_from_errno(int err);

/* ------------------------------------------------------------------ */
/* Legacy thread callbacks (no effect since Libgcrypt 1.6)             */
/* ------------------------------------------------------------------ */

#define GCRY_THREAD_OPTION_DEFAULT 0
#define GCRY_THREAD_OPTION_USER 1
#define GCRY_THREAD_OPTION_PTH 2
#define GCRY_THREAD_OPTION_PTHREAD 3
#define GCRY_THREAD_OPTION_VERSION 1

struct gcry_thread_cbs {
    unsigned int option;
} _GCRY_GCC_ATTR_DEPRECATED;

#define GCRY_THREAD_OPTION_PTH_IMPL                            \
    static struct gcry_thread_cbs gcry_threads_pth = {         \
        (GCRY_THREAD_OPTION_PTH | (GCRY_THREAD_OPTION_VERSION << 8)) \
    }

#define GCRY_THREAD_OPTION_PTHREAD_IMPL                        \
    static struct gcry_thread_cbs gcry_threads_pthread = {     \
        (GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 8)) \
    }

/* ------------------------------------------------------------------ */
/* Basic object types                                                  */
/* ------------------------------------------------------------------ */

struct gcry_context;
typedef struct gcry_context *gcry_ctx_t;

struct gcry_mpi;
typedef struct gcry_mpi *gcry_mpi_t;
struct gcry_mpi_point;
typedef struct gcry_mpi_point *gcry_mpi_point_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_mpi *GCRY_MPI _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_mpi *GcryMPI _GCRY_GCC_ATTR_DEPRECATED;
#endif

typedef struct {
    size_t size;
    size_t off;
    size_t len;
    void *data;
} gcry_buffer_t;

const char *gcry_check_version(const char *req_version);

/* ------------------------------------------------------------------ */
/* Control commands                                                    */
/* ------------------------------------------------------------------ */

enum gcry_ctl_cmds {
    GCRYCTL_CFB_SYNC = 3,
    GCRYCTL_RESET = 4,
    GCRYCTL_FINALIZE = 5,
    GCRYCTL_GET_KEYLEN = 6,
    GCRYCTL_GET_BLKLEN = 7,
    GCRYCTL_TEST_ALGO = 8,
    GCRYCTL_IS_SECURE = 9,
    GCRYCTL_GET_ASNOID = 10,
    GCRYCTL_ENABLE_ALGO = 11,
    GCRYCTL_DISABLE_ALGO = 12,
    GCRYCTL_DUMP_RANDOM_STATS = 13,
    GCRYCTL_DUMP_SECMEM_STATS = 14,
    GCRYCTL_GET_ALGO_NPKEY = 15,
    GCRYCTL_GET_ALGO_NSKEY = 16,
    GCRYCTL_GET_ALGO_NSIGN = 17,
    GCRYCTL_GET_ALGO_NENCR = 18,
    GCRYCTL_SET_VERBOSITY = 19,
    GCRYCTL_SET_DEBUG_FLAGS = 20,
    GCRYCTL_CLEAR_DEBUG_FLAGS = 21,
    GCRYCTL_USE_SECURE_RNDPOOL = 22,
    GCRYCTL_DUMP_MEMORY_STATS = 23,
    GCRYCTL_INIT_SECMEM = 24,
    GCRYCTL_TERM_SECMEM = 25,
    GCRYCTL_DISABLE_SECMEM_WARN = 27,
    GCRYCTL_SUSPEND_SECMEM_WARN = 28,
    GCRYCTL_RESUME_SECMEM_WARN = 29,
    GCRYCTL_DROP_PRIVS = 30,
    GCRYCTL_ENABLE_M_GUARD = 31,
    GCRYCTL_START_DUMP = 32,
    GCRYCTL_STOP_DUMP = 33,
    GCRYCTL_GET_ALGO_USAGE = 34,
    GCRYCTL_IS_ALGO_ENABLED = 35,
    GCRYCTL_DISABLE_INTERNAL_LOCKING = 36,
    GCRYCTL_DISABLE_SECMEM = 37,
    GCRYCTL_INITIALIZATION_FINISHED = 38,
    GCRYCTL_INITIALIZATION_FINISHED_P = 39,
    GCRYCTL_ANY_INITIALIZATION_P = 40,
    GCRYCTL_SET_CBC_CTS = 41,
    GCRYCTL_SET_CBC_MAC = 42,
    GCRYCTL_ENABLE_QUICK_RANDOM = 44,
    GCRYCTL_SET_RANDOM_SEED_FILE = 45,
    GCRYCTL_UPDATE_RANDOM_SEED_FILE = 46,
    GCRYCTL_SET_THREAD_CBS = 47,
    GCRYCTL_FAST_POLL = 48,
    GCRYCTL_SET_RANDOM_DAEMON_SOCKET = 49,
    GCRYCTL_USE_RANDOM_DAEMON = 50,
    GCRYCTL_FAKED_RANDOM_P = 51,
    GCRYCTL_SET_RNDEGD_SOCKET = 52,
    GCRYCTL_PRINT_CONFIG = 53,
    GCRYCTL_OPERATIONAL_P = 54,
    GCRYCTL_FIPS_MODE_P = 55,
    GCRYCTL_FORCE_FIPS_MODE = 56,
    GCRYCTL_SELFTEST = 57,
    GCRYCTL_DISABLE_HWF = 63,
    GCRYCTL_SET_ENFORCED_FIPS_FLAG = 64,
    GCRYCTL_SET_PREFERRED_RNG_TYPE = 65,
    GCRYCTL_GET_CURRENT_RNG_TYPE = 66,
    GCRYCTL_DISABLE_LOCKED_SECMEM = 67,
    GCRYCTL_DISABLE_PRIV_DROP = 68,
    GCRYCTL_SET_CCM_LENGTHS = 69,
    GCRYCTL_CLOSE_RANDOM_DEVICE = 70,
    GCRYCTL_INACTIVATE_FIPS_FLAG = 71,
    GCRYCTL_REACTIVATE_FIPS_FLAG = 72,
    GCRYCTL_SET_SBOX = 73,
    GCRYCTL_DRBG_REINIT = 74,
    GCRYCTL_SET_TAGLEN = 75,
    GCRYCTL_GET_TAGLEN = 76,
    GCRYCTL_REINIT_SYSCALL_CLAMP = 77,
    GCRYCTL_AUTO_EXPAND_SECMEM = 78,
    GCRYCTL_SET_ALLOW_WEAK_KEY = 79,
    GCRYCTL_SET_DECRYPTION_TAG = 80,
    GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER = 81,
    GCRYCTL_FIPS_SERVICE_INDICATOR_KDF = 82,
    GCRYCTL_NO_FIPS_MODE = 83,
    GCRYCTL_FIPS_SERVICE_INDICATOR_FUNCTION = 84,
    GCRYCTL_FIPS_SERVICE_INDICATOR_MAC = 85,
    GCRYCTL_FIPS_SERVICE_INDICATOR_MD = 86,
    GCRYCTL_FIPS_SERVICE_INDICATOR_PK_FLAGS = 87,
    GCRYCTL_MD_CUSTOMIZE = 88,
    GCRYCTL_FIPS_SERVICE_INDICATOR = 89,
    GCRYCTL_FIPS_REJECT_NON_FIPS = 90
};

gcry_error_t gcry_control(enum gcry_ctl_cmds CMD, ...);

/* ------------------------------------------------------------------ */
/* S-expressions                                                       */
/* ------------------------------------------------------------------ */

struct gcry_sexp;
typedef struct gcry_sexp *gcry_sexp_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_sexp *GCRY_SEXP _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_sexp *GcrySexp _GCRY_GCC_ATTR_DEPRECATED;
#endif

enum gcry_sexp_format {
    GCRYSEXP_FMT_DEFAULT = 0,
    GCRYSEXP_FMT_CANON = 1,
    GCRYSEXP_FMT_BASE64 = 2,
    GCRYSEXP_FMT_ADVANCED = 3
};

gcry_error_t gcry_sexp_new(gcry_sexp_t *retsexp, const void *buffer,
                           size_t length, int autodetect);
gcry_error_t gcry_sexp_create(gcry_sexp_t *retsexp, void *buffer,
                              size_t length, int autodetect,
                              void (*freefnc)(void *));
gcry_error_t gcry_sexp_sscan(gcry_sexp_t *retsexp, size_t *erroff,
                             const char *buffer, size_t length);
gcry_error_t gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff,
                             const char *format, ...);
gcry_error_t gcry_sexp_build_array(gcry_sexp_t *retsexp, size_t *erroff,
                                   const char *format, void **arg_list);
void gcry_sexp_release(gcry_sexp_t sexp);
size_t gcry_sexp_canon_len(const unsigned char *buffer, size_t length,
                           size_t *erroff, gcry_error_t *errcode);
size_t gcry_sexp_sprint(gcry_sexp_t sexp, int mode, void *buffer,
                        size_t maxlength);
void gcry_sexp_dump(const gcry_sexp_t a);
gcry_sexp_t gcry_sexp_cons(const gcry_sexp_t a, const gcry_sexp_t b);
gcry_sexp_t gcry_sexp_alist(const gcry_sexp_t *array);
gcry_sexp_t gcry_sexp_vlist(const gcry_sexp_t a, ...);
gcry_sexp_t gcry_sexp_append(const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_prepend(const gcry_sexp_t a, const gcry_sexp_t n);
gcry_sexp_t gcry_sexp_find_token(gcry_sexp_t list, const char *tok,
                                 size_t toklen);
int gcry_sexp_length(const gcry_sexp_t list);
gcry_sexp_t gcry_sexp_nth(const gcry_sexp_t list, int number);
gcry_sexp_t gcry_sexp_car(const gcry_sexp_t list);
gcry_sexp_t gcry_sexp_cdr(const gcry_sexp_t list);
gcry_sexp_t gcry_sexp_cadr(const gcry_sexp_t list);
const char *gcry_sexp_nth_data(const gcry_sexp_t list, int number,
                               size_t *datalen);
void *gcry_sexp_nth_buffer(const gcry_sexp_t list, int number,
                           size_t *rlength);
char *gcry_sexp_nth_string(gcry_sexp_t list, int number);
gcry_mpi_t gcry_sexp_nth_mpi(gcry_sexp_t list, int number, int mpifmt);
gpg_error_t gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path,
                                    const char *list, ...)
_GCRY_GCC_ATTR_SENTINEL(0);

/* ------------------------------------------------------------------ */
/* Multi precision integers                                            */
/* ------------------------------------------------------------------ */

enum gcry_mpi_format {
    GCRYMPI_FMT_NONE = 0,
    GCRYMPI_FMT_STD = 1,
    GCRYMPI_FMT_PGP = 2,
    GCRYMPI_FMT_SSH = 3,
    GCRYMPI_FMT_HEX = 4,
    GCRYMPI_FMT_USG = 5,
    GCRYMPI_FMT_OPAQUE = 8
};

enum gcry_mpi_flag {
    GCRYMPI_FLAG_SECURE = 1,
    GCRYMPI_FLAG_OPAQUE = 2,
    GCRYMPI_FLAG_IMMUTABLE = 4,
    GCRYMPI_FLAG_CONST = 8,
    GCRYMPI_FLAG_USER1 = 0x0100,
    GCRYMPI_FLAG_USER2 = 0x0200,
    GCRYMPI_FLAG_USER3 = 0x0400,
    GCRYMPI_FLAG_USER4 = 0x0800
};

#define GCRYMPI_CONST_ONE (_gcry_mpi_get_const(1))
#define GCRYMPI_CONST_TWO (_gcry_mpi_get_const(2))
#define GCRYMPI_CONST_THREE (_gcry_mpi_get_const(3))
#define GCRYMPI_CONST_FOUR (_gcry_mpi_get_const(4))
#define GCRYMPI_CONST_EIGHT (_gcry_mpi_get_const(8))

gcry_mpi_t gcry_mpi_new(unsigned int nbits);
gcry_mpi_t gcry_mpi_snew(unsigned int nbits);
void gcry_mpi_release(gcry_mpi_t a);
gcry_mpi_t gcry_mpi_copy(const gcry_mpi_t a);
void gcry_mpi_snatch(gcry_mpi_t w, gcry_mpi_t u);
gcry_mpi_t gcry_mpi_set(gcry_mpi_t w, const gcry_mpi_t u);
gcry_mpi_t gcry_mpi_set_ui(gcry_mpi_t w, unsigned long u);
gpg_error_t gcry_mpi_get_ui(unsigned int *w, gcry_mpi_t u);
void gcry_mpi_swap(gcry_mpi_t a, gcry_mpi_t b);
int gcry_mpi_is_neg(gcry_mpi_t a);
void gcry_mpi_neg(gcry_mpi_t w, gcry_mpi_t u);
void gcry_mpi_abs(gcry_mpi_t w);
int gcry_mpi_cmp(const gcry_mpi_t u, const gcry_mpi_t v);
int gcry_mpi_cmp_ui(const gcry_mpi_t u, unsigned long v);
gcry_error_t gcry_mpi_scan(gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
                           const void *buffer, size_t buflen,
                           size_t *nscanned);
gcry_error_t gcry_mpi_print(enum gcry_mpi_format format,
                            unsigned char *buffer, size_t buflen,
                            size_t *nwritten, const gcry_mpi_t a);
gcry_error_t gcry_mpi_aprint(enum gcry_mpi_format format,
                             unsigned char **buffer, size_t *nwritten,
                             const gcry_mpi_t a);
void gcry_mpi_dump(const gcry_mpi_t a);
void gcry_mpi_add(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
void gcry_mpi_add_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
void gcry_mpi_addm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
void gcry_mpi_sub(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
void gcry_mpi_sub_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
void gcry_mpi_subm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
void gcry_mpi_mul(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
void gcry_mpi_mul_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
void gcry_mpi_mulm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
void gcry_mpi_mul_2exp(gcry_mpi_t w, gcry_mpi_t u, unsigned long cnt);
void gcry_mpi_div(gcry_mpi_t q, gcry_mpi_t r, gcry_mpi_t dividend,
                  gcry_mpi_t divisor, int round);
void gcry_mpi_mod(gcry_mpi_t r, gcry_mpi_t dividend, gcry_mpi_t divisor);
void gcry_mpi_powm(gcry_mpi_t w, const gcry_mpi_t b, const gcry_mpi_t e,
                   const gcry_mpi_t m);
int gcry_mpi_gcd(gcry_mpi_t g, gcry_mpi_t a, gcry_mpi_t b);
int gcry_mpi_invm(gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m);

gcry_mpi_point_t gcry_mpi_point_new(unsigned int nbits);
void gcry_mpi_point_release(gcry_mpi_point_t point);
gcry_mpi_point_t gcry_mpi_point_copy(gcry_mpi_point_t point);
void gcry_mpi_point_get(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
                        gcry_mpi_point_t point);
void gcry_mpi_point_snatch_get(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
                               gcry_mpi_point_t point);
gcry_mpi_point_t gcry_mpi_point_set(gcry_mpi_point_t point, gcry_mpi_t x,
                                    gcry_mpi_t y, gcry_mpi_t z);
gcry_mpi_point_t gcry_mpi_point_snatch_set(gcry_mpi_point_t point,
                                           gcry_mpi_t x, gcry_mpi_t y,
                                           gcry_mpi_t z);

gpg_error_t gcry_mpi_ec_new(gcry_ctx_t *r_ctx, gcry_sexp_t keyparam,
                            const char *curvename);
gcry_mpi_t gcry_mpi_ec_get_mpi(const char *name, gcry_ctx_t ctx, int copy);
gcry_mpi_point_t gcry_mpi_ec_get_point(const char *name, gcry_ctx_t ctx,
                                       int copy);
gpg_error_t gcry_mpi_ec_set_mpi(const char *name, gcry_mpi_t newvalue,
                                gcry_ctx_t ctx);
gpg_error_t gcry_mpi_ec_set_point(const char *name,
                                  gcry_mpi_point_t newvalue, gcry_ctx_t ctx);
gpg_error_t gcry_mpi_ec_decode_point(gcry_mpi_point_t result,
                                     gcry_mpi_t value, gcry_ctx_t ctx);
int gcry_mpi_ec_get_affine(gcry_mpi_t x, gcry_mpi_t y,
                           gcry_mpi_point_t point, gcry_ctx_t ctx);
void gcry_mpi_ec_dup(gcry_mpi_point_t w, gcry_mpi_point_t u, gcry_ctx_t ctx);
void gcry_mpi_ec_add(gcry_mpi_point_t w, gcry_mpi_point_t u,
                     gcry_mpi_point_t v, gcry_ctx_t ctx);
void gcry_mpi_ec_sub(gcry_mpi_point_t w, gcry_mpi_point_t u,
                     gcry_mpi_point_t v, gcry_ctx_t ctx);
void gcry_mpi_ec_mul(gcry_mpi_point_t w, gcry_mpi_t n, gcry_mpi_point_t u,
                     gcry_ctx_t ctx);
int gcry_mpi_ec_curve_point(gcry_mpi_point_t w, gcry_ctx_t ctx);

unsigned int gcry_mpi_get_nbits(gcry_mpi_t a);
int gcry_mpi_test_bit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_set_bit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_clear_bit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_set_highbit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_clear_highbit(gcry_mpi_t a, unsigned int n);
void gcry_mpi_rshift(gcry_mpi_t x, gcry_mpi_t a, unsigned int n);
void gcry_mpi_lshift(gcry_mpi_t x, gcry_mpi_t a, unsigned int n);
gcry_mpi_t gcry_mpi_set_opaque(gcry_mpi_t a, void *p, unsigned int nbits);
gcry_mpi_t gcry_mpi_set_opaque_copy(gcry_mpi_t a, const void *p,
                                    unsigned int nbits);
void *gcry_mpi_get_opaque(gcry_mpi_t a, unsigned int *nbits);
void gcry_mpi_set_flag(gcry_mpi_t a, enum gcry_mpi_flag flag);
void gcry_mpi_clear_flag(gcry_mpi_t a, enum gcry_mpi_flag flag);
int gcry_mpi_get_flag(gcry_mpi_t a, enum gcry_mpi_flag flag);
gcry_mpi_t _gcry_mpi_get_const(int no);

#ifndef GCRYPT_NO_MPI_MACROS
#define mpi_new(n) gcry_mpi_new((n))
#define mpi_secure_new(n) gcry_mpi_snew((n))
#define mpi_release(a)        \
        do {                      \
            gcry_mpi_release((a));\
            (a) = NULL;           \
        } while (0)
#define mpi_copy(a) gcry_mpi_copy((a))
#define mpi_snatch(w, u) gcry_mpi_snatch((w), (u))
#define mpi_set(w, u) gcry_mpi_set((w), (u))
#define mpi_set_ui(w, u) gcry_mpi_set_ui((w), (u))
#define mpi_get_ui(w, u) gcry_mpi_get_ui((w), (u))
#define mpi_abs(w) gcry_mpi_abs((w))
#define mpi_neg(w, u) gcry_mpi_neg((w), (u))
#define mpi_cmp(u, v) gcry_mpi_cmp((u), (v))
#define mpi_cmp_ui(u, v) gcry_mpi_cmp_ui((u), (v))
#define mpi_is_neg(a) gcry_mpi_is_neg((a))
#define mpi_add_ui(w, u, v) gcry_mpi_add_ui((w), (u), (v))
#define mpi_add(w, u, v) gcry_mpi_add((w), (u), (v))
#define mpi_addm(w, u, v, m) gcry_mpi_addm((w), (u), (v), (m))
#define mpi_sub_ui(w, u, v) gcry_mpi_sub_ui((w), (u), (v))
#define mpi_sub(w, u, v) gcry_mpi_sub((w), (u), (v))
#define mpi_subm(w, u, v, m) gcry_mpi_subm((w), (u), (v), (m))
#define mpi_mul_ui(w, u, v) gcry_mpi_mul_ui((w), (u), (v))
#define mpi_mul_2exp(w, u, v) gcry_mpi_mul_2exp((w), (u), (v))
#define mpi_mul(w, u, v) gcry_mpi_mul((w), (u), (v))
#define mpi_mulm(w, u, v, m) gcry_mpi_mulm((w), (u), (v), (m))
#define mpi_powm(w, b, e, m) gcry_mpi_powm((w), (b), (e), (m))
#define mpi_tdiv(q, r, a, m) gcry_mpi_div((q), (r), (a), (m), 0)
#define mpi_fdiv(q, r, a, m) gcry_mpi_div((q), (r), (a), (m), -1)
#define mpi_mod(r, a, m) gcry_mpi_mod((r), (a), (m))
#define mpi_gcd(g, a, b) gcry_mpi_gcd((g), (a), (b))
#define mpi_invm(g, a, b) gcry_mpi_invm((g), (a), (b))
#define mpi_point_new(n) gcry_mpi_point_new((n))
#define mpi_point_release(p)        \
        do {                            \
            gcry_mpi_point_release((p));\
            (p) = NULL;                 \
        } while (0)
#define mpi_point_copy(p) gcry_mpi_point_copy((p))
#define mpi_point_get(x, y, z, p) gcry_mpi_point_get((x), (y), (z), (p))
#define mpi_point_snatch_get(x, y, z, p) \
        gcry_mpi_point_snatch_get((x), (y), (z), (p))
#define mpi_point_set(p, x, y, z) gcry_mpi_point_set((p), (x), (y), (z))
#define mpi_point_snatch_set(p, x, y, z) \
        gcry_mpi_point_snatch_set((p), (x), (y), (z))
#define mpi_get_nbits(a) gcry_mpi_get_nbits((a))
#define mpi_test_bit(a, b) gcry_mpi_test_bit((a), (b))
#define mpi_set_bit(a, b) gcry_mpi_set_bit((a), (b))
#define mpi_set_highbit(a, b) gcry_mpi_set_highbit((a), (b))
#define mpi_clear_bit(a, b) gcry_mpi_clear_bit((a), (b))
#define mpi_clear_highbit(a, b) gcry_mpi_clear_highbit((a), (b))
#define mpi_rshift(a, b, c) gcry_mpi_rshift((a), (b), (c))
#define mpi_lshift(a, b, c) gcry_mpi_lshift((a), (b), (c))
#define mpi_set_opaque(a, b, c) gcry_mpi_set_opaque((a), (b), (c))
#define mpi_get_opaque(a, b) gcry_mpi_get_opaque((a), (b))
#endif /* GCRYPT_NO_MPI_MACROS */

/* ------------------------------------------------------------------ */
/* Symmetric ciphers                                                   */
/* ------------------------------------------------------------------ */

struct gcry_cipher_handle;
typedef struct gcry_cipher_handle *gcry_cipher_hd_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_cipher_handle *GCRY_CIPHER_HD _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_cipher_handle *GcryCipherHd _GCRY_GCC_ATTR_DEPRECATED;
#endif

enum gcry_cipher_algos {
    GCRY_CIPHER_NONE = 0,
    GCRY_CIPHER_IDEA = 1,
    GCRY_CIPHER_3DES = 2,
    GCRY_CIPHER_CAST5 = 3,
    GCRY_CIPHER_BLOWFISH = 4,
    GCRY_CIPHER_SAFER_SK128 = 5,
    GCRY_CIPHER_DES_SK = 6,
    GCRY_CIPHER_AES = 7,
    GCRY_CIPHER_AES192 = 8,
    GCRY_CIPHER_AES256 = 9,
    GCRY_CIPHER_TWOFISH = 10,
    GCRY_CIPHER_ARCFOUR = 301,
    GCRY_CIPHER_DES = 302,
    GCRY_CIPHER_TWOFISH128 = 303,
    GCRY_CIPHER_SERPENT128 = 304,
    GCRY_CIPHER_SERPENT192 = 305,
    GCRY_CIPHER_SERPENT256 = 306,
    GCRY_CIPHER_RFC2268_40 = 307,
    GCRY_CIPHER_RFC2268_128 = 308,
    GCRY_CIPHER_SEED = 309,
    GCRY_CIPHER_CAMELLIA128 = 310,
    GCRY_CIPHER_CAMELLIA192 = 311,
    GCRY_CIPHER_CAMELLIA256 = 312,
    GCRY_CIPHER_SALSA20 = 313,
    GCRY_CIPHER_SALSA20R12 = 314,
    GCRY_CIPHER_GOST28147 = 315,
    GCRY_CIPHER_CHACHA20 = 316,
    GCRY_CIPHER_GOST28147_MESH = 317,
    GCRY_CIPHER_SM4 = 318,
    GCRY_CIPHER_ARIA128 = 319,
    GCRY_CIPHER_ARIA192 = 320,
    GCRY_CIPHER_ARIA256 = 321
};

#define GCRY_CIPHER_AES128 GCRY_CIPHER_AES
#define GCRY_CIPHER_RIJNDAEL GCRY_CIPHER_AES
#define GCRY_CIPHER_RIJNDAEL128 GCRY_CIPHER_AES128
#define GCRY_CIPHER_RIJNDAEL192 GCRY_CIPHER_AES192
#define GCRY_CIPHER_RIJNDAEL256 GCRY_CIPHER_AES256

enum gcry_cipher_modes {
    GCRY_CIPHER_MODE_NONE = 0,
    GCRY_CIPHER_MODE_ECB = 1,
    GCRY_CIPHER_MODE_CFB = 2,
    GCRY_CIPHER_MODE_CBC = 3,
    GCRY_CIPHER_MODE_STREAM = 4,
    GCRY_CIPHER_MODE_OFB = 5,
    GCRY_CIPHER_MODE_CTR = 6,
    GCRY_CIPHER_MODE_AESWRAP = 7,
    GCRY_CIPHER_MODE_CCM = 8,
    GCRY_CIPHER_MODE_GCM = 9,
    GCRY_CIPHER_MODE_POLY1305 = 10,
    GCRY_CIPHER_MODE_OCB = 11,
    GCRY_CIPHER_MODE_CFB8 = 12,
    GCRY_CIPHER_MODE_XTS = 13,
    GCRY_CIPHER_MODE_EAX = 14,
    GCRY_CIPHER_MODE_SIV = 15,
    GCRY_CIPHER_MODE_GCM_SIV = 16
};

enum gcry_cipher_flags {
    GCRY_CIPHER_SECURE = 1,
    GCRY_CIPHER_ENABLE_SYNC = 2,
    GCRY_CIPHER_CBC_CTS = 4,
    GCRY_CIPHER_CBC_MAC = 8,
    GCRY_CIPHER_EXTENDED = 16
};

enum gcry_cipher_geniv_methods {
    GCRY_CIPHER_GENIV_METHOD_CONCAT = 1,
    GCRY_CIPHER_GENIV_METHOD_XOR = 2
};

#define GCRY_GCM_BLOCK_LEN (128 / 8)
#define GCRY_CCM_BLOCK_LEN (128 / 8)
#define GCRY_OCB_BLOCK_LEN (128 / 8)
#define GCRY_XTS_BLOCK_LEN (128 / 8)
#define GCRY_SIV_BLOCK_LEN (128 / 8)

gcry_error_t gcry_cipher_open(gcry_cipher_hd_t *handle, int algo, int mode,
                              unsigned int flags);
void gcry_cipher_close(gcry_cipher_hd_t h);
gcry_error_t gcry_cipher_ctl(gcry_cipher_hd_t h, int cmd, void *buffer,
                             size_t buflen);
gcry_error_t gcry_cipher_info(gcry_cipher_hd_t h, int what, void *buffer,
                              size_t *nbytes);
gcry_error_t gcry_cipher_algo_info(int algo, int what, void *buffer,
                                   size_t *nbytes);
const char *gcry_cipher_algo_name(int algorithm) _GCRY_GCC_ATTR_PURE;
int gcry_cipher_map_name(const char *name) _GCRY_GCC_ATTR_PURE;
int gcry_cipher_mode_from_oid(const char *string) _GCRY_GCC_ATTR_PURE;
gcry_error_t gcry_cipher_encrypt(gcry_cipher_hd_t h, void *out,
                                 size_t outsize, const void *in,
                                 size_t inlen);
gcry_error_t gcry_cipher_decrypt(gcry_cipher_hd_t h, void *out,
                                 size_t outsize, const void *in,
                                 size_t inlen);
gcry_error_t gcry_cipher_setkey(gcry_cipher_hd_t hd, const void *key,
                                size_t keylen);
gcry_error_t gcry_cipher_setiv(gcry_cipher_hd_t hd, const void *iv,
                               size_t ivlen);
gcry_error_t gcry_cipher_setup_geniv(gcry_cipher_hd_t hd, int method,
                                     const void *fixed_iv,
                                     size_t fixed_ivlen, const void *dyn_iv,
                                     size_t dyn_ivlen);
gcry_error_t gcry_cipher_geniv(gcry_cipher_hd_t hd, void *iv, size_t ivlen);
gcry_error_t gcry_cipher_authenticate(gcry_cipher_hd_t hd, const void *abuf,
                                      size_t abuflen);
gcry_error_t gcry_cipher_gettag(gcry_cipher_hd_t hd, void *outtag,
                                size_t taglen);
gcry_error_t gcry_cipher_checktag(gcry_cipher_hd_t hd, const void *intag,
                                  size_t taglen);

#define gcry_cipher_reset(h) gcry_cipher_ctl((h), GCRYCTL_RESET, NULL, 0)
#define gcry_cipher_sync(h) gcry_cipher_ctl((h), GCRYCTL_CFB_SYNC, NULL, 0)
#define gcry_cipher_cts(h, on) \
    gcry_cipher_ctl((h), GCRYCTL_SET_CBC_CTS, NULL, on)
#define gcry_cipher_set_sbox(h, oid) \
    gcry_cipher_ctl((h), GCRYCTL_SET_SBOX, (void *)oid, 0);
#define gcry_cipher_final(a) gcry_cipher_ctl((a), GCRYCTL_FINALIZE, NULL, 0)

gpg_error_t gcry_cipher_setctr(gcry_cipher_hd_t hd, const void *ctr,
                               size_t ctrlen);
size_t gcry_cipher_get_algo_keylen(int algo);
size_t gcry_cipher_get_algo_blklen(int algo);

#define gcry_cipher_test_algo(a) \
    gcry_cipher_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)
#define gcry_cipher_set_decryption_tag(a, tag, taglen) \
    gcry_cipher_ctl((a), GCRYCTL_SET_DECRYPTION_TAG, (void *)(tag), (taglen))

/* ------------------------------------------------------------------ */
/* Public key algorithms                                               */
/* ------------------------------------------------------------------ */

enum gcry_pk_algos {
    GCRY_PK_RSA = 1,
    GCRY_PK_RSA_E = 2,
    GCRY_PK_RSA_S = 3,
    GCRY_PK_ELG_E = 16,
    GCRY_PK_DSA = 17,
    GCRY_PK_ECC = 18,
    GCRY_PK_ELG = 20,
    GCRY_PK_ECDSA = 301,
    GCRY_PK_ECDH = 302,
    GCRY_PK_EDDSA = 303,
    GCRY_PK_MLDSA = 332,
    GCRY_PK_KEM = 333
};

#define GCRY_PK_USAGE_SIGN 1
#define GCRY_PK_USAGE_ENCR 2
#define GCRY_PK_USAGE_CERT 4
#define GCRY_PK_USAGE_AUTH 8
#define GCRY_PK_USAGE_UNKN 128

#define GCRY_PK_GET_PUBKEY 1
#define GCRY_PK_GET_SECKEY 2

gcry_error_t gcry_pk_encrypt(gcry_sexp_t *result, gcry_sexp_t data,
                             gcry_sexp_t pkey);
gcry_error_t gcry_pk_decrypt(gcry_sexp_t *result, gcry_sexp_t data,
                             gcry_sexp_t skey);
gcry_error_t gcry_pk_sign(gcry_sexp_t *result, gcry_sexp_t data,
                          gcry_sexp_t skey);
gcry_error_t gcry_pk_verify(gcry_sexp_t sigval, gcry_sexp_t data,
                            gcry_sexp_t pkey);
gcry_error_t gcry_pk_testkey(gcry_sexp_t key);
gcry_error_t gcry_pk_genkey(gcry_sexp_t *r_key, gcry_sexp_t s_parms);
gcry_error_t gcry_pk_ctl(int cmd, void *buffer, size_t buflen);
gcry_error_t gcry_pk_algo_info(int algo, int what, void *buffer,
                               size_t *nbytes);
const char *gcry_pk_algo_name(int algorithm) _GCRY_GCC_ATTR_PURE;
int gcry_pk_map_name(const char *name) _GCRY_GCC_ATTR_PURE;
unsigned int gcry_pk_get_nbits(gcry_sexp_t key) _GCRY_GCC_ATTR_PURE;
unsigned char *gcry_pk_get_keygrip(gcry_sexp_t key, unsigned char *array);
const char *gcry_pk_get_curve(gcry_sexp_t key, int iterator,
                              unsigned int *r_nbits);
gcry_sexp_t gcry_pk_get_param(int algo, const char *name);

#define gcry_pk_test_algo(a) \
    gcry_pk_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)

gcry_error_t gcry_pubkey_get_sexp(gcry_sexp_t *r_sexp, int mode,
                                  gcry_ctx_t ctx);

/* Modern ECC helpers. */
enum gcry_ecc_curves {
    GCRY_ECC_CURVE25519 = 1,
    GCRY_ECC_CURVE448 = 2
};

unsigned int gcry_ecc_get_algo_keylen(int curveid);
gpg_error_t gcry_ecc_mul_point(int curveid, unsigned char *result,
                               const unsigned char *scalar,
                               const unsigned char *point);

/* ------------------------------------------------------------------ */
/* Message digests                                                     */
/* ------------------------------------------------------------------ */

enum gcry_md_algos {
    GCRY_MD_NONE = 0,
    GCRY_MD_MD5 = 1,
    GCRY_MD_SHA1 = 2,
    GCRY_MD_RMD160 = 3,
    GCRY_MD_MD2 = 5,
    GCRY_MD_TIGER = 6,
    GCRY_MD_HAVAL = 7,
    GCRY_MD_SHA256 = 8,
    GCRY_MD_SHA384 = 9,
    GCRY_MD_SHA512 = 10,
    GCRY_MD_SHA224 = 11,
    GCRY_MD_MD4 = 301,
    GCRY_MD_CRC32 = 302,
    GCRY_MD_CRC32_RFC1510 = 303,
    GCRY_MD_CRC24_RFC2440 = 304,
    GCRY_MD_WHIRLPOOL = 305,
    GCRY_MD_TIGER1 = 306,
    GCRY_MD_TIGER2 = 307,
    GCRY_MD_GOSTR3411_94 = 308,
    GCRY_MD_STRIBOG256 = 309,
    GCRY_MD_STRIBOG512 = 310,
    GCRY_MD_GOSTR3411_CP = 311,
    GCRY_MD_SHA3_224 = 312,
    GCRY_MD_SHA3_256 = 313,
    GCRY_MD_SHA3_384 = 314,
    GCRY_MD_SHA3_512 = 315,
    GCRY_MD_SHAKE128 = 316,
    GCRY_MD_SHAKE256 = 317,
    GCRY_MD_BLAKE2B_512 = 318,
    GCRY_MD_BLAKE2B_384 = 319,
    GCRY_MD_BLAKE2B_256 = 320,
    GCRY_MD_BLAKE2B_160 = 321,
    GCRY_MD_BLAKE2S_256 = 322,
    GCRY_MD_BLAKE2S_224 = 323,
    GCRY_MD_BLAKE2S_160 = 324,
    GCRY_MD_BLAKE2S_128 = 325,
    GCRY_MD_SM3 = 326,
    GCRY_MD_SHA512_256 = 327,
    GCRY_MD_SHA512_224 = 328,
    GCRY_MD_CSHAKE128 = 329,
    GCRY_MD_CSHAKE256 = 330
};

enum gcry_md_flags {
    GCRY_MD_FLAG_SECURE = 1,
    GCRY_MD_FLAG_HMAC = 2,
    GCRY_MD_FLAG_BUGEMU1 = 0x0100
};

struct gcry_md_context;

/* The layout of this structure is part of the ABI: the gcry_md_putc()
 * macro below touches its members directly. */
typedef struct gcry_md_handle {
    struct gcry_md_context *ctx;
    int bufpos;
    int bufsize;
    unsigned char buf[1];
} *gcry_md_hd_t;

#ifndef GCRYPT_NO_DEPRECATED
typedef struct gcry_md_handle *GCRY_MD_HD _GCRY_GCC_ATTR_DEPRECATED;
typedef struct gcry_md_handle *GcryMDHd _GCRY_GCC_ATTR_DEPRECATED;
#endif

gcry_error_t gcry_md_open(gcry_md_hd_t *h, int algo, unsigned int flags);
void gcry_md_close(gcry_md_hd_t hd);
gcry_error_t gcry_md_enable(gcry_md_hd_t hd, int algo);
gcry_error_t gcry_md_copy(gcry_md_hd_t *bhd, gcry_md_hd_t ahd);
void gcry_md_reset(gcry_md_hd_t hd);
gcry_error_t gcry_md_ctl(gcry_md_hd_t hd, int cmd, void *buffer,
                         size_t buflen);
void gcry_md_write(gcry_md_hd_t hd, const void *buffer, size_t length);
unsigned char *gcry_md_read(gcry_md_hd_t hd, int algo);
gpg_error_t gcry_md_extract(gcry_md_hd_t hd, int algo, void *buffer,
                            size_t length);
void gcry_md_hash_buffer(int algo, void *digest, const void *buffer,
                         size_t length);
gpg_error_t gcry_md_hash_buffers(int algo, unsigned int flags, void *digest,
                                 const gcry_buffer_t *iov, int iovcnt);
gpg_error_t gcry_md_hash_buffers_ext(int algo, unsigned int flags,
                                     void *digest, int digestlen,
                                     const gcry_buffer_t *iov, int iovcnt);
int gcry_md_get_algo(gcry_md_hd_t hd);
unsigned int gcry_md_get_algo_dlen(int algo);
int gcry_md_is_enabled(gcry_md_hd_t a, int algo);
int gcry_md_is_secure(gcry_md_hd_t a);
gcry_error_t gcry_md_info(gcry_md_hd_t h, int what, void *buffer,
                          size_t *nbytes) _GCRY_ATTR_INTERNAL;
gcry_error_t gcry_md_algo_info(int algo, int what, void *buffer,
                               size_t *nbytes);
const char *gcry_md_algo_name(int algo) _GCRY_GCC_ATTR_PURE;
int gcry_md_map_name(const char *name) _GCRY_GCC_ATTR_PURE;
gcry_error_t gcry_md_setkey(gcry_md_hd_t hd, const void *key, size_t keylen);
void gcry_md_debug(gcry_md_hd_t hd, const char *suffix);

#define gcry_md_putc(h, c)                                \
    do {                                                  \
        gcry_md_hd_t h__ = (h);                           \
        if ((h__)->bufpos == (h__)->bufsize)              \
            gcry_md_write((h__), NULL, 0);                \
        (h__)->buf[(h__)->bufpos++] = (c) & 0xff;         \
    } while (0)

#define gcry_md_final(a) gcry_md_ctl((a), GCRYCTL_FINALIZE, NULL, 0)
#define gcry_md_test_algo(a) \
    gcry_md_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)
#define gcry_md_get_asnoid(a, b, n) \
    gcry_md_algo_info((a), GCRYCTL_GET_ASNOID, (b), (n))

struct gcry_cshake_customization {
    const void *n;
    unsigned int n_len;
    const void *s;
    unsigned int s_len;
};

/* ------------------------------------------------------------------ */
/* Message authentication codes                                        */
/* ------------------------------------------------------------------ */

struct gcry_mac_handle;
typedef struct gcry_mac_handle *gcry_mac_hd_t;

enum gcry_mac_algos {
    GCRY_MAC_NONE = 0,
    GCRY_MAC_GOST28147_IMIT = 1,
    GCRY_MAC_HMAC_SHA256 = 101,
    GCRY_MAC_HMAC_SHA224 = 102,
    GCRY_MAC_HMAC_SHA512 = 103,
    GCRY_MAC_HMAC_SHA384 = 104,
    GCRY_MAC_HMAC_SHA1 = 105,
    GCRY_MAC_HMAC_MD5 = 106,
    GCRY_MAC_HMAC_MD4 = 107,
    GCRY_MAC_HMAC_RMD160 = 108,
    GCRY_MAC_HMAC_TIGER1 = 109,
    GCRY_MAC_HMAC_WHIRLPOOL = 110,
    GCRY_MAC_HMAC_GOSTR3411_94 = 111,
    GCRY_MAC_HMAC_STRIBOG256 = 112,
    GCRY_MAC_HMAC_STRIBOG512 = 113,
    GCRY_MAC_HMAC_MD2 = 114,
    GCRY_MAC_HMAC_SHA3_224 = 115,
    GCRY_MAC_HMAC_SHA3_256 = 116,
    GCRY_MAC_HMAC_SHA3_384 = 117,
    GCRY_MAC_HMAC_SHA3_512 = 118,
    GCRY_MAC_HMAC_GOSTR3411_CP = 119,
    GCRY_MAC_HMAC_BLAKE2B_512 = 120,
    GCRY_MAC_HMAC_BLAKE2B_384 = 121,
    GCRY_MAC_HMAC_BLAKE2B_256 = 122,
    GCRY_MAC_HMAC_BLAKE2B_160 = 123,
    GCRY_MAC_HMAC_BLAKE2S_256 = 124,
    GCRY_MAC_HMAC_BLAKE2S_224 = 125,
    GCRY_MAC_HMAC_BLAKE2S_160 = 126,
    GCRY_MAC_HMAC_BLAKE2S_128 = 127,
    GCRY_MAC_HMAC_SM3 = 128,
    GCRY_MAC_HMAC_SHA512_256 = 129,
    GCRY_MAC_HMAC_SHA512_224 = 130,
    GCRY_MAC_CMAC_AES = 201,
    GCRY_MAC_CMAC_3DES = 202,
    GCRY_MAC_CMAC_CAMELLIA = 203,
    GCRY_MAC_CMAC_CAST5 = 204,
    GCRY_MAC_CMAC_BLOWFISH = 205,
    GCRY_MAC_CMAC_TWOFISH = 206,
    GCRY_MAC_CMAC_SERPENT = 207,
    GCRY_MAC_CMAC_SEED = 208,
    GCRY_MAC_CMAC_RFC2268 = 209,
    GCRY_MAC_CMAC_IDEA = 210,
    GCRY_MAC_CMAC_GOST28147 = 211,
    GCRY_MAC_CMAC_SM4 = 212,
    GCRY_MAC_CMAC_ARIA = 213,
    GCRY_MAC_GMAC_AES = 401,
    GCRY_MAC_GMAC_CAMELLIA = 402,
    GCRY_MAC_GMAC_TWOFISH = 403,
    GCRY_MAC_GMAC_SERPENT = 404,
    GCRY_MAC_GMAC_SEED = 405,
    GCRY_MAC_GMAC_SM4 = 406,
    GCRY_MAC_GMAC_ARIA = 407,
    GCRY_MAC_POLY1305 = 501,
    GCRY_MAC_POLY1305_AES = 502,
    GCRY_MAC_POLY1305_CAMELLIA = 503,
    GCRY_MAC_POLY1305_TWOFISH = 504,
    GCRY_MAC_POLY1305_SERPENT = 505,
    GCRY_MAC_POLY1305_SEED = 506,
    GCRY_MAC_POLY1305_SM4 = 507,
    GCRY_MAC_POLY1305_ARIA = 508
};

enum gcry_mac_flags {
    GCRY_MAC_FLAG_SECURE = 1
};

gcry_error_t gcry_mac_open(gcry_mac_hd_t *handle, int algo,
                           unsigned int flags, gcry_ctx_t ctx);
void gcry_mac_close(gcry_mac_hd_t h);
gcry_error_t gcry_mac_ctl(gcry_mac_hd_t h, int cmd, void *buffer,
                          size_t buflen);
gcry_error_t gcry_mac_algo_info(int algo, int what, void *buffer,
                                size_t *nbytes);
gcry_error_t gcry_mac_setkey(gcry_mac_hd_t hd, const void *key,
                             size_t keylen);
gcry_error_t gcry_mac_setiv(gcry_mac_hd_t hd, const void *iv, size_t ivlen);
gcry_error_t gcry_mac_write(gcry_mac_hd_t hd, const void *buffer,
                            size_t length);
gcry_error_t gcry_mac_read(gcry_mac_hd_t hd, void *buffer, size_t *buflen);
gcry_error_t gcry_mac_verify(gcry_mac_hd_t hd, const void *buffer,
                             size_t buflen);
int gcry_mac_get_algo(gcry_mac_hd_t hd);
unsigned int gcry_mac_get_algo_maclen(int algo);
unsigned int gcry_mac_get_algo_keylen(int algo);
const char *gcry_mac_algo_name(int algorithm) _GCRY_GCC_ATTR_PURE;
int gcry_mac_map_name(const char *name) _GCRY_GCC_ATTR_PURE;

#define gcry_mac_reset(h) gcry_mac_ctl((h), GCRYCTL_RESET, NULL, 0)
#define gcry_mac_test_algo(a) \
    gcry_mac_algo_info((a), GCRYCTL_TEST_ALGO, NULL, NULL)

/* ------------------------------------------------------------------ */
/* Key derivation                                                      */
/* ------------------------------------------------------------------ */

enum gcry_kdf_algos {
    GCRY_KDF_NONE = 0,
    GCRY_KDF_SIMPLE_S2K = 16,
    GCRY_KDF_SALTED_S2K = 17,
    GCRY_KDF_ITERSALTED_S2K = 19,
    GCRY_KDF_PBKDF1 = 33,
    GCRY_KDF_PBKDF2 = 34,
    GCRY_KDF_SCRYPT = 48,
    GCRY_KDF_ARGON2 = 64,
    GCRY_KDF_BALLOON = 65,
    GCRY_KDF_ONESTEP_KDF = 96,
    GCRY_KDF_ONESTEP_KDF_MAC = 97,
    GCRY_KDF_HKDF = 98,
    GCRY_KDF_X963_KDF = 101
};

enum gcry_kdf_subalgo_argon2 {
    GCRY_KDF_ARGON2D = 0,
    GCRY_KDF_ARGON2I = 1,
    GCRY_KDF_ARGON2ID = 2
};

gpg_error_t gcry_kdf_derive(const void *passphrase, size_t passphraselen,
                            int algo, int subalgo, const void *salt,
                            size_t saltlen, unsigned long iterations,
                            size_t keysize, void *keybuffer);

typedef struct gcry_kdf_handle *gcry_kdf_hd_t;

typedef void (*gcry_kdf_job_fn_t)(void *priv);
typedef int (*gcry_kdf_dispatch_job_fn_t)(void *jobs_context,
                                          gcry_kdf_job_fn_t job_fn,
                                          void *job_priv);
typedef int (*gcry_kdf_wait_all_jobs_fn_t)(void *jobs_context);

typedef struct gcry_kdf_thread_ops {
    void *jobs_context;
    gcry_kdf_dispatch_job_fn_t dispatch_job;
    gcry_kdf_wait_all_jobs_fn_t wait_all_jobs;
} gcry_kdf_thread_ops_t;

gcry_error_t gcry_kdf_open(gcry_kdf_hd_t *hd, int algo, int subalgo,
                           const unsigned long *param, unsigned int paramlen,
                           const void *passphrase, size_t passphraselen,
                           const void *salt, size_t saltlen, const void *key,
                           size_t keylen, const void *ad, size_t adlen);
gcry_error_t gcry_kdf_compute(gcry_kdf_hd_t h,
                              const gcry_kdf_thread_ops_t *ops);
gcry_error_t gcry_kdf_final(gcry_kdf_hd_t h, size_t resultlen, void *result);
void gcry_kdf_close(gcry_kdf_hd_t h);

/* ------------------------------------------------------------------ */
/* Key encapsulation                                                   */
/* ------------------------------------------------------------------ */

enum gcry_kem_algos {
    GCRY_KEM_NONE = 0,
    GCRY_KEM_SNTRUP761 = 1,
#define GCRY_KEM_SNTRUP761 GCRY_KEM_SNTRUP761
    GCRY_KEM_CM6688128F = 2,
#define GCRY_KEM_CM6688128F GCRY_KEM_CM6688128F
    GCRY_KEM_MLKEM512 = 3,
#define GCRY_KEM_RAW_MLKEM512 GCRY_KEM_RAW_MLKEM512
    GCRY_KEM_MLKEM768 = 4,
#define GCRY_KEM_RAW_MLKEM768 GCRY_KEM_RAW_MLKEM768
    GCRY_KEM_MLKEM1024 = 5,
#define GCRY_KEM_RAW_MLKEM1024 GCRY_KEM_RAW_MLKEM1024
    GCRY_KEM_RAW_X25519 = 31,
#define GCRY_KEM_RAW_X25519 GCRY_KEM_RAW_X25519
    GCRY_KEM_RAW_X448 = 32,
#define GCRY_KEM_RAW_X448 GCRY_KEM_RAW_X448
    GCRY_KEM_RAW_BP256 = 33,
#define GCRY_KEM_RAW_BP256 GCRY_KEM_RAW_BP256
    GCRY_KEM_RAW_BP384 = 34,
#define GCRY_KEM_RAW_BP384 GCRY_KEM_RAW_BP384
    GCRY_KEM_RAW_BP512 = 35,
#define GCRY_KEM_RAW_BP512 GCRY_KEM_RAW_BP512
    GCRY_KEM_RAW_P256R1 = 36,
#define GCRY_KEM_RAW_P256R1 GCRY_KEM_RAW_P256R1
    GCRY_KEM_RAW_P384R1 = 37,
#define GCRY_KEM_RAW_P384R1 GCRY_KEM_RAW_P384R1
    GCRY_KEM_RAW_P521R1 = 38,
#define GCRY_KEM_RAW_P521R1 GCRY_KEM_RAW_P521R1
    GCRY_KEM_RAW_P256K1 = 39,
#define GCRY_KEM_RAW_P256K1 GCRY_KEM_RAW_P256K1
    GCRY_KEM_DHKEM25519 = 41,
#define GCRY_KEM_DHKEM25519 GCRY_KEM_DHKEM25519
    GCRY_KEM_DHKEM448 = 42,
#define GCRY_KEM_DHKEM448 GCRY_KEM_DHKEM448
    GCRY_KEM_DHKEMP256R1 = 43,
#define GCRY_KEM_DHKEMP256R1 GCRY_KEM_DHKEMP256R1
    GCRY_KEM_DHKEMP384R1 = 44,
#define GCRY_KEM_DHKEMP384R1 GCRY_KEM_DHKEMP384R1
    GCRY_KEM_DHKEMP521R1 = 45
#define GCRY_KEM_DHKEMP521R1 GCRY_KEM_DHKEMP521R1
};

#define GCRY_KEM_SNTRUP761_SECKEY_LEN 1763
#define GCRY_KEM_SNTRUP761_PUBKEY_LEN 1158
#define GCRY_KEM_SNTRUP761_ENCAPS_LEN 1039
#define GCRY_KEM_SNTRUP761_CIPHER_LEN GCRY_KEM_SNTRUP761_ENCAPS_LEN
#define GCRY_KEM_SNTRUP761_SHARED_LEN 32

#define GCRY_KEM_CM6688128F_SECKEY_LEN 13932
#define GCRY_KEM_CM6688128F_PUBKEY_LEN 1044992
#define GCRY_KEM_CM6688128F_ENCAPS_LEN 208
#define GCRY_KEM_CM6688128F_CIPHER_LEN GCRY_KEM_CM6688128F_ENCAPS_LEN
#define GCRY_KEM_CM6688128F_SHARED_LEN 32

#define GCRY_KEM_MLKEM_RANDOM_LEN 32
#define GCRY_KEM_MLKEM512_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN
#define GCRY_KEM_MLKEM768_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN
#define GCRY_KEM_MLKEM1024_RANDOM_LEN GCRY_KEM_MLKEM_RANDOM_LEN

#define GCRY_KEM_MLKEM512_SECKEY_LEN (2 * 384 + 2 * 384 + 32 + 2 * 32)
#define GCRY_KEM_MLKEM512_PUBKEY_LEN (2 * 384 + 32)
#define GCRY_KEM_MLKEM512_ENCAPS_LEN (128 + 2 * 320)
#define GCRY_KEM_MLKEM512_CIPHER_LEN GCRY_KEM_MLKEM512_ENCAPS_LEN
#define GCRY_KEM_MLKEM512_SHARED_LEN 32

#define GCRY_KEM_MLKEM768_SECKEY_LEN (3 * 384 + 3 * 384 + 32 + 2 * 32)
#define GCRY_KEM_MLKEM768_PUBKEY_LEN (3 * 384 + 32)
#define GCRY_KEM_MLKEM768_ENCAPS_LEN (128 + 3 * 320)
#define GCRY_KEM_MLKEM768_CIPHER_LEN GCRY_KEM_MLKEM768_ENCAPS_LEN
#define GCRY_KEM_MLKEM768_SHARED_LEN 32

#define GCRY_KEM_MLKEM1024_SECKEY_LEN (4 * 384 + 4 * 384 + 32 + 2 * 32)
#define GCRY_KEM_MLKEM1024_PUBKEY_LEN (4 * 384 + 32)
#define GCRY_KEM_MLKEM1024_ENCAPS_LEN (160 + 4 * 352)
#define GCRY_KEM_MLKEM1024_CIPHER_LEN GCRY_KEM_MLKEM1024_ENCAPS_LEN
#define GCRY_KEM_MLKEM1024_SHARED_LEN 32

#define GCRY_KEM_ECC_X25519_SECKEY_LEN 32
#define GCRY_KEM_ECC_X25519_PUBKEY_LEN 32
#define GCRY_KEM_ECC_X25519_ENCAPS_LEN 32
#define GCRY_KEM_ECC_X25519_CIPHER_LEN GCRY_KEM_ECC_X25519_ENCAPS_LEN
#define GCRY_KEM_RAW_X25519_SHARED_LEN 32

#define GCRY_KEM_DHKEM25519_SECKEY_LEN GCRY_KEM_ECC_X25519_SECKEY_LEN
#define GCRY_KEM_DHKEM25519_PUBKEY_LEN GCRY_KEM_ECC_X25519_PUBKEY_LEN
#define GCRY_KEM_DHKEM25519_ENCAPS_LEN GCRY_KEM_ECC_X25519_ENCAPS_LEN
#define GCRY_KEM_DHKEM25519_CIPHER_LEN GCRY_KEM_DHKEM25519_ENCAPS_LEN
#define GCRY_KEM_DHKEM25519_SHARED_LEN 32

#define GCRY_KEM_ECC_X448_SECKEY_LEN 56
#define GCRY_KEM_ECC_X448_PUBKEY_LEN 56
#define GCRY_KEM_ECC_X448_ENCAPS_LEN 56
#define GCRY_KEM_ECC_X448_CIPHER_LEN GCRY_KEM_ECC_X448_ENCAPS_LEN
#define GCRY_KEM_RAW_X448_SHARED_LEN 56

#define GCRY_KEM_DHKEM448_SECKEY_LEN GCRY_KEM_ECC_X448_SECKEY_LEN
#define GCRY_KEM_DHKEM448_PUBKEY_LEN GCRY_KEM_ECC_X448_PUBKEY_LEN
#define GCRY_KEM_DHKEM448_ENCAPS_LEN GCRY_KEM_ECC_X448_ENCAPS_LEN
#define GCRY_KEM_DHKEM448_CIPHER_LEN GCRY_KEM_DHKEM448_ENCAPS_LEN
#define GCRY_KEM_DHKEM448_SHARED_LEN 56

#define GCRY_KEM_ECC_BP256_SECKEY_LEN 32
#define GCRY_KEM_ECC_BP256_PUBKEY_LEN (1 + 32 + 32)
#define GCRY_KEM_ECC_BP256_ENCAPS_LEN (1 + 32 + 32)
#define GCRY_KEM_ECC_BP256_CIPHER_LEN GCRY_KEM_ECC_BP256_ENCAPS_LEN
#define GCRY_KEM_RAW_BP256_SHARED_LEN (1 + 32 + 32)

#define GCRY_KEM_ECC_BP384_SECKEY_LEN 48
#define GCRY_KEM_ECC_BP384_PUBKEY_LEN (1 + 48 + 48)
#define GCRY_KEM_ECC_BP384_ENCAPS_LEN (1 + 48 + 48)
#define GCRY_KEM_ECC_BP384_CIPHER_LEN GCRY_KEM_ECC_BP384_ENCAPS_LEN
#define GCRY_KEM_RAW_BP384_SHARED_LEN (1 + 48 + 48)

gcry_error_t gcry_kem_genkey(int algo, void *pubkey, size_t pubkey_len,
                             void *seckey, size_t seckey_len,
                             const void *optional, size_t optional_len);
gcry_error_t gcry_kem_keypair(int algo, void *pubkey, size_t pubkey_len,
                              void *seckey, size_t seckey_len);
gcry_error_t gcry_kem_encap(int algo, const void *pubkey, size_t pubkey_len,
                            void *ciphertext, size_t ciphertext_len,
                            void *shared, size_t shared_len,
                            const void *optional, size_t optional_len);
gcry_error_t gcry_kem_decap(int algo, const void *seckey, size_t seckey_len,
                            const void *ciphertext, size_t ciphertext_len,
                            void *shared, size_t shared_len,
                            const void *optional, size_t optional_len);

/* ------------------------------------------------------------------ */
/* Random numbers                                                      */
/* ------------------------------------------------------------------ */

enum gcry_rng_types {
    GCRY_RNG_TYPE_STANDARD = 1,
    GCRY_RNG_TYPE_FIPS = 2,
    GCRY_RNG_TYPE_SYSTEM = 3
};

typedef enum gcry_random_level {
    GCRY_WEAK_RANDOM = 0,
    GCRY_STRONG_RANDOM = 1,
    GCRY_VERY_STRONG_RANDOM = 2
} gcry_random_level_t;

void gcry_randomize(void *buffer, size_t length,
                    enum gcry_random_level level);
gcry_error_t gcry_random_add_bytes(const void *buffer, size_t length,
                                   int quality);

#define gcry_fast_random_poll() gcry_control(GCRYCTL_FAST_POLL, NULL)

void *gcry_random_bytes(size_t nbytes, enum gcry_random_level level)
_GCRY_GCC_ATTR_MALLOC;
void *gcry_random_bytes_secure(size_t nbytes, enum gcry_random_level level)
_GCRY_GCC_ATTR_MALLOC;
void gcry_mpi_randomize(gcry_mpi_t w, unsigned int nbits,
                        enum gcry_random_level level);
void gcry_create_nonce(void *buffer, size_t length);

/* ------------------------------------------------------------------ */
/* Prime numbers                                                       */
/* ------------------------------------------------------------------ */

#define GCRY_PRIME_CHECK_AT_FINISH 0
#define GCRY_PRIME_CHECK_AT_GOT_PRIME 1
#define GCRY_PRIME_CHECK_AT_MAYBE_PRIME 2

typedef int (*gcry_prime_check_func_t)(void *arg, int mode,
                                       gcry_mpi_t candidate);

#define GCRY_PRIME_FLAG_SECRET (1 << 0)
#define GCRY_PRIME_FLAG_SPECIAL_FACTOR (1 << 1)

gcry_error_t gcry_prime_generate(gcry_mpi_t *prime, unsigned int prime_bits,
                                 unsigned int factor_bits,
                                 gcry_mpi_t **factors,
                                 gcry_prime_check_func_t cb_func,
                                 void *cb_arg,
                                 gcry_random_level_t random_level,
                                 unsigned int flags);
gcry_error_t gcry_prime_group_generator(gcry_mpi_t *r_g, gcry_mpi_t prime,
                                        gcry_mpi_t *factors,
                                        gcry_mpi_t start_g);
void gcry_prime_release_factors(gcry_mpi_t *factors);
gcry_error_t gcry_prime_check(gcry_mpi_t x, unsigned int flags);

/* ------------------------------------------------------------------ */
/* Miscellaneous                                                       */
/* ------------------------------------------------------------------ */

void gcry_ctx_release(gcry_ctx_t ctx);

void gcry_log_debug(const char *fmt, ...) _GCRY_GCC_ATTR_PRINTF(1, 2);
void gcry_log_debughex(const char *text, const void *buffer, size_t length);
void gcry_log_debugmpi(const char *text, gcry_mpi_t mpi);
void gcry_log_debugpnt(const char *text, gcry_mpi_point_t point,
                       gcry_ctx_t ctx);
void gcry_log_debugsxp(const char *text, gcry_sexp_t sexp);

char *gcry_get_config(int mode, const char *what);

#define gcry_get_fips_service_indicator() \
    gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR)

#define GCRY_FIPS_FLAG_REJECT_KDF (1 << 0)
#define GCRY_FIPS_FLAG_REJECT_MD_MD5 (1 << 1)
#define GCRY_FIPS_FLAG_REJECT_MD_OTHERS (1 << 2)
#define GCRY_FIPS_FLAG_REJECT_MAC (1 << 3)
#define GCRY_FIPS_FLAG_REJECT_CIPHER (1 << 4)
#define GCRY_FIPS_FLAG_REJECT_PK (1 << 5)
#define GCRY_FIPS_FLAG_REJECT_PK_MD (1 << 6)
#define GCRY_FIPS_FLAG_REJECT_PK_GOST_SM2 (1 << 7)
#define GCRY_FIPS_FLAG_REJECT_CIPHER_MODE (1 << 8)
#define GCRY_FIPS_FLAG_REJECT_MD_SHA1 (1 << 9)
#define GCRY_FIPS_FLAG_REJECT_PK_ECC_K (1 << 10)
#define GCRY_FIPS_FLAG_REJECT_PK_FLAGS (1 << 11)

#define GCRY_FIPS_FLAG_REJECT_MD                                 \
    (GCRY_FIPS_FLAG_REJECT_MD_MD5 | GCRY_FIPS_FLAG_REJECT_MD_SHA1 \
     | GCRY_FIPS_FLAG_REJECT_MD_OTHERS)

#define GCRY_FIPS_FLAG_REJECT_COMPAT110                                    \
    (GCRY_FIPS_FLAG_REJECT_MD_OTHERS | GCRY_FIPS_FLAG_REJECT_MAC           \
     | GCRY_FIPS_FLAG_REJECT_CIPHER | GCRY_FIPS_FLAG_REJECT_KDF            \
     | GCRY_FIPS_FLAG_REJECT_PK)

#define GCRY_FIPS_FLAG_REJECT_DEFAULT GCRY_FIPS_FLAG_REJECT_COMPAT110

enum gcry_log_levels {
    GCRY_LOG_CONT = 0,
    GCRY_LOG_INFO = 10,
    GCRY_LOG_WARN = 20,
    GCRY_LOG_ERROR = 30,
    GCRY_LOG_FATAL = 40,
    GCRY_LOG_BUG = 50,
    GCRY_LOG_DEBUG = 100
};

typedef void (*gcry_handler_progress_t)(void *, const char *, int, int, int);
typedef void *(*gcry_handler_alloc_t)(size_t n);
typedef int (*gcry_handler_secure_check_t)(const void *);
typedef void *(*gcry_handler_realloc_t)(void *p, size_t n);
typedef void (*gcry_handler_free_t)(void *);
typedef int (*gcry_handler_no_mem_t)(void *, size_t, unsigned int);
typedef void (*gcry_handler_error_t)(void *, int, const char *);
typedef void (*gcry_handler_log_t)(void *, int, const char *, va_list);

void gcry_set_progress_handler(gcry_handler_progress_t cb, void *cb_data);
void gcry_set_allocation_handler(gcry_handler_alloc_t func_alloc,
                                 gcry_handler_alloc_t func_alloc_secure,
                                 gcry_handler_secure_check_t func_secure_check,
                                 gcry_handler_realloc_t func_realloc,
                                 gcry_handler_free_t func_free);
void gcry_set_outofcore_handler(gcry_handler_no_mem_t h, void *opaque);
void gcry_set_fatalerror_handler(gcry_handler_error_t fnc, void *opaque);
void gcry_set_log_handler(gcry_handler_log_t f,
                          void *opaque) _GCRY_ATTR_INTERNAL;
void gcry_set_gettext_handler(const char *(*f)(const char *));

void *gcry_malloc(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_calloc(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_malloc_secure(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_calloc_secure(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_realloc(void *a, size_t n);
char *gcry_strdup(const char *string) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xmalloc(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xcalloc(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xmalloc_secure(size_t n) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xcalloc_secure(size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
void *gcry_xrealloc(void *a, size_t n);
char *gcry_xstrdup(const char *a) _GCRY_GCC_ATTR_MALLOC;
void gcry_free(void *a);
int gcry_is_secure(const void *a) _GCRY_GCC_ATTR_PURE;

#define gcry_fips_mode_active() !!gcry_control(GCRYCTL_FIPS_MODE_P, 0)

gcry_error_t gcry_pk_hash_sign(gcry_sexp_t *result, const char *data_tmpl,
                               gcry_sexp_t skey, gcry_md_hd_t hd,
                               gcry_ctx_t ctx);
gcry_error_t gcry_pk_hash_verify(gcry_sexp_t sigval, const char *data_tmpl,
                                 gcry_sexp_t pkey, gcry_md_hd_t hd,
                                 gcry_ctx_t ctx);
gcry_error_t gcry_pk_random_override_new(gcry_ctx_t *r_ctx,
                                         const unsigned char *p, size_t len);
#define gcry_pk_input_data_push gcry_pk_random_override_new

#ifdef __cplusplus
}
#endif
#endif /* _GCRYPT_H */
