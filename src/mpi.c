/*
 * mpi.c - Multi precision integers backed by OpenSSL BIGNUMs.
 *
 * A gcry_mpi_t wraps a BIGNUM plus Libgcrypt's flag word and the "opaque"
 * byte string variant.  Import/export formats (STD, USG, PGP, SSH, HEX)
 * follow the reference implementation exactly.
 */
#include "gcrypt-int.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

/* Same limits as the reference implementation. */
#define MAX_EXTERN_SCAN_BYTES (16 * 1024 * 1024)
#define MAX_EXTERN_MPI_BITS 16384

#define MUTABLE_FLAGS                                             \
    (GCRYMPI_FLAG_USER1 | GCRYMPI_FLAG_USER2 | GCRYMPI_FLAG_USER3 \
     | GCRYMPI_FLAG_USER4)

/* One BN_CTX per thread.  Every arithmetic entry point needs a context
 * and allocating one per call costs more than many of the operations
 * themselves; OpenSSL's BN_CTX_start/end nesting makes sharing safe even
 * when one of our functions calls another. */
static pthread_once_t ctx_key_once = PTHREAD_ONCE_INIT;
static pthread_key_t ctx_key;
static int ctx_key_ok;

static void
ctx_destroy(void *p)
{
    BN_CTX_free(p);
}

static void
ctx_key_init(void)
{
    ctx_key_ok = pthread_key_create(&ctx_key, ctx_destroy) == 0;
}

static BN_CTX *
new_ctx(void)
{
    BN_CTX *ctx = NULL;

    pthread_once(&ctx_key_once, ctx_key_init);

    if (ctx_key_ok) {
        ctx = pthread_getspecific(ctx_key);

        if (ctx) {
            return ctx;
        }

        ctx = BN_CTX_new_ex(_gcry_libctx());

        if (ctx && pthread_setspecific(ctx_key, ctx) == 0) {
            return ctx;
        }
    }

    if (!ctx) {
        ctx = BN_CTX_new_ex(_gcry_libctx());
    }

    if (!ctx) {
        _gcry_fatal_error(GPG_ERR_ENOMEM, NULL);
    }

    return ctx;
}

/* Counterpart of new_ctx(): the per-thread context is kept. */
static void
release_ctx(BN_CTX *ctx)
{
    if (ctx_key_ok && pthread_getspecific(ctx_key) == ctx) {
        return;
    }

    BN_CTX_free(ctx);
}

static void
bn_fail(const char *what)
{
    ERR_clear_error();
    _gcry_fatal_error(GPG_ERR_INTERNAL, what);
}

void
_gcry_mpi_immutable_failed(void)
{
    log_info("Warning: trying to change an immutable MPI\n");
}

gcry_mpi_t
_gcry_mpi_alloc(int secure)
{
    gcry_mpi_t a = _gcry_xcalloc(1, sizeof * a);

    a->bn = secure ? BN_secure_new() : BN_new();

    if (!a->bn) {
        _gcry_fatal_error(GPG_ERR_ENOMEM, NULL);
    }

    a->flags = secure ? GCRYMPI_FLAG_SECURE : 0;
    return a;
}

/* Wrap an existing BIGNUM; ownership is transferred. */
gcry_mpi_t
_gcry_mpi_new_from_bn(BIGNUM *bn, int secure)
{
    gcry_mpi_t a = _gcry_xcalloc(1, sizeof * a);

    a->bn = bn;
    a->flags = secure ? GCRYMPI_FLAG_SECURE : 0;
    return a;
}

BIGNUM *
_gcry_mpi_bn(gcry_mpi_t a)
{
    if (mpi_is_opaque(a)) {
        _gcry_log(GCRY_LOG_BUG, "arithmetic on an opaque MPI\n");
    }

    return a->bn;
}

static void
free_opaque(gcry_mpi_t a)
{
    if (a->opaque) {
        if (mpi_is_secure(a)) {
            _gcry_wipememory(a->opaque, (a->opaque_nbits + 7) / 8);
        }

        _gcry_free(a->opaque);
    }

    a->opaque = NULL;
    a->opaque_nbits = 0;
    a->flags &= ~(unsigned int)GCRYMPI_FLAG_OPAQUE;
}

/* ------------------------------------------------------------------ */
/* Allocation and assignment                                           */
/* ------------------------------------------------------------------ */

gcry_mpi_t
gcry_mpi_new(unsigned int nbits)
{
    (void)nbits;
    return _gcry_mpi_alloc(0);
}

gcry_mpi_t
gcry_mpi_snew(unsigned int nbits)
{
    (void)nbits;
    return _gcry_mpi_alloc(1);
}

void
gcry_mpi_release(gcry_mpi_t a)
{
    if (!a) {
        return;
    }

    if (a->flags & GCRYMPI_FLAG_CONST) {
        return; /* Constants are never released. */
    }

    free_opaque(a);
    BN_clear_free(a->bn);
    _gcry_free(a);
}

gcry_mpi_t
gcry_mpi_copy(const gcry_mpi_t a)
{
    gcry_mpi_t b;

    if (!a) {
        return NULL;
    }

    b = _gcry_mpi_alloc(mpi_is_secure(a));

    if (mpi_is_opaque(a)) {
        unsigned int n = (a->opaque_nbits + 7) / 8;

        if (a->opaque && n) {
            b->opaque = mpi_is_secure(a) ? _gcry_xmalloc_secure(n)
                        : _gcry_xmalloc(n);
            memcpy(b->opaque, a->opaque, n);
        }

        b->opaque_nbits = a->opaque_nbits;
    } else if (!BN_copy(b->bn, a->bn)) {
        bn_fail("BN_copy failed");
    }

    b->flags = a->flags
               & ~(unsigned int)(GCRYMPI_FLAG_IMMUTABLE | GCRYMPI_FLAG_CONST);
    return b;
}

void
gcry_mpi_snatch(gcry_mpi_t w, gcry_mpi_t u)
{
    if (!w) {
        gcry_mpi_release(u);
        return;
    }

    if (mpi_is_immutable(w)) {
        _gcry_mpi_immutable_failed();
        return;
    }

    free_opaque(w);
    BN_clear_free(w->bn);
    w->bn = u->bn;
    w->opaque = u->opaque;
    w->opaque_nbits = u->opaque_nbits;
    w->flags = u->flags;
    _gcry_free(u);
}

gcry_mpi_t
gcry_mpi_set(gcry_mpi_t w, const gcry_mpi_t u)
{
    if (!w) {
        w = _gcry_mpi_alloc(mpi_is_secure(u));
    }

    if (mpi_is_immutable(w)) {
        _gcry_mpi_immutable_failed();
        return w;
    }

    if (w == u) {
        return w;
    }

    free_opaque(w);

    if (mpi_is_opaque(u)) {
        unsigned int n = (u->opaque_nbits + 7) / 8;

        if (u->opaque && n) {
            w->opaque = mpi_is_secure(u) ? _gcry_xmalloc_secure(n)
                        : _gcry_xmalloc(n);
            memcpy(w->opaque, u->opaque, n);
        }

        w->opaque_nbits = u->opaque_nbits;
        BN_zero(w->bn);
    } else if (!BN_copy(w->bn, u->bn)) {
        bn_fail("BN_copy failed");
    }

    w->flags = u->flags
               & ~(unsigned int)(GCRYMPI_FLAG_IMMUTABLE | GCRYMPI_FLAG_CONST);
    return w;
}

gcry_mpi_t
gcry_mpi_set_ui(gcry_mpi_t w, unsigned long u)
{
    if (!w) {
        w = _gcry_mpi_alloc(0);
    }

    if (mpi_is_immutable(w)) {
        _gcry_mpi_immutable_failed();
        return w;
    }

    free_opaque(w);

    if (!BN_set_word(w->bn, u)) {
        bn_fail("BN_set_word failed");
    }

    w->flags &= GCRYMPI_FLAG_SECURE;
    return w;
}

gpg_error_t
gcry_mpi_get_ui(unsigned int *w, gcry_mpi_t u)
{
    BN_ULONG x;

    if (mpi_is_opaque(u) || BN_is_negative(u->bn)
        || BN_num_bits(u->bn) > 32) {
        return GCRY_ERR(GPG_ERR_ERANGE);
    }

    x = BN_get_word(u->bn);
    *w = (unsigned int)x;
    return 0;
}

void
gcry_mpi_swap(gcry_mpi_t a, gcry_mpi_t b)
{
    struct gcry_mpi tmp = *a;

    *a = *b;
    *b = tmp;
}

int
gcry_mpi_is_neg(gcry_mpi_t a)
{
    if (mpi_is_opaque(a)) {
        return 0;
    }

    return BN_is_negative(a->bn) && !BN_is_zero(a->bn);
}

void
gcry_mpi_neg(gcry_mpi_t w, gcry_mpi_t u)
{
    if (w != u) {
        gcry_mpi_set(w, u);
    } else if (mpi_is_immutable(w)) {
        _gcry_mpi_immutable_failed();
        return;
    }

    BN_set_negative(w->bn, !BN_is_negative(u->bn));
}

void
gcry_mpi_abs(gcry_mpi_t w)
{
    if (mpi_is_immutable(w)) {
        _gcry_mpi_immutable_failed();
        return;
    }

    BN_set_negative(w->bn, 0);
}

int
gcry_mpi_cmp(const gcry_mpi_t u, const gcry_mpi_t v)
{
    if (mpi_is_opaque(u) || mpi_is_opaque(v)) {
        if (!mpi_is_opaque(u)) {
            return -1;
        }

        if (!mpi_is_opaque(v)) {
            return 1;
        }

        if (u->opaque_nbits < v->opaque_nbits) {
            return -1;
        }

        if (u->opaque_nbits > v->opaque_nbits) {
            return 1;
        }

        if (!u->opaque_nbits) {
            return 0;
        }

        return memcmp(u->opaque, v->opaque, (u->opaque_nbits + 7) / 8);
    }

    return BN_cmp(u->bn, v->bn);
}

int
gcry_mpi_cmp_ui(const gcry_mpi_t u, unsigned long v)
{
    BIGNUM *tmp;
    int rc;

    if (mpi_is_opaque(u)) {
        return 1;
    }

    tmp = BN_new();

    if (!tmp || !BN_set_word(tmp, v)) {
        bn_fail("BN_set_word failed");
    }

    rc = BN_cmp(u->bn, tmp);
    BN_free(tmp);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Import / export                                                     */
/* ------------------------------------------------------------------ */

/* Return the magnitude of A as a big-endian byte string without leading
 * zeros (or little-endian, zero padded to FILL_LE bytes).  The buffer is
 * allocated with at least one byte. */
unsigned char *
_gcry_mpi_get_buffer(gcry_mpi_t a, unsigned int fill_le,
                     unsigned int *nbytes, int *sign)
{
    unsigned int n;
    unsigned int alloc;
    unsigned char *buf;

    if (sign) {
        *sign = BN_is_negative(a->bn);
    }

    n = (unsigned int)BN_num_bytes(a->bn);
    alloc = n > fill_le ? n : fill_le;

    if (!alloc) {
        alloc = 1;
    }

    buf = mpi_is_secure(a) ? _gcry_malloc_secure(alloc) : _gcry_malloc(alloc);

    if (!buf) {
        return NULL;
    }

    memset(buf, 0, alloc);

    if (n) {
        BN_bn2bin(a->bn, buf);
    }

    if (fill_le) {
        unsigned int i;
        unsigned int len = n;

        /* Reverse the magnitude into little endian order; the padding
         * bytes beyond LEN are already zero. */
        for (i = 0; i < len / 2; i++) {
            unsigned char t = buf[i];

            buf[i] = buf[len - 1 - i];
            buf[len - 1 - i] = t;
        }

        *nbytes = alloc > fill_le ? alloc : fill_le;
        return buf;
    }

    *nbytes = n;
    return buf;
}

void
_gcry_mpi_set_buffer(gcry_mpi_t a, const void *buffer, unsigned int nbytes,
                     int sign)
{
    free_opaque(a);

    if (!BN_bin2bn(buffer, (int)nbytes, a->bn)) {
        bn_fail("BN_bin2bn failed");
    }

    BN_set_negative(a->bn, sign);
}

/* Interpret N two's complement bytes as a signed value. */
static gcry_err_code_t
set_twos_complement(gcry_mpi_t a, const unsigned char *s, size_t n)
{
    if (!n) {
        BN_zero(a->bn);
        return 0;
    }

    if (s[0] & 0x80) {
        unsigned char *tmp = _gcry_malloc(n);
        size_t i;

        if (!tmp) {
            return _gcry_err_code_from_syserror();
        }

        for (i = 0; i < n; i++) {
            tmp[i] = (unsigned char)~s[i];
        }

        if (!BN_bin2bn(tmp, (int)n, a->bn) || !BN_add_word(a->bn, 1)) {
            _gcry_free(tmp);
            return GPG_ERR_INTERNAL;
        }

        _gcry_free(tmp);
        BN_set_negative(a->bn, 1);
    } else if (!BN_bin2bn(s, (int)n, a->bn)) {
        return GPG_ERR_INTERNAL;
    }

    return 0;
}

/* Two's complement of a magnitude buffer in place (invert, add one). */
static void
twos_complement(unsigned char *p, size_t n)
{
    size_t i;
    unsigned int carry = 1;

    for (i = n; i > 0; i--) {
        unsigned int v = (unsigned int)(unsigned char)~p[i - 1] + carry;

        p[i - 1] = (unsigned char)(v & 0xff);
        carry = v >> 8;
    }
}

gcry_err_code_t
_gcry_mpi_scan(gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
               const void *buffer_arg, size_t buflen, size_t *nscanned)
{
    const unsigned char *buffer = buffer_arg;
    gcry_mpi_t a = NULL;
    gcry_err_code_t rc = 0;
    int secure = buffer && _gcry_is_secure(buffer);

    if (buflen > MAX_EXTERN_SCAN_BYTES) {
        if (nscanned) {
            *nscanned = 0;
        }

        return GPG_ERR_INV_OBJ;
    }

    if (!buffer) {
        return GPG_ERR_INV_ARG;
    }

    switch (format) {
    case GCRYMPI_FMT_STD:
        a = _gcry_mpi_alloc(secure);
        rc = set_twos_complement(a, buffer, buflen);

        if (nscanned) {
            *nscanned = buflen;
        }

        break;

    case GCRYMPI_FMT_USG:
        a = _gcry_mpi_alloc(secure);

        if (buflen && !BN_bin2bn(buffer, (int)buflen, a->bn)) {
            rc = GPG_ERR_INTERNAL;
        }

        if (nscanned) {
            *nscanned = buflen;
        }

        break;

    case GCRYMPI_FMT_PGP: {
        unsigned int nbits;
        unsigned int nbytes;

        if (buflen < 2) {
            if (nscanned) {
                *nscanned = 0;
            }

            return GPG_ERR_INV_OBJ;
        }

        nbits = ((unsigned int)buffer[0] << 8) | buffer[1];

        if (nbits > MAX_EXTERN_MPI_BITS) {
            if (nscanned) {
                *nscanned = 0;
            }

            return GPG_ERR_INV_OBJ;
        }

        nbytes = (nbits + 7) / 8;

        if ((size_t)nbytes + 2 > buflen) {
            if (nscanned) {
                *nscanned = 2;
            }

            return GPG_ERR_INV_OBJ;
        }

        a = _gcry_mpi_alloc(secure);

        if (nbytes && !BN_bin2bn(buffer + 2, (int)nbytes, a->bn)) {
            rc = GPG_ERR_INTERNAL;
        }

        if (nscanned) {
            *nscanned = (size_t)nbytes + 2;
        }

        break;
    }

    case GCRYMPI_FMT_SSH: {
        size_t n;

        if (buflen < 4) {
            return GPG_ERR_TOO_SHORT;
        }

        n = ((size_t)buffer[0] << 24) | ((size_t)buffer[1] << 16)
            | ((size_t)buffer[2] << 8) | buffer[3];

        if (n > buflen - 4) {
            return GPG_ERR_TOO_LARGE;
        }

        a = _gcry_mpi_alloc(secure);
        rc = set_twos_complement(a, buffer + 4, n);

        if (nscanned) {
            *nscanned = n + 4;
        }

        break;
    }

    case GCRYMPI_FMT_HEX: {
        const char *s = (const char *)buffer;
        size_t slen;
        int negative = 0;
        BIGNUM *tmp = NULL;

        if (buflen) {
            return GPG_ERR_INV_ARG; /* Only C strings are supported. */
        }

        slen = strlen(s);

        if (slen > MAX_EXTERN_SCAN_BYTES) {
            return GPG_ERR_INV_OBJ;
        }

        if (*s == '-') {
            negative = 1;
            s++;
        }

        if (s[0] == '0' && s[1] == 'x') {
            s += 2;
        }

        {
            const char *q;

            for (q = s; *q; q++) {
                if (!((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f')
                      || (*q >= 'A' && *q <= 'F'))) {
                    return GPG_ERR_INV_OBJ;
                }
            }
        }

        a = _gcry_mpi_alloc(secure);

        if (*s) {
            if (BN_hex2bn(&tmp, s) <= 0 || !tmp) {
                rc = GPG_ERR_INV_OBJ;
            } else {
                BN_clear_free(a->bn);
                a->bn = tmp;
            }
        }

        if (!rc) {
            BN_set_negative(a->bn, negative);
        }

        if (nscanned) {
            *nscanned = slen;
        }

        break;
    }

    default:
        return GPG_ERR_INV_ARG;
    }

    if (rc) {
        ERR_clear_error();
        gcry_mpi_release(a);
        return rc;
    }

    if (ret_mpi) {
        *ret_mpi = a;
    } else {
        gcry_mpi_release(a);
    }

    return 0;
}

gcry_err_code_t
_gcry_mpi_print(enum gcry_mpi_format format, unsigned char *buffer,
                size_t buflen, size_t *nwritten, const gcry_mpi_t a)
{
    size_t dummy_nwritten;
    int negative;
    unsigned int n;
    unsigned char *tmp;

    if (!nwritten) {
        nwritten = &dummy_nwritten;
    }

    *nwritten = 0;

    if (mpi_is_opaque(a)) {
        return GPG_ERR_INV_OBJ;
    }

    negative = BN_is_negative(a->bn) && !BN_is_zero(a->bn);

    switch (format) {
    case GCRYMPI_FMT_STD:
    case GCRYMPI_FMT_SSH: {
        int extra = 0;
        size_t prefix = format == GCRYMPI_FMT_SSH ? 4 : 0;

        if (!negative) {
            /* Common case: the magnitude is the encoding, with a leading
             * zero if the top bit is set; write it straight out. */
            n = (unsigned int)BN_num_bytes(a->bn);
            extra = (n && BN_num_bits(a->bn) % 8 == 0) ? 1 : 0;

            if (buffer && n + (unsigned int)extra + prefix > buflen) {
                return GPG_ERR_TOO_SHORT;
            }

            if (buffer) {
                unsigned char *s = buffer;
                unsigned int total = n + (unsigned int)extra;

                if (prefix) {
                    s[0] = (unsigned char)(total >> 24);
                    s[1] = (unsigned char)(total >> 16);
                    s[2] = (unsigned char)(total >> 8);
                    s[3] = (unsigned char)total;
                    s += 4;
                }

                if (extra) {
                    *s++ = 0;
                }

                if (n) {
                    BN_bn2bin(a->bn, s);
                }
            }

            *nwritten = n + (unsigned int)extra + prefix;
            return 0;
        }

        tmp = _gcry_mpi_get_buffer(a, 0, &n, NULL);

        if (!tmp) {
            return _gcry_err_code_from_syserror();
        }

        if (negative) {
            twos_complement(tmp, n);

            if (!(tmp[0] & 0x80)) {
                n++;
                extra = 2; /* Sign extension byte 0xff. */
            }
        } else if (n && (tmp[0] & 0x80)) {
            n++;
            extra = 1; /* Leading 0x00 to keep it positive. */
        }

        if (buffer && n + prefix > buflen) {
            _gcry_free(tmp);
            return GPG_ERR_TOO_SHORT;
        }

        if (buffer) {
            unsigned char *s = buffer;

            if (prefix) {
                s[0] = (unsigned char)(n >> 24);
                s[1] = (unsigned char)(n >> 16);
                s[2] = (unsigned char)(n >> 8);
                s[3] = (unsigned char)n;
                s += 4;
            }

            if (extra == 1) {
                *s++ = 0;
            } else if (extra) {
                *s++ = 0xff;
            }

            memcpy(s, tmp, n - (extra ? 1u : 0u));
        }

        _gcry_free(tmp);
        *nwritten = n + prefix;
        return 0;
    }

    case GCRYMPI_FMT_USG:
        n = (unsigned int)BN_num_bytes(a->bn);

        if (buffer && n > buflen) {
            return GPG_ERR_TOO_SHORT;
        }

        if (buffer && n) {
            BN_bn2bin(a->bn, buffer);
        }

        *nwritten = n;
        return 0;

    case GCRYMPI_FMT_PGP: {
        unsigned int nbits = (unsigned int)BN_num_bits(a->bn);

        if (negative) {
            return GPG_ERR_INV_ARG;
        }

        n = (nbits + 7) / 8;

        if (buffer && (size_t)n + 2 > buflen) {
            return GPG_ERR_TOO_SHORT;
        }

        if (buffer) {
            buffer[0] = (unsigned char)(nbits >> 8);
            buffer[1] = (unsigned char)nbits;

            if (n) {
                BN_bn2bin(a->bn, buffer + 2);
            }
        }

        *nwritten = (size_t)n + 2;
        return 0;
    }

    case GCRYMPI_FMT_HEX: {
        static const char hexdigits[] = "0123456789ABCDEF";
        int extra = 0;
        size_t needed;
        unsigned int i;

        tmp = _gcry_mpi_get_buffer(a, 0, &n, NULL);

        if (!tmp) {
            return _gcry_err_code_from_syserror();
        }

        if (!n || (tmp[0] & 0x80)) {
            extra = 2;
        }

        needed = 2 * (size_t)n + (size_t)extra + (negative ? 1u : 0u) + 1;

        if (buffer && needed > buflen) {
            _gcry_free(tmp);
            return GPG_ERR_TOO_SHORT;
        }

        if (buffer) {
            unsigned char *s = buffer;

            if (negative) {
                *s++ = '-';
            }

            if (extra) {
                *s++ = '0';
                *s++ = '0';
            }

            for (i = 0; i < n; i++) {
                *s++ = (unsigned char)hexdigits[tmp[i] >> 4];
                *s++ = (unsigned char)hexdigits[tmp[i] & 0x0f];
            }

            *s = 0;
        }

        _gcry_free(tmp);
        *nwritten = needed;
        return 0;
    }

    default:
        return GPG_ERR_INV_ARG;
    }
}

gcry_err_code_t
_gcry_mpi_aprint(enum gcry_mpi_format format, unsigned char **buffer,
                 size_t *nwritten, const gcry_mpi_t a)
{
    size_t n;
    gcry_err_code_t rc;

    *buffer = NULL;
    rc = _gcry_mpi_print(format, NULL, 0, &n, a);

    if (rc) {
        return rc;
    }

    *buffer = mpi_is_secure(a) ? _gcry_malloc_secure(n ? n : 1)
              : _gcry_malloc(n ? n : 1);

    if (!*buffer) {
        return _gcry_err_code_from_syserror();
    }

    if (!n) {
        **buffer = 0;
    }

    rc = _gcry_mpi_print(format, *buffer, n, &n, a);

    if (rc) {
        _gcry_free(*buffer);
        *buffer = NULL;
    } else if (nwritten) {
        *nwritten = n;
    }

    return rc;
}

gcry_error_t
gcry_mpi_scan(gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
              const void *buffer, size_t buflen, size_t *nscanned)
{
    return GCRY_ERR(_gcry_mpi_scan(ret_mpi, format, buffer, buflen,
                                   nscanned));
}

gcry_error_t
gcry_mpi_print(enum gcry_mpi_format format, unsigned char *buffer,
               size_t buflen, size_t *nwritten, const gcry_mpi_t a)
{
    return GCRY_ERR(_gcry_mpi_print(format, buffer, buflen, nwritten, a));
}

gcry_error_t
gcry_mpi_aprint(enum gcry_mpi_format format, unsigned char **buffer,
                size_t *nwritten, const gcry_mpi_t a)
{
    return GCRY_ERR(_gcry_mpi_aprint(format, buffer, nwritten, a));
}

void
gcry_mpi_dump(const gcry_mpi_t a)
{
    if (!a) {
        _gcry_log(GCRY_LOG_CONT, " [nil]");
        return;
    }

    if (mpi_is_opaque(a)) {
        unsigned int n = (a->opaque_nbits + 7) / 8;
        unsigned int i;

        _gcry_log(GCRY_LOG_CONT, " [%u bit]", a->opaque_nbits);

        for (i = 0; i < n && a->opaque; i++) {
            _gcry_log(GCRY_LOG_CONT, "%02X", a->opaque[i]);
        }

        return;
    }

    {
        char *hex = BN_bn2hex(a->bn);

        _gcry_log(GCRY_LOG_CONT, " %s", hex ? hex : "[out of core]");
        OPENSSL_free(hex);
    }
}

/* ------------------------------------------------------------------ */
/* Arithmetic                                                          */
/* ------------------------------------------------------------------ */

#define CHECK_MUTABLE(w)                   \
    do {                                   \
        if (mpi_is_immutable(w)) {         \
            _gcry_mpi_immutable_failed();  \
            return;                        \
        }                                  \
    } while (0)

void
gcry_mpi_add(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v)
{
    CHECK_MUTABLE(w);
    free_opaque(w);

    if (!BN_add(w->bn, _gcry_mpi_bn(u), _gcry_mpi_bn(v))) {
        bn_fail("BN_add failed");
    }
}

void
gcry_mpi_add_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v)
{
    CHECK_MUTABLE(w);

    if (w != u) {
        gcry_mpi_set(w, u);
    }

    free_opaque(w);

    if (!BN_add_word(w->bn, v)) {
        bn_fail("BN_add_word failed");
    }
}

void
gcry_mpi_addm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m)
{
    BN_CTX *ctx;

    CHECK_MUTABLE(w);
    free_opaque(w);
    ctx = new_ctx();

    if (!BN_mod_add(w->bn, _gcry_mpi_bn(u), _gcry_mpi_bn(v),
                    _gcry_mpi_bn(m), ctx)) {
        bn_fail("BN_mod_add failed");
    }

    release_ctx(ctx);
}

void
gcry_mpi_sub(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v)
{
    CHECK_MUTABLE(w);
    free_opaque(w);

    if (!BN_sub(w->bn, _gcry_mpi_bn(u), _gcry_mpi_bn(v))) {
        bn_fail("BN_sub failed");
    }
}

void
gcry_mpi_sub_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v)
{
    CHECK_MUTABLE(w);

    if (w != u) {
        gcry_mpi_set(w, u);
    }

    free_opaque(w);

    if (!BN_sub_word(w->bn, v)) {
        bn_fail("BN_sub_word failed");
    }
}

void
gcry_mpi_subm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m)
{
    BN_CTX *ctx;

    CHECK_MUTABLE(w);
    free_opaque(w);
    ctx = new_ctx();

    if (!BN_mod_sub(w->bn, _gcry_mpi_bn(u), _gcry_mpi_bn(v),
                    _gcry_mpi_bn(m), ctx)) {
        bn_fail("BN_mod_sub failed");
    }

    release_ctx(ctx);
}

void
gcry_mpi_mul(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v)
{
    BN_CTX *ctx;

    CHECK_MUTABLE(w);
    free_opaque(w);
    ctx = new_ctx();

    if (!BN_mul(w->bn, _gcry_mpi_bn(u), _gcry_mpi_bn(v), ctx)) {
        bn_fail("BN_mul failed");
    }

    release_ctx(ctx);
}

void
gcry_mpi_mul_ui(gcry_mpi_t w, gcry_mpi_t u, unsigned long v)
{
    CHECK_MUTABLE(w);

    if (w != u) {
        gcry_mpi_set(w, u);
    }

    free_opaque(w);

    if (!BN_mul_word(w->bn, v)) {
        bn_fail("BN_mul_word failed");
    }
}

void
gcry_mpi_mulm(gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m)
{
    BN_CTX *ctx;

    CHECK_MUTABLE(w);
    free_opaque(w);
    ctx = new_ctx();

    if (!BN_mod_mul(w->bn, _gcry_mpi_bn(u), _gcry_mpi_bn(v),
                    _gcry_mpi_bn(m), ctx)) {
        bn_fail("BN_mod_mul failed");
    }

    release_ctx(ctx);
}

void
gcry_mpi_mul_2exp(gcry_mpi_t w, gcry_mpi_t u, unsigned long cnt)
{
    CHECK_MUTABLE(w);
    free_opaque(w);

    if (!BN_lshift(w->bn, _gcry_mpi_bn(u), (int)cnt)) {
        bn_fail("BN_lshift failed");
    }
}

/* Division with truncation (ROUND == 0) or flooring (ROUND < 0): with
 * flooring the remainder takes the sign of the divisor. */
void
gcry_mpi_div(gcry_mpi_t q, gcry_mpi_t r, gcry_mpi_t dividend,
             gcry_mpi_t divisor, int round)
{
    BN_CTX *ctx;
    BIGNUM *tq;
    BIGNUM *tr;

    if (q && mpi_is_immutable(q)) {
        _gcry_mpi_immutable_failed();
        return;
    }

    if (r && mpi_is_immutable(r)) {
        _gcry_mpi_immutable_failed();
        return;
    }

    ctx = new_ctx();
    BN_CTX_start(ctx);
    tq = BN_CTX_get(ctx);
    tr = BN_CTX_get(ctx);

    if (!tr || !BN_div(tq, tr, _gcry_mpi_bn(dividend), _gcry_mpi_bn(divisor),
                       ctx)) {
        bn_fail("BN_div failed");
    }

    if (round < 0 && !BN_is_zero(tr)
        && BN_is_negative(tr) != BN_is_negative(divisor->bn)) {
        if (!BN_sub(tq, tq, BN_value_one())
            || !BN_add(tr, tr, divisor->bn)) {
            bn_fail("BN_sub failed");
        }
    }

    if (q) {
        free_opaque(q);

        if (!BN_copy(q->bn, tq)) {
            bn_fail("BN_copy failed");
        }
    }

    if (r) {
        free_opaque(r);

        if (!BN_copy(r->bn, tr)) {
            bn_fail("BN_copy failed");
        }
    }

    BN_CTX_end(ctx);
    release_ctx(ctx);
}

void
gcry_mpi_mod(gcry_mpi_t r, gcry_mpi_t dividend, gcry_mpi_t divisor)
{
    gcry_mpi_div(NULL, r, dividend, divisor, -1);
}

void
gcry_mpi_powm(gcry_mpi_t w, const gcry_mpi_t b, const gcry_mpi_t e,
              const gcry_mpi_t m)
{
    BN_CTX *ctx;

    CHECK_MUTABLE(w);
    free_opaque(w);
    ctx = new_ctx();

    if (!BN_mod_exp(w->bn, _gcry_mpi_bn(b), _gcry_mpi_bn(e), _gcry_mpi_bn(m),
                    ctx)) {
        bn_fail("BN_mod_exp failed");
    }

    release_ctx(ctx);
}

int
gcry_mpi_gcd(gcry_mpi_t g, gcry_mpi_t a, gcry_mpi_t b)
{
    BN_CTX *ctx;
    BIGNUM *ta;
    BIGNUM *tb;
    int rc;

    if (mpi_is_immutable(g)) {
        _gcry_mpi_immutable_failed();
        return 0;
    }

    free_opaque(g);
    ctx = new_ctx();
    BN_CTX_start(ctx);
    ta = BN_CTX_get(ctx);
    tb = BN_CTX_get(ctx);

    if (!tb || !BN_copy(ta, _gcry_mpi_bn(a)) || !BN_copy(tb, _gcry_mpi_bn(b))) {
        bn_fail("BN_copy failed");
    }

    BN_set_negative(ta, 0);
    BN_set_negative(tb, 0);

    if (!BN_gcd(g->bn, ta, tb, ctx)) {
        bn_fail("BN_gcd failed");
    }

    rc = BN_is_one(g->bn);
    BN_CTX_end(ctx);
    release_ctx(ctx);
    return rc;
}

int
gcry_mpi_invm(gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m)
{
    BN_CTX *ctx;
    BIGNUM *res;

    if (mpi_is_immutable(x)) {
        _gcry_mpi_immutable_failed();
        return 0;
    }

    free_opaque(x);
    ctx = new_ctx();
    res = BN_mod_inverse(x->bn, _gcry_mpi_bn(a), _gcry_mpi_bn(m), ctx);
    release_ctx(ctx);

    if (!res) {
        ERR_clear_error();
        return 0;
    }

    return 1;
}

/* ------------------------------------------------------------------ */
/* Bit operations                                                      */
/* ------------------------------------------------------------------ */

unsigned int
gcry_mpi_get_nbits(gcry_mpi_t a)
{
    if (mpi_is_opaque(a)) {
        return a->opaque_nbits;
    }

    return (unsigned int)BN_num_bits(a->bn);
}

int
gcry_mpi_test_bit(gcry_mpi_t a, unsigned int n)
{
    if (mpi_is_opaque(a)) {
        return 0;
    }

    return BN_is_bit_set(a->bn, (int)n);
}

void
gcry_mpi_set_bit(gcry_mpi_t a, unsigned int n)
{
    CHECK_MUTABLE(a);

    if (!BN_set_bit(_gcry_mpi_bn(a), (int)n)) {
        bn_fail("BN_set_bit failed");
    }
}

void
gcry_mpi_clear_bit(gcry_mpi_t a, unsigned int n)
{
    CHECK_MUTABLE(a);

    if (!BN_clear_bit(_gcry_mpi_bn(a), (int)n)) {
        ERR_clear_error(); /* Bit was beyond the current size: no-op. */
    }
}

void
gcry_mpi_set_highbit(gcry_mpi_t a, unsigned int n)
{
    CHECK_MUTABLE(a);

    if (!BN_mask_bits(_gcry_mpi_bn(a), (int)n + 1)) {
        ERR_clear_error();
    }

    if (!BN_set_bit(a->bn, (int)n)) {
        bn_fail("BN_set_bit failed");
    }
}

void
gcry_mpi_clear_highbit(gcry_mpi_t a, unsigned int n)
{
    CHECK_MUTABLE(a);

    if (!BN_mask_bits(_gcry_mpi_bn(a), (int)n)) {
        ERR_clear_error();
    }
}

void
gcry_mpi_rshift(gcry_mpi_t x, gcry_mpi_t a, unsigned int n)
{
    CHECK_MUTABLE(x);
    free_opaque(x);

    if (!BN_rshift(x->bn, _gcry_mpi_bn(a), (int)n)) {
        bn_fail("BN_rshift failed");
    }
}

void
gcry_mpi_lshift(gcry_mpi_t x, gcry_mpi_t a, unsigned int n)
{
    CHECK_MUTABLE(x);
    free_opaque(x);

    if (!BN_lshift(x->bn, _gcry_mpi_bn(a), (int)n)) {
        bn_fail("BN_lshift failed");
    }
}

/* ------------------------------------------------------------------ */
/* Opaque values and flags                                             */
/* ------------------------------------------------------------------ */

gcry_mpi_t
gcry_mpi_set_opaque(gcry_mpi_t a, void *p, unsigned int nbits)
{
    if (!a) {
        a = _gcry_mpi_alloc(0);
    }

    if (mpi_is_immutable(a)) {
        _gcry_mpi_immutable_failed();
        return a;
    }

    free_opaque(a);
    BN_zero(a->bn);
    a->opaque = p;
    a->opaque_nbits = nbits;
    a->flags = GCRYMPI_FLAG_OPAQUE | (a->flags & MUTABLE_FLAGS);

    if (_gcry_is_secure(p)) {
        a->flags |= GCRYMPI_FLAG_SECURE;
    }

    return a;
}

gcry_mpi_t
gcry_mpi_set_opaque_copy(gcry_mpi_t a, const void *p, unsigned int nbits)
{
    unsigned int n = (nbits + 7) / 8;
    void *d;

    d = _gcry_is_secure(p) ? _gcry_malloc_secure(n) : _gcry_malloc(n);

    if (!d) {
        return NULL;
    }

    memcpy(d, p, n);
    return gcry_mpi_set_opaque(a, d, nbits);
}

void *
gcry_mpi_get_opaque(gcry_mpi_t a, unsigned int *nbits)
{
    if (!mpi_is_opaque(a)) {
        _gcry_log(GCRY_LOG_BUG, "mpi_get_opaque on normal mpi\n");
    }

    if (nbits) {
        *nbits = a->opaque_nbits;
    }

    return a->opaque;
}

void
gcry_mpi_set_flag(gcry_mpi_t a, enum gcry_mpi_flag flag)
{
    switch (flag) {
    case GCRYMPI_FLAG_SECURE:
        a->flags |= GCRYMPI_FLAG_SECURE;
        BN_set_flags(a->bn, BN_FLG_SECURE | BN_FLG_CONSTTIME);
        break;

    case GCRYMPI_FLAG_CONST:
        a->flags |= GCRYMPI_FLAG_CONST | GCRYMPI_FLAG_IMMUTABLE;
        break;

    case GCRYMPI_FLAG_IMMUTABLE:
        a->flags |= GCRYMPI_FLAG_IMMUTABLE;
        break;

    case GCRYMPI_FLAG_USER1:
    case GCRYMPI_FLAG_USER2:
    case GCRYMPI_FLAG_USER3:
    case GCRYMPI_FLAG_USER4:
        a->flags |= (unsigned int)flag;
        break;

    case GCRYMPI_FLAG_OPAQUE:
    default:
        _gcry_log(GCRY_LOG_BUG, "invalid flag value\n");
    }
}

void
gcry_mpi_clear_flag(gcry_mpi_t a, enum gcry_mpi_flag flag)
{
    switch (flag) {
    case GCRYMPI_FLAG_IMMUTABLE:
        if (!(a->flags & GCRYMPI_FLAG_CONST)) {
            a->flags &= ~(unsigned int)GCRYMPI_FLAG_IMMUTABLE;
        }

        break;

    case GCRYMPI_FLAG_USER1:
    case GCRYMPI_FLAG_USER2:
    case GCRYMPI_FLAG_USER3:
    case GCRYMPI_FLAG_USER4:
        a->flags &= ~(unsigned int)flag;
        break;

    case GCRYMPI_FLAG_CONST:
    case GCRYMPI_FLAG_SECURE:
    case GCRYMPI_FLAG_OPAQUE:
    default:
        _gcry_log(GCRY_LOG_BUG, "invalid flag value\n");
    }
}

int
gcry_mpi_get_flag(gcry_mpi_t a, enum gcry_mpi_flag flag)
{
    switch (flag) {
    case GCRYMPI_FLAG_SECURE:
    case GCRYMPI_FLAG_OPAQUE:
    case GCRYMPI_FLAG_IMMUTABLE:
    case GCRYMPI_FLAG_CONST:
    case GCRYMPI_FLAG_USER1:
    case GCRYMPI_FLAG_USER2:
    case GCRYMPI_FLAG_USER3:
    case GCRYMPI_FLAG_USER4:
        return !!(a->flags & (unsigned int)flag);

    default:
        _gcry_log(GCRY_LOG_BUG, "invalid flag value\n");
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

static pthread_once_t const_once = PTHREAD_ONCE_INIT;
static gcry_mpi_t constants[9];

static void
init_constants(void)
{
    static const int values[] = { 1, 2, 3, 4, 8 };
    size_t i;

    for (i = 0; i < DIM(values); i++) {
        gcry_mpi_t m = _gcry_mpi_alloc(0);

        gcry_mpi_set_ui(m, (unsigned long)values[i]);
        m->flags |= GCRYMPI_FLAG_CONST | GCRYMPI_FLAG_IMMUTABLE;
        constants[values[i]] = m;
    }
}

gcry_mpi_t
_gcry_mpi_get_const(int no)
{
    pthread_once(&const_once, init_constants);

    if (no < 0 || (size_t)no >= DIM(constants) || !constants[no]) {
        _gcry_log(GCRY_LOG_BUG, "invalid mpi constant %d requested\n", no);
    }

    return constants[no];
}

/* ------------------------------------------------------------------ */
/* Random values                                                       */
/* ------------------------------------------------------------------ */

void
gcry_mpi_randomize(gcry_mpi_t w, unsigned int nbits,
                   enum gcry_random_level level)
{
    size_t nbytes = (nbits + 7) / 8;
    unsigned char *p;
    int ok;

    CHECK_MUTABLE(w);
    p = mpi_is_secure(w) ? _gcry_xmalloc_secure(nbytes ? nbytes : 1)
        : _gcry_xmalloc(nbytes ? nbytes : 1);

    if (level == GCRY_WEAK_RANDOM) {
        ok = RAND_bytes_ex(_gcry_libctx(), p, nbytes, 0);
    } else {
        ok = RAND_priv_bytes_ex(_gcry_libctx(), p, nbytes, 0);
    }

    if (ok <= 0) {
        _gcry_free(p);
        _gcry_fatal_error(GPG_ERR_INTERNAL, "random number generator failed");
    }

    _gcry_mpi_set_buffer(w, p, (unsigned int)nbytes, 0);
    _gcry_wipememory(p, nbytes);
    _gcry_free(p);
}

/* ------------------------------------------------------------------ */
/* Points                                                              */
/* ------------------------------------------------------------------ */

gcry_mpi_point_t
gcry_mpi_point_new(unsigned int nbits)
{
    gcry_mpi_point_t p = _gcry_xcalloc(1, sizeof * p);

    (void)nbits;
    p->x = _gcry_mpi_alloc(0);
    p->y = _gcry_mpi_alloc(0);
    p->z = _gcry_mpi_alloc(0);
    return p;
}

void
gcry_mpi_point_release(gcry_mpi_point_t point)
{
    if (!point) {
        return;
    }

    gcry_mpi_release(point->x);
    gcry_mpi_release(point->y);
    gcry_mpi_release(point->z);
    _gcry_free(point);
}

gcry_mpi_point_t
gcry_mpi_point_copy(gcry_mpi_point_t point)
{
    gcry_mpi_point_t p;

    if (!point) {
        return NULL;
    }

    p = _gcry_xcalloc(1, sizeof * p);
    p->x = gcry_mpi_copy(point->x);
    p->y = gcry_mpi_copy(point->y);
    p->z = gcry_mpi_copy(point->z);
    return p;
}

void
gcry_mpi_point_get(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
                   gcry_mpi_point_t point)
{
    if (x) {
        gcry_mpi_set(x, point->x);
    }

    if (y) {
        gcry_mpi_set(y, point->y);
    }

    if (z) {
        gcry_mpi_set(z, point->z);
    }
}

void
gcry_mpi_point_snatch_get(gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
                          gcry_mpi_point_t point)
{
    gcry_mpi_point_get(x, y, z, point);
    gcry_mpi_point_release(point);
}

gcry_mpi_point_t
gcry_mpi_point_set(gcry_mpi_point_t point, gcry_mpi_t x, gcry_mpi_t y,
                   gcry_mpi_t z)
{
    if (!point) {
        point = gcry_mpi_point_new(0);
    }

    if (x) {
        gcry_mpi_set(point->x, x);
    } else {
        gcry_mpi_set_ui(point->x, 0);
    }

    if (y) {
        gcry_mpi_set(point->y, y);
    } else {
        gcry_mpi_set_ui(point->y, 0);
    }

    if (z) {
        gcry_mpi_set(point->z, z);
    } else {
        gcry_mpi_set_ui(point->z, 0);
    }

    return point;
}

gcry_mpi_point_t
gcry_mpi_point_snatch_set(gcry_mpi_point_t point, gcry_mpi_t x, gcry_mpi_t y,
                          gcry_mpi_t z)
{
    if (!point) {
        point = gcry_mpi_point_new(0);
    }

    if (x) {
        gcry_mpi_snatch(point->x, x);
    } else {
        gcry_mpi_set_ui(point->x, 0);
    }

    if (y) {
        gcry_mpi_snatch(point->y, y);
    } else {
        gcry_mpi_set_ui(point->y, 0);
    }

    if (z) {
        gcry_mpi_snatch(point->z, z);
    } else {
        gcry_mpi_set_ui(point->z, 0);
    }

    return point;
}
