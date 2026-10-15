/*
 * sexp.c - S-expression objects.
 *
 * An S-expression is stored as a single flat buffer of tagged items, the
 * same layout the reference implementation uses, because several public
 * functions hand out pointers into that buffer and others (gcry_sexp_nth
 * on a data element, normalisation of "()" to NULL) have observable
 * behaviour that falls naturally out of it:
 *
 *   ST_OPEN                      '('
 *   ST_DATA <len16> <bytes...>   a data element (length < 65536)
 *   ST_CLOSE                     ')'
 *   ST_STOP                      end of buffer, always present, value 0
 */
#include "gcrypt-int.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

typedef unsigned short DATALEN;

#define ST_STOP 0
#define ST_DATA 1
#define ST_OPEN 3
#define ST_CLOSE 4

#define MAX_DATALEN 65535u

#define TOKEN_SPECIALS "-./_:*+="

/* Is C one of the characters allowed in an unquoted token: a letter, a
 * digit or one of TOKEN_SPECIALS?  A range test instead of strchr() on a
 * character table, since this runs for every input byte.  Like the
 * reference implementation's strchr() test, a NUL byte counts as a token
 * character (it matches the table's terminator there). */
static int
tokencharp(int c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')) {
        return 1;
    }

    switch (c) {
    case 0:
    case '-':
    case '.':
    case '/':
    case '_':
    case ':':
    case '*':
    case '+':
    case '=':
        return 1;

    default:
        return 0;
    }
}

static int
whitespacep(const char *p)
{
    return *p == ' ' || *p == '\t' || *p == '\v' || *p == '\f'
           || *p == '\r' || *p == '\n';
}

static int
digitp(const char *p)
{
    return *p >= '0' && *p <= '9';
}

static int
octdigitp(const char *p)
{
    return *p >= '0' && *p <= '7';
}

static int
hexdigitp(const char *p)
{
    return digitp(p) || (*p >= 'A' && *p <= 'F') || (*p >= 'a' && *p <= 'f');
}

static int
alphap(const unsigned char *p)
{
    return (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z');
}

static int
hextonibble(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    if (c >= 'A' && c <= 'F') {
        return 10 + c - 'A';
    }

    if (c >= 'a' && c <= 'f') {
        return 10 + c - 'a';
    }

    return 0;
}

static DATALEN
get_len(const unsigned char *p)
{
    DATALEN n;

    memcpy(&n, p, sizeof n);
    return n;
}

static void
put_len(unsigned char *p, size_t n)
{
    DATALEN len = (DATALEN)n;

    memcpy(p, &len, sizeof len);
}

/* Skip one complete item (data element or whole list) starting at P and
 * return a pointer just past it.  P must not point at ST_STOP. */
static const unsigned char *
skip_item(const unsigned char *p)
{
    int level = 0;

    do {
        switch (*p) {
        case ST_DATA:
            p += 1 + sizeof(DATALEN) + get_len(p + 1);
            break;

        case ST_OPEN:
            level++;
            p++;
            break;

        case ST_CLOSE:
            level--;
            p++;
            break;

        default:
            return p; /* ST_STOP or corrupt. */
        }
    } while (level > 0);

    return p;
}

/* Length of the buffer up to and including the ST_STOP byte. */
static size_t
buffer_size(const gcry_sexp_t sexp)
{
    const unsigned char *p = sexp->d;

    while (*p != ST_STOP) {
        p = skip_item(p);
    }

    return (size_t)(p - sexp->d) + 1;
}

static gcry_sexp_t
alloc_sexp(size_t nbytes, int secure)
{
    return secure ? _gcry_malloc_secure(nbytes) : _gcry_malloc(nbytes);
}

static gcry_sexp_t
normalize(gcry_sexp_t list)
{
    if (!list) {
        return NULL;
    }

    if (list->d[0] == ST_STOP
        || (list->d[0] == ST_OPEN && list->d[1] == ST_CLOSE)) {
        gcry_sexp_release(list);
        return NULL;
    }

    return list;
}

/* ------------------------------------------------------------------ */
/* Release                                                             */
/* ------------------------------------------------------------------ */

void
gcry_sexp_release(gcry_sexp_t sexp)
{
    if (!sexp) {
        return;
    }

    if (_gcry_is_secure(sexp)) {
        _gcry_wipememory(sexp->d, buffer_size(sexp));
    }

    _gcry_free(sexp);
}

/* ------------------------------------------------------------------ */
/* Scanner                                                             */
/* ------------------------------------------------------------------ */

struct builder {
    gcry_sexp_t sexp;
    size_t allocated;
    unsigned char *pos;
};

static gcry_err_code_t
make_space(struct builder *c, size_t n)
{
    size_t used = (size_t)(c->pos - c->sexp->d);

    if (used + n + sizeof(DATALEN) + 1 >= c->allocated) {
        gcry_sexp_t newsexp;
        size_t need = n + sizeof(DATALEN) + 1;
        size_t newsize = c->allocated + 2 * need;

        /* Grow geometrically so that long inputs do not realloc per item. */
        if (newsize < 2 * c->allocated) {
            newsize = 2 * c->allocated;
        }

        if (newsize <= c->allocated) {
            return GPG_ERR_TOO_LARGE;
        }

        newsexp = _gcry_realloc(c->sexp, sizeof * newsexp + newsize - 1);

        if (!newsexp) {
            return _gcry_err_code_from_syserror();
        }

        c->allocated = newsize;
        c->sexp = newsexp;
        c->pos = newsexp->d + used;
    }

    return 0;
}

/* Move the buffer under construction into secure memory. */
static gcry_err_code_t
switch_to_secure(struct builder *c)
{
    gcry_sexp_t newsexp;
    size_t used = (size_t)(c->pos - c->sexp->d);

    if (_gcry_is_secure(c->sexp)) {
        return 0;
    }

    newsexp = _gcry_malloc_secure(sizeof * newsexp + c->allocated - 1);

    if (!newsexp) {
        return _gcry_err_code_from_syserror();
    }

    memcpy(newsexp->d, c->sexp->d, used);
    _gcry_free(c->sexp);
    c->sexp = newsexp;
    c->pos = newsexp->d + used;
    return 0;
}

static void
store_data(struct builder *c, const void *data, size_t n)
{
    *c->pos++ = ST_DATA;
    put_len(c->pos, n);
    c->pos += sizeof(DATALEN);

    if (n) {
        memcpy(c->pos, data, n);
    }

    c->pos += n;
}

/* Decode the escapes of a quoted string whose quotes have been stripped.
 * The input is known to be syntactically valid. */
static size_t
unquote_string(const char *string, size_t length, unsigned char *buf)
{
    int esc = 0;
    const unsigned char *s = (const unsigned char *)string;
    unsigned char *d = buf;
    size_t n = length;

    for (; n; n--, s++) {
        if (esc) {
            switch (*s) {
            case 'b':
                *d++ = '\b';
                break;

            case 't':
                *d++ = '\t';
                break;

            case 'v':
                *d++ = '\v';
                break;

            case 'n':
                *d++ = '\n';
                break;

            case 'f':
                *d++ = '\f';
                break;

            case 'r':
                *d++ = '\r';
                break;

            case '"':
                *d++ = '"';
                break;

            case '\'':
                *d++ = '\'';
                break;

            case '\\':
                *d++ = '\\';
                break;

            case '\r':
                if (n > 1 && s[1] == '\n') {
                    s++;
                    n--;
                }

                break;

            case '\n':
                if (n > 1 && s[1] == '\r') {
                    s++;
                    n--;
                }

                break;

            case 'x':
                if (n > 2 && hexdigitp((const char *)s + 1)
                    && hexdigitp((const char *)s + 2)) {
                    *d++ = (unsigned char)(hextonibble(s[1]) * 16
                                           + hextonibble(s[2]));
                    s += 2;
                    n -= 2;
                }

                break;

            default:
                if (n > 2 && octdigitp((const char *)s)
                    && octdigitp((const char *)s + 1)
                    && octdigitp((const char *)s + 2)) {
                    *d++ = (unsigned char)((s[0] - '0') * 64
                                           + (s[1] - '0') * 8 + (s[2] - '0'));
                    s += 2;
                    n -= 2;
                }

                break;
            }

            esc = 0;
        } else if (*s == '\\') {
            esc = 1;
        } else {
            *d++ = *s;
        }
    }

    return (size_t)(d - buf);
}

static int
b64_value(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }

    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }

    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }

    if (c == '+') {
        return 62;
    }

    if (c == '/') {
        return 63;
    }

    return -1;
}

/* Decode base64 text (no whitespace) in place of OUT; returns the number
 * of bytes produced or (size_t)-1 on malformed input. */
static size_t
b64_decode(const char *in, size_t inlen, unsigned char *out)
{
    unsigned int acc = 0;
    int bits = 0;
    size_t n = 0;
    size_t i;

    for (i = 0; i < inlen; i++) {
        int v;

        if (in[i] == '=') {
            break;
        }

        v = b64_value(in[i]);

        if (v < 0) {
            return (size_t) -1;
        }

        acc = (acc << 6) | (unsigned int)v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out[n++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }

    for (; i < inlen; i++) {
        if (in[i] != '=') {
            return (size_t) -1;
        }
    }

    return n;
}

/* The core scanner.  With ARGFLAG set, printf-like directives are honoured:
 *   %m  signed MPI        %M  unsigned MPI
 *   %s  C string          %d  int as decimal     %u  unsigned as decimal
 *   %b  (int len, const void *buf)
 *   %S  an existing gcry_sexp_t, inserted as a sublist
 * Arguments come from ARG_LIST (an array of pointers) if that is non-NULL,
 * otherwise from the va_list. */
static gcry_err_code_t
do_vsexp_sscan(gcry_sexp_t *retsexp, size_t *erroff, const char *buffer,
               size_t length, int argflag, void **arg_list, va_list arg_ptr)
{
    gcry_err_code_t err = 0;
    const char *p;
    size_t n;
    const char *digptr = NULL;
    const char *quoted = NULL;
    const char *tokenp = NULL;
    const char *hexfmt = NULL;
    const char *base64 = NULL;
    const char *disphint = NULL;
    const char *percent = NULL;
    size_t hexcount = 0;
    size_t b64count = 0;
    int quoted_esc = 0;
    size_t datalen = 0;
    size_t dummy_erroff;
    struct builder c;
    int arg_counter = 0;
    int level = 0;

    if (!retsexp) {
        return GPG_ERR_INV_ARG;
    }

    *retsexp = NULL;

    if (!buffer) {
        return GPG_ERR_INV_ARG;
    }

    if (!erroff) {
        erroff = &dummy_erroff;
    }

#define ARG_NEXT(storage, type)                                   \
    do {                                                          \
        if (!arg_list)                                            \
            storage = va_arg(arg_ptr, type);                      \
        else                                                      \
            storage = *((type *)(arg_list[arg_counter++]));       \
    } while (0)

#define MAKE_SPACE(len)                               \
    do {                                              \
        gcry_err_code_t ms_err_ = make_space(&c, (len)); \
        if (ms_err_) {                                \
            err = ms_err_;                            \
            *erroff = (size_t)(p - buffer);           \
            goto leave;                               \
        }                                             \
    } while (0)

#define FAIL(code)                          \
    do {                                    \
        *erroff = (size_t)(p - buffer);     \
        err = (code);                       \
        goto leave;                         \
    } while (0)

    /* Canonical "L:" prefixes shrink to the 3 byte ST_DATA header but a
     * single digit length grows by one, so start with some slack. */
    c.allocated = length + length / 4 + 64;
    c.sexp = alloc_sexp(sizeof * c.sexp + c.allocated - 1,
                        length && _gcry_is_secure(buffer));

    if (!c.sexp) {
        err = _gcry_err_code_from_syserror();
        *erroff = 0;
        goto leave;
    }

    c.pos = c.sexp->d;

    for (p = buffer, n = length; n; p++, n--) {
        if (tokenp && !hexfmt) {
            if (tokencharp((unsigned char) * p)) {
                continue;
            }

            datalen = (size_t)(p - tokenp);

            if (datalen > MAX_DATALEN) {
                FAIL(GPG_ERR_INV_ARG);
            }

            MAKE_SPACE(datalen);
            store_data(&c, tokenp, datalen);
            tokenp = NULL;
        }

        if (quoted) {
            if (quoted_esc) {
                switch (*p) {
                case 'b':
                case 't':
                case 'v':
                case 'n':
                case 'f':
                case 'r':
                case '"':
                case '\'':
                case '\\':
                    quoted_esc = 0;
                    break;

                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                    if (!(n > 2 && octdigitp(p + 1) && octdigitp(p + 2))) {
                        FAIL(GPG_ERR_SEXP_BAD_QUOTATION);
                    }

                    p += 2;
                    n -= 2;
                    quoted_esc = 0;
                    break;

                case 'x':
                    if (!(n > 2 && hexdigitp(p + 1) && hexdigitp(p + 2))) {
                        FAIL(GPG_ERR_SEXP_BAD_QUOTATION);
                    }

                    p += 2;
                    n -= 2;
                    quoted_esc = 0;
                    break;

                case '\r':
                    if (n > 1 && p[1] == '\n') {
                        p++;
                        n--;
                    }

                    quoted_esc = 0;
                    break;

                case '\n':
                    if (n > 1 && p[1] == '\r') {
                        p++;
                        n--;
                    }

                    quoted_esc = 0;
                    break;

                default:
                    FAIL(GPG_ERR_SEXP_BAD_QUOTATION);
                }
            } else if (*p == '\\') {
                quoted_esc = 1;
            } else if (*p == '"') {
                unsigned char *save;
                size_t len;

                quoted++; /* Skip the opening quote. */
                MAKE_SPACE((size_t)(p - quoted));
                *c.pos++ = ST_DATA;
                save = c.pos;
                put_len(c.pos, 0);
                c.pos += sizeof(DATALEN);
                len = unquote_string(quoted, (size_t)(p - quoted), c.pos);
                c.pos += len;

                if (len > MAX_DATALEN) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                put_len(save, len);
                quoted = NULL;
            }
        } else if (hexfmt) {
            if (isxdigit((unsigned char) * p)) {
                hexcount++;
            } else if (*p == '#') {
                if (hexcount & 1) {
                    FAIL(GPG_ERR_SEXP_ODD_HEX_NUMBERS);
                }

                datalen = hexcount / 2;

                if (datalen > MAX_DATALEN) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                MAKE_SPACE(datalen);
                *c.pos++ = ST_DATA;
                put_len(c.pos, datalen);
                c.pos += sizeof(DATALEN);

                for (hexfmt++; hexfmt < p; hexfmt++) {
                    int tmpc;

                    if (whitespacep(hexfmt)) {
                        continue;
                    }

                    tmpc = hextonibble((unsigned char) * hexfmt);

                    for (hexfmt++; hexfmt < p && whitespacep(hexfmt);
                         hexfmt++) {
                        ;
                    }

                    if (hexfmt < p) {
                        tmpc = tmpc * 16 + hextonibble((unsigned char) * hexfmt);
                    }

                    *c.pos++ = (unsigned char)tmpc;
                }

                hexfmt = NULL;
            } else if (!whitespacep(p)) {
                FAIL(GPG_ERR_SEXP_BAD_HEX_CHAR);
            }
        } else if (base64) {
            if (digitp(p) || alphap((const unsigned char *)p) || *p == '+'
                || *p == '/' || *p == '=') {
                b64count++;
            } else if (*p == '|') {
                size_t maxlen = (b64count / 4 + 1) * 3;
                unsigned char *tmp = _gcry_malloc(maxlen);

                if (!tmp) {
                    err = _gcry_err_code_from_syserror();
                    goto leave;
                }

                datalen = b64_decode(base64 + 1, b64count, tmp);

                if (datalen == (size_t) -1) {
                    _gcry_free(tmp);
                    FAIL(GPG_ERR_SEXP_BAD_CHARACTER);
                }

                if (datalen > MAX_DATALEN) {
                    _gcry_free(tmp);
                    FAIL(GPG_ERR_INV_ARG);
                }

                {
                    gcry_err_code_t ms_err = make_space(&c, datalen);

                    if (ms_err) {
                        _gcry_free(tmp);
                        FAIL(ms_err);
                    }
                }

                store_data(&c, tmp, datalen);
                _gcry_free(tmp);
                base64 = NULL;
            } else {
                FAIL(GPG_ERR_SEXP_BAD_CHARACTER);
            }
        } else if (digptr) {
            if (digitp(p)) {
                ;
            } else if (*p == ':') {
                const char *d;

                /* All characters from DIGPTR to P are known to be digits;
                 * anything beyond MAX_DATALEN is rejected while adding. */
                datalen = 0;

                for (d = digptr; d < p; d++) {
                    datalen = datalen * 10 + (size_t)(*d - '0');

                    if (datalen > MAX_DATALEN) {
                        break;
                    }
                }

                digptr = NULL;

                if (datalen > MAX_DATALEN) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                if (datalen > n - 1) {
                    FAIL(GPG_ERR_SEXP_STRING_TOO_LONG);
                }

                MAKE_SPACE(datalen);
                store_data(&c, p + 1, datalen);
                n -= datalen;
                p += datalen;
            } else if (*p == '"') {
                digptr = NULL; /* The optional length prefix is ignored. */
                quoted = p;
                quoted_esc = 0;
            } else if (*p == '#') {
                digptr = NULL;
                hexfmt = p;
                hexcount = 0;
            } else if (*p == '|') {
                digptr = NULL;
                base64 = p;
                b64count = 0;
            } else {
                FAIL(GPG_ERR_SEXP_INV_LEN_SPEC);
            }
        } else if (percent) {
            if (*p == 'm' || *p == 'M') {
                gcry_mpi_t m;
                size_t nm = 0;
                enum gcry_mpi_format mpifmt =
                    *p == 'm' ? GCRYMPI_FMT_STD : GCRYMPI_FMT_USG;

                ARG_NEXT(m, gcry_mpi_t);

                if (!m) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                if (mpi_is_opaque(m)) {
                    unsigned int nbits;
                    const void *mp = gcry_mpi_get_opaque(m, &nbits);

                    nm = (nbits + 7) / 8;

                    if (mp && nm) {
                        if (nm > MAX_DATALEN) {
                            FAIL(GPG_ERR_INV_ARG);
                        }

                        MAKE_SPACE(nm);

                        if (mpi_is_secure(m)) {
                            err = switch_to_secure(&c);

                            if (err) {
                                goto leave;
                            }
                        }

                        store_data(&c, mp, nm);
                    }
                } else {
                    if (mpifmt == GCRYMPI_FMT_USG && gcry_mpi_is_neg(m)) {
                        err = GPG_ERR_INV_ARG;
                        goto leave;
                    }

                    unsigned char *lenpos;

                    /* STD needs at most one byte more than the magnitude
                     * for the sign; reserve that and print straight into
                     * the buffer instead of measuring with a dry run. */
                    nm = (size_t)BN_num_bytes(_gcry_mpi_bn(m)) + 1;

                    if (nm > MAX_DATALEN) {
                        FAIL(GPG_ERR_INV_ARG);
                    }

                    MAKE_SPACE(nm);

                    if (mpi_is_secure(m)) {
                        err = switch_to_secure(&c);

                        if (err) {
                            goto leave;
                        }
                    }

                    *c.pos++ = ST_DATA;
                    lenpos = c.pos;
                    c.pos += sizeof(DATALEN);
                    err = _gcry_mpi_print(mpifmt, c.pos, nm, &nm, m);

                    if (err) {
                        goto leave;
                    }

                    put_len(lenpos, nm);
                    c.pos += nm;
                }
            } else if (*p == 's') {
                const char *astr;
                size_t alen;

                ARG_NEXT(astr, const char *);

                if (!astr) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                alen = strlen(astr);

                if (alen > MAX_DATALEN) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                MAKE_SPACE(alen);
                store_data(&c, astr, alen);
            } else if (*p == 'b') {
                const char *astr;
                int alen;

                ARG_NEXT(alen, int);
                ARG_NEXT(astr, const char *);

                if (alen < 0 || (size_t)alen > MAX_DATALEN) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                if (alen && !astr) {
                    FAIL(GPG_ERR_INV_ARG);
                }

                MAKE_SPACE((size_t)alen);

                if (alen && _gcry_is_secure(astr)) {
                    err = switch_to_secure(&c);

                    if (err) {
                        goto leave;
                    }
                }

                store_data(&c, astr, (size_t)alen);
            } else if (*p == 'd') {
                int aint;
                char buf[35];
                size_t alen;

                ARG_NEXT(aint, int);
                snprintf(buf, sizeof buf, "%d", aint);
                alen = strlen(buf);
                MAKE_SPACE(alen);
                store_data(&c, buf, alen);
            } else if (*p == 'u') {
                unsigned int aint;
                char buf[35];
                size_t alen;

                ARG_NEXT(aint, unsigned int);
                snprintf(buf, sizeof buf, "%u", aint);
                alen = strlen(buf);
                MAKE_SPACE(alen);
                store_data(&c, buf, alen);
            } else if (*p == 'S') {
                gcry_sexp_t asexp;

                ARG_NEXT(asexp, gcry_sexp_t);

                if (asexp && asexp->d[0] == ST_OPEN) {
                    const unsigned char *end = skip_item(asexp->d);
                    size_t alen = (size_t)(end - asexp->d);

                    MAKE_SPACE(alen);

                    if (_gcry_is_secure(asexp)) {
                        err = switch_to_secure(&c);

                        if (err) {
                            goto leave;
                        }
                    }

                    memcpy(c.pos, asexp->d, alen);
                    c.pos += alen;
                }
            } else {
                FAIL(GPG_ERR_SEXP_INV_LEN_SPEC);
            }

            percent = NULL;
        } else if (*p == '(') {
            if (disphint) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_DH);
            }

            MAKE_SPACE(0);
            *c.pos++ = ST_OPEN;
            level++;
        } else if (*p == ')') {
            if (disphint) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_DH);
            }

            if (level == 0) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_PAREN);
            }

            MAKE_SPACE(0);
            *c.pos++ = ST_CLOSE;
            level--;
        } else if (*p == '"') {
            quoted = p;
            quoted_esc = 0;
        } else if (*p == '#') {
            hexfmt = p;
            hexcount = 0;
        } else if (*p == '|') {
            base64 = p;
            b64count = 0;
        } else if (*p == '[') {
            if (disphint) {
                FAIL(GPG_ERR_SEXP_NESTED_DH);
            }

            disphint = p;
        } else if (*p == ']') {
            if (!disphint) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_DH);
            }

            disphint = NULL;
        } else if (digitp(p)) {
            if (*p == '0') {
                FAIL(GPG_ERR_SEXP_ZERO_PREFIX);
            }

            digptr = p;
        } else if (tokencharp((unsigned char) * p)) {
            tokenp = p;
        } else if (whitespacep(p)) {
            ;
        } else if (*p == '{') {
            FAIL(GPG_ERR_SEXP_UNEXPECTED_PUNC);
        } else if (*p == '&' || *p == '\\') {
            FAIL(GPG_ERR_SEXP_UNEXPECTED_PUNC);
        } else if (argflag && *p == '%') {
            percent = p;
        } else {
            FAIL(GPG_ERR_SEXP_BAD_CHARACTER);
        }
    }

    /* A token may run until the end of the input. */
    if (tokenp && !hexfmt) {
        datalen = (size_t)(p - tokenp);

        if (datalen > MAX_DATALEN) {
            FAIL(GPG_ERR_INV_ARG);
        }

        MAKE_SPACE(datalen);
        store_data(&c, tokenp, datalen);
        tokenp = NULL;
    }

    MAKE_SPACE(0);
    *c.pos++ = ST_STOP;

    if (level && !err) {
        err = GPG_ERR_SEXP_UNMATCHED_PAREN;
    }

leave:

    if (err) {
        if (c.sexp) {
            if (_gcry_is_secure(c.sexp)) {
                _gcry_wipememory(c.sexp, sizeof * c.sexp + c.allocated - 1);
            }

            _gcry_free(c.sexp);
        }
    } else {
        *retsexp = normalize(c.sexp);
    }

    return err;
#undef ARG_NEXT
#undef MAKE_SPACE
#undef FAIL
}

static gcry_err_code_t
do_sexp_sscan(gcry_sexp_t *retsexp, size_t *erroff, const char *buffer,
              size_t length, int argflag, void **arg_list, ...)
{
    gcry_err_code_t rc;
    va_list arg_ptr;

    va_start(arg_ptr, arg_list);
    rc = do_vsexp_sscan(retsexp, erroff, buffer, length, argflag, arg_list,
                        arg_ptr);
    va_end(arg_ptr);
    return rc;
}

gcry_err_code_t
_gcry_sexp_vbuild(gcry_sexp_t *retsexp, size_t *erroff, const char *format,
                  va_list arg_ptr)
{
    return do_vsexp_sscan(retsexp, erroff, format, strlen(format), 1, NULL,
                          arg_ptr);
}

gcry_err_code_t
_gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff, const char *format,
                 ...)
{
    gcry_err_code_t rc;
    va_list arg_ptr;

    va_start(arg_ptr, format);
    rc = _gcry_sexp_vbuild(retsexp, erroff, format, arg_ptr);
    va_end(arg_ptr);
    return rc;
}

gcry_err_code_t
_gcry_sexp_sscan(gcry_sexp_t *retsexp, size_t *erroff, const char *buffer,
                 size_t length)
{
    return do_sexp_sscan(retsexp, erroff, buffer, length, 0, NULL);
}

/* ------------------------------------------------------------------ */
/* Creation                                                            */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
sexp_create(gcry_sexp_t *retsexp, const void *buffer, size_t length,
            int autodetect)
{
    gcry_err_code_t errcode;

    if (!retsexp) {
        return GPG_ERR_INV_ARG;
    }

    *retsexp = NULL;

    if (autodetect < 0 || autodetect > 1 || !buffer) {
        return GPG_ERR_INV_ARG;
    }

    if (!length && !autodetect) {
        length = gcry_sexp_canon_len(buffer, 0, NULL, &errcode);

        if (!length) {
            return gcry_err_code(errcode);
        }
    } else if (!length && autodetect) {
        length = strlen(buffer);
    }

    return do_sexp_sscan(retsexp, NULL, buffer, length, 0, NULL);
}

gcry_err_code_t
_gcry_sexp_new(gcry_sexp_t *retsexp, const void *buffer, size_t length,
               int autodetect)
{
    return sexp_create(retsexp, buffer, length, autodetect);
}

gcry_error_t
gcry_sexp_create(gcry_sexp_t *retsexp, void *buffer, size_t length,
                 int autodetect, void (*freefnc)(void *))
{
    gcry_err_code_t rc = sexp_create(retsexp, buffer, length, autodetect);

    if (!rc && freefnc) {
        /* The data has been copied, so the caller's buffer can go now. */
        freefnc(buffer);
    }

    return GCRY_ERR(rc);
}

gcry_error_t
gcry_sexp_new(gcry_sexp_t *retsexp, const void *buffer, size_t length,
              int autodetect)
{
    return GCRY_ERR(sexp_create(retsexp, buffer, length, autodetect));
}

gcry_error_t
gcry_sexp_sscan(gcry_sexp_t *retsexp, size_t *erroff, const char *buffer,
                size_t length)
{
    return GCRY_ERR(_gcry_sexp_sscan(retsexp, erroff, buffer, length));
}

gcry_error_t
gcry_sexp_build(gcry_sexp_t *retsexp, size_t *erroff, const char *format,
                ...)
{
    gcry_err_code_t rc;
    va_list arg_ptr;

    va_start(arg_ptr, format);
    rc = _gcry_sexp_vbuild(retsexp, erroff, format, arg_ptr);
    va_end(arg_ptr);
    return GCRY_ERR(rc);
}

gcry_error_t
gcry_sexp_build_array(gcry_sexp_t *retsexp, size_t *erroff,
                      const char *format, void **arg_list)
{
    return GCRY_ERR(do_sexp_sscan(retsexp, erroff, format, strlen(format), 1,
                                  arg_list));
}

/* ------------------------------------------------------------------ */
/* Structural operations                                               */
/* ------------------------------------------------------------------ */

/* Build a new list whose elements are the given items.  Each item is a
 * pointer/length pair of internal representation to be inserted as-is. */
struct item {
    const unsigned char *p;
    size_t n;
};

static gcry_sexp_t
make_list(const struct item *items, size_t nitems, int secure)
{
    size_t total = 3; /* ST_OPEN, ST_CLOSE, ST_STOP */
    size_t i;
    gcry_sexp_t list;
    unsigned char *d;

    for (i = 0; i < nitems; i++) {
        total += items[i].n;
    }

    list = alloc_sexp(sizeof * list + total - 1, secure);

    if (!list) {
        return NULL;
    }

    d = list->d;
    *d++ = ST_OPEN;

    for (i = 0; i < nitems; i++) {
        memcpy(d, items[i].p, items[i].n);
        d += items[i].n;
    }

    *d++ = ST_CLOSE;
    *d = ST_STOP;
    return normalize(list);
}

/* The internal content of SEXP as an element to be embedded into another
 * list: a list is embedded whole; NULL contributes nothing. */
static struct item
item_of(const gcry_sexp_t sexp)
{
    struct item it = { NULL, 0 };

    if (sexp && sexp->d[0] != ST_STOP) {
        it.p = sexp->d;
        it.n = (size_t)(skip_item(sexp->d) - sexp->d);
    }

    return it;
}

gcry_sexp_t
gcry_sexp_cons(const gcry_sexp_t a, const gcry_sexp_t b)
{
    struct item items[2];

    items[0] = item_of(a);
    items[1] = item_of(b);
    return make_list(items, 2, _gcry_is_secure(a) || _gcry_is_secure(b));
}

gcry_sexp_t
gcry_sexp_alist(const gcry_sexp_t *array)
{
    size_t n = 0;
    size_t i;
    struct item *items;
    gcry_sexp_t result;
    int secure = 0;

    if (!array) {
        return NULL;
    }

    while (array[n]) {
        n++;
    }

    items = _gcry_malloc((n ? n : 1) * sizeof * items);

    if (!items) {
        return NULL;
    }

    for (i = 0; i < n; i++) {
        items[i] = item_of(array[i]);
        secure |= _gcry_is_secure(array[i]);
    }

    result = make_list(items, n, secure);
    _gcry_free(items);
    return result;
}

gcry_sexp_t
gcry_sexp_vlist(const gcry_sexp_t a, ...)
{
    va_list ap;
    size_t n = 0;
    size_t cap = 8;
    gcry_sexp_t *array = _gcry_malloc(cap * sizeof * array);
    gcry_sexp_t cur = a;
    gcry_sexp_t result;

    if (!array) {
        return NULL;
    }

    va_start(ap, a);

    while (cur) {
        if (n + 1 >= cap) {
            gcry_sexp_t *tmp;

            cap *= 2;
            tmp = _gcry_realloc(array, cap * sizeof * array);

            if (!tmp) {
                _gcry_free(array);
                va_end(ap);
                return NULL;
            }

            array = tmp;
        }

        array[n++] = cur;
        cur = va_arg(ap, gcry_sexp_t);
    }

    va_end(ap);
    array[n] = NULL;
    result = gcry_sexp_alist(array);
    _gcry_free(array);
    return result;
}

/* Elements of list A (without the surrounding parentheses). */
static struct item
inner_of(const gcry_sexp_t a)
{
    struct item it = { NULL, 0 };

    if (a && a->d[0] == ST_OPEN) {
        const unsigned char *end = skip_item(a->d);

        it.p = a->d + 1;
        it.n = (size_t)(end - a->d) - 2;
    }

    return it;
}

gcry_sexp_t
gcry_sexp_append(const gcry_sexp_t a, const gcry_sexp_t n)
{
    struct item items[2];

    items[0] = inner_of(a);
    items[1] = item_of(n);
    return make_list(items, 2, _gcry_is_secure(a) || _gcry_is_secure(n));
}

gcry_sexp_t
gcry_sexp_prepend(const gcry_sexp_t a, const gcry_sexp_t n)
{
    struct item items[2];

    items[0] = item_of(n);
    items[1] = inner_of(a);
    return make_list(items, 2, _gcry_is_secure(a) || _gcry_is_secure(n));
}

/* Copy the complete item at HEAD (a list) into a new object. */
static gcry_sexp_t
copy_list_at(const unsigned char *head, int secure)
{
    const unsigned char *end = skip_item(head);
    size_t n = (size_t)(end - head);
    gcry_sexp_t newlist = alloc_sexp(sizeof * newlist + n, secure);

    if (!newlist) {
        return NULL;
    }

    memcpy(newlist->d, head, n);
    newlist->d[n] = ST_STOP;
    return normalize(newlist);
}

gcry_sexp_t
gcry_sexp_find_token(gcry_sexp_t list, const char *tok, size_t toklen)
{
    const unsigned char *p;

    if (!list) {
        return NULL;
    }

    if (!toklen) {
        toklen = strlen(tok);
    }

    p = list->d;

    while (*p != ST_STOP) {
        if (*p == ST_OPEN && p[1] == ST_DATA) {
            const unsigned char *head = p;
            DATALEN n = get_len(p + 2);
            const unsigned char *data = p + 2 + sizeof(DATALEN);

            if (n == toklen && !memcmp(data, tok, toklen)) {
                return copy_list_at(head, _gcry_is_secure(list));
            }

            p = data + n;
        } else if (*p == ST_DATA) {
            p += 1 + sizeof(DATALEN) + get_len(p + 1);
        } else {
            p++;
        }
    }

    return NULL;
}

int
gcry_sexp_length(const gcry_sexp_t list)
{
    const unsigned char *p;
    int length = 0;
    int level = 0;

    if (!list) {
        return 0;
    }

    p = list->d;

    while (*p != ST_STOP) {
        if (*p == ST_DATA) {
            if (level == 1) {
                length++;
            }

            p += 1 + sizeof(DATALEN) + get_len(p + 1);
        } else if (*p == ST_OPEN) {
            if (level == 1) {
                length++;
            }

            level++;
            p++;
        } else {
            level--;
            p++;
        }
    }

    return length;
}

/* Position of element NUMBER of LIST, or NULL. */
static const unsigned char *
find_nth(const gcry_sexp_t list, int number)
{
    const unsigned char *p;

    if (!list) {
        return NULL;
    }

    p = list->d;

    if (*p == ST_OPEN) {
        p++;
    } else if (number) {
        return NULL;
    }

    while (number > 0) {
        if (*p == ST_STOP || *p == ST_CLOSE) {
            return NULL;
        }

        p = skip_item(p);
        number--;
    }

    if (*p == ST_STOP || *p == ST_CLOSE) {
        return NULL;
    }

    return p;
}

gcry_sexp_t
gcry_sexp_nth(const gcry_sexp_t list, int number)
{
    const unsigned char *p;

    if (!list || list->d[0] != ST_OPEN || number < 0) {
        return NULL;
    }

    p = find_nth(list, number);

    if (!p) {
        return NULL;
    }

    if (*p == ST_DATA) {
        DATALEN n = get_len(p + 1);
        size_t total = 1 + 1 + sizeof(DATALEN) + n + 1 + 1;
        gcry_sexp_t newlist = alloc_sexp(sizeof * newlist + total - 1,
                                         _gcry_is_secure(list));
        unsigned char *d;

        if (!newlist) {
            return NULL;
        }

        d = newlist->d;
        *d++ = ST_OPEN;
        memcpy(d, p, 1 + sizeof(DATALEN) + n);
        d += 1 + sizeof(DATALEN) + n;
        *d++ = ST_CLOSE;
        *d = ST_STOP;
        return normalize(newlist);
    }

    if (*p == ST_OPEN) {
        return copy_list_at(p, _gcry_is_secure(list));
    }

    return NULL;
}

gcry_sexp_t
gcry_sexp_car(const gcry_sexp_t list)
{
    return gcry_sexp_nth(list, 0);
}

static const char *
do_nth_data(const gcry_sexp_t list, int number, size_t *datalen)
{
    const unsigned char *p;

    *datalen = 0;

    if (number < 0) {
        return NULL;
    }

    p = find_nth(list, number);

    if (!p || *p != ST_DATA) {
        return NULL;
    }

    *datalen = get_len(p + 1);
    return (const char *)p + 1 + sizeof(DATALEN);
}

const char *
gcry_sexp_nth_data(const gcry_sexp_t list, int number, size_t *datalen)
{
    size_t dummy;

    return do_nth_data(list, number, datalen ? datalen : &dummy);
}

void *
gcry_sexp_nth_buffer(const gcry_sexp_t list, int number, size_t *rlength)
{
    const char *s;
    size_t n;
    void *buf;
    size_t dummy;

    if (!rlength) {
        rlength = &dummy;
    }

    *rlength = 0;
    s = do_nth_data(list, number, &n);

    if (!s || !n) {
        return NULL;
    }

    buf = _gcry_is_secure(list) ? _gcry_malloc_secure(n) : _gcry_malloc(n);

    if (!buf) {
        return NULL;
    }

    memcpy(buf, s, n);
    *rlength = n;
    return buf;
}

char *
gcry_sexp_nth_string(gcry_sexp_t list, int number)
{
    const char *s;
    size_t n;
    char *buf;

    s = do_nth_data(list, number, &n);

    if (!s || n < 1) {
        return NULL;
    }

    buf = _gcry_is_secure(list) ? _gcry_malloc_secure(n + 1)
          : _gcry_malloc(n + 1);

    if (!buf) {
        return NULL;
    }

    memcpy(buf, s, n);
    buf[n] = 0;
    return buf;
}

gcry_mpi_t
gcry_sexp_nth_mpi(gcry_sexp_t list, int number, int mpifmt)
{
    size_t n;
    gcry_mpi_t a;

    if (mpifmt == GCRYMPI_FMT_OPAQUE) {
        void *p = gcry_sexp_nth_buffer(list, number, &n);

        if (!p) {
            return NULL;
        }

        a = _gcry_is_secure(list) ? gcry_mpi_snew(0) : gcry_mpi_new(0);

        if (a) {
            gcry_mpi_set_opaque(a, p, (unsigned int)(n * 8));
        } else {
            _gcry_free(p);
        }

        return a;
    } else {
        const char *s;

        if (!mpifmt) {
            mpifmt = GCRYMPI_FMT_STD;
        }

        s = do_nth_data(list, number, &n);

        if (!s) {
            return NULL;
        }

        if (_gcry_mpi_scan(&a, (enum gcry_mpi_format)mpifmt, s, n, NULL)) {
            return NULL;
        }

        return a;
    }
}

gcry_sexp_t
gcry_sexp_cdr(const gcry_sexp_t list)
{
    const unsigned char *p;
    const unsigned char *head;
    const unsigned char *end;
    size_t n;
    gcry_sexp_t newlist;
    unsigned char *d;

    if (!list || list->d[0] != ST_OPEN) {
        return NULL;
    }

    p = list->d + 1;

    if (*p == ST_STOP || *p == ST_CLOSE) {
        return NULL;
    }

    head = skip_item(p); /* Skip the car. */
    end = head;

    while (*end != ST_CLOSE) {
        if (*end == ST_STOP) {
            return NULL;
        }

        end = skip_item(end);
    }

    n = (size_t)(end - head);
    newlist = alloc_sexp(sizeof * newlist + n + 2, _gcry_is_secure(list));

    if (!newlist) {
        return NULL;
    }

    d = newlist->d;
    *d++ = ST_OPEN;
    memcpy(d, head, n);
    d += n;
    *d++ = ST_CLOSE;
    *d = ST_STOP;
    return normalize(newlist);
}

gcry_sexp_t
gcry_sexp_cadr(const gcry_sexp_t list)
{
    gcry_sexp_t a = gcry_sexp_cdr(list);
    gcry_sexp_t b = gcry_sexp_car(a);

    gcry_sexp_release(a);
    return b;
}

/* ------------------------------------------------------------------ */
/* Printer                                                             */
/* ------------------------------------------------------------------ */

/* 0 = binary (hex), 1 = quoted string possible, 2 = bare token possible. */
static int
suitable_encoding(const unsigned char *buffer, size_t length)
{
    const unsigned char *s;
    int maybe_token = 1;

    if (!length) {
        return 1;
    }

    if (*buffer & 0x80) {
        return 0;
    }

    for (s = buffer; length; s++, length--) {
        if (!*s) {
            return 0;
        }

        if ((*s < 0x20 || (*s >= 0x7f && *s <= 0xa0))
            && !strchr("\b\t\v\n\f\r\"'\\", *s)) {
            return 0;
        }

        if (maybe_token && !alphap(s) && !digitp((const char *)s)
            && !strchr(TOKEN_SPECIALS, *s)) {
            maybe_token = 0;
        }
    }

    if (maybe_token && !digitp((const char *)buffer)) {
        return 2;
    }

    return 1;
}

static size_t
convert_to_hex(const unsigned char *src, size_t len, char *dest)
{
    static const char hexdigits[] = "0123456789ABCDEF";
    size_t i;

    if (dest) {
        *dest++ = '#';

        for (i = 0; i < len; i++) {
            *dest++ = hexdigits[src[i] >> 4];
            *dest++ = hexdigits[src[i] & 0x0f];
        }

        *dest++ = '#';
    }

    return len * 2 + 2;
}

static size_t
convert_to_string(const unsigned char *s, size_t len, char *dest)
{
    size_t count = 2;
    char *p = dest;

    if (dest) {
        *p++ = '"';
    }

    for (; len; len--, s++) {
        const char *esc = NULL;

        switch (*s) {
        case '\b':
            esc = "\\b";
            break;

        case '\t':
            esc = "\\t";
            break;

        case '\v':
            esc = "\\v";
            break;

        case '\n':
            esc = "\\n";
            break;

        case '\f':
            esc = "\\f";
            break;

        case '\r':
            esc = "\\r";
            break;

        case '"':
            esc = "\\\"";
            break;

        case '\'':
            esc = "\\'";
            break;

        case '\\':
            esc = "\\\\";
            break;

        default:
            break;
        }

        if (esc) {
            if (dest) {
                *p++ = esc[0];
                *p++ = esc[1];
            }

            count += 2;
        } else if (*s < 0x20 || (*s >= 0x7f && *s <= 0xa0)) {
            if (dest) {
                snprintf(p, 5, "\\x%02x", *s);
                p += 4;
            }

            count += 4;
        } else {
            if (dest) {
                *p++ = (char) * s;
            }

            count++;
        }
    }

    if (dest) {
        *p++ = '"';
    }

    return count;
}

static size_t
convert_to_token(const unsigned char *src, size_t len, char *dest)
{
    if (dest) {
        memcpy(dest, src, len);
    }

    return len;
}

size_t
gcry_sexp_sprint(gcry_sexp_t list, int mode, void *buffer, size_t maxlength)
{
    static const unsigned char empty[3] = { ST_OPEN, ST_CLOSE, ST_STOP };
    const unsigned char *s;
    char *d = buffer;
    DATALEN n;
    char numbuf[20];
    size_t len = 0;
    int i;
    int indent = 0;

    s = list ? list->d : empty;

    while (*s != ST_STOP) {
        switch (*s) {
        case ST_OPEN:
            s++;

            if (mode != GCRYSEXP_FMT_CANON) {
                if (indent) {
                    len++;
                }

                len += (size_t)indent;
            }

            len++;

            if (buffer) {
                if (len >= maxlength) {
                    return 0;
                }

                if (mode != GCRYSEXP_FMT_CANON) {
                    if (indent) {
                        *d++ = '\n';
                    }

                    for (i = 0; i < indent; i++) {
                        *d++ = ' ';
                    }
                }

                *d++ = '(';
            }

            indent++;
            break;

        case ST_CLOSE:
            s++;
            len++;

            if (buffer) {
                if (len >= maxlength) {
                    return 0;
                }

                *d++ = ')';
            }

            indent--;

            if (*s != ST_OPEN && *s != ST_STOP && mode != GCRYSEXP_FMT_CANON) {
                len++;
                len += (size_t)indent;

                if (buffer) {
                    if (len >= maxlength) {
                        return 0;
                    }

                    *d++ = '\n';

                    for (i = 0; i < indent; i++) {
                        *d++ = ' ';
                    }
                }
            }

            break;

        case ST_DATA:
            s++;
            n = get_len(s);
            s += sizeof(DATALEN);

            if (mode == GCRYSEXP_FMT_ADVANCED) {
                int type = suitable_encoding(s, n);
                size_t nn;

                switch (type) {
                case 1:
                    nn = convert_to_string(s, n, NULL);
                    break;

                case 2:
                    nn = convert_to_token(s, n, NULL);
                    break;

                default:
                    nn = convert_to_hex(s, n, NULL);
                    break;
                }

                len += nn;

                if (buffer) {
                    if (len >= maxlength) {
                        return 0;
                    }

                    switch (type) {
                    case 1:
                        convert_to_string(s, n, d);
                        break;

                    case 2:
                        convert_to_token(s, n, d);
                        break;

                    default:
                        convert_to_hex(s, n, d);
                        break;
                    }

                    d += nn;
                }

                if (s[n] != ST_CLOSE) {
                    len++;

                    if (buffer) {
                        if (len >= maxlength) {
                            return 0;
                        }

                        *d++ = ' ';
                    }
                }
            } else {
                snprintf(numbuf, sizeof numbuf, "%u:", (unsigned int)n);
                len += strlen(numbuf) + n;

                if (buffer) {
                    if (len >= maxlength) {
                        return 0;
                    }

                    memcpy(d, numbuf, strlen(numbuf));
                    d += strlen(numbuf);
                    memcpy(d, s, n);
                    d += n;
                }
            }

            s += n;
            break;

        default:
            BUG();
        }
    }

    if (mode != GCRYSEXP_FMT_CANON) {
        len++;

        if (buffer) {
            if (len >= maxlength) {
                return 0;
            }

            *d++ = '\n';
        }
    }

    if (buffer) {
        if (len >= maxlength) {
            return 0;
        }

        *d = 0;
    } else {
        len++;
    }

    return len;
}

void
gcry_sexp_dump(const gcry_sexp_t a)
{
    gcry_log_debugsxp(NULL, a);
}

size_t
gcry_sexp_canon_len(const unsigned char *buffer, size_t length,
                    size_t *erroff, gcry_error_t *errcode)
{
    const unsigned char *p;
    const unsigned char *disphint = NULL;
    size_t datalen = 0;
    size_t dummy_erroff;
    gcry_error_t dummy_errcode;
    size_t count = 0;
    int level = 0;

    if (!erroff) {
        erroff = &dummy_erroff;
    }

    if (!errcode) {
        errcode = &dummy_errcode;
    }

    *errcode = 0;
    *erroff = 0;

    if (!buffer) {
        return 0;
    }

    if (*buffer != '(') {
        *errcode = GCRY_ERR(GPG_ERR_SEXP_NOT_CANONICAL);
        return 0;
    }

#define FAIL(code)                      \
    do {                                \
        *erroff = count;                \
        *errcode = GCRY_ERR(code);      \
        return 0;                       \
    } while (0)

    for (p = buffer;; p++, count++) {
        if (length && count >= length) {
            FAIL(GPG_ERR_SEXP_STRING_TOO_LONG);
        }

        if (datalen) {
            if (*p == ':') {
                if (length && count + datalen >= length) {
                    FAIL(GPG_ERR_SEXP_STRING_TOO_LONG);
                }

                count += datalen;
                p += datalen;
                datalen = 0;
            } else if (digitp((const char *)p)) {
                datalen = datalen * 10 + (size_t)(*p - '0');
            } else {
                FAIL(GPG_ERR_SEXP_INV_LEN_SPEC);
            }
        } else if (*p == '(') {
            if (disphint) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_DH);
            }

            level++;
        } else if (*p == ')') {
            if (!level) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_PAREN);
            }

            if (disphint) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_DH);
            }

            if (!--level) {
                return ++count;
            }
        } else if (*p == '[') {
            if (disphint) {
                FAIL(GPG_ERR_SEXP_NESTED_DH);
            }

            disphint = p;
        } else if (*p == ']') {
            if (!disphint) {
                FAIL(GPG_ERR_SEXP_UNMATCHED_DH);
            }

            disphint = NULL;
        } else if (digitp((const char *)p)) {
            if (*p == '0') {
                FAIL(GPG_ERR_SEXP_ZERO_PREFIX);
            }

            datalen = (size_t)(*p - '0');
        } else if (*p == '&' || *p == '\\') {
            FAIL(GPG_ERR_SEXP_UNEXPECTED_PUNC);
        } else {
            FAIL(GPG_ERR_SEXP_BAD_CHARACTER);
        }
    }

#undef FAIL
}

/* ------------------------------------------------------------------ */
/* Parameter extraction                                                */
/* ------------------------------------------------------------------ */

/* Find the first sublist in [START, END) whose first element is TOK and
 * return a pointer to its ST_OPEN byte, or NULL.  END may be NULL to scan
 * up to the ST_STOP marker.  Same search as gcry_sexp_find_token, without
 * copying the result. */
static const unsigned char *
find_token_in(const unsigned char *start, const unsigned char *end,
              const char *tok, size_t toklen)
{
    const unsigned char *p = start;

    while ((!end || p < end) && *p != ST_STOP) {
        if (*p == ST_OPEN && p[1] == ST_DATA) {
            DATALEN n = get_len(p + 2);
            const unsigned char *data = p + 2 + sizeof(DATALEN);

            if (n == toklen && !memcmp(data, tok, toklen)) {
                return p;
            }

            p = data + n;
        } else if (*p == ST_DATA) {
            p += 1 + sizeof(DATALEN) + get_len(p + 1);
        } else {
            p++;
        }
    }

    return NULL;
}

/* The data element following the token of the sublist at HEAD, or NULL
 * when there is none or it is itself a list. */
static const unsigned char *
list_value_at(const unsigned char *head, size_t *r_len)
{
    const unsigned char *p = skip_item(head + 1);

    *r_len = 0;

    if (*p != ST_DATA) {
        return NULL;
    }

    *r_len = get_len(p + 1);
    return p + 1 + sizeof(DATALEN);
}

/* Copy N bytes into a fresh buffer with an extra NUL, NULL if N is 0. */
static char *
copy_value_string(const unsigned char *s, size_t n, int secure)
{
    char *buf;

    if (!s || n < 1) {
        return NULL;
    }

    buf = secure ? _gcry_malloc_secure(n + 1) : _gcry_malloc(n + 1);

    if (!buf) {
        return NULL;
    }

    memcpy(buf, s, n);
    buf[n] = 0;
    return buf;
}

static const unsigned char empty_list[1] = { ST_STOP };

gcry_err_code_t
_gcry_sexp_vextract_param(gcry_sexp_t sexp, const char *path,
                          const char *list, va_list arg_ptr)
{
    gcry_err_code_t rc;
    const char *s;
    const char *s2;
    void **array[20];
    char arrayisdesc[20];
    int idx;
    int mode = '+';
    int submode = 0;
    char *tmpstr = NULL;
    const unsigned char *scope;      /* Where to look for list tokens. */
    const unsigned char *scope_end;  /* NULL: up to ST_STOP. */
    const unsigned char *head;       /* The matching sublist. */
    int secure;

    /* arrayisdesc: 0 MPI, 1 caller buffer, 2 our buffer, 's' string,
     * 'x' plain integer (nothing to free). */
    memset(arrayisdesc, 0, sizeof arrayisdesc);

    /* Collect all output pointers first, so that on error everything
     * allocated so far can be released. */
    for (s = list, idx = 0; *s && idx < (int)DIM(array); s++) {
        if (*s == '&' || *s == '+' || *s == '-' || *s == '/' || *s == '?') {
            ;
        } else if (*s == '%') {
            s++;

            if (*s == 'l' && (s[1] == 'u' || s[1] == 'd')) {
                s++;
            } else if (*s == 'z' && s[1] == 'u') {
                s++;
            } else if (*s == '#' && s[1] == 's') {
                s++;
            }

            continue;
        } else if (whitespacep(s)) {
            ;
        } else {
            if (*s == '\'') {
                s++;
                s2 = strchr(s, '\'');

                if (!s2 || s2 == s) {
                    return GPG_ERR_SYNTAX;
                }

                s = s2;
            }

            array[idx] = va_arg(arg_ptr, void *);

            if (!array[idx]) {
                return GPG_ERR_MISSING_VALUE;
            }

            idx++;
        }
    }

    if (*s) {
        return GPG_ERR_LIMIT_REACHED;
    }

    if (va_arg(arg_ptr, gcry_mpi_t *)) {
        return GPG_ERR_INV_ARG;
    }

    /* A NULL list simply contains nothing, as gcry_sexp_find_token has it. */
    secure = sexp ? _gcry_is_secure(sexp) : 0;
    scope = sexp ? sexp->d : empty_list;
    scope_end = NULL;

    /* Follow PATH, narrowing the scope to the matching sublist each time
     * instead of copying it. */
    while (path && *path) {
        size_t n;

        s = strchr(path, '!');

        if (s == path) {
            rc = GPG_ERR_NOT_FOUND;
            goto cleanup;
        }

        n = s ? (size_t)(s - path) : 0;
        head = find_token_in(scope, scope_end, path, n ? n : strlen(path));

        if (!head) {
            rc = GPG_ERR_NOT_FOUND;
            goto cleanup;
        }

        scope = head;
        scope_end = skip_item(head);

        if (n) {
            path += n + 1;
        } else {
            path = NULL;
        }
    }

    for (s = list, idx = 0; *s; s++) {
        if (*s == '&' || *s == '+' || *s == '-' || *s == '/') {
            mode = *s;
        } else if (*s == '%') {
            s++;

            if (!*s) {
                break;
            }

            if (*s == 's' || *s == 'd' || *s == 'u') {
                mode = *s;
                submode = 0;
            } else if (*s == 'l' && (s[1] == 'u' || s[1] == 'd')) {
                mode = s[1];
                submode = 'l';
                s++;
            } else if (*s == 'z' && s[1] == 'u') {
                mode = s[1];
                submode = 'z';
                s++;
            } else if (*s == '#' && s[1] == 's') {
                mode = s[1];
                submode = '#';
                s++;
            }

            continue;
        } else if (whitespacep(s)) {
            ;
        } else if (*s == '?') {
            ;
        } else {
            const unsigned char *val;
            size_t vlen;

            if (*s == '\'') {
                s++;
                s2 = strchr(s, '\'');

                if (!s2 || s2 == s) {
                    rc = GPG_ERR_SYNTAX;
                    goto cleanup;
                }

                head = find_token_in(scope, scope_end, s, (size_t)(s2 - s));
                s = s2;
            } else {
                head = find_token_in(scope, scope_end, s, 1);
            }

            if (!head && s[1] == '?') {
                /* Optional element missing: leave a well defined value. */
                if (mode == '&') {
                    gcry_buffer_t *spec = (gcry_buffer_t *)array[idx];

                    if (!spec->data) {
                        spec->size = 0;
                        spec->off = 0;
                    }

                    spec->len = 0;
                } else if (mode == 's') {
                    *array[idx] = NULL;
                    arrayisdesc[idx] = 's';
                } else if (mode == 'd') {
                    if (submode == 'l') {
                        *(long *)array[idx] = 0;
                    } else {
                        *(int *)array[idx] = 0;
                    }

                    arrayisdesc[idx] = 'x';
                } else if (mode == 'u') {
                    if (submode == 'l') {
                        *(unsigned long *)array[idx] = 0;
                    } else if (submode == 'z') {
                        *(size_t *)array[idx] = 0;
                    } else {
                        *(unsigned int *)array[idx] = 0;
                    }

                    arrayisdesc[idx] = 'x';
                } else {
                    *array[idx] = NULL;
                }
            } else if (!head) {
                rc = GPG_ERR_NO_OBJ;
                goto cleanup;
            } else {
                val = list_value_at(head, &vlen);

                if (mode == '&') {
                    gcry_buffer_t *spec = (gcry_buffer_t *)array[idx];

                    if (!val || !vlen) {
                        rc = GPG_ERR_INV_OBJ;
                        goto cleanup;
                    }

                    if (spec->data) {
                        if (spec->off + vlen > spec->size) {
                            rc = GPG_ERR_BUFFER_TOO_SHORT;
                            goto cleanup;
                        }

                        memcpy((char *)spec->data + spec->off, val, vlen);
                        spec->len = vlen;
                        arrayisdesc[idx] = 1;
                    } else {
                        spec->data = secure ? _gcry_malloc_secure(vlen)
                                     : _gcry_malloc(vlen);

                        if (!spec->data) {
                            rc = GPG_ERR_INV_OBJ;
                            goto cleanup;
                        }

                        memcpy(spec->data, val, vlen);
                        spec->size = vlen;
                        spec->len = vlen;
                        spec->off = 0;
                        arrayisdesc[idx] = 2;
                    }
                } else if (mode == 's') {
                    if (submode == '#') {
                        /* All values of the list, space separated. */
                        size_t needed = 0;
                        const unsigned char *q;
                        char *p;

                        for (q = skip_item(head + 1);
                             *q != ST_CLOSE && *q != ST_STOP;
                             q = skip_item(q)) {
                            needed += (*q == ST_DATA ? get_len(q + 1) : 2u)
                                      + 1;
                        }

                        if (!needed) {
                            *array[idx] = p = _gcry_malloc(1);

                            if (p) {
                                *p = 0;
                            }
                        } else if ((*array[idx] = p = _gcry_malloc(needed))) {
                            for (q = skip_item(head + 1);
                                 *q != ST_CLOSE && *q != ST_STOP;
                                 q = skip_item(q)) {
                                size_t n;

                                if (*q == ST_DATA) {
                                    n = get_len(q + 1);
                                    memcpy(p, q + 1 + sizeof(DATALEN), n);
                                } else {
                                    memcpy(p, "()", (n = 2));
                                }

                                p[n] = ' ';
                                p += n + 1;
                            }

                            if (p != *array[idx]) {
                                p[-1] = 0;
                            }
                        }
                    } else {
                        *array[idx] = copy_value_string(val, vlen, secure);
                    }

                    if (!*array[idx]) {
                        rc = _gcry_err_code_from_syserror();
                        goto cleanup;
                    }

                    arrayisdesc[idx] = 's';
                } else if (mode == 'd') {
                    long along;

                    _gcry_free(tmpstr);
                    tmpstr = copy_value_string(val, vlen, secure);

                    if (!tmpstr) {
                        rc = _gcry_err_code_from_syserror();
                        goto cleanup;
                    }

                    along = strtol(tmpstr, NULL, 10);

                    if (submode == 'l') {
                        *(long *)array[idx] = along;
                    } else {
                        *(int *)array[idx] = (int)along;
                    }

                    arrayisdesc[idx] = 'x';
                } else if (mode == 'u') {
                    unsigned long aulong;

                    _gcry_free(tmpstr);
                    tmpstr = copy_value_string(val, vlen, secure);

                    if (!tmpstr) {
                        rc = _gcry_err_code_from_syserror();
                        goto cleanup;
                    }

                    aulong = strtoul(tmpstr, NULL, 10);

                    if (submode == 'l') {
                        *(unsigned long *)array[idx] = aulong;
                    } else if (submode == 'z') {
                        *(size_t *)array[idx] = (size_t)aulong;
                    } else {
                        *(unsigned int *)array[idx] = (unsigned int)aulong;
                    }

                    arrayisdesc[idx] = 'x';
                } else if (mode == '/') {
                    /* Opaque: a private copy of the raw bytes. */
                    void *buf = NULL;
                    gcry_mpi_t a = NULL;

                    if (val && vlen) {
                        buf = secure ? _gcry_malloc_secure(vlen)
                              : _gcry_malloc(vlen);
                    }

                    if (buf) {
                        memcpy(buf, val, vlen);
                        a = secure ? gcry_mpi_snew(0) : gcry_mpi_new(0);

                        if (a) {
                            gcry_mpi_set_opaque(a, buf,
                                                (unsigned int)(vlen * 8));
                        } else {
                            _gcry_free(buf);
                        }
                    }

                    *array[idx] = a;

                    if (!a) {
                        rc = GPG_ERR_INV_OBJ;
                        goto cleanup;
                    }
                } else {
                    gcry_mpi_t a = NULL;
                    enum gcry_mpi_format fmt = mode == '-' ? GCRYMPI_FMT_STD
                                               : GCRYMPI_FMT_USG;

                    if (!val || _gcry_mpi_scan(&a, fmt, val, vlen, NULL)) {
                        a = NULL;
                    }

                    *array[idx] = a;

                    if (!a) {
                        rc = GPG_ERR_INV_OBJ;
                        goto cleanup;
                    }
                }
            }

            idx++;
        }
    }

    _gcry_free(tmpstr);
    return 0;

cleanup:
    _gcry_free(tmpstr);

    while (idx--) {
        if (!arrayisdesc[idx]) {
            gcry_mpi_release(*array[idx]);
            *array[idx] = NULL;
        } else if (arrayisdesc[idx] == 1) {
            gcry_buffer_t *spec = (gcry_buffer_t *)array[idx];

            spec->len = 0;
        } else if (arrayisdesc[idx] == 2) {
            gcry_buffer_t *spec = (gcry_buffer_t *)array[idx];

            _gcry_free(spec->data);
            spec->data = NULL;
            spec->size = spec->off = spec->len = 0;
        } else if (arrayisdesc[idx] == 's') {
            _gcry_free(*array[idx]);
            *array[idx] = NULL;
        }
    }

    return rc;
}

gcry_err_code_t
_gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path,
                         const char *list, ...)
{
    gcry_err_code_t rc;
    va_list arg_ptr;

    va_start(arg_ptr, list);
    rc = _gcry_sexp_vextract_param(sexp, path, list, arg_ptr);
    va_end(arg_ptr);
    return rc;
}

gpg_error_t
gcry_sexp_extract_param(gcry_sexp_t sexp, const char *path,
                        const char *list, ...)
{
    gcry_err_code_t rc;
    va_list arg_ptr;

    va_start(arg_ptr, list);
    rc = _gcry_sexp_vextract_param(sexp, path, list, arg_ptr);
    va_end(arg_ptr);
    return GCRY_ERR(rc);
}

/* Convert a hex string to a newly allocated binary buffer. */
void *
_gcry_hex2buffer(const char *string, size_t *r_length)
{
    const char *s;
    unsigned char *buffer;
    size_t length = 0;

    buffer = _gcry_malloc(strlen(string) / 2 + 1);

    if (!buffer) {
        *r_length = 0;
        return NULL;
    }

    for (s = string; *s; s += 2) {
        if (!hexdigitp(s) || !hexdigitp(s + 1)) {
            _gcry_free(buffer);
            errno = EINVAL;
            *r_length = 0;
            return NULL;
        }

        buffer[length++] = (unsigned char)(hextonibble(s[0]) * 16
                                           + hextonibble(s[1]));
    }

    *r_length = length;
    return buffer;
}
