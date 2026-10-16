/*
 * misc.c - Logging, fatal error handling and the assorted handler
 * registration functions.
 */
#include "gcrypt-int.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int verbosity_level;
static gcry_handler_log_t log_handler;
static void *log_handler_value;
static gcry_handler_error_t fatal_error_handler;
static void *fatal_error_handler_value;
static const char *(*user_gettext_handler)(const char *);
static gcry_handler_progress_t progress_cb;
static void *progress_cb_data;

void
_gcry_set_log_verbosity(int level)
{
    verbosity_level = level;
}

int
_gcry_log_verbosity(void)
{
    return verbosity_level;
}

void
_gcry_logv(int level, const char *fmt, va_list ap)
{
    if (log_handler) {
        log_handler(log_handler_value, level, fmt, ap);
    } else {
        switch (level) {
        case GCRY_LOG_CONT:
            break;

        case GCRY_LOG_INFO:
            break;

        case GCRY_LOG_WARN:
            break;

        case GCRY_LOG_ERROR:
            break;

        case GCRY_LOG_FATAL:
            fputs("Fatal: ", stderr);
            break;

        case GCRY_LOG_BUG:
            fputs("Ohhhh jeeee: ", stderr);
            break;

        case GCRY_LOG_DEBUG:
            fputs("DBG: ", stderr);
            break;

        default:
            fprintf(stderr, "[Unknown log level %d]: ", level);
            break;
        }

        vfprintf(stderr, fmt, ap);
    }

    if (level == GCRY_LOG_FATAL || level == GCRY_LOG_BUG) {
        fflush(stderr);
        abort();
    }
}

void
_gcry_log(int level, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _gcry_logv(level, fmt, ap);
    va_end(ap);
}

/*
 * Hex dump in the reference library's layout: "TEXT:TEXT2" followed by
 * the bytes, wrapped after 32 bytes with a backslash and an indentation
 * matching the header.  A TEXT2 that is a bracketed annotation (the
 * "[N bit]" of opaque MPIs) goes on its own line and the data starts on
 * the next, indented by two more than the text.  With a NULL TEXT only
 * the bare bytes are printed, without wrapping or a final newline.
 */
static void
do_printhex(const char *text, const char *text2, const void *buffer,
            size_t length)
{
    int wrap = 0;
    int cnt = 0;

    if (text && *text) {
        wrap = 1;
        _gcry_log(GCRY_LOG_DEBUG, "%s:%s", text, text2);

        if (text2[1] == '[' && length && buffer) {
            _gcry_log(GCRY_LOG_CONT, "\n");
            text2 = " ";
            _gcry_log(GCRY_LOG_DEBUG, "%*s  ", (int)strlen(text), "");
        }
    }

    if (length && buffer) {
        const unsigned char *p = buffer;

        for (; length--; p++) {
            _gcry_log(GCRY_LOG_CONT, "%02x", *p);

            if (wrap && ++cnt == 32 && length) {
                cnt = 0;
                _gcry_log(GCRY_LOG_CONT, " \\\n");
                _gcry_log(GCRY_LOG_DEBUG, "%*s %*s", (int)strlen(text), "",
                          (int)strlen(text2), "");
            }
        }
    }

    if (text) {
        _gcry_log(GCRY_LOG_CONT, "\n");
    }
}

void
_gcry_log_printhex(const char *text, const void *buffer, size_t length)
{
    do_printhex(text, " ", buffer, length);
}

void
_gcry_fatal_error(int rc, const char *text)
{
    if (!text) {
        text = gcry_strerror((gcry_error_t)rc);
    }

    if (fatal_error_handler && !_gcry_fips_mode()) {
        fatal_error_handler(fatal_error_handler_value, rc, text);
    }

    fputs("\nFatal error: ", stderr);
    fputs(text, stderr);
    fputs("\n", stderr);
    fflush(stderr);
    abort();
}

void
_gcry_bug(const char *file, int line, const char *func)
{
    _gcry_log(GCRY_LOG_BUG, "... this is a bug (%s:%d:%s)\n", file, line,
              func ? func : "?");
    abort();
}

void
_gcry_progress(const char *what, int printchar, int current, int total)
{
    if (progress_cb) {
        progress_cb(progress_cb_data, what, printchar, current, total);
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void
gcry_set_progress_handler(gcry_handler_progress_t cb, void *cb_data)
{
    progress_cb = cb;
    progress_cb_data = cb_data;
}

void
gcry_set_fatalerror_handler(gcry_handler_error_t fnc, void *opaque)
{
    fatal_error_handler = fnc;
    fatal_error_handler_value = opaque;
}

void
gcry_set_log_handler(gcry_handler_log_t f, void *opaque)
{
    log_handler = f;
    log_handler_value = opaque;
}

void
gcry_set_gettext_handler(const char *(*f)(const char *))
{
    user_gettext_handler = f;
}

void
gcry_log_debug(const char *fmt, ...)
{
    va_list ap;

    if (!fmt) {
        _gcry_fatal_error(GPG_ERR_INV_ARG, "gcry_log_debug: NULL argument");
    }

    va_start(ap, fmt);
    _gcry_logv(GCRY_LOG_DEBUG, fmt, ap);
    va_end(ap);
}

void
gcry_log_debughex(const char *text, const void *buffer, size_t length)
{
    _gcry_log_printhex(text, buffer, length);
}

void
gcry_log_debugmpi(const char *text, gcry_mpi_t mpi)
{
    if (!mpi) {
        do_printhex(text ? text : " ", " (null)", NULL, 0);
    } else if (mpi_is_opaque(mpi)) {
        unsigned int nbits;
        const unsigned char *p = gcry_mpi_get_opaque(mpi, &nbits);
        char prefix[40];

        snprintf(prefix, sizeof prefix, " [%u bit]", nbits);
        do_printhex(text ? text : " ", prefix, p, (nbits + 7) / 8);
    } else {
        unsigned int rawlen;
        int sign;
        unsigned char *raw = _gcry_mpi_get_buffer(mpi, 0, &rawlen, &sign);

        if (!raw) {
            do_printhex(text ? text : " ", " [out of core]", NULL, 0);
        } else {
            if (!rawlen) {
                do_printhex(text, sign ? "-" : "+", "", 1);
            } else {
                do_printhex(text, sign ? "-" : "+", raw, rawlen);
            }

            _gcry_free(raw);
        }
    }
}

/*
 * Point dump in the reference layout: "TEXT.x"/"TEXT.y" for the affine
 * coordinates when a context allows the conversion, otherwise the
 * projective "TEXT.X"/"TEXT.Y"/"TEXT.Z".  The reference aborts for
 * Montgomery curves (no affine y); here they fall back to the
 * projective form.  A NULL text prints as "(null)", like printf does.
 */
void
gcry_log_debugpnt(const char *text, gcry_mpi_point_t point, gcry_ctx_t ctx)
{
    mpi_ec_t ec = ctx ? _gcry_ctx_get_ec(ctx) : NULL;
    char buf[100];

    if (!text) {
        text = "(null)";
    }

    if (!point) {
        snprintf(buf, sizeof buf, "%s.*", text);
        gcry_log_debugmpi(buf, NULL);
        return;
    }

    if (ec && ec->model != GCRY_ECC_MODEL_MONTGOMERY) {
        gcry_mpi_t x = gcry_mpi_new(0);
        gcry_mpi_t y = gcry_mpi_new(0);
        int ok = !_gcry_mpi_ec_affine(x, y, point, ec);

        if (ok) {
            snprintf(buf, sizeof buf, "%s.x", text);
            gcry_log_debugmpi(buf, x);
            snprintf(buf, sizeof buf, "%s.y", text);
            gcry_log_debugmpi(buf, y);
        }

        gcry_mpi_release(x);
        gcry_mpi_release(y);

        if (ok) {
            return;
        }
    }

    snprintf(buf, sizeof buf, "%s.X", text);
    gcry_log_debugmpi(buf, point->x);
    snprintf(buf, sizeof buf, "%s.Y", text);
    gcry_log_debugmpi(buf, point->y);
    snprintf(buf, sizeof buf, "%s.Z", text);
    gcry_log_debugmpi(buf, point->z);
}

/* The number of closing parentheses at P when nothing but closing
 * parentheses and white space follow; 0 otherwise. */
static int
count_closing_parens(const char *p)
{
    int count = 0;

    for (; *p; p++) {
        if (*p == ')') {
            count++;
        } else if (!strchr("\n \t", *p)) {
            return 0;
        }
    }

    return count;
}

/*
 * S-expression dump in the reference layout: "TEXT: " followed by the
 * advanced format, continuation lines indented under the text, and the
 * trailing run of closing parentheses pulled onto the last line.  A TEXT
 * containing a newline is printed as is and every line of the expression
 * is then a debug line of its own.
 */
void
gcry_log_debugsxp(const char *text, gcry_sexp_t sexp)
{
    int with_lf = 0;

    if (text && *text) {
        with_lf = strchr(text, '\n') != NULL;

        if (with_lf) {
            _gcry_log(GCRY_LOG_DEBUG, "%s", text);
        } else {
            _gcry_log(GCRY_LOG_DEBUG, "%s: ", text);
        }
    }

    if (sexp) {
        size_t size = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
        char *buf = _gcry_xmalloc(size);
        const char *p = buf;
        int any = 0;

        gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, size);

        do {
            const char *pend;
            int n_closing;

            if (any && !with_lf) {
                _gcry_log(GCRY_LOG_DEBUG, "%*s  ", text ? (int)strlen(text) : 0,
                          "");
            } else {
                any = 1;
            }

            pend = strchr(p, '\n');
            size = pend ? (size_t)(pend - p) : strlen(p);
            _gcry_log(with_lf ? GCRY_LOG_DEBUG : GCRY_LOG_CONT, "%.*s",
                      (int)size, p);
            p = pend ? pend + 1 : p + size;
            n_closing = count_closing_parens(p);

            if (n_closing) {
                while (n_closing--) {
                    _gcry_log(GCRY_LOG_CONT, ")");
                }

                p = "";
            }

            _gcry_log(GCRY_LOG_CONT, "\n");
        } while (*p);

        _gcry_free(buf);
    } else if (text) {
        _gcry_log(GCRY_LOG_CONT, "\n");
    }
}
