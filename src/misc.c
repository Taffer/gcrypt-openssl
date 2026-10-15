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

static void
do_printhex(const char *text, const char *text2, const void *buffer,
            size_t length)
{
    const unsigned char *p = buffer;
    size_t i;
    char line[80];
    size_t n = 0;

    if (text && *text) {
        _gcry_log(GCRY_LOG_DEBUG, "%s:%s", text, text2 ? text2 : " ");
    } else {
        _gcry_log(GCRY_LOG_DEBUG, "%s", text2 ? text2 : " ");
    }

    for (i = 0; i < length; i++) {
        n += (size_t)snprintf(line + n, sizeof line - n, "%02x", p[i]);

        if (n >= sizeof line - 3) {
            _gcry_log(GCRY_LOG_CONT, "%s", line);
            n = 0;
            line[0] = 0;
        }
    }

    if (n) {
        _gcry_log(GCRY_LOG_CONT, "%s", line);
    }

    _gcry_log(GCRY_LOG_CONT, "\n");
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

void
gcry_log_debugpnt(const char *text, gcry_mpi_point_t point, gcry_ctx_t ctx)
{
    _gcry_log_printpnt(text, point, ctx);
}

void
gcry_log_debugsxp(const char *text, gcry_sexp_t sexp)
{
    if (text && *text) {
        if (strchr(text, '\n')) {
            _gcry_log(GCRY_LOG_DEBUG, "%s", text);
        } else {
            _gcry_log(GCRY_LOG_DEBUG, "%s: ", text);
        }
    }

    if (sexp) {
        size_t size = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
        char *buf = _gcry_xmalloc(size);
        char *p;

        gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, size);

        /* Drop the trailing newline the printer adds; we add our own. */
        p = buf + strlen(buf);

        while (p > buf && p[-1] == '\n') {
            *--p = 0;
        }

        _gcry_log(GCRY_LOG_CONT, "%s\n", buf);
        _gcry_free(buf);
    } else if (text) {
        _gcry_log(GCRY_LOG_CONT, "\n");
    }
}
