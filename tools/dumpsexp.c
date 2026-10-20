/* dumpsexp - debug tool for S-expressions.
 *
 * Command-line compatible with the dumpsexp program that ships with the
 * reference Libgcrypt: the same options, the same hex dump of the input
 * with the parser's view of the data interleaved, the same error cursor.
 * Unlike the reference tool, --advanced really does what its help text
 * says: the input is parsed with gcry_sexp_new() and printed in advanced
 * format, which also validates it.
 *
 * This file is in the public domain.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#define PGM "dumpsexp"

static int verbose;    /* --verbose: show the parser's state changes. */
static int decimal;    /* --decimal: offsets in decimal, not hex. */
static int assume_hex; /* --assume-hex: the input is a hex dump. */
static int advanced;   /* --advanced: parse and print in advanced format. */

static void
print_version(int with_help)
{
    fputs(PGM " (Libgcrypt) " GCRYPT_VERSION "\n"
          "gcrypt-openssl implementation; this program is in the public "
          "domain.\n"
          "There is NO WARRANTY, to the extent permitted by law.\n",
          stdout);

    if (with_help) {
        fputs("\n"
              "Usage: " PGM " [OPTIONS] [file]\n"
              "Debug tool for S-expressions\n"
              "\n"
              "  --decimal     Print offsets using decimal notation\n"
              "  --assume-hex  Assume input is a hex dump\n"
              "  --advanced    Print file in advanced format\n"
              "  --verbose     Show what we are doing\n"
              "  --version     Print version of the program and exit\n"
              "  --help        Display this help and exit\n",
              stdout);
    }
    exit(0);
}

static void
print_usage(void)
{
    fputs("usage: " PGM " [OPTIONS] [file]\n", stderr);
    fputs("       (use --help to display options)\n", stderr);
    exit(1);
}

static void
logit(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fputs(PGM ": ", stderr);
    vfprintf(stderr, format, ap);
    putc('\n', stderr);
    va_end(ap);
}

static int
is_space(int c)
{
    return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r'
           || c == '\n';
}

static int
is_digit(int c)
{
    return c >= '0' && c <= '9';
}

static int
is_hexdigit(int c)
{
    return is_digit(c) || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

static int
hexval(int c)
{
    if (c <= '9') {
        return c - '0';
    }
    if (c <= 'F') {
        return c - 'A' + 10;
    }
    return c - 'a' + 10;
}

/* Read the next input byte, decoding pairs of hex digits when the input
 * is a hex dump.  Whitespace between digits is skipped. */
static int
next_byte(FILE *fp)
{
    int c1, c2;

    if (!assume_hex) {
        return getc(fp);
    }

    do {
        c1 = getc(fp);
    } while (c1 != EOF && is_space(c1));

    if (c1 == EOF) {
        return EOF;
    }
    if (!is_hexdigit(c1)) {
        logit("non hex-digit encountered");
        return EOF;
    }

    do {
        c2 = getc(fp);
    } while (c2 != EOF && is_space(c2));

    if (c2 == EOF) {
        logit("error reading second hex nibble");
        return EOF;
    }
    if (!is_hexdigit(c2)) {
        logit("second hex nibble is not a hex-digit");
        return EOF;
    }
    return hexval(c1) * 16 + hexval(c2);
}

/* ------------------------------------------------------------------------
 * The hex dump.  Raw input bytes collect in a 16-byte line buffer that is
 * printed when full, at the end, or whenever a message needs to point at
 * the byte just read.  After such a message the bytes already shown on the
 * line are kept but blanked so the remainder of the line continues under
 * the right columns.
 * ---------------------------------------------------------------------- */

#define LINE_BYTES 16

static unsigned char line[LINE_BYTES];
static int line_len;             /* Bytes in line[]. */
static int line_skip;            /* Leading bytes already printed. */
static int line_printed;         /* Bytes shown on the last flushed line. */
static unsigned long line_offset; /* Input offset of line[0]. */

static void
flush_line(void)
{
    int i;

    if (!line_len) {
        return;
    }
    line_printed = 0;
    printf(decimal ? "%08lu " : "%08lx ", line_offset);

    for (i = 0; i < line_len; i++) {
        if (i == 8) {
            putchar(' ');
        }
        if (i < line_skip) {
            fputs("   ", stdout);
        } else {
            printf(" %02x", line[i]);
            line_offset++;
        }
        line_printed++;
    }
    for (; i < LINE_BYTES; i++) {
        if (i == 8) {
            putchar(' ');
        }
        fputs("   ", stdout);
    }
    fputs("  |", stdout);

    for (i = 0; i < line_len; i++) {
        if (i < line_skip) {
            putchar(' ');
        } else if (line[i] >= ' ' && line[i] <= '~' && line[i] != '|') {
            putchar(line[i]);
        } else {
            putchar('.');
        }
    }
    puts("|");
    line_len = 0;
    line_skip = 0;
}

static void
add_raw(int c)
{
    if (line_len >= LINE_BYTES) {
        flush_line();
    }
    line[line_len++] = (unsigned char)c;
}

/* Print a line with a caret under the last byte shown; with BOTH also
 * under its character in the right-hand column. */
static void
print_cursor(int both)
{
    int i;

    flush_line();
    printf("%8s ", "");

    for (i = 0; i < LINE_BYTES; i++) {
        if (i == 8) {
            putchar(' ');
        }
        if (i + 1 == line_printed) {
            fputs(" ^ ", stdout);

            if (!both) {
                break;
            }
        } else {
            fputs("   ", stdout);
        }
    }
    if (both) {
        fputs("   ", stdout);

        for (i = 0; i < line_printed - 1; i++) {
            putchar(' ');
        }
        putchar('^');
    }
    line_len = line_skip = line_printed;
}

static void
print_error(const char *text)
{
    print_cursor(1);
    printf("\n          Error: %s\n", text);
}

static void
print_state(const char *text)
{
    if (verbose) {
        print_cursor(0);
        puts(text);
    }
}

/* ------------------------------------------------------------------------
 * The scanner.  Mirrors the canonical/advanced S-expression syntax the
 * library accepts and reports what the reference tool reports.  Returns 0
 * on success, -1 on a read error.
 * ---------------------------------------------------------------------- */

static const char token_chars[] = "abcdefghijklmnopqrstuvwxyz"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "0123456789-./_:*+=";

enum state {
    ST_INIT,
    ST_NUMBER,
    ST_DATA,
    ST_STRING,
    ST_ESCAPE,
    ST_OCT_ESC,
    ST_HEX_ESC,
    ST_HEXFMT,
    ST_BASE64
};

static int
scan_and_dump(FILE *fp)
{
    enum state state = ST_INIT;
    int c;
    int in_token = 0;
    int hexcount = 0;
    int disphint = 0;
    int esc_len = 0;
    unsigned long datalen = 0;

    while ((c = next_byte(fp)) != EOF) {
        add_raw(c);

        switch (state) {
        case ST_INIT:
            if (in_token) {
                if (strchr(token_chars, c)) {
                    putchar(c);
                    continue;
                }
                in_token = 0;
            }
init_state:

            if (c == '(') {
                if (disphint) {
                    print_error("unmatched display hint");
                    disphint = 0;
                }
                print_state("open");
            } else if (c == ')') {
                if (disphint) {
                    print_error("unmatched display hint");
                    disphint = 0;
                }
                print_state("close");
            } else if (c == '"') {
                state = ST_STRING;
                print_state("beginstring");
            } else if (c == '#') {
                state = ST_HEXFMT;
                hexcount = 0;
                print_state("beginhex");
            } else if (c == '|') {
                state = ST_BASE64;
                print_state("beginbase64");
            } else if (c == '[') {
                if (disphint) {
                    print_error("nested display hint");
                }
                disphint = c;
            } else if (c == ']') {
                if (!disphint) {
                    print_error("no open display hint");
                }
                disphint = 0;
            } else if (is_digit(c)) {
                if (c == '0') {
                    print_error("zero prefixed length");
                }
                state = ST_NUMBER;
                datalen = (unsigned long)(c - '0');
            } else if (strchr(token_chars, c)) {
                putchar(c);
                in_token = 1;
            } else if (is_space(c)) {
                /* Nothing. */
            } else if (c == '{') {
                print_error("rescanning is not supported");
            } else if (c == '&' || c == '\\') {
                print_error("reserved punctuation detected");
            } else {
                print_error("bad character detected");
            }
            break;

        case ST_NUMBER:
            if (is_digit(c)) {
                unsigned long next = datalen * 10 + (unsigned long)(c - '0');

                if (next < datalen) {
                    print_error("overflow in data length");
                    state = ST_INIT;
                    datalen = 0;
                } else {
                    datalen = next;
                }
            } else if (c == ':') {
                if (!datalen) {
                    print_error("no data length");
                    state = ST_INIT;
                } else {
                    state = ST_DATA;
                    print_state("begindata");
                }
            } else if (c == '"' || c == '#' || c == '|') {
                /* The length prefix is optional for these forms. */
                goto init_state;
            } else {
                print_error("invalid length specification");
            }
            break;

        case ST_DATA:
            if (datalen) {
                datalen--;
            }
            if (!datalen) {
                state = ST_INIT;
                print_state("enddata");
            }
            break;

        case ST_STRING:
            if (c == '"') {
                print_state("endstring");
                state = ST_INIT;
            } else if (c == '\\') {
                state = ST_ESCAPE;
            }
            break;

        case ST_ESCAPE:
            switch (c) {
            case 'b':
            case 't':
            case 'v':
            case 'n':
            case 'f':
            case 'r':
            case '"':
            case '\'':
            case '\\':
            case '\r':
            case '\n':
                state = ST_STRING;
                break;

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
                state = ST_OCT_ESC;
                esc_len = 1;
                break;

            case 'x':
                state = ST_HEX_ESC;
                esc_len = 0;
                break;

            default:
                print_error("invalid escape sequence");
                state = ST_STRING;
                break;
            }
            break;

        case ST_OCT_ESC:
            if (esc_len < 3 && c >= '0' && c <= '7') {
                if (++esc_len == 3) {
                    state = ST_STRING;
                }
            } else {
                state = ST_STRING;
            }
            break;

        case ST_HEX_ESC:
            if (esc_len < 2 && is_hexdigit(c)) {
                if (++esc_len == 2) {
                    state = ST_STRING;
                }
            } else {
                state = ST_STRING;
            }
            break;

        case ST_HEXFMT:
            if (is_hexdigit(c)) {
                hexcount++;
            } else if (c == '#') {
                if (hexcount & 1) {
                    print_error("odd number of hex digits");
                }
                print_state("endhex");
                state = ST_INIT;
            } else if (!is_space(c)) {
                print_error("bad hex character");
            }
            break;

        case ST_BASE64:
            if (c == '|') {
                print_state("endbase64");
                state = ST_INIT;
            }
            break;
        }
    }
    flush_line();

    if (ferror(fp)) {
        logit("error reading input: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------------
 * --advanced: parse the whole input with the library and print it in
 * advanced format.  Returns 0 on success.
 * ---------------------------------------------------------------------- */

static int
parse_and_print_advanced(FILE *fp)
{
    unsigned char *buf = NULL;
    size_t len = 0, cap = 0;
    size_t erroff = 0;
    size_t outlen;
    char *out;
    gcry_sexp_t sexp;
    gcry_error_t err;
    int c;

    while ((c = next_byte(fp)) != EOF) {
        if (len == cap) {
            unsigned char *grown;

            cap = cap ? cap * 2 : 4096;
            grown = realloc(buf, cap);

            if (!grown) {
                free(buf);
                logit("out of memory");
                return -1;
            }
            buf = grown;
        }
        buf[len++] = (unsigned char)c;
    }
    if (ferror(fp)) {
        free(buf);
        logit("error reading input: %s", strerror(errno));
        return -1;
    }

    err = gcry_sexp_sscan(&sexp, &erroff, buf ? (const char *)buf : "", len);
    free(buf);

    if (err) {
        logit("parsing failed at offset %lu: %s", (unsigned long)erroff,
              gcry_strerror(err));
        return -1;
    }

    outlen = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    out = malloc(outlen);

    if (!out) {
        gcry_sexp_release(sexp);
        logit("out of memory");
        return -1;
    }
    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, out, outlen);
    fputs(out, stdout);
    free(out);
    gcry_sexp_release(sexp);
    return 0;
}

static int
process(FILE *fp)
{
    return advanced ? parse_and_print_advanced(fp) : scan_and_dump(fp);
}

int
main(int argc, char **argv)
{
    int rc = 0;

    if (argc) {
        argc--;
        argv++;
    }
    while (argc && argv[0][0] == '-' && argv[0][1] == '-') {
        if (!argv[0][2]) {
            argc--;
            argv++;
            break;
        } else if (!strcmp(*argv, "--version")) {
            print_version(0);
        } else if (!strcmp(*argv, "--help")) {
            print_version(1);
        } else if (!strcmp(*argv, "--verbose")) {
            verbose = 1;
        } else if (!strcmp(*argv, "--decimal")) {
            decimal = 1;
        } else if (!strcmp(*argv, "--assume-hex")) {
            assume_hex = 1;
        } else if (!strcmp(*argv, "--advanced")) {
            advanced = 1;
        } else {
            print_usage();
        }
        argc--;
        argv++;
    }

    if (advanced) {
        if (!gcry_check_version(GCRYPT_VERSION)) {
            logit("libgcrypt is too old (need %s, have %s)", GCRYPT_VERSION,
                  gcry_check_version(NULL));
            return 1;
        }
        gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    }

    if (!argc) {
        rc = process(stdin) ? 1 : 0;
    } else {
        for (; argc; argc--, argv++) {
            FILE *fp = fopen(*argv, "rb");

            if (!fp) {
                logit("can't open `%s': %s", *argv, strerror(errno));
                rc = 1;
                continue;
            }
            if (process(fp)) {
                rc = 1;
            }
            fclose(fp);
        }
    }
    return rc;
}
