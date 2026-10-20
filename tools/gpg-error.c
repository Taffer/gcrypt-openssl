/* gpg-error - map error numbers to names and descriptions and back.
 *
 * Command-line compatible with the gpg-error program that ships with the
 * reference libgpg-error: the same commands (lib-version, list, defines,
 * fopen, chdir, mkdir, fconcat), options (--quiet, --desc, --openmode)
 * and output formats.  Error numbers may be given in decimal or hex, or
 * as a symbolic name (GPG_ERR_BAD_KEY, BAD_KEY, EPERM, GPG_ERR_SOURCE_GPG)
 * or a description ("Bad session key").  The names come from gcrypt.h at
 * build time (gpg-error-names.h); the descriptions come from the library
 * so that they always agree with what gcry_strerror reports.
 *
 * --desc prints the longer explanation of a code from libgpg-error's
 * errorref.txt when that file is installed; it is looked up in the
 * directory GPG_ERROR_ERRORREF_DIR, the usual /usr/share/libgpg-error,
 * or the file named by the GPG_ERROR_ERRORREF environment variable.
 *
 * This file is in the public domain.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gcrypt.h>

#include "gpg-error-names.h"

#define PGM "gpg-error"

#ifndef GPG_ERROR_ERRORREF_DIR
    #define GPG_ERROR_ERRORREF_DIR "/usr/share/libgpg-error"
#endif

#define SOURCE_SHIFT 24
#define SOURCE_MASK 127u
#define CODE_MASK 65535u

static int opt_quiet;
static int opt_desc;
static const char *opt_openmode = "r";

static int
to_upper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}

static int
strcasecmp_ascii(const char *a, const char *b)
{
    while (*a && to_upper((unsigned char) * a) == to_upper((unsigned char) * b)) {
        a++;
        b++;
    }
    return to_upper((unsigned char) * a) - to_upper((unsigned char) * b);
}

static const char *
source_name(unsigned int src)
{
    size_t i;

    for (i = 0; i < sizeof source_names / sizeof source_names[0]; i++) {
        if (source_names[i].value == src) {
            return source_names[i].name;
        }
    }
    return NULL;
}

static const char *
code_name(unsigned int code)
{
    size_t i;

    for (i = 0; i < sizeof code_names / sizeof code_names[0]; i++) {
        if (code_names[i].value == code) {
            return code_names[i].name;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* errorref.txt                                                        */
/* ------------------------------------------------------------------ */

static char *errorref;      /* The whole file, or NULL. */
static int errorref_loaded;

static char *
read_whole_file(const char *name)
{
    FILE *fp = fopen(name, "r");
    char *data = NULL;
    size_t len = 0, cap = 0;

    if (!fp) {
        return NULL;
    }
    for (;;) {
        size_t n;

        if (len + 4096 + 1 > cap) {
            char *p;

            cap = cap ? cap * 2 : 65536;
            p = realloc(data, cap);

            if (!p) {
                free(data);
                fclose(fp);
                return NULL;
            }
            data = p;
        }
        n = fread(data + len, 1, cap - len - 1, fp);
        len += n;

        if (!n) {
            break;
        }
    }
    fclose(fp);

    if (data) {
        data[len] = 0;
    }
    return data;
}

static void
load_errorref(void)
{
    const char *env = getenv("GPG_ERROR_ERRORREF");

    errorref_loaded = 1;

    if (env && *env) {
        errorref = read_whole_file(env);
        return;
    }
    errorref = read_whole_file(GPG_ERROR_ERRORREF_DIR "/errorref.txt");

    if (!errorref) {
        errorref = read_whole_file("/usr/share/libgpg-error/errorref.txt");
    }
}

/* Print the explanation of the error code NAME: the lines of errorref.txt
 * that follow its entry, up to the next entry.  Without one, or without
 * the file, a single empty line is printed, as the reference tool does. */
static void
print_description(const char *name)
{
    size_t namelen = strlen(name);
    const char *p;

    if (!errorref_loaded) {
        load_errorref();
    }
    for (p = errorref; p && *p;) {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);

        if (linelen > namelen && !memcmp(p, name, namelen)
            && (p[namelen] == ' ' || p[namelen] == '\t')) {
            const char *body = eol ? eol + 1 : p + linelen;
            const char *q = body;

            /* The entry ends where the next one starts. */
            while (*q) {
                if (!strncmp(q, "GPG_ERR_", 8)) {
                    break;
                }
                q = strchr(q, '\n');

                if (!q) {
                    q = body + strlen(body);
                    break;
                }
                q++;
            }
            fwrite(body, 1, (size_t)(q - body), stdout);
            return;
        }
        if (!eol) {
            break;
        }
        p = eol + 1;
    }
    putchar('\n');
}

/* ------------------------------------------------------------------ */
/* Looking up and printing error values                                */
/* ------------------------------------------------------------------ */

static void
print_value(unsigned int value)
{
    unsigned int src = (value >> SOURCE_SHIFT) & SOURCE_MASK;
    unsigned int code = value & CODE_MASK;
    const char *sname = source_name(src);
    const char *cname = code_name(code);

    printf("%u = (%u, %u) = (%s, %s) = (%s, %s)\n", value, src, code,
           sname ? sname : "-", cname ? cname : "-",
           gcry_strsource((gcry_error_t)value),
           gcry_strerror((gcry_error_t)value));

    if (opt_desc && cname) {
        print_description(cname);
    }
}

/* Turn the command line word S into an error value: a number, a source
 * or code name (the GPG_ERR_ prefix of a code is optional), or the
 * description of a source or code.  Returns 0 if nothing matches.  As in
 * the reference tool, a number followed by anything else counts as 0. */
static int
value_from_string(const char *s, unsigned int *value)
{
    char *tail;
    unsigned long n;
    size_t i;

    errno = 0;
    n = strtoul(s, &tail, 0);

    if (tail != s && *tail) {
        *value = 0;
        return 1;
    }
    if (!(tail == s && *s) && n <= 0xffffffffUL) {
        *value = (unsigned int)n;
        return 1;
    }

    for (i = 0; i < sizeof source_names / sizeof source_names[0]; i++) {
        if (!strcasecmp_ascii(source_names[i].name, s)) {
            *value = source_names[i].value << SOURCE_SHIFT;
            return 1;
        }
    }
    for (i = 0; i < sizeof code_names / sizeof code_names[0]; i++) {
        if (!strcasecmp_ascii(code_names[i].name, s)
            || !strcasecmp_ascii(code_names[i].name + 8, s)) {
            *value = code_names[i].value;
            return 1;
        }
    }
    for (i = 0; i < sizeof source_names / sizeof source_names[0]; i++) {
        unsigned int v = source_names[i].value << SOURCE_SHIFT;

        if (!strcasecmp_ascii(gcry_strsource((gcry_error_t)v), s)) {
            *value = v;
            return 1;
        }
    }
    for (i = 0; i < sizeof code_names / sizeof code_names[0]; i++) {
        unsigned int v = code_names[i].value;

        if (!strcasecmp_ascii(gcry_strerror((gcry_error_t)v), s)) {
            *value = v;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static void
cmd_list(void)
{
    size_t i;

    for (i = 0; i < sizeof source_names / sizeof source_names[0]; i++) {
        unsigned int v = source_names[i].value << SOURCE_SHIFT;

        printf("%u = (%u, -) = (%s, -) = (%s, -)\n", v, source_names[i].value,
               source_names[i].name, gcry_strsource((gcry_error_t)v));

        if (opt_desc) {
            putchar('\n');
        }
    }
    for (i = 0; i < sizeof code_names / sizeof code_names[0]; i++) {
        unsigned int v = code_names[i].value;

        printf("%u = (-, %u) = (-, %s) = (-, %s)\n", v, v, code_names[i].name,
               gcry_strerror((gcry_error_t)v));

        if (opt_desc) {
            print_description(code_names[i].name);
        }
    }
}

static void
cmd_defines(void)
{
    size_t i;

    for (i = 0; i < sizeof source_names / sizeof source_names[0]; i++) {
        printf("#define %-24s %2u\n", source_names[i].name,
               source_names[i].value);
    }
    for (i = 0; i < sizeof code_names / sizeof code_names[0]; i++) {
        printf("#define %-32s %5u\n", code_names[i].name, code_names[i].value);
    }
}

static void
cmd_lib_version(void)
{
    const char *v = gcry_check_version(NULL);

    printf("Version from header: %s (0x%06x)\n", GCRYPT_VERSION,
           (unsigned int)GCRYPT_VERSION_NUMBER);
    printf("Version from binary: %s\n", v ? v : "?");
    printf("Copyright blurb ...: This is gcrypt-openssl %s - the Libgcrypt "
           "API on OpenSSL\n"
           "                     This library is in the public domain.\n",
           v ? v : GCRYPT_VERSION);
}

static int
cmd_fopen(const char *name)
{
    FILE *fp = fopen(name, opt_openmode);

    if (!fp) {
        fprintf(stderr, PGM ": error opening '%s': %s\n", name,
                gcry_strerror(gcry_error_from_errno(errno)));
        return 1;
    }
    fclose(fp);

    if (!opt_quiet) {
        printf("success opening '%s'\n", name);
    }
    return 0;
}

static int
cmd_chdir(const char *name)
{
    if (chdir(name)) {
        fprintf(stderr, PGM ": error chdir '%s': %s\n", name,
                gcry_strerror(gcry_error_from_errno(errno)));
        return 1;
    }
    if (!opt_quiet) {
        printf("success chdir '%s'\n", name);
    }
    return 0;
}

static int
cmd_mkdir(const char *name)
{
    if (mkdir(name, S_IRWXU)) {
        fprintf(stderr, PGM ": error mkdir '%s': %s\n", name,
                gcry_strerror(gcry_error_from_errno(errno)));
        return 1;
    }
    if (!opt_quiet) {
        printf("success mkdir '%s'\n", name);
    }
    return 0;
}

/* Join the parts with slashes; flag bit 1 makes the result absolute by
 * prefixing the current directory. */
static int
cmd_fconcat(int argc, char **argv)
{
    long flags;
    int i;

    if (argc < 2) {
        fputs("Usage: " PGM " fconcat <flags> <part1> [<part2> ...]\n\n"
              "       For <flags> see GPGRT_FCONCAT_*\n",
              stderr);
        return 2;
    }
    flags = strtol(argv[0], NULL, 0);

    if ((flags & 1) && argv[1][0] != '/') {
        size_t cap = 256;
        char *cwd = NULL;

        for (;;) {
            char *p = realloc(cwd, cap);

            if (!p) {
                free(cwd);
                fprintf(stderr, PGM ": out of memory\n");
                return 1;
            }
            cwd = p;

            if (getcwd(cwd, cap)) {
                break;
            }
            if (errno != ERANGE) {
                fprintf(stderr, PGM ": error getting current directory: %s\n",
                        gcry_strerror(gcry_error_from_errno(errno)));
                free(cwd);
                return 1;
            }
            cap *= 2;
        }
        printf("%s/", cwd);
        free(cwd);
    }
    for (i = 1; i < argc; i++) {
        printf("%s%s", i > 1 ? "/" : "", argv[i]);
    }
    putchar('\n');
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

/* The usage line always goes to stderr, as in the reference tool, even
 * as part of --help. */
static void
usage_line(void)
{
    fputs("Usage: " PGM " [commands] [options] error-numbers\n", stderr);
}

static void
help(void)
{
    fputs(PGM " (Libgcrypt) " GCRYPT_VERSION "\n"
          "gcrypt-openssl implementation; this program is in the public "
          "domain.\n"
          "There is NO WARRANTY, to the extent permitted by law.\n",
          stdout);
    usage_line();
    fputs("\nMap error numbers to strings and vice versa.\n\n"
          "Commands:\n"
          " \n"
          "     lib-version     Print library version\n"
          "     list            Print all error codes\n"
          "     defines         Print all error codes as #define lines\n"
          "     fopen           Open the given file\n"
          "     chdir           Try a chdir to the given directory\n"
          "     mkdir           Create the given directory\n"
          "     fconcat         Construct a file name\n"
          "\nOptions:\n"
          " \n"
          " -q, --quiet         Silence some output\n"
          " -d, --desc          Print with error description\n"
          "     --openmode      Specify the open mode\n"
          "\nPlease report bugs to the gcrypt-openssl project.\n",
          stdout);
}

enum command {
    CMD_NONE,
    CMD_LIB_VERSION,
    CMD_LIST,
    CMD_DEFINES,
    CMD_FOPEN,
    CMD_CHDIR,
    CMD_MKDIR,
    CMD_FCONCAT
};

static enum command
command_from_name(const char *name) {
    static const struct {
        const char *name;
        enum command cmd;
    } table[] = {
        { "lib-version", CMD_LIB_VERSION }, { "list", CMD_LIST },
        { "defines", CMD_DEFINES },         { "fopen", CMD_FOPEN },
        { "chdir", CMD_CHDIR },             { "mkdir", CMD_MKDIR },
        { "fconcat", CMD_FCONCAT },
    };
    size_t i;

    for (i = 0; i < sizeof table / sizeof table[0]; i++)
    {
        if (!strcmp(table[i].name, name)) {
            return table[i].cmd;
        }
    }
    return CMD_NONE;
}

static void
invalid_option(const char *opt)
{
    fprintf(stderr, PGM ": invalid option \"%s\"\n", opt);
    usage_line();
    exit(2);
}

int
main(int argc, char **argv)
{
    enum command cmd = CMD_NONE;
    int status = 0;
    int i;

    argc--;
    argv++;

    /* Options and commands come first; the first word that is neither
     * starts the error numbers, after which nothing is parsed. */
    while (argc) {
        const char *a = *argv;

        if (!strcmp(a, "--")) {
            argc--;
            argv++;
            break;
        } else if (a[0] == '-' && a[1] == '-') {
            enum command c = command_from_name(a + 2);

            if (c != CMD_NONE) {
                cmd = c;
            } else if (!strcmp(a, "--help")) {
                help();
                return 0;
            } else if (!strcmp(a, "--version")) {
                fputs(PGM " (Libgcrypt) " GCRYPT_VERSION "\n"
                      "gcrypt-openssl implementation; this program is in "
                      "the public domain.\n"
                      "There is NO WARRANTY, to the extent permitted by "
                      "law.\n",
                      stdout);
                return 0;
            } else if (!strcmp(a, "--quiet")) {
                opt_quiet = 1;
            } else if (!strcmp(a, "--desc")) {
                opt_desc = 1;
            } else if (!strcmp(a, "--openmode")) {
                if (argc < 2) {
                    fprintf(stderr,
                            PGM ": missing argument for option \"%s\"\n", a);
                    usage_line();
                    return 2;
                }
                opt_openmode = argv[1];
                argc--;
                argv++;
            } else if (!strcmp(a, "--locale")) {
                fputs(PGM ": this command is only useful on Windows\n",
                      stderr);
                return 0;
            } else {
                invalid_option(a);
            }
        } else if (a[0] == '-' && a[1]) {
            const char *p;

            for (p = a + 1; *p; p++) {
                if (*p == 'q') {
                    opt_quiet = 1;
                } else if (*p == 'd') {
                    opt_desc = 1;
                } else if (*p == 'h') {
                    help();
                    return 0;
                } else {
                    invalid_option(a);
                }
            }
        } else if (cmd == CMD_NONE && command_from_name(a) != CMD_NONE) {
            cmd = command_from_name(a);
        } else {
            break;
        }
        argc--;
        argv++;
    }

    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, PGM ": libgcrypt is too old (need %s, have %s)\n",
                GCRYPT_VERSION, gcry_check_version(NULL));
        return 2;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    switch (cmd) {
    case CMD_LIB_VERSION:
    case CMD_LIST:
    case CMD_DEFINES:
        if (argc) {
            usage_line();
            return 2;
        }
        if (cmd == CMD_LIB_VERSION) {
            cmd_lib_version();
        } else if (cmd == CMD_LIST) {
            cmd_list();
        } else {
            cmd_defines();
        }
        break;

    case CMD_FOPEN:
    case CMD_CHDIR:
    case CMD_MKDIR:
        if (argc != 1) {
            usage_line();
            return 2;
        }
        if (cmd == CMD_FOPEN) {
            status = cmd_fopen(argv[0]);
        } else if (cmd == CMD_CHDIR) {
            status = cmd_chdir(argv[0]);
        } else {
            status = cmd_mkdir(argv[0]);
        }
        break;

    case CMD_FCONCAT:
        status = cmd_fconcat(argc, argv);
        break;

    case CMD_NONE:
    default:
        if (!argc) {
            usage_line();
            return 2;
        }
        for (i = 0; i < argc; i++) {
            unsigned int value;

            if (!value_from_string(argv[i], &value)) {
                fprintf(stderr, PGM ": warning: could not recognize %s\n",
                        argv[i]);
                status = 1;
            } else {
                print_value(value);
            }
        }
        break;
    }

    if (fflush(stdout) || ferror(stdout)) {
        fprintf(stderr, PGM ": error writing output: %s\n", strerror(errno));
        return 1;
    }
    return status;
}
