/* mpicalc - RPN calculator on gcry_mpi_t values.
 *
 * Command-line compatible with the mpicalc program that ships with the
 * reference Libgcrypt: numbers are hexadecimal, optionally prefixed with
 * '-', operators are single characters (or "++" and "--") separated by
 * blanks, and '?' prints the operator table.  Two differences: "--" really
 * decrements (the reference tool's is a no-op), and the version banner
 * names this implementation.
 *
 * This file is in the public domain.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#define MPICALC_VERSION "2.0"
#define NEED_LIBGCRYPT_VERSION "1.6.0"

#define STACKSIZE 500
static gcry_mpi_t stack[STACKSIZE];
static int stackidx;

static int
underflow(int needed)
{
    if (stackidx < needed) {
        fputs("stack underflow\n", stderr);
        return 1;
    }
    return 0;
}

static gcry_mpi_t
top(int depth)
{
    return stack[stackidx - 1 - depth];
}

static int
scan_mpi(gcry_mpi_t dest, const char *text)
{
    gcry_mpi_t val;
    gcry_error_t err;

    err = gcry_mpi_scan(&val, GCRYMPI_FMT_HEX, text, 0, NULL);

    if (err) {
        fprintf(stderr, "scanning input failed: %s\n", gcry_strerror(err));
        return -1;
    }
    gcry_mpi_set(dest, val);
    gcry_mpi_release(val);
    return 0;
}

static void
print_mpi(gcry_mpi_t a)
{
    unsigned char *buf;
    gcry_error_t err;

    err = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &buf, NULL, a);

    if (err) {
        fprintf(stderr, "[error printing number: %s]\n", gcry_strerror(err));
        return;
    }
    fputs((char *)buf, stdout);
    gcry_free(buf);
}

/* Binary operators: [0] := [1] op [0], dropping one item. */

static void
do_add(void)
{
    if (!underflow(2)) {
        gcry_mpi_add(top(1), top(1), top(0));
        stackidx--;
    }
}

static void
do_sub(void)
{
    if (!underflow(2)) {
        gcry_mpi_sub(top(1), top(1), top(0));
        stackidx--;
    }
}

static void
do_mul(void)
{
    if (!underflow(2)) {
        gcry_mpi_mul(top(1), top(1), top(0));
        stackidx--;
    }
}

static void
do_div(void)
{
    if (!underflow(2)) {
        /* Floor division, as the reference tool's mpi_fdiv. */
        gcry_mpi_div(top(1), NULL, top(1), top(0), -1);
        stackidx--;
    }
}

static void
do_rem(void)
{
    if (!underflow(2)) {
        gcry_mpi_mod(top(1), top(1), top(0));
        stackidx--;
    }
}

static void
do_inv(void)
{
    if (!underflow(2)) {
        gcry_mpi_t r = gcry_mpi_new(0);

        gcry_mpi_invm(r, top(1), top(0));
        gcry_mpi_set(top(1), r);
        gcry_mpi_release(r);
        stackidx--;
    }
}

static void
do_gcd(void)
{
    if (!underflow(2)) {
        gcry_mpi_t r = gcry_mpi_new(0);

        gcry_mpi_gcd(r, top(1), top(0));
        gcry_mpi_set(top(1), r);
        gcry_mpi_release(r);
        stackidx--;
    }
}

/* Ternary operators: [0] := [2] op [1] mod [0], dropping two items. */

static void
do_mulm(void)
{
    if (!underflow(3)) {
        gcry_mpi_mulm(top(2), top(2), top(1), top(0));
        stackidx -= 2;
    }
}

static void
do_powm(void)
{
    if (!underflow(3)) {
        gcry_mpi_t r = gcry_mpi_new(0);

        gcry_mpi_powm(r, top(2), top(1), top(0));
        gcry_mpi_release(top(2));
        stack[stackidx - 3] = r;
        stackidx -= 2;
    }
}

/* Unary operators on [0]. */

static void
do_inc(void)
{
    if (!underflow(1)) {
        gcry_mpi_add_ui(top(0), top(0), 1);
    }
}

static void
do_dec(void)
{
    if (!underflow(1)) {
        gcry_mpi_sub_ui(top(0), top(0), 1);
    }
}

static void
do_lshift(void)
{
    if (!underflow(1)) {
        gcry_mpi_lshift(top(0), top(0), 1);
    }
}

static void
do_rshift(void)
{
    if (!underflow(1)) {
        gcry_mpi_rshift(top(0), top(0), 1);
    }
}

static void
do_nbits(void)
{
    if (!underflow(1)) {
        gcry_mpi_set_ui(top(0), gcry_mpi_get_nbits(top(0)));
    }
}

static void
do_primecheck(void)
{
    gcry_error_t err;

    if (underflow(1)) {
        return;
    }
    err = gcry_prime_check(top(0), 0);
    gcry_mpi_set_ui(top(0), !err);

    if (err && gcry_err_code(err) != GPG_ERR_NO_PRIME) {
        fprintf(stderr, "checking prime failed: %s\n", gcry_strerror(err));
    }
}

/* Stack manipulation. */

static void
do_drop(void)
{
    if (!underflow(1)) {
        gcry_mpi_release(top(0));
        stack[stackidx - 1] = NULL;
        stackidx--;
    }
}

static void
do_dup(void)
{
    if (underflow(1)) {
        return;
    }
    if (stackidx >= STACKSIZE) {
        fputs("stack overflow\n", stderr);
        return;
    }
    gcry_mpi_release(stack[stackidx]);
    stack[stackidx] = gcry_mpi_copy(top(0));
    stackidx++;
}

static void
do_swap(void)
{
    if (!underflow(2)) {
        gcry_mpi_t tmp = top(0);

        stack[stackidx - 1] = top(1);
        stack[stackidx - 2] = tmp;
    }
}

static void
do_clear(void)
{
    int i;

    for (i = 0; i < stackidx; i++) {
        gcry_mpi_release(stack[i]);
        stack[i] = NULL;
    }
    stackidx = 0;
}

static void
do_print_top(void)
{
    if (!stackidx) {
        puts("stack is empty");
    } else {
        print_mpi(top(0));
        putchar('\n');
    }
}

static void
do_print_stack(void)
{
    int i;

    for (i = stackidx - 1; i >= 0; i--) {
        printf("[%2d]: ", i);
        print_mpi(stack[i]);
        putchar('\n');
    }
}

/* Push the number in TEXT (with its 0x prefix and optional sign). */
static void
push_number(const char *text)
{
    if (stackidx >= STACKSIZE) {
        fputs("stack overflow\n", stderr);
        return;
    }
    if (!stack[stackidx]) {
        stack[stackidx] = gcry_mpi_new(0);
    }
    if (scan_mpi(stack[stackidx], text)) {
        fputs("invalid number\n", stderr);
    } else {
        stackidx++;
    }
}

static void
print_help(void)
{
    fputs("+   add           [0] := [1] + [0]          {-1}\n"
          "-   subtract      [0] := [1] - [0]          {-1}\n"
          "*   multiply      [0] := [1] * [0]          {-1}\n"
          "/   divide        [0] := [1] / [0]          {-1}\n"
          "%   modulo        [0] := [1] % [0]          {-1}\n"
          "<   left shift    [0] := [0] << 1           {0}\n"
          ">   right shift   [0] := [0] >> 1           {0}\n"
          "++  increment     [0] := [0]++              {0}\n"
          "--  decrement     [0] := [0]--              {0}\n"
          "m   multiply mod  [0] := [2] * [1] mod [0]  {-2}\n"
          "^   power mod     [0] := [2] ^ [1] mod [0]  {-2}\n"
          "I   inverse mod   [0] := [1]^-1 mod [0]     {-1}\n"
          "G   gcd           [0] := gcd([1],[0])       {-1}\n"
          "i   remove item   [0] := [1]                {-1}\n"
          "d   dup item      [-1] := [0]               {+1}\n"
          "r   reverse       [0] := [1], [1] := [0]    {0}\n"
          "b   # of bits     [0] := nbits([0])         {0}\n"
          "P   prime check   [0] := is_prime([0])?1:0  {0}\n"
          "c   clear stack\n"
          "p   print top item\n"
          "f   print the stack\n"
          "#   ignore until end of line\n"
          "?   print this help\n",
          stdout);
}

/* Read a byte of input, skipping non-ASCII bytes with one notice. */
static int
next_char(void)
{
    static int warned;
    int c;

    for (;;) {
        c = getc(stdin);

        if (c == EOF || !(c & 0x80)) {
            return c;
        }
        if (!warned) {
            warned = 1;
            fputs("note: Non ASCII characters are ignored\n", stderr);
        }
    }
}

int
main(int argc, char **argv)
{
    const char *pgm = "mpicalc";
    int last_argc = -1;
    int print_config = 0;
    int c;
    char number[4096];
    size_t numlen = 0;
    enum { WAITING, IN_NUMBER, IN_COMMENT } state = WAITING;

    if (argc) {
        const char *slash = strrchr(*argv, '/');

        pgm = slash ? slash + 1 : *argv;
        argc--;
        argv++;
    }

    while (argc && last_argc != argc) {
        last_argc = argc;

        if (!strcmp(*argv, "--")) {
            argc--;
            argv++;
            break;
        } else if (!strcmp(*argv, "--version") || !strcmp(*argv, "--help")) {
            printf("%s " MPICALC_VERSION "\n"
                   "libgcrypt %s (gcrypt-openssl)\n"
                   "This program is in the public domain.\n"
                   "There is NO WARRANTY, to the extent permitted by law.\n"
                   "\n"
                   "Syntax: mpicalc [options]\n"
                   "Simple interactive big integer RPN calculator\n"
                   "\n"
                   "Options:\n"
                   "  --version           print version information\n"
                   "  --print-config      print the Libgcrypt config\n"
                   "  --disable-hwf NAME  disable feature NAME\n",
                   pgm, gcry_check_version(NULL));
            return 0;
        } else if (!strcmp(*argv, "--print-config")) {
            argc--;
            argv++;
            print_config = 1;
        } else if (!strcmp(*argv, "--disable-hwf")) {
            argc--;
            argv++;

            if (argc) {
                if (gcry_control(GCRYCTL_DISABLE_HWF, *argv, NULL)) {
                    fprintf(stderr,
                            "%s: unknown hardware feature `%s'"
                            " - option ignored\n",
                            pgm, *argv);
                }
                argc--;
                argv++;
            }
        }
    }

    if (argc) {
        fprintf(stderr, "usage: %s [options]  (--help for help)\n", pgm);
        return 1;
    }

    if (!gcry_check_version(NEED_LIBGCRYPT_VERSION)) {
        fprintf(stderr, "%s: Libgcrypt is too old (need %s, have %s)\n", pgm,
                NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
        return 1;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (print_config) {
        gcry_control(GCRYCTL_PRINT_CONFIG, stdout);
        return 0;
    }

    while ((c = next_char()) != EOF) {
        switch (state) {
        case WAITING:
            if (isdigit(c)) {
                state = IN_NUMBER;
                ungetc(c, stdin);
                strcpy(number, "0x");
                numlen = 2;
            } else if (isspace(c)) {
                /* Nothing. */
            } else {
                switch (c) {
                case '#':
                    state = IN_COMMENT;
                    break;

                case '+':
                    if ((c = next_char()) == '+') {
                        do_inc();
                    } else {
                        ungetc(c, stdin);
                        do_add();
                    }
                    break;

                case '-':
                    if ((c = next_char()) == '-') {
                        do_dec();
                    } else if (isxdigit(c)) {
                        state = IN_NUMBER;
                        ungetc(c, stdin);
                        strcpy(number, "-0x");
                        numlen = 3;
                    } else {
                        ungetc(c, stdin);
                        do_sub();
                    }
                    break;

                case '*':
                    do_mul();
                    break;

                case 'm':
                    do_mulm();
                    break;

                case '/':
                    do_div();
                    break;

                case '%':
                    do_rem();
                    break;

                case '^':
                    do_powm();
                    break;

                case '<':
                    do_lshift();
                    break;

                case '>':
                    do_rshift();
                    break;

                case 'I':
                    do_inv();
                    break;

                case 'G':
                    do_gcd();
                    break;

                case 'i':
                    do_drop();
                    break;

                case 'd':
                    do_dup();
                    break;

                case 'r':
                    do_swap();
                    break;

                case 'b':
                    do_nbits();
                    break;

                case 'P':
                    do_primecheck();
                    break;

                case 'c':
                    do_clear();
                    break;

                case 'p':
                    do_print_top();
                    break;

                case 'f':
                    do_print_stack();
                    break;

                case '?':
                    print_help();
                    break;

                default:
                    fputs("invalid operator\n", stderr);
                    break;
                }
            }
            break;

        case IN_NUMBER:
            if (!isxdigit(c)) {
                state = WAITING;
                ungetc(c, stdin);

                if (numlen < sizeof number) {
                    number[numlen] = '\0';
                }
                push_number(number);
            } else if (numlen < sizeof number - 1) {
                number[numlen++] = (char)c;
            } else if (numlen == sizeof number - 1) {
                number[numlen] = '\0';
                fputs("input too large - truncated\n", stderr);
                numlen++;
            }
            break;

        case IN_COMMENT:
            if (c == '\n') {
                state = WAITING;
            }
            break;
        }
    }

    do_clear();
    return 0;
}
