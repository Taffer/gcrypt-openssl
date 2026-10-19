#define _POSIX_C_SOURCE 200809L

#include <gcrypt.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdarg.h>
#include <stdlib.h>

#include "test_common.h"

/* The upstream header marks the log handler setter deprecated; it is
 * still the only way to observe the logger. */
#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* Run FN in a child and report how it ended: its exit code, or 1000 plus
 * the signal number.  The fatal paths abort, so they cannot run in the
 * test process itself. */
static int
run_child(void (*fn)(void))
{
    pid_t pid;
    int status = 0;

    fflush(NULL); /* The child's exit() must not replay our buffers. */
    pid = fork();

    if (pid == 0) {
        if (!freopen("/dev/null", "w", stderr)) {
            test_child_exit(99);
        }

        fn();
        test_child_exit(0);
    }

    if (pid < 0) {
        return -1;
    }

    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        return 1000 + WTERMSIG(status);
    }

    return -1;
}

static gcry_mpi_t
from_hex(const char *hex)
{
    gcry_mpi_t m = NULL;

    if (gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, hex, 0, NULL)) {
        return NULL;
    }

    return m;
}

/* Hex representation (caller frees with gcry_free). */
static char *
to_hex(gcry_mpi_t m)
{
    unsigned char *buf = NULL;

    if (gcry_mpi_aprint(GCRYMPI_FMT_HEX, &buf, NULL, m)) {
        return NULL;
    }

    return (char *)buf;
}

TEST(basic_values)
{
    gcry_mpi_t a = gcry_mpi_new(0);
    gcry_mpi_t b;
    unsigned int ui = 0;

    ASSERT_NOT_NULL(a);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 0));
    ASSERT_EQ(0, gcry_mpi_get_nbits(a));
    gcry_mpi_set_ui(a, 1000);
    ASSERT_EQ(10, gcry_mpi_get_nbits(a));
    ASSERT_OK(gcry_mpi_get_ui(&ui, a));
    ASSERT_EQ(1000, ui);
    ASSERT_TRUE(gcry_mpi_cmp_ui(a, 999) > 0);
    ASSERT_TRUE(gcry_mpi_cmp_ui(a, 1001) < 0);

    b = gcry_mpi_copy(a);
    ASSERT_EQ(0, gcry_mpi_cmp(a, b));
    gcry_mpi_add_ui(b, b, 1);
    ASSERT_TRUE(gcry_mpi_cmp(a, b) < 0);
    gcry_mpi_swap(a, b);
    ASSERT_TRUE(gcry_mpi_cmp(a, b) > 0);

    gcry_mpi_neg(a, a);
    ASSERT_TRUE(gcry_mpi_is_neg(a));
    ASSERT_ERR(GPG_ERR_ERANGE, gcry_mpi_get_ui(&ui, a));
    gcry_mpi_abs(a);
    ASSERT_FALSE(gcry_mpi_is_neg(a));

    gcry_mpi_set(b, a);
    ASSERT_EQ(0, gcry_mpi_cmp(a, b));
    gcry_mpi_snatch(b, a); /* a is consumed */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 1001));
    gcry_mpi_release(b);

    a = gcry_mpi_set_ui(NULL, 0xffffffffUL);
    ASSERT_OK(gcry_mpi_get_ui(&ui, a));
    ASSERT_EQ(0xffffffffUL, ui);
    gcry_mpi_mul_ui(a, a, 2);
    ASSERT_ERR(GPG_ERR_ERANGE, gcry_mpi_get_ui(&ui, a));
    gcry_mpi_release(a);
}

TEST(arithmetic)
{
    gcry_mpi_t a = gcry_mpi_set_ui(NULL, 7);
    gcry_mpi_t b = gcry_mpi_set_ui(NULL, 3);
    gcry_mpi_t m = gcry_mpi_set_ui(NULL, 5);
    gcry_mpi_t r = gcry_mpi_new(0);
    gcry_mpi_t q = gcry_mpi_new(0);

    gcry_mpi_add(r, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 10));
    gcry_mpi_sub(r, b, a);
    ASSERT_TRUE(gcry_mpi_is_neg(r));
    gcry_mpi_abs(r);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 4));
    gcry_mpi_mul(r, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 21));
    gcry_mpi_sub_ui(r, r, 1);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 20));
    gcry_mpi_mul_2exp(r, b, 4);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 48));

    gcry_mpi_addm(r, a, b, m); /* 10 mod 5 */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 0));
    gcry_mpi_subm(r, b, a, m); /* -4 mod 5 = 1 */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_mulm(r, a, b, m); /* 21 mod 5 = 1 */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));

    /* Truncating division: 7 / 3 = 2 rem 1; -7 / 3 = -2 rem -1. */
    gcry_mpi_div(q, r, a, b, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(q, 2));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_neg(a, a);
    gcry_mpi_div(q, r, a, b, 0);
    ASSERT_TRUE(gcry_mpi_is_neg(q));
    ASSERT_TRUE(gcry_mpi_is_neg(r));
    /* Flooring division: -7 / 3 = -3 rem 2. */
    gcry_mpi_div(q, r, a, b, -1);
    gcry_mpi_abs(q);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(q, 3));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));
    gcry_mpi_mod(r, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));
    gcry_mpi_abs(a);
    gcry_mpi_div(NULL, r, a, b, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_div(q, NULL, a, b, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(q, 2));

    /* powm: 2^10 mod 1000 = 24 */
    gcry_mpi_set_ui(a, 2);
    gcry_mpi_set_ui(b, 10);
    gcry_mpi_set_ui(m, 1000);
    gcry_mpi_powm(r, a, b, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 24));

    /* gcd / invm */
    gcry_mpi_set_ui(a, 12);
    gcry_mpi_set_ui(b, 18);
    ASSERT_EQ(0, gcry_mpi_gcd(r, a, b));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 6));
    gcry_mpi_set_ui(b, 7);
    ASSERT_EQ(1, gcry_mpi_gcd(r, a, b));
    gcry_mpi_set_ui(a, 3);
    ASSERT_EQ(1, gcry_mpi_invm(r, a, b)); /* 3^-1 mod 7 = 5 */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 5));
    gcry_mpi_set_ui(a, 2);
    gcry_mpi_set_ui(b, 4);
    ASSERT_EQ(0, gcry_mpi_invm(r, a, b)); /* no inverse */

    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(m);
    gcry_mpi_release(r);
    gcry_mpi_release(q);
}

TEST(bit_operations)
{
    gcry_mpi_t a = gcry_mpi_set_ui(NULL, 0);
    gcry_mpi_t b = gcry_mpi_new(0);

    gcry_mpi_set_bit(a, 5);
    ASSERT_TRUE(gcry_mpi_test_bit(a, 5));
    ASSERT_FALSE(gcry_mpi_test_bit(a, 4));
    ASSERT_FALSE(gcry_mpi_test_bit(a, 100));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 32));
    gcry_mpi_set_bit(a, 0);
    gcry_mpi_clear_bit(a, 5);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 1));
    gcry_mpi_clear_bit(a, 77); /* beyond the value: no effect */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 1));

    gcry_mpi_set_ui(a, 0xff);
    gcry_mpi_set_highbit(a, 3); /* keep bits 0..2, set bit 3 -> 0x0f */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 0x0f));
    gcry_mpi_set_highbit(a, 9); /* -> 0x20f */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 0x20f));
    gcry_mpi_clear_highbit(a, 3); /* -> 0x07 */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 0x07));

    gcry_mpi_lshift(b, a, 8);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 0x700));
    gcry_mpi_rshift(b, b, 9);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 3));
    gcry_mpi_rshift(b, b, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 3));
    ASSERT_EQ(2, gcry_mpi_get_nbits(b));

    gcry_mpi_release(a);
    gcry_mpi_release(b);
}

TEST(formats_hex)
{
    gcry_mpi_t m;
    char *h;
    size_t nscanned = 0;
    gcry_mpi_t zero = gcry_mpi_new(0);

    m = from_hex("00FF");
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 255));
    h = to_hex(m);
    ASSERT_STR_EQ("00FF", h); /* top bit set gets a 00 prefix */
    gcry_free(h);
    gcry_mpi_release(m);

    m = from_hex("0x7f");
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 127));
    h = to_hex(m);
    ASSERT_STR_EQ("7F", h);
    gcry_free(h);
    gcry_mpi_release(m);

    m = from_hex("-0A");
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 10));
    gcry_mpi_neg(m, m);
    h = to_hex(m);
    ASSERT_STR_EQ("-0A", h);
    gcry_free(h);
    gcry_mpi_release(m);

    m = from_hex("123"); /* odd digit count is fine */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x123));
    gcry_mpi_release(m);

    h = to_hex(zero);
    ASSERT_STR_EQ("00", h);
    gcry_free(h);
    gcry_mpi_release(zero);

    ASSERT_NULL(from_hex("12G4"));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "11", 2, NULL));
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "ABCD", 0, &nscanned));
    ASSERT_EQ(4, nscanned);
    gcry_mpi_release(m);

    /* Buffer too short reports the needed size. */
    m = from_hex("FFFF");
    {
        unsigned char buf[4];
        size_t nwritten = 0;

        ASSERT_ERR(GPG_ERR_TOO_SHORT,
                   gcry_mpi_print(GCRYMPI_FMT_HEX, buf, sizeof buf, &nwritten, m));
        ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, NULL, 0, &nwritten, m));
        ASSERT_EQ(7, nwritten); /* "00FFFF" + NUL */
    }
    gcry_mpi_release(m);
}

TEST(formats_std_usg)
{
    gcry_mpi_t m = from_hex("81");
    gcry_mpi_t n = NULL;
    unsigned char buf[16];
    size_t nw = 0;
    size_t ns = 0;

    /* 0x81 is positive: STD needs a leading zero, USG does not. */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, m));
    ASSERT_EQ(2, nw);
    ASSERT_MEM_EQ("\x00\x81", buf, 2);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, buf, sizeof buf, &nw, m));
    ASSERT_EQ(1, nw);
    ASSERT_EQ(0x81, buf[0]);

    /* -129 in two's complement is FF7F; -1 is FF; -128 is 80. */
    gcry_mpi_neg(m, m);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, m));
    ASSERT_EQ(2, nw);
    ASSERT_MEM_EQ("\xff\x7f", buf, 2);
    ASSERT_OK(gcry_mpi_scan(&n, GCRYMPI_FMT_STD, buf, nw, &ns));
    ASSERT_EQ(2, ns);
    ASSERT_EQ(0, gcry_mpi_cmp(m, n));
    gcry_mpi_release(n);

    gcry_mpi_set_ui(m, 1);
    gcry_mpi_neg(m, m);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, m));
    ASSERT_EQ(1, nw);
    ASSERT_EQ(0xff, buf[0]);
    gcry_mpi_set_ui(m, 128);
    gcry_mpi_neg(m, m);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, m));
    ASSERT_EQ(1, nw);
    ASSERT_EQ(0x80, buf[0]);
    ASSERT_OK(gcry_mpi_scan(&n, GCRYMPI_FMT_STD, buf, 1, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp(m, n));
    gcry_mpi_release(n);

    /* USG ignores the sign; STD of zero is empty. */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, buf, sizeof buf, &nw, m));
    ASSERT_EQ(1, nw);
    ASSERT_EQ(0x80, buf[0]);
    gcry_mpi_set_ui(m, 0);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, m));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_scan(&n, GCRYMPI_FMT_USG, "\x01\x02", 2, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(n, 0x102));
    gcry_mpi_release(n);
    ASSERT_OK(gcry_mpi_scan(&n, GCRYMPI_FMT_USG, "", 0, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(n, 0));
    gcry_mpi_release(n);

    gcry_mpi_release(m);
}

TEST(formats_pgp_ssh)
{
    gcry_mpi_t m = from_hex("0100");
    gcry_mpi_t n = NULL;
    unsigned char buf[16];
    size_t nw = 0;
    size_t ns = 0;

    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_PGP, buf, sizeof buf, &nw, m));
    ASSERT_EQ(4, nw);
    ASSERT_MEM_EQ("\x00\x09\x01\x00", buf, 4);
    ASSERT_OK(gcry_mpi_scan(&n, GCRYMPI_FMT_PGP, buf, sizeof buf, &ns));
    ASSERT_EQ(4, ns);
    ASSERT_EQ(0, gcry_mpi_cmp(m, n));
    gcry_mpi_release(n);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&n, GCRYMPI_FMT_PGP, buf, 3, &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&n, GCRYMPI_FMT_PGP, buf, 1, &ns));
    gcry_mpi_neg(m, m);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_print(GCRYMPI_FMT_PGP, buf, sizeof buf,
                                               &nw, m));
    gcry_mpi_abs(m);

    /* SSH: 4-byte length then STD bytes. 0x0100 -> 00000002 0100 */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, sizeof buf, &nw, m));
    ASSERT_EQ(6, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x02\x01\x00", buf, 6);
    ASSERT_OK(gcry_mpi_scan(&n, GCRYMPI_FMT_SSH, buf, nw, &ns));
    ASSERT_EQ(6, ns);
    ASSERT_EQ(0, gcry_mpi_cmp(m, n));
    gcry_mpi_release(n);
    gcry_mpi_set_ui(m, 0x80);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, sizeof buf, &nw, m));
    ASSERT_EQ(6, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x02\x00\x80", buf, 6);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_scan(&n, GCRYMPI_FMT_SSH, buf, 3, NULL));
    buf[3] = 0x10;
    ASSERT_ERR(GPG_ERR_TOO_LARGE, gcry_mpi_scan(&n, GCRYMPI_FMT_SSH, buf, 6, NULL));

    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_print((enum gcry_mpi_format)77, buf, 1,
                                               &nw, m));
    gcry_mpi_release(m);
}

TEST(opaque_and_flags)
{
    gcry_mpi_t a = gcry_mpi_new(0);
    gcry_mpi_t b;
    unsigned char *p = gcry_malloc(3);
    unsigned int nbits = 0;
    void *q;

    memcpy(p, "\x01\x02\x03", 3);
    ASSERT_NOT_NULL(gcry_mpi_set_opaque(a, p, 24));
    ASSERT_TRUE(gcry_mpi_get_flag(a, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(24, gcry_mpi_get_nbits(a));
    q = gcry_mpi_get_opaque(a, &nbits);
    ASSERT_TRUE(q == p);
    ASSERT_EQ(24, nbits);

    b = gcry_mpi_copy(a);
    ASSERT_TRUE(gcry_mpi_get_flag(b, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_cmp(a, b));
    q = gcry_mpi_get_opaque(b, &nbits);
    ASSERT_TRUE(q != p);
    ASSERT_MEM_EQ(p, q, 3);
    gcry_mpi_release(b);

    b = gcry_mpi_set_opaque_copy(NULL, "\x01\x02\x04", 24);
    ASSERT_TRUE(gcry_mpi_cmp(a, b) < 0);
    gcry_mpi_release(b);

    /* Assigning a number clears the opaque state. */
    gcry_mpi_set_ui(a, 5);
    ASSERT_FALSE(gcry_mpi_get_flag(a, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 5));

    gcry_mpi_set_flag(a, GCRYMPI_FLAG_USER2);
    ASSERT_TRUE(gcry_mpi_get_flag(a, GCRYMPI_FLAG_USER2));
    gcry_mpi_clear_flag(a, GCRYMPI_FLAG_USER2);
    ASSERT_FALSE(gcry_mpi_get_flag(a, GCRYMPI_FLAG_USER2));

    gcry_mpi_set_flag(a, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_set_ui(a, 6); /* ignored with a warning */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 5));
    gcry_mpi_clear_flag(a, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_set_ui(a, 6);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 6));
    gcry_mpi_release(a);

    /* Constants are shared, immutable and survive release. */
    ASSERT_EQ(0, gcry_mpi_cmp_ui(GCRYMPI_CONST_ONE, 1));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(GCRYMPI_CONST_EIGHT, 8));
    ASSERT_TRUE(gcry_mpi_get_flag(GCRYMPI_CONST_TWO, GCRYMPI_FLAG_CONST));
    gcry_mpi_release(GCRYMPI_CONST_THREE);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(GCRYMPI_CONST_THREE, 3));
    b = gcry_mpi_copy(GCRYMPI_CONST_FOUR);
    ASSERT_FALSE(gcry_mpi_get_flag(b, GCRYMPI_FLAG_CONST));
    gcry_mpi_add_ui(b, b, 1);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 5));
    gcry_mpi_release(b);
}

TEST(secure_and_random)
{
    gcry_mpi_t a = gcry_mpi_snew(256);
    gcry_mpi_t b = gcry_mpi_new(0);
    unsigned char *buf = NULL;
    size_t n = 0;

    ASSERT_TRUE(gcry_mpi_get_flag(a, GCRYMPI_FLAG_SECURE));
    gcry_mpi_randomize(a, 256, GCRY_STRONG_RANDOM);
    ASSERT_TRUE(gcry_mpi_get_nbits(a) <= 256);
    ASSERT_TRUE(gcry_mpi_get_nbits(a) > 200); /* overwhelmingly likely */
    gcry_mpi_randomize(b, 128, GCRY_WEAK_RANDOM);
    ASSERT_TRUE(gcry_mpi_get_nbits(b) <= 128);
    ASSERT_TRUE(gcry_mpi_cmp(a, b) != 0);

    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_USG, &buf, &n, a));
    ASSERT_TRUE(gcry_is_secure(buf));
    ASSERT_EQ((gcry_mpi_get_nbits(a) + 7) / 8, n);
    gcry_free(buf);

    gcry_mpi_release(a);
    gcry_mpi_release(b);
}

/* Scanning from secure memory gives a secure MPI in every format, the
 * hex format included (it is parsed through a temporary) and the two's
 * complement formats with a negative value (they go through an inverted
 * copy of the input, which must be secure and wiped as well). */
TEST(scan_from_secure_memory)
{
    static const unsigned char neg[] = { 0xff, 0x00, 0x01 };
    static const unsigned char ssh[] = { 0, 0, 0, 3, 0xff, 0x00, 0x01 };
    gcry_mpi_t m = NULL;
    gcry_mpi_t plain;
    unsigned char *sec;
    unsigned char *buf = NULL;
    size_t n = 0;
    char *hex;

    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    sec = gcry_malloc_secure(32);
    ASSERT_NOT_NULL(sec);

    strcpy((char *)sec, "-0x0123456789abcdef");
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, sec, 0, NULL));
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_SECURE));
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    hex = to_hex(m);
    ASSERT_STR_EQ("-0123456789ABCDEF", hex);
    ASSERT_TRUE(gcry_is_secure(hex));
    gcry_free(hex);
    gcry_mpi_release(m);
    m = NULL;

    memcpy(sec, neg, sizeof neg);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_STD, sec, sizeof neg, NULL));
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_SECURE));
    plain = from_hex("-FFFF");
    ASSERT_NOT_NULL(plain);
    ASSERT_EQ(0, gcry_mpi_cmp(m, plain));
    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_STD, &buf, &n, m));
    ASSERT_TRUE(gcry_is_secure(buf));
    ASSERT_EQ(sizeof neg, n);
    ASSERT_MEM_EQ(neg, buf, n);
    gcry_free(buf);
    gcry_mpi_release(m);
    m = NULL;

    memcpy(sec, ssh, sizeof ssh);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_SSH, sec, sizeof ssh, NULL));
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_SECURE));
    ASSERT_EQ(0, gcry_mpi_cmp(m, plain));
    gcry_mpi_release(m);
    gcry_mpi_release(plain);
    gcry_free(sec);
}

/* Modular exponentiation and inversion with secret operands take
 * OpenSSL's constant-time paths; the results are the same as with plain
 * operands, whichever operand is the secure one. */
TEST(secure_powm_and_invm)
{
    static const char *const bases[] = { "2", "3", "0123456789ABCDEF",
                                         "FFFFFFFFFFFFFFFFFFFFFFFF", "0"
                                       };
    static const char *const mods[] = {
        "7", "3E8", "FFFFFFFFFFFFFFC5", "10000000000000000",
        "D2A3E29F53B9A1D7CA5C04D6E4A9F2B1C7E8D9F0A1B2C3D4E5F60718293A4B5F"
    };
    size_t i;
    size_t j;
    int which;

    for (i = 0; i < sizeof bases / sizeof bases[0]; i++) {
        for (j = 0; j < sizeof mods / sizeof mods[0]; j++) {
            gcry_mpi_t b = from_hex(bases[i]);
            gcry_mpi_t e = from_hex("1F3B9D5C7E1A2B4C6D8E9F00112233445566778899AA");
            gcry_mpi_t m = from_hex(mods[j]);
            gcry_mpi_t want = gcry_mpi_new(0);
            gcry_mpi_t want_inv = gcry_mpi_new(0);
            int have_inv;

            ASSERT_NOT_NULL(b);
            ASSERT_NOT_NULL(e);
            ASSERT_NOT_NULL(m);
            gcry_mpi_powm(want, b, e, m);
            have_inv = gcry_mpi_invm(want_inv, b, m);

            /* Each operand secure in turn, then the result only. */
            for (which = 0; which < 4; which++) {
                gcry_mpi_t sb = gcry_mpi_copy(b);
                gcry_mpi_t se = gcry_mpi_copy(e);
                gcry_mpi_t sm = gcry_mpi_copy(m);
                gcry_mpi_t r = which == 3 ? gcry_mpi_snew(0) : gcry_mpi_new(0);
                gcry_mpi_t inv = which == 3 ? gcry_mpi_snew(0)
                                 : gcry_mpi_new(0);

                gcry_mpi_set_flag(which == 0 ? sb : which == 1 ? se : sm,
                                  GCRYMPI_FLAG_SECURE);
                gcry_mpi_powm(r, sb, se, sm);
                ASSERT_EQ(0, gcry_mpi_cmp(want, r));
                ASSERT_EQ(have_inv, gcry_mpi_invm(inv, sb, sm));

                if (have_inv) {
                    ASSERT_EQ(0, gcry_mpi_cmp(want_inv, inv));
                }

                gcry_mpi_release(sb);
                gcry_mpi_release(se);
                gcry_mpi_release(sm);
                gcry_mpi_release(r);
                gcry_mpi_release(inv);
            }

            gcry_mpi_release(b);
            gcry_mpi_release(e);
            gcry_mpi_release(m);
            gcry_mpi_release(want);
            gcry_mpi_release(want_inv);
        }
    }

    /* The result may alias an operand. */
    {
        gcry_mpi_t a = gcry_mpi_snew(0);
        gcry_mpi_t m = from_hex("FFFFFFFFFFFFFFC5");
        gcry_mpi_t want = from_hex("FFFFFFFFFFFFFFC5");

        gcry_mpi_set_ui(a, 3);
        gcry_mpi_powm(a, a, a, m);
        ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 27));
        gcry_mpi_sub_ui(want, want, 1);
        gcry_mpi_powm(a, a, want, m); /* Fermat: a^(p-1) = 1 mod p. */
        ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 1));
        gcry_mpi_release(a);
        gcry_mpi_release(m);
        gcry_mpi_release(want);
    }
}

TEST(points)
{
    gcry_mpi_point_t p = gcry_mpi_point_new(0);
    gcry_mpi_point_t q;
    gcry_mpi_t x = gcry_mpi_set_ui(NULL, 1);
    gcry_mpi_t y = gcry_mpi_set_ui(NULL, 2);
    gcry_mpi_t z = gcry_mpi_set_ui(NULL, 3);
    gcry_mpi_t t = gcry_mpi_new(0);

    ASSERT_NOT_NULL(p);
    gcry_mpi_point_set(p, x, y, z);
    gcry_mpi_point_get(t, NULL, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 1));
    gcry_mpi_point_get(NULL, t, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 2));

    /* Copying a NULL point yields a new point at the origin. */
    q = gcry_mpi_point_copy(NULL);
    ASSERT_NOT_NULL(q);
    gcry_mpi_point_get(t, NULL, NULL, q);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_release(q);

    q = gcry_mpi_point_copy(p);
    gcry_mpi_point_get(NULL, NULL, t, q);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 3));
    gcry_mpi_point_set(q, NULL, NULL, NULL);
    gcry_mpi_point_get(t, NULL, NULL, q);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_release(q);

    /* snatch_set consumes x, y, z; snatch_get consumes the point. */
    q = gcry_mpi_point_snatch_set(NULL, x, y, z);
    gcry_mpi_point_snatch_get(t, NULL, NULL, q);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 1));

    gcry_mpi_point_release(p);
    gcry_mpi_point_release(NULL);
    gcry_mpi_release(t);
}

TEST(scan_edge_cases)
{
    gcry_mpi_t m = NULL;
    size_t ns = 99;
    unsigned char *big;

    /* Two's complement input of every shape. */
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_STD, "", 0, &ns));
    ASSERT_EQ(0, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_STD, "\x00\x81", 2, &ns));
    ASSERT_EQ(2, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x81));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_STD, "\x00\x00\x01", 3, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 1));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_STD, "\xff\xff", 2, NULL));
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 1));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_STD, "\x80", 1, NULL));
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x80));
    gcry_mpi_release(m);

    /* PGP: oversized bit counts are refused, trailing bytes ignored. */
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_PGP,
                                              "\xff\xff\x01", 3, &ns));
    ASSERT_EQ(0, ns);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_PGP, "\x00\x00", 2, &ns));
    ASSERT_EQ(2, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_PGP, "\x00\x09\x01\x00\xee", 5,
                            &ns));
    ASSERT_EQ(4, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x100));
    gcry_mpi_release(m);

    /* SSH: an empty body is zero, negative bodies are two's complement. */
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_SSH, "\x00\x00\x00\x00", 4, &ns));
    ASSERT_EQ(4, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_SSH, "\x00\x00\x00\x02\xff\x7f\xaa",
                            7, &ns));
    ASSERT_EQ(6, ns);
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x81));
    gcry_mpi_release(m);

    /* HEX: empty, sign only and prefix only are all zero. */
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "", 0, &ns));
    ASSERT_EQ(0, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "-", 0, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    ASSERT_FALSE(gcry_mpi_is_neg(m));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "0x", 0, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "-0x0a", 0, NULL));
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 10));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "abcDEF", 0, &ns));
    ASSERT_EQ(6, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0xabcdef));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "-00", 0, NULL));
    ASSERT_FALSE(gcry_mpi_is_neg(m));
    gcry_mpi_release(m);

    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_scan(&m, (enum gcry_mpi_format)77,
                                              "\x01", 1, NULL));
    /* The result may be discarded. */
    ASSERT_OK(gcry_mpi_scan(NULL, GCRYMPI_FMT_USG, "\x01", 1, &ns));
    ASSERT_EQ(1, ns);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_USG, "\x00\x00\x05", 3, NULL));
    ASSERT_EQ(3, gcry_mpi_get_nbits(m));
    gcry_mpi_release(m);

    /* Inputs beyond 16 MiB are rejected before anything is allocated. */
    big = calloc(16u * 1024 * 1024 + 1, 1);
    ASSERT_NOT_NULL(big);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_USG, big,
                                              16u * 1024 * 1024 + 1, &ns));
    ASSERT_EQ(0, ns);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_STD, big,
                                              16u * 1024 * 1024 + 1, NULL));
    free(big);
}

TEST(print_edge_cases)
{
    gcry_mpi_t m = from_hex("81");
    unsigned char buf[16];
    unsigned char *abuf = NULL;
    size_t nw = 99;
    size_t an = 99;

    ASSERT_NOT_NULL(m);
    gcry_mpi_neg(m, m); /* -129 */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, sizeof buf, &nw, m));
    ASSERT_EQ(6, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x02\xff\x7f", buf, 6);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 5, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_STD, buf, 1, &nw,
                                                 m));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, NULL, 0, &nw, m));
    ASSERT_EQ(6, nw);
    gcry_mpi_set_ui(m, 128);
    gcry_mpi_neg(m, m);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, sizeof buf, &nw, m));
    ASSERT_EQ(5, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x01\x80", buf, 5);

    /* Zero in the length prefixed formats. */
    gcry_mpi_set_ui(m, 0);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, sizeof buf, &nw, m));
    ASSERT_EQ(4, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x00", buf, 4);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_PGP, buf, sizeof buf, &nw, m));
    ASSERT_EQ(2, nw);
    ASSERT_MEM_EQ("\x00\x00", buf, 2);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_PGP, buf, 1, &nw,
                                                 m));
    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_USG, &abuf, &an, m));
    ASSERT_NOT_NULL(abuf);
    ASSERT_EQ(0, an);
    gcry_free(abuf);
    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_STD, &abuf, &an, m));
    ASSERT_NOT_NULL(abuf);
    ASSERT_EQ(0, an);
    gcry_free(abuf);
    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_PGP, &abuf, NULL, m));
    ASSERT_MEM_EQ("\x00\x00", abuf, 2);
    gcry_free(abuf);

    /* Unsigned output and sizing without a buffer or a count. */
    gcry_mpi_set_ui(m, 0x1234);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_USG, buf, 1, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nw, m));
    ASSERT_EQ(2, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, NULL, m));
    ASSERT_MEM_EQ("\x12\x34", buf, 2);

    gcry_mpi_release(m);
}

TEST(opaque_comparisons)
{
    gcry_mpi_t a = from_hex("05");
    gcry_mpi_t b;
    gcry_mpi_t o1 = gcry_mpi_set_opaque_copy(NULL, "\x01\x02", 16);
    gcry_mpi_t o2 = gcry_mpi_set_opaque_copy(NULL, "\x01\x02\x03", 24);
    gcry_mpi_t o3 = gcry_mpi_set_opaque_copy(NULL, "\x01\x02", 12);

    ASSERT_NOT_NULL(a);
    ASSERT_NOT_NULL(o1);
    ASSERT_NOT_NULL(o2);
    ASSERT_NOT_NULL(o3);

    /* gcry_mpi_set allocates when needed and tolerates w == u. */
    b = gcry_mpi_set(NULL, a);
    ASSERT_NOT_NULL(b);
    ASSERT_EQ(0, gcry_mpi_cmp(a, b));
    ASSERT_TRUE(gcry_mpi_set(b, b) == b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 5));

    /* An opaque value sorts below every number, even a negative one, and
     * compares equal to the word zero only. */
    ASSERT_EQ(1, gcry_mpi_cmp(a, o1));
    ASSERT_EQ(-1, gcry_mpi_cmp(o1, a));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(o1, 0));
    ASSERT_EQ(-1, gcry_mpi_cmp_ui(o1, 5));

    /* Opaque values order by bit length first, then by content. */
    ASSERT_TRUE(gcry_mpi_cmp(o1, o2) < 0);
    ASSERT_TRUE(gcry_mpi_cmp(o2, o1) > 0);
    ASSERT_TRUE(gcry_mpi_cmp(o1, o3) > 0);
    ASSERT_TRUE(gcry_mpi_cmp(o3, o1) < 0);
    ASSERT_EQ(0, gcry_mpi_cmp(o1, o1));
    ASSERT_FALSE(gcry_mpi_is_neg(o1));
    ASSERT_FALSE(gcry_mpi_test_bit(o1, 0));
    ASSERT_EQ(12, gcry_mpi_get_nbits(o3));

    /* Negation into another MPI and back in place. */
    gcry_mpi_neg(b, a);
    ASSERT_TRUE(gcry_mpi_is_neg(b));
    gcry_mpi_neg(b, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 5));
    gcry_mpi_neg(b, b);
    ASSERT_TRUE(gcry_mpi_cmp(b, a) < 0);
    ASSERT_TRUE(gcry_mpi_cmp(a, b) > 0);
    ASSERT_TRUE(gcry_mpi_cmp_ui(b, 0) < 0);
    ASSERT_EQ(1, gcry_mpi_cmp(b, o1)); /* -5 is still above an opaque. */
    ASSERT_EQ(-1, gcry_mpi_cmp(o1, b));

    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(o1);
    gcry_mpi_release(o2);
    gcry_mpi_release(o3);
}

/* Opaque values print as their raw bytes in every format. */
TEST(opaque_printing)
{
    gcry_mpi_t o = gcry_mpi_set_opaque_copy(NULL, "\x01\x02\x03", 24);
    gcry_mpi_t small = gcry_mpi_set_opaque_copy(NULL, "\x0f\xff", 12);
    gcry_mpi_t empty = gcry_mpi_set_opaque(NULL, NULL, 0);
    unsigned char buf[16];
    unsigned char *abuf = NULL;
    size_t nw = 0;

    ASSERT_NOT_NULL(o);
    ASSERT_NOT_NULL(small);
    ASSERT_NOT_NULL(empty);

    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, o));
    ASSERT_EQ(3, nw);
    ASSERT_MEM_EQ("\x01\x02\x03", buf, 3);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, buf, sizeof buf, &nw, o));
    ASSERT_EQ(3, nw);
    ASSERT_MEM_EQ("\x01\x02\x03", buf, 3);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_PGP, buf, sizeof buf, &nw, o));
    ASSERT_EQ(5, nw);
    ASSERT_MEM_EQ("\x00\x18\x01\x02\x03", buf, 5);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, sizeof buf, &nw, o));
    ASSERT_EQ(7, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x03\x01\x02\x03", buf, 7);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, buf, sizeof buf, &nw, o));
    ASSERT_EQ(7, nw);
    ASSERT_STR_EQ("010203", (char *)buf);

    /* Measuring and allocating work too. */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, NULL, 0, &nw, o));
    ASSERT_EQ(7, nw);
    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_PGP, &abuf, &nw, o));
    ASSERT_EQ(5, nw);
    ASSERT_MEM_EQ("\x00\x18\x01\x02\x03", abuf, 5);
    gcry_free(abuf);

    /* The byte count comes from the bit length, and the buffer limit is
     * checked. */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, buf, 2, &nw, small));
    ASSERT_EQ(2, nw);
    ASSERT_MEM_EQ("\x0f\xff", buf, 2);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, sizeof buf, &nw, small));
    ASSERT_EQ(2, nw);
    ASSERT_ERR(GPG_ERR_TOO_SHORT,
               gcry_mpi_print(GCRYMPI_FMT_USG, buf, 1, &nw, small));

    /* An opaque value without bytes has nothing to print. */
    ASSERT_ERR(GPG_ERR_ENOENT,
               gcry_mpi_print(GCRYMPI_FMT_USG, buf, sizeof buf, &nw, empty));

    gcry_mpi_release(o);
    gcry_mpi_release(small);
    gcry_mpi_release(empty);
}

/* Upstream checks GCRYMPI_FLAG_IMMUTABLE only in the assignment-like
 * functions; the arithmetic ones overwrite the result regardless. */
TEST(immutable_arithmetic)
{
    gcry_mpi_t w = gcry_mpi_set_ui(NULL, 10);
    gcry_mpi_t a = gcry_mpi_set_ui(NULL, 7);
    gcry_mpi_t b = gcry_mpi_set_ui(NULL, 3);
    gcry_mpi_t q = gcry_mpi_new(0);

    ASSERT_NOT_NULL(w);
    gcry_mpi_set_flag(w, GCRYMPI_FLAG_IMMUTABLE);

    /* Refused, with a warning on the log. */
    gcry_mpi_add(w, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 10));
    gcry_mpi_rshift(w, a, 1);
    gcry_mpi_lshift(w, a, 1);
    gcry_mpi_set_bit(w, 0);
    gcry_mpi_clear_bit(w, 1);
    gcry_mpi_set_highbit(w, 5);
    gcry_mpi_clear_highbit(w, 3);
    gcry_mpi_randomize(w, 16, GCRY_WEAK_RANDOM);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 10));

    /* Performed regardless of the flag. */
    gcry_mpi_add_ui(w, a, 1);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 8));
    gcry_mpi_sub(w, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 4));
    gcry_mpi_sub_ui(w, a, 2);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 5));
    gcry_mpi_mul(w, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 21));
    gcry_mpi_mul_ui(w, a, 2);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 14));
    gcry_mpi_mul_2exp(w, a, 2);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 28));
    gcry_mpi_div(w, NULL, a, b, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 2));
    gcry_mpi_div(q, w, a, b, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    gcry_mpi_mod(w, a, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    gcry_mpi_addm(w, a, b, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    gcry_mpi_subm(w, a, b, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    gcry_mpi_mulm(w, a, b, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 0));
    gcry_mpi_powm(w, a, b, b);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    ASSERT_EQ(1, gcry_mpi_gcd(w, a, b));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    ASSERT_EQ(1, gcry_mpi_invm(w, a, b));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 1));
    ASSERT_TRUE(gcry_mpi_get_flag(w, GCRYMPI_FLAG_IMMUTABLE));

    gcry_mpi_clear_flag(w, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_release(w);
    gcry_mpi_release(a);
    gcry_mpi_release(b);
    gcry_mpi_release(q);
}

/* An MPI turned into a constant can never be released; keeping it
 * reachable from here stops leak checkers from reporting it.  Volatile so
 * that an optimising compiler cannot drop the never-read store and turn
 * the block into a "definitely lost" report under Valgrind. */
static gcry_mpi_t volatile kept_constant;

TEST(immutable_refusals)
{
    gcry_mpi_t r = from_hex("01");
    gcry_mpi_t u = from_hex("09");
    gcry_mpi_t q = from_hex("02");

    ASSERT_NOT_NULL(r);
    ASSERT_NOT_NULL(u);
    ASSERT_NOT_NULL(q);
    gcry_mpi_set_flag(r, GCRYMPI_FLAG_IMMUTABLE);

    /* Assignments to an immutable MPI are ignored (with a warning). */
    gcry_mpi_neg(r, r);
    ASSERT_FALSE(gcry_mpi_is_neg(r));
    gcry_mpi_set_opaque(r, NULL, 0);
    ASSERT_FALSE(gcry_mpi_get_flag(r, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_snatch(r, u);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_release(u); /* Not consumed. */
    gcry_mpi_clear_flag(r, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_set_ui(r, 3);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 3));
    gcry_mpi_release(r);

    /* CONST implies IMMUTABLE and cannot be cleared again. */
    gcry_mpi_set_flag(q, GCRYMPI_FLAG_CONST);
    ASSERT_TRUE(gcry_mpi_get_flag(q, GCRYMPI_FLAG_CONST));
    ASSERT_TRUE(gcry_mpi_get_flag(q, GCRYMPI_FLAG_IMMUTABLE));
    gcry_mpi_clear_flag(q, GCRYMPI_FLAG_IMMUTABLE);
    ASSERT_TRUE(gcry_mpi_get_flag(q, GCRYMPI_FLAG_IMMUTABLE));
    gcry_mpi_set_ui(q, 77);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(q, 2));
    /* A constant is never released, so Q is deliberately kept. */
    kept_constant = q;
}

TEST(arithmetic_edges)
{
    gcry_mpi_t a = from_hex("05");
    gcry_mpi_t n = from_hex("-07");
    gcry_mpi_t three = from_hex("03");
    gcry_mpi_t six = from_hex("06");
    gcry_mpi_t minus3 = from_hex("-03");
    gcry_mpi_t minus1 = from_hex("-01");
    gcry_mpi_t m = from_hex("08");
    gcry_mpi_t z = gcry_mpi_new(0);
    gcry_mpi_t r = gcry_mpi_new(0);
    unsigned int ui = 99;

    ASSERT_NOT_NULL(a);
    ASSERT_NOT_NULL(n);
    ASSERT_NOT_NULL(minus1);

    /* Immediate operands with a distinct destination. */
    gcry_mpi_add_ui(r, a, 3);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 8));
    gcry_mpi_sub_ui(r, a, 7);
    ASSERT_TRUE(gcry_mpi_is_neg(r));
    gcry_mpi_abs(r);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));
    gcry_mpi_mul_ui(r, a, 3);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 15));

    /* High bit operations beyond the current size. */
    gcry_mpi_set_ui(r, 0x3f);
    gcry_mpi_set_highbit(r, 10);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 0x43f));
    gcry_mpi_clear_highbit(r, 20);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 0x43f));
    gcry_mpi_clear_highbit(r, 0);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 0));
    gcry_mpi_set_ui(r, 1);
    gcry_mpi_lshift(r, r, 200);
    ASSERT_EQ(201, gcry_mpi_get_nbits(r));
    gcry_mpi_rshift(r, r, 300);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 0));

    /* Floored modulus with negative operands. */
    gcry_mpi_mod(r, n, three);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));
    gcry_mpi_mod(r, a, n);
    ASSERT_TRUE(gcry_mpi_is_neg(r));
    gcry_mpi_abs(r);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));
    gcry_mpi_div(r, NULL, a, n, -1);
    ASSERT_EQ(0, gcry_mpi_cmp(r, minus1));
    gcry_mpi_div(NULL, r, a, n, -1);
    gcry_mpi_abs(r);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));

    /* gcd with zero and with negative numbers. */
    ASSERT_EQ(0, gcry_mpi_gcd(r, a, z));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 5));
    ASSERT_EQ(0, gcry_mpi_gcd(r, z, z));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 0));
    ASSERT_EQ(0, gcry_mpi_gcd(r, minus3, six));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 3));
    ASSERT_EQ(1, gcry_mpi_invm(r, a, m));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 5));

    /* Modular exponentiation corner cases: 5^0, 0^0 and 5^-1 mod 8. */
    gcry_mpi_powm(r, a, z, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_powm(r, z, z, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));
    gcry_mpi_powm(r, a, minus1, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 5));
    gcry_mpi_addm(r, a, a, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 2));
    gcry_mpi_subm(r, z, a, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 3));
    gcry_mpi_mulm(r, a, a, m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(r, 1));

    /* Zero has no sign and no bits. */
    ASSERT_EQ(0, gcry_mpi_get_nbits(z));
    ASSERT_FALSE(gcry_mpi_is_neg(z));
    gcry_mpi_neg(r, z);
    ASSERT_FALSE(gcry_mpi_is_neg(r));
    ASSERT_OK(gcry_mpi_get_ui(&ui, z));
    ASSERT_EQ(0, ui);

    /* NULL handling and the strongest random level. */
    ASSERT_NULL(gcry_mpi_copy(NULL));
    gcry_mpi_snatch(NULL, six); /* Releases SIX. */
    gcry_mpi_randomize(r, 64, GCRY_VERY_STRONG_RANDOM);
    ASSERT_TRUE(gcry_mpi_get_nbits(r) <= 64);

    gcry_mpi_release(a);
    gcry_mpi_release(n);
    gcry_mpi_release(three);
    gcry_mpi_release(minus3);
    gcry_mpi_release(minus1);
    gcry_mpi_release(m);
    gcry_mpi_release(z);
    gcry_mpi_release(r);
}

TEST(point_edges)
{
    gcry_mpi_point_t p;
    gcry_mpi_t t = gcry_mpi_new(0);
    gcry_mpi_t y = from_hex("02");

    ASSERT_NOT_NULL(y);

    /* NULL point and NULL coordinates allocate and zero as needed. */
    p = gcry_mpi_point_set(NULL, NULL, NULL, NULL);
    ASSERT_NOT_NULL(p);
    gcry_mpi_set_ui(t, 9);
    gcry_mpi_point_get(t, NULL, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_release(p);

    p = gcry_mpi_point_snatch_set(NULL, NULL, y, NULL);
    ASSERT_NOT_NULL(p);
    gcry_mpi_set_ui(t, 9);
    gcry_mpi_point_get(t, NULL, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_get(NULL, t, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 2));
    gcry_mpi_set_ui(t, 9);
    gcry_mpi_point_get(NULL, NULL, t, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_release(p);

    p = gcry_mpi_point_snatch_set(NULL, from_hex("03"), NULL, from_hex("04"));
    ASSERT_NOT_NULL(p);
    gcry_mpi_set_ui(t, 9);
    gcry_mpi_point_get(NULL, t, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_get(t, NULL, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 3));
    gcry_mpi_point_get(NULL, NULL, t, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 4));
    gcry_mpi_point_release(p);

    /* The size hint does not change the initial value. */
    p = gcry_mpi_point_new(256);
    gcry_mpi_set_ui(t, 9);
    gcry_mpi_point_get(t, NULL, NULL, p);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(t, 0));
    gcry_mpi_point_release(p);
    gcry_mpi_release(t);
}

TEST(dump)
{
    gcry_mpi_t a = from_hex("05");
    gcry_mpi_t o = gcry_mpi_set_opaque_copy(NULL, "\x01", 8);
    int saved;
    int devnull;

    ASSERT_NOT_NULL(a);
    ASSERT_NOT_NULL(o);

    /* The dumps go to the log on stderr; silence them. */
    fflush(stderr);
    saved = dup(2);
    devnull = open("/dev/null", O_WRONLY);

    if (saved >= 0 && devnull >= 0) {
        dup2(devnull, 2);
    }

    gcry_mpi_dump(a);
    gcry_mpi_dump(o);
    gcry_mpi_dump(NULL);
    fflush(stderr);

    if (saved >= 0) {
        dup2(saved, 2);
        close(saved);
    }

    if (devnull >= 0) {
        close(devnull);
    }

    gcry_mpi_release(a);
    gcry_mpi_release(o);
}

/* Invalid arguments are reported instead of dereferenced.  Only the
 * functions with an error return (or a NULL/0 result) are covered here;
 * the void arithmetic functions raise a fatal error instead. */
TEST(argument_checks)
{
    gcry_mpi_t a = gcry_mpi_set_ui(NULL, 5);
    gcry_mpi_t b = gcry_mpi_set_ui(NULL, 3);
    gcry_mpi_t o;
    unsigned int ui = 42;
    unsigned int nbits = 42;
    unsigned char sentinel[1] = { 'x' };
    unsigned char *abuf = sentinel;
    size_t nw = 42;

    ASSERT_NOT_NULL(a);
    ASSERT_NOT_NULL(b);

    /* Scan: the buffer is required even for an empty value. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_scan(&o, GCRYMPI_FMT_USG, NULL, 0,
                                              NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_scan(&o, GCRYMPI_FMT_STD, NULL, 4,
                                              NULL));

    /* Print and aprint need a value; aprint needs its output pointer. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_print(GCRYMPI_FMT_STD, NULL, 0, &nw,
                                               NULL));
    ASSERT_EQ(0, nw);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_aprint(GCRYMPI_FMT_HEX, NULL, &nw,
                                                a));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_aprint(GCRYMPI_FMT_HEX, &abuf, &nw,
                                                NULL));
    ASSERT_NULL(abuf);
    abuf = sentinel;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_aprint((enum gcry_mpi_format)77,
                                                &abuf, &nw, a));
    ASSERT_NULL(abuf);

    /* get_ui needs both the destination and the value. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_get_ui(NULL, a));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_get_ui(&ui, NULL));
    ASSERT_EQ(42, ui);

    /* Predicates and sizes report 0 for a NULL value. */
    ASSERT_EQ(0, gcry_mpi_is_neg(NULL));
    ASSERT_EQ(0, gcry_mpi_get_nbits(NULL));
    ASSERT_EQ(0, gcry_mpi_test_bit(NULL, 0));
    ASSERT_EQ(0, gcry_mpi_get_flag(NULL, GCRYMPI_FLAG_SECURE));

    /* gcd and invm report "no" without touching anything. */
    ASSERT_EQ(0, gcry_mpi_gcd(NULL, a, b));
    ASSERT_EQ(0, gcry_mpi_gcd(a, NULL, b));
    ASSERT_EQ(0, gcry_mpi_gcd(a, b, NULL));
    ASSERT_EQ(0, gcry_mpi_invm(NULL, a, b));
    ASSERT_EQ(0, gcry_mpi_invm(a, NULL, b));
    ASSERT_EQ(0, gcry_mpi_invm(a, b, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 5));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(b, 3));

    /* Opaque values: a NULL buffer is only valid when it is empty. */
    ASSERT_NULL(gcry_mpi_set_opaque(a, NULL, 8));
    ASSERT_FALSE(gcry_mpi_get_flag(a, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 5));
    ASSERT_NULL(gcry_mpi_set_opaque(NULL, NULL, 8));
    ASSERT_NULL(gcry_mpi_set_opaque_copy(NULL, NULL, 8));
    ASSERT_NULL(gcry_mpi_set_opaque_copy(a, NULL, 1));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(a, 5));
    o = gcry_mpi_set_opaque_copy(NULL, NULL, 0);
    ASSERT_NOT_NULL(o);
    ASSERT_TRUE(gcry_mpi_get_flag(o, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_get_nbits(o));
    gcry_mpi_release(o);
    ASSERT_NULL(gcry_mpi_get_opaque(NULL, &nbits));
    ASSERT_EQ(42, nbits);

    /* An unknown constant selector is a fatal error, so only the valid
     * selectors can be exercised here. */
    ASSERT_NOT_NULL(_gcry_mpi_get_const(1));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(GCRYMPI_CONST_FOUR, 4));

    gcry_mpi_release(a);
    gcry_mpi_release(b);
}

TEST(print_too_short)
{
    gcry_mpi_t m = from_hex("1234");
    gcry_mpi_t top = from_hex("80");
    gcry_mpi_t neg = from_hex("-1234");
    gcry_mpi_t o = gcry_mpi_set_opaque_copy(NULL, "\x81\x02", 16);
    unsigned char buf[16];
    unsigned char *abuf = NULL;
    size_t nw;

    ASSERT_NOT_NULL(m);
    ASSERT_NOT_NULL(top);
    ASSERT_NOT_NULL(neg);
    ASSERT_NOT_NULL(o);

    /* Every format refuses a short buffer with GPG_ERR_TOO_SHORT and a
     * zero count; the required size comes from a call without buffer. */
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_STD, buf, 1, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, NULL, 0, &nw, m));
    ASSERT_EQ(2, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, 2, &nw, m));
    ASSERT_MEM_EQ("\x12\x34", buf, 2);
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_USG, buf, 1, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_PGP, buf, 3, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_PGP, buf, 4, &nw, m));
    ASSERT_EQ(4, nw);
    ASSERT_MEM_EQ("\x00\x0d\x12\x34", buf, 4);
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 5, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 6, &nw, m));
    ASSERT_EQ(6, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x02\x12\x34", buf, 6);
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 4, &nw,
                                                 m));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, NULL, 0, &nw, m));
    ASSERT_EQ(5, nw); /* With the terminating NUL. */
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 5, &nw, m));
    ASSERT_EQ(5, nw);
    ASSERT_STR_EQ("1234", (char *)buf);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 5, &nw,
                                                 neg));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 6, &nw, neg));
    ASSERT_EQ(6, nw);
    ASSERT_STR_EQ("-1234", (char *)buf);

    /* A set top bit costs a leading zero in the signed formats, which
     * the buffer must have room for. */
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_STD, buf, 1, &nw,
                                                 top));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, 2, &nw, top));
    ASSERT_EQ(2, nw);
    ASSERT_MEM_EQ("\x00\x80", buf, 2);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, buf, 1, &nw, top));
    ASSERT_EQ(1, nw);
    ASSERT_MEM_EQ("\x80", buf, 1);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 5, &nw,
                                                 top));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 6, &nw, top));
    ASSERT_EQ(6, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x02\x00\x80", buf, 6);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_PGP, buf, sizeof buf, &nw, top));
    ASSERT_EQ(3, nw);
    ASSERT_MEM_EQ("\x00\x08\x80", buf, 3);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 4, &nw,
                                                 top));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 5, &nw, top));
    ASSERT_STR_EQ("0080", (char *)buf);

    /* An opaque value whose first byte has the top bit set gets the same
     * leading zero in STD, SSH and HEX, and none in USG and PGP. */
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_STD, buf, 2, &nw,
                                                 o));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_STD, buf, 3, &nw, o));
    ASSERT_EQ(3, nw);
    ASSERT_MEM_EQ("\x00\x81\x02", buf, 3);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 6, &nw,
                                                 o));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_SSH, buf, 7, &nw, o));
    ASSERT_EQ(7, nw);
    ASSERT_MEM_EQ("\x00\x00\x00\x03\x00\x81\x02", buf, 7);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_USG, buf, 2, &nw, o));
    ASSERT_EQ(2, nw);
    ASSERT_MEM_EQ("\x81\x02", buf, 2);
    nw = 99;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_PGP, buf, 3, &nw,
                                                 o));
    ASSERT_EQ(0, nw);
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_PGP, buf, 4, &nw, o));
    ASSERT_EQ(4, nw);
    ASSERT_MEM_EQ("\x00\x10\x81\x02", buf, 4);
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 6, &nw,
                                                 o));
    ASSERT_OK(gcry_mpi_print(GCRYMPI_FMT_HEX, buf, 7, &nw, o));
    ASSERT_EQ(7, nw);
    ASSERT_STR_EQ("008102", (char *)buf);
    ASSERT_OK(gcry_mpi_aprint(GCRYMPI_FMT_STD, &abuf, &nw, o));
    ASSERT_EQ(3, nw);
    ASSERT_MEM_EQ("\x00\x81\x02", abuf, 3);
    gcry_free(abuf);

    gcry_mpi_release(m);
    gcry_mpi_release(top);
    gcry_mpi_release(neg);
    gcry_mpi_release(o);
}

TEST(scan_hex_invalid)
{
    gcry_mpi_t m = NULL;
    size_t ns = 99;
    char *big;

    /* Only hex digits may follow the optional sign and "0x" prefix. */
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "zz", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "0xzz", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "-0xzz", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "12g4", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "0X12", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "0x-12", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "--12", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, " 12", 0,
                                              &ns));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "12 ", 0,
                                              &ns));
    ASSERT_EQ(99, ns); /* Untouched on error. */
    /* A hex string carries its own length, so BUFLEN must be zero. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "12", 2,
                                              &ns));

    /* An odd number of digits is fine, with or without sign and prefix;
     * the count covers the whole string. */
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "abc", 0, &ns));
    ASSERT_EQ(3, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0xabc));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "0xABC", 0, &ns));
    ASSERT_EQ(5, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0xabc));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "-0xabc", 0, &ns));
    ASSERT_EQ(6, ns);
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0xabc));
    gcry_mpi_release(m);
    ASSERT_OK(gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, "-0x", 0, &ns));
    ASSERT_EQ(3, ns);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    ASSERT_FALSE(gcry_mpi_is_neg(m));
    gcry_mpi_release(m);

    /* Like the binary formats, hex input beyond 16 MiB is rejected. */
    big = malloc(16u * 1024 * 1024 + 2);
    ASSERT_NOT_NULL(big);
    memset(big, 'a', 16u * 1024 * 1024 + 1);
    big[16u * 1024 * 1024 + 1] = 0;
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, big, 0,
                                              NULL));
    free(big);
}

TEST(set_abs_and_opaque_edges)
{
    gcry_mpi_t w = from_hex("0a");
    gcry_mpi_t u = from_hex("0b");
    gcry_mpi_t n = from_hex("-0b");
    gcry_mpi_t o = gcry_mpi_set_opaque_copy(NULL, "\x81\x02", 16);
    gcry_mpi_t e1 = gcry_mpi_set_opaque(NULL, NULL, 0);
    gcry_mpi_t e2 = gcry_mpi_set_opaque(NULL, NULL, 0);
    gcry_mpi_t so;
    gcry_mpi_t copy;
    unsigned char *secbuf;
    unsigned int nbits = 99;

    ASSERT_NOT_NULL(w);
    ASSERT_NOT_NULL(u);
    ASSERT_NOT_NULL(n);
    ASSERT_NOT_NULL(o);
    ASSERT_NOT_NULL(e1);
    ASSERT_NOT_NULL(e2);

    /* Assignments to an immutable MPI are ignored with a warning; the
     * target is returned untouched.  The same goes for gcry_mpi_abs. */
    gcry_mpi_set_flag(w, GCRYMPI_FLAG_IMMUTABLE);
    ASSERT_TRUE(gcry_mpi_set(w, u) == w);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 10));
    ASSERT_TRUE(gcry_mpi_set(w, o) == w);
    ASSERT_FALSE(gcry_mpi_get_flag(w, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 10));
    gcry_mpi_clear_flag(w, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_set_flag(n, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_abs(n);
    ASSERT_TRUE(gcry_mpi_is_neg(n));
    gcry_mpi_clear_flag(n, GCRYMPI_FLAG_IMMUTABLE);
    gcry_mpi_abs(n);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(n, 11));

    /* Assigning an opaque value makes the target an opaque copy with a
     * buffer of its own. */
    ASSERT_TRUE(gcry_mpi_set(w, o) == w);
    ASSERT_TRUE(gcry_mpi_get_flag(w, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(16, gcry_mpi_get_nbits(w));
    ASSERT_EQ(0, gcry_mpi_cmp(w, o));
    ASSERT_TRUE(gcry_mpi_get_opaque(w, &nbits) != gcry_mpi_get_opaque(o, NULL));
    ASSERT_EQ(16, nbits);
    ASSERT_MEM_EQ("\x81\x02", gcry_mpi_get_opaque(w, NULL), 2);
    copy = gcry_mpi_set(NULL, o);
    ASSERT_NOT_NULL(copy);
    ASSERT_EQ(0, gcry_mpi_cmp(copy, o));
    gcry_mpi_release(copy);
    /* Back to a number, then to an empty opaque value. */
    ASSERT_TRUE(gcry_mpi_set(w, u) == w);
    ASSERT_FALSE(gcry_mpi_get_flag(w, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(w, 11));
    ASSERT_TRUE(gcry_mpi_set(w, e1) == w);
    ASSERT_TRUE(gcry_mpi_get_flag(w, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(0, gcry_mpi_get_nbits(w));
    ASSERT_NULL(gcry_mpi_get_opaque(w, &nbits));
    ASSERT_EQ(0, nbits);

    /* Empty opaque values compare equal to each other and sort below
     * any opaque value with content. */
    ASSERT_EQ(0, gcry_mpi_cmp(e1, e2));
    ASSERT_EQ(0, gcry_mpi_cmp(w, e1));
    ASSERT_TRUE(gcry_mpi_cmp(e1, o) < 0);
    ASSERT_TRUE(gcry_mpi_cmp(o, e1) > 0);

    /* A buffer from secure memory makes the opaque MPI secure, and the
     * copy taken by gcry_mpi_set follows suit. */
    secbuf = gcry_malloc_secure(2);
    ASSERT_NOT_NULL(secbuf);
    memcpy(secbuf, "\x81\x02", 2);
    so = gcry_mpi_set_opaque(NULL, secbuf, 16);
    ASSERT_NOT_NULL(so);
    ASSERT_TRUE(gcry_mpi_get_flag(so, GCRYMPI_FLAG_SECURE));
    ASSERT_TRUE(gcry_mpi_get_flag(so, GCRYMPI_FLAG_OPAQUE));
    copy = gcry_mpi_set(NULL, so);
    ASSERT_NOT_NULL(copy);
    ASSERT_TRUE(gcry_mpi_get_flag(copy, GCRYMPI_FLAG_SECURE));
    ASSERT_TRUE(gcry_is_secure(gcry_mpi_get_opaque(copy, NULL)));
    ASSERT_EQ(0, gcry_mpi_cmp(copy, so));
    gcry_mpi_release(copy);
    gcry_mpi_release(so);

    /* A number is moved into secure memory by setting the flag. */
    ASSERT_FALSE(gcry_mpi_get_flag(u, GCRYMPI_FLAG_SECURE));
    gcry_mpi_set_flag(u, GCRYMPI_FLAG_SECURE);
    ASSERT_TRUE(gcry_mpi_get_flag(u, GCRYMPI_FLAG_SECURE));
    gcry_mpi_add_ui(u, u, 1);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(u, 12));
    copy = gcry_mpi_copy(u);
    ASSERT_NOT_NULL(copy);
    ASSERT_TRUE(gcry_mpi_get_flag(copy, GCRYMPI_FLAG_SECURE));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(copy, 12));
    gcry_mpi_release(copy);

    gcry_mpi_release(w);
    gcry_mpi_release(u);
    gcry_mpi_release(n);
    gcry_mpi_release(o);
    gcry_mpi_release(e1);
    gcry_mpi_release(e2);
}

/* The MPI misuse paths are reported as bugs through the logger, which
 * then aborts.  The log handler sees the message first, so a child can
 * leave with a code of its own from there (and flush its coverage). */
static void
bug_exit_handler(void *opaque, int level, const char *fmt, va_list ap)
{
    (void)opaque;
    (void)fmt;
    (void)ap;

    if (level == GCRY_LOG_BUG) {
        test_child_exit(42);
    }
}

/* The children below exit from inside the log handler, so their MPIs are
 * never released.  Parking them here keeps them reachable; volatile stops
 * an optimising compiler from dropping the store, which would make
 * Valgrind report the block as definitely lost in the child. */
static gcry_mpi_t volatile fatal_kept[2];

static void
fatal_mpi_get_opaque_normal(void)
{
    gcry_mpi_t a = fatal_kept[0] = gcry_mpi_set_ui(NULL, 5);

    gcry_set_log_handler(bug_exit_handler, NULL);
    gcry_mpi_get_opaque(a, NULL);
}

static void
fatal_mpi_set_flag_opaque(void)
{
    gcry_mpi_t a = fatal_kept[0] = gcry_mpi_set_ui(NULL, 5);

    gcry_set_log_handler(bug_exit_handler, NULL);
    gcry_mpi_set_flag(a, GCRYMPI_FLAG_OPAQUE);
}

static void
fatal_mpi_clear_flag_const(void)
{
    gcry_mpi_t a = fatal_kept[0] = gcry_mpi_set_ui(NULL, 5);

    gcry_set_log_handler(bug_exit_handler, NULL);
    gcry_mpi_clear_flag(a, GCRYMPI_FLAG_CONST);
}

static void
fatal_mpi_get_flag_unknown(void)
{
    gcry_mpi_t a = fatal_kept[0] = gcry_mpi_set_ui(NULL, 5);

    gcry_set_log_handler(bug_exit_handler, NULL);
    gcry_mpi_get_flag(a, (enum gcry_mpi_flag)0x1000);
}

static void
fatal_mpi_opaque_arithmetic(void)
{
    gcry_mpi_t o = fatal_kept[0] = gcry_mpi_set_opaque_copy(NULL, "\x01", 8);
    gcry_mpi_t r = fatal_kept[1] = gcry_mpi_new(0);

    gcry_set_log_handler(bug_exit_handler, NULL);
    gcry_mpi_add(r, o, o);
}

static void
fatal_mpi_unknown_constant(void)
{
    gcry_set_log_handler(bug_exit_handler, NULL);
    _gcry_mpi_get_const(99);
}

static void
fatal_mpi_get_opaque_unhandled(void)
{
    gcry_mpi_t a = fatal_kept[0] = gcry_mpi_set_ui(NULL, 5);

    gcry_mpi_get_opaque(a, NULL);
}

TEST(fatal_misuse)
{
    /* Caller bugs the reference library treats as fatal: the process
     * aborts after logging, so each runs in a child of its own. */
    ASSERT_EQ(42, run_child(fatal_mpi_get_opaque_normal));
    ASSERT_EQ(42, run_child(fatal_mpi_set_flag_opaque));
    ASSERT_EQ(42, run_child(fatal_mpi_clear_flag_const));
    ASSERT_EQ(42, run_child(fatal_mpi_get_flag_unknown));
    ASSERT_EQ(42, run_child(fatal_mpi_opaque_arithmetic));
    ASSERT_EQ(42, run_child(fatal_mpi_unknown_constant));
    ASSERT_EQ(1000 + SIGABRT, run_child(fatal_mpi_get_opaque_unhandled));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(basic_values);
    RUN_TEST(arithmetic);
    RUN_TEST(bit_operations);
    RUN_TEST(formats_hex);
    RUN_TEST(formats_std_usg);
    RUN_TEST(formats_pgp_ssh);
    RUN_TEST(opaque_and_flags);
    RUN_TEST(secure_and_random);
    RUN_TEST(scan_from_secure_memory);
    RUN_TEST(secure_powm_and_invm);
    RUN_TEST(points);
    RUN_TEST(scan_edge_cases);
    RUN_TEST(print_edge_cases);
    RUN_TEST(opaque_comparisons);
    RUN_TEST(opaque_printing);
    RUN_TEST(immutable_arithmetic);
    RUN_TEST(immutable_refusals);
    RUN_TEST(arithmetic_edges);
    RUN_TEST(point_edges);
    RUN_TEST(dump);
    RUN_TEST(argument_checks);
    RUN_TEST(print_too_short);
    RUN_TEST(scan_hex_invalid);
    RUN_TEST(set_abs_and_opaque_edges);
    RUN_TEST(fatal_misuse);
    return TEST_RESULT();
}
