#define _POSIX_C_SOURCE 200809L

#include <gcrypt.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>

#include "test_common.h"

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
    return TEST_RESULT();
}
