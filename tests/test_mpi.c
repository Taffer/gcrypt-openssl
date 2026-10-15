#include <gcrypt.h>

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
    return TEST_RESULT();
}
