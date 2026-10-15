#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

/* Return the canonical encoding of SEXP as a freshly allocated string.  The
 * canonical encoding never contains NUL bytes for the data used here. */
static char *
canon(gcry_sexp_t sexp)
{
    size_t n = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
    char *buf = malloc(n + 1);

    if (!buf) {
        return NULL;
    }

    n = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, buf, n + 1);
    buf[n] = 0;
    return buf;
}

static char *
advanced(gcry_sexp_t sexp)
{
    size_t n = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    char *buf = malloc(n);

    if (!buf) {
        return NULL;
    }

    gcry_sexp_sprint(sexp, GCRYSEXP_FMT_ADVANCED, buf, n);
    return buf;
}

TEST(scan_tokens_and_canon_print)
{
    gcry_sexp_t s = NULL;
    size_t erroff = 99;
    char *c;

    ASSERT_OK(gcry_sexp_sscan(&s, &erroff, "(foo bar (baz 3:qux))", 21));
    ASSERT_NOT_NULL(s);
    c = canon(s);
    ASSERT_STR_EQ("(3:foo3:bar(3:baz3:qux))", c);
    free(c);
    ASSERT_EQ(3, gcry_sexp_length(s));
    gcry_sexp_release(s);

    ASSERT_OK(gcry_sexp_new(&s, "(a (b c) d)", 0, 1));
    c = canon(s);
    ASSERT_STR_EQ("(1:a(1:b1:c)1:d)", c);
    free(c);
    gcry_sexp_release(s);
}

TEST(scan_hex_quoted_base64)
{
    gcry_sexp_t s = NULL;
    const char *d;
    size_t n;

    ASSERT_OK(gcry_sexp_new(&s, "(x #01 02 ff# \"a\\tb\\x41\\101\" |AQID| 2:zz)",
                            0, 1));
    ASSERT_EQ(5, gcry_sexp_length(s));

    d = gcry_sexp_nth_data(s, 1, &n);
    ASSERT_EQ(3, n);
    ASSERT_MEM_EQ("\x01\x02\xff", d, 3);

    d = gcry_sexp_nth_data(s, 2, &n);
    ASSERT_EQ(5, n);
    ASSERT_MEM_EQ("a\tbAA", d, 5);

    d = gcry_sexp_nth_data(s, 3, &n);
    ASSERT_EQ(3, n);
    ASSERT_MEM_EQ("\x01\x02\x03", d, 3);

    d = gcry_sexp_nth_data(s, 4, &n);
    ASSERT_EQ(2, n);
    ASSERT_MEM_EQ("zz", d, 2);
    gcry_sexp_release(s);
}

TEST(scan_errors)
{
    gcry_sexp_t s = (gcry_sexp_t)1;
    size_t erroff = 0;

    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_PAREN,
               gcry_sexp_sscan(&s, &erroff, "(a (b)", strlen("(a (b)")));
    ASSERT_NULL(s);
    s = (gcry_sexp_t)1;
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_PAREN,
               gcry_sexp_sscan(&s, &erroff, "(a))", strlen("(a))")));
    ASSERT_EQ(3, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_ODD_HEX_NUMBERS,
               gcry_sexp_sscan(&s, &erroff, "(a #123#)", strlen("(a #123#)")));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_HEX_CHAR,
               gcry_sexp_sscan(&s, &erroff, "(a #12zz#)", strlen("(a #12zz#)")));
    ASSERT_ERR(GPG_ERR_SEXP_ZERO_PREFIX,
               gcry_sexp_sscan(&s, &erroff, "(a 01:x)", strlen("(a 01:x)")));
    ASSERT_ERR(GPG_ERR_SEXP_STRING_TOO_LONG,
               gcry_sexp_sscan(&s, &erroff, "(a 9:x)", strlen("(a 9:x)")));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_QUOTATION,
               gcry_sexp_sscan(&s, &erroff, "(a \"\\q\")", 8));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_CHARACTER,
               gcry_sexp_sscan(&s, &erroff, "(a %)", strlen("(a %)")));
    ASSERT_ERR(GPG_ERR_SEXP_UNEXPECTED_PUNC,
               gcry_sexp_sscan(&s, &erroff, "(a {b})", strlen("(a {b})")));
    ASSERT_ERR(GPG_ERR_SEXP_NESTED_DH,
               gcry_sexp_sscan(&s, &erroff, "(a [b [c])", strlen("(a [b [c])")));
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_DH,
               gcry_sexp_sscan(&s, &erroff, "(a ])", strlen("(a ])")));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_sscan(NULL, NULL, "(a)", 3));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_sscan(&s, NULL, NULL, 0));

    /* Empty lists normalise to NULL without error. */
    s = (gcry_sexp_t)1;
    ASSERT_OK(gcry_sexp_sscan(&s, NULL, "()", 2));
    ASSERT_NULL(s);
    ASSERT_OK(gcry_sexp_sscan(&s, NULL, "   ", 3));
    ASSERT_NULL(s);
}

TEST(build_with_format_directives)
{
    gcry_sexp_t s = NULL;
    gcry_sexp_t inner = NULL;
    gcry_mpi_t m = gcry_mpi_set_ui(NULL, 0x1234);
    gcry_mpi_t neg = gcry_mpi_set_ui(NULL, 1);
    char *c;
    size_t erroff;

    gcry_mpi_neg(neg, neg);

    ASSERT_OK(gcry_sexp_build(&inner, NULL, "(inner %d %u)", -5, 7u));
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(top %s %b %m %M %S)", "str", 3,
                              "\x00\x01\x02", m, m, inner));
    c = canon(s);
    ASSERT_TRUE(!memcmp(c, "(3:top3:str3:", 13));
    ASSERT_TRUE(!memcmp(c + 13, "\x00\x01\x02" "2:\x12\x34" "2:\x12\x34"
                        "(5:inner2:-51:7))", 24));
    free(c);
    gcry_sexp_release(s);

    /* A negative value in %m gets a sign byte; %M refuses negatives. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(n %m)", neg));
    c = canon(s);
    ASSERT_STR_EQ("(1:n1:\xff)", c);
    free(c);
    gcry_sexp_release(s);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_build(&s, NULL, "(n %M)", neg));

    /* Unknown directive. */
    ASSERT_ERR(GPG_ERR_SEXP_INV_LEN_SPEC,
               gcry_sexp_build(&s, &erroff, "(n %q)", 1));

    /* Array form. */
    {
        int len = 2;
        const char *buf = "hi";
        void *args[2];
        const char *d;
        size_t n;

        args[0] = &len;
        args[1] = &buf;
        ASSERT_OK(gcry_sexp_build_array(&s, NULL, "(arr %b)", args));
        d = gcry_sexp_nth_data(s, 1, &n);
        ASSERT_EQ(2, n);
        ASSERT_MEM_EQ("hi", d, 2);
        gcry_sexp_release(s);
    }

    gcry_sexp_release(inner);
    gcry_mpi_release(m);
    gcry_mpi_release(neg);
}

TEST(navigation)
{
    gcry_sexp_t s = NULL;
    gcry_sexp_t l;
    gcry_sexp_t l2;
    char *c;
    char *str;
    void *buf;
    size_t n;

    ASSERT_OK(gcry_sexp_new(&s, "(public-key (rsa (n #00AB#) (e #010001#)))",
                            0, 1));

    l = gcry_sexp_find_token(s, "rsa", 0);
    ASSERT_NOT_NULL(l);
    ASSERT_EQ(3, gcry_sexp_length(l));
    c = canon(l);
    ASSERT_MEM_EQ("(3:rsa(1:n2:\x00\xab)(1:e3:\x01\x00\x01))", c, 26);
    free(c);

    l2 = gcry_sexp_find_token(l, "e", 1);
    ASSERT_NOT_NULL(l2);
    str = gcry_sexp_nth_string(l2, 0);
    ASSERT_STR_EQ("e", str);
    gcry_free(str);
    buf = gcry_sexp_nth_buffer(l2, 1, &n);
    ASSERT_EQ(3, n);
    ASSERT_MEM_EQ("\x01\x00\x01", buf, 3);
    gcry_free(buf);
    ASSERT_NULL(gcry_sexp_nth_data(l2, 2, &n));
    ASSERT_NULL(gcry_sexp_nth_buffer(l2, 7, &n));
    gcry_sexp_release(l2);

    ASSERT_NULL(gcry_sexp_find_token(s, "nope", 0));

    /* car / cdr / cadr / nth */
    l2 = gcry_sexp_car(l);
    c = canon(l2);
    ASSERT_STR_EQ("(3:rsa)", c);
    free(c);
    gcry_sexp_release(l2);

    l2 = gcry_sexp_cdr(l);
    ASSERT_EQ(2, gcry_sexp_length(l2));
    /* "((1:n2:..)(1:e3:...))" is 21 bytes plus the terminating NUL. */
    ASSERT_EQ(22, gcry_sexp_sprint(l2, GCRYSEXP_FMT_CANON, NULL, 0));
    gcry_sexp_release(l2);

    l2 = gcry_sexp_cadr(l);
    str = gcry_sexp_nth_string(l2, 0);
    ASSERT_STR_EQ("n", str);
    gcry_free(str);
    gcry_sexp_release(l2);

    l2 = gcry_sexp_nth(l, 2);
    str = gcry_sexp_nth_string(l2, 0);
    ASSERT_STR_EQ("e", str);
    gcry_free(str);
    gcry_sexp_release(l2);
    ASSERT_NULL(gcry_sexp_nth(l, 3));
    ASSERT_NULL(gcry_sexp_nth(NULL, 0));
    ASSERT_EQ(0, gcry_sexp_length(NULL));

    gcry_sexp_release(l);
    gcry_sexp_release(s);
}

TEST(nth_mpi_and_extract_param)
{
    gcry_sexp_t s = NULL;
    gcry_mpi_t n = NULL;
    gcry_mpi_t e = NULL;
    gcry_mpi_t d = NULL;
    gcry_mpi_t m;
    gcry_sexp_t l;
    unsigned int ui;
    char *curve = NULL;
    char *flags = NULL;
    int nbits = 0;
    gcry_buffer_t qbuf = { 0, 0, 0, NULL };

    ASSERT_OK(gcry_sexp_new(&s,
                            "(key (n #00AB#) (e #010001#) (curve Ed25519)"
                            " (flags eddsa comp) (nbits 4:2048)"
                            " (q #0405#))", 0, 1));

    l = gcry_sexp_find_token(s, "e", 0);
    m = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);
    ASSERT_NOT_NULL(m);
    ASSERT_OK(gcry_mpi_get_ui(&ui, m));
    ASSERT_EQ(65537, ui);
    gcry_mpi_release(m);
    m = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_OPAQUE);
    ASSERT_NOT_NULL(m);
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(24, gcry_mpi_get_nbits(m));
    gcry_mpi_release(m);
    m = gcry_sexp_nth_mpi(l, 0, GCRYMPI_FMT_USG); /* token "e" scans as 0x65 */
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 'e'));
    gcry_mpi_release(m);
    ASSERT_NULL(gcry_sexp_nth_mpi(l, 5, GCRYMPI_FMT_USG));
    gcry_sexp_release(l);

    ASSERT_OK(gcry_sexp_extract_param(s, NULL,
                                      "ne&q/d?%s'curve'%#s'flags'%d'nbits'",
                                      &n, &e, &qbuf, &d, &curve, &flags,
                                      &nbits, NULL));
    ASSERT_NOT_NULL(n);
    ASSERT_NOT_NULL(e);
    ASSERT_NULL(d);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(n, 0xab));
    ASSERT_EQ(2, qbuf.len);
    ASSERT_MEM_EQ("\x04\x05", qbuf.data, 2);
    ASSERT_STR_EQ("Ed25519", curve);
    ASSERT_STR_EQ("eddsa comp", flags);
    ASSERT_EQ(2048, nbits);
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    gcry_free(qbuf.data);
    gcry_free(curve);
    gcry_free(flags);

    /* A missing mandatory parameter releases everything already found. */
    n = e = NULL;
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_sexp_extract_param(s, NULL, "nx", &n, &e,
                                                       NULL));
    ASSERT_NULL(n);
    ASSERT_NULL(e);

    /* Path drill-down. */
    gcry_sexp_release(s);
    ASSERT_OK(gcry_sexp_new(&s, "(private-key (rsa (n #11#) (e #03#)))", 0, 1));
    ASSERT_OK(gcry_sexp_extract_param(s, "private-key!rsa", "ne", &n, &e, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(n, 0x11));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(e, 3));
    gcry_mpi_release(n);
    gcry_mpi_release(e);
    n = NULL; /* Output MPIs must be NULL before the call. */
    ASSERT_ERR(GPG_ERR_NOT_FOUND,
               gcry_sexp_extract_param(s, "public-key", "n", &n, NULL));
    gcry_sexp_release(s);
}

TEST(canon_len)
{
    size_t erroff = 0;
    gcry_error_t err = 0;
    const char *good = "(3:foo3:bar)trailing";
    size_t n;

    n = gcry_sexp_canon_len((const unsigned char *)good, 0, &erroff, &err);
    ASSERT_EQ(12, n);
    ASSERT_OK(err);
    n = gcry_sexp_canon_len((const unsigned char *)good, 5, &erroff, &err);
    ASSERT_EQ(0, n);
    ASSERT_ERR(GPG_ERR_SEXP_STRING_TOO_LONG, err);
    n = gcry_sexp_canon_len((const unsigned char *)"3:foo", 0, &erroff, &err);
    ASSERT_EQ(0, n);
    ASSERT_ERR(GPG_ERR_SEXP_NOT_CANONICAL, err);
    n = gcry_sexp_canon_len((const unsigned char *)"(foo)", 0, &erroff, &err);
    ASSERT_ERR(GPG_ERR_SEXP_BAD_CHARACTER, err);
    ASSERT_EQ(1, erroff);

    /* gcry_sexp_new with length 0 and no autodetect uses canon_len. */
    {
        gcry_sexp_t s = NULL;
        char *c;

        ASSERT_OK(gcry_sexp_new(&s, good, 0, 0));
        c = canon(s);
        ASSERT_STR_EQ("(3:foo3:bar)", c);
        free(c);
        gcry_sexp_release(s);
    }
}

TEST(advanced_print)
{
    gcry_sexp_t s = NULL;
    char *a;

    ASSERT_OK(gcry_sexp_new(&s, "(a (b #0102#) \"quoted string\" 1:5)", 0, 1));
    a = advanced(s);
    ASSERT_STR_EQ("(a \n (b #0102#)\n \"quoted string\" \"5\")\n", a);
    free(a);
    gcry_sexp_release(s);

    /* Too small a buffer yields 0. */
    ASSERT_OK(gcry_sexp_new(&s, "(abc)", 0, 1));
    {
        char small[4];

        ASSERT_EQ(0, gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, small, sizeof small));
        ASSERT_EQ(8, gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, NULL, 0));
    }
    gcry_sexp_release(s);
}

TEST(list_construction)
{
    gcry_sexp_t a = NULL;
    gcry_sexp_t b = NULL;
    gcry_sexp_t r;
    char *c;

    ASSERT_OK(gcry_sexp_new(&a, "(a x)", 0, 1));
    ASSERT_OK(gcry_sexp_new(&b, "(b y)", 0, 1));

    r = gcry_sexp_cons(a, b);
    c = canon(r);
    ASSERT_STR_EQ("((1:a1:x)(1:b1:y))", c);
    free(c);
    gcry_sexp_release(r);

    r = gcry_sexp_append(a, b);
    c = canon(r);
    ASSERT_STR_EQ("(1:a1:x(1:b1:y))", c);
    free(c);
    gcry_sexp_release(r);

    r = gcry_sexp_prepend(a, b);
    c = canon(r);
    ASSERT_STR_EQ("((1:b1:y)1:a1:x)", c);
    free(c);
    gcry_sexp_release(r);

    r = gcry_sexp_vlist(a, b, NULL);
    c = canon(r);
    ASSERT_STR_EQ("((1:a1:x)(1:b1:y))", c);
    free(c);
    gcry_sexp_release(r);

    {
        gcry_sexp_t arr[3];

        arr[0] = b;
        arr[1] = a;
        arr[2] = NULL;
        r = gcry_sexp_alist(arr);
        c = canon(r);
        ASSERT_STR_EQ("((1:b1:y)(1:a1:x))", c);
        free(c);
        gcry_sexp_release(r);
    }

    gcry_sexp_release(a);
    gcry_sexp_release(b);
}

TEST(secure_memory_propagation)
{
    gcry_sexp_t s = NULL;
    gcry_mpi_t m = gcry_mpi_snew(0);
    char *secbuf;

    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    gcry_mpi_set_ui(m, 42);
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_SECURE));
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(d %m)", m));
    ASSERT_TRUE(gcry_is_secure(s));
    secbuf = gcry_sexp_nth_string(s, 1);
    ASSERT_TRUE(gcry_is_secure(secbuf));
    gcry_free(secbuf);
    gcry_sexp_release(s);
    gcry_mpi_release(m);

    ASSERT_OK(gcry_sexp_build(&s, NULL, "(d 1:x)"));
    ASSERT_FALSE(gcry_is_secure(s));
    gcry_sexp_release(s);
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(scan_tokens_and_canon_print);
    RUN_TEST(scan_hex_quoted_base64);
    RUN_TEST(scan_errors);
    RUN_TEST(build_with_format_directives);
    RUN_TEST(navigation);
    RUN_TEST(nth_mpi_and_extract_param);
    RUN_TEST(canon_len);
    RUN_TEST(advanced_print);
    RUN_TEST(list_construction);
    RUN_TEST(secure_memory_propagation);
    return TEST_RESULT();
}
