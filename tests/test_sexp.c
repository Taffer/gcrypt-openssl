#define _POSIX_C_SOURCE 200809L

#include <gcrypt.h>

#include <fcntl.h>
#include <unistd.h>

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

    /* cdr is upstream's oddity: the second element alone, wrapped. */
    l2 = gcry_sexp_cdr(l);
    ASSERT_EQ(1, gcry_sexp_length(l2));
    c = canon(l2);
    ASSERT_MEM_EQ("((1:n2:\x00\xab))", c, 11);
    free(c);
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

    /* Long argument lists grow the internal array. */
    r = gcry_sexp_vlist(a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a,
                        a, a, a, a, a, a, b, NULL);
    ASSERT_EQ(25, gcry_sexp_length(r));
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
    {
        gcry_buffer_t b = { 0, 0, 0, NULL };

        ASSERT_OK(gcry_sexp_extract_param(s, NULL, "&d", &b, NULL));
        ASSERT_EQ(1, b.len);
        ASSERT_TRUE(gcry_is_secure(b.data));
        gcry_free(b.data);
    }
    gcry_sexp_release(s);
    gcry_mpi_release(m);

    ASSERT_OK(gcry_sexp_build(&s, NULL, "(d 1:x)"));
    ASSERT_FALSE(gcry_is_secure(s));
    gcry_sexp_release(s);
}

/* Scan into S, failing the test on error. */
static gcry_sexp_t
scan(const char *text, size_t len)
{
    gcry_sexp_t s = NULL;

    if (gcry_sexp_sscan(&s, NULL, text, len ? len : strlen(text))) {
        return NULL;
    }

    return s;
}

/* Scan TEXT and compare the canonical form with EXPECT. */
static int
canon_equals(const char *text, size_t len, const char *expect,
             size_t expectlen)
{
    gcry_sexp_t s = scan(text, len);
    char *c;
    size_t n;
    int ok;

    if (!s) {
        return 0;
    }

    n = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, NULL, 0) - 1;
    c = canon(s);
    ok = n == expectlen && !memcmp(c, expect, expectlen);
    free(c);
    gcry_sexp_release(s);
    return ok;
}

TEST(quoted_string_escapes)
{
    size_t erroff = 0;
    gcry_sexp_t s = (gcry_sexp_t)1;

    /* Every single character escape. */
    ASSERT_TRUE(canon_equals("(a \"x\\b\\t\\v\\n\\f\\r\\\"\\'\\\\y\")", 0,
                             "(1:a11:x\b\t\v\n\f\r\"'\\y)", 19));
    /* A backslash before a line break continues the string. */
    ASSERT_TRUE(canon_equals("(a \"ab\\\r\ncd\")", 0, "(1:a4:abcd)", 11));
    ASSERT_TRUE(canon_equals("(a \"ab\\\n\rcd\")", 0, "(1:a4:abcd)", 11));
    ASSERT_TRUE(canon_equals("(a \"ab\\\rcd\")", 0, "(1:a4:abcd)", 11));
    /* Octal escapes need three digits, hex escapes two. */
    ASSERT_TRUE(canon_equals("(a \"\\101\\102\")", 0, "(1:a2:AB)", 9));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_QUOTATION,
               gcry_sexp_sscan(&s, &erroff, "(a \"\\x4\")", 9));
    ASSERT_EQ(5, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_BAD_QUOTATION,
               gcry_sexp_sscan(&s, &erroff, "(a \"\\01\")", 9));
    ASSERT_EQ(5, erroff);
    /* An unterminated string swallows the closing parenthesis. */
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_PAREN,
               gcry_sexp_sscan(&s, &erroff, "(a \"abc)", 8));
}

TEST(base64_tokens)
{
    size_t erroff = 0;
    gcry_sexp_t s = (gcry_sexp_t)1;

    ASSERT_TRUE(canon_equals("(a |aGVsbG8=|)", 0, "(1:a5:hello)", 12));
    ASSERT_TRUE(canon_equals("(a |YWI|)", 0, "(1:a2:ab)", 9));
    ASSERT_TRUE(canon_equals("(a |YQ==|)", 0, "(1:a1:a)", 8));
    ASSERT_TRUE(canon_equals("(a |abc0123+/9z|)", 0,
                             "(1:a8:\x69\xb7\x34\xd7\x6d\xfe\xff\xdc)", 15));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_CHARACTER,
               gcry_sexp_sscan(&s, &erroff, "(a |YQ-|)", 9));
    ASSERT_EQ(6, erroff);
}

/* Behaviour shared with upstream that looks like bugs but is relied on:
 * a bare token terminated by the end of the input is dropped, data after
 * the closing parenthesis is kept, cdr wraps sublists, and base64 decoding
 * stops at the first pad while still emitting a lone partial sextet. */
TEST(upstream_scanner_quirks)
{
    gcry_sexp_t s = (gcry_sexp_t)1;
    gcry_sexp_t t;
    size_t erroff = 999;
    char *c;

    /* A trailing token is not stored; "abc" alone scans to nothing. */
    ASSERT_OK(gcry_sexp_sscan(&s, &erroff, "abc", 3));
    ASSERT_NULL(s);
    ASSERT_TRUE(canon_equals("(a) b", 0, "(1:a)", 5));
    ASSERT_TRUE(canon_equals("(a)b", 0, "(1:a)", 5));
    /* The hint's content is just a token; the hint itself is not kept. */
    ASSERT_TRUE(canon_equals("(a) [h]x", 0, "(1:a)1:h", 8));
    /* ... but a delimiter after the token keeps it. */
    ASSERT_TRUE(canon_equals("abc (a)", 0, "3:abc(1:a)", 10));
    ASSERT_TRUE(canon_equals("(a) x(b)", 0, "(1:a)1:x(1:b)", 13));
    /* Other data after the closing parenthesis is kept as well. */
    ASSERT_TRUE(canon_equals("(a) 2:xy", 0, "(1:a)2:xy", 9));
    ASSERT_TRUE(canon_equals("(a) (b)", 0, "(1:a)(1:b)", 10));

    /* cdr of a list whose second element is a sublist. */
    ASSERT_OK(gcry_sexp_new(&s, "(a (b c) (d e) f)", 0, 1));
    t = gcry_sexp_cdr(s);
    ASSERT_NOT_NULL(t);
    ASSERT_EQ(1, gcry_sexp_length(t));
    c = canon(t);
    ASSERT_STR_EQ("((1:b1:c))", c);
    free(c);
    gcry_sexp_release(t);
    gcry_sexp_release(s);
    ASSERT_OK(gcry_sexp_new(&s, "((a b) c)", 0, 1));
    t = gcry_sexp_cdr(s);
    c = canon(t);
    ASSERT_STR_EQ("(1:c)", c);
    free(c);
    gcry_sexp_release(t);
    gcry_sexp_release(s);

    /* Base64: decoding stops at the first '=', what follows is ignored,
     * a pad after one sextet still yields a byte, "||" is refused. */
    ASSERT_TRUE(canon_equals("(a |YQ=X|)", 0, "(1:a1:a)", 8));
    ASSERT_TRUE(canon_equals("(a |YQ=Xz|)", 0, "(1:a1:a)", 8));
    ASSERT_TRUE(canon_equals("(a |YQ==YQ==|)", 0, "(1:a1:a)", 8));
    ASSERT_TRUE(canon_equals("(a |YQ|)", 0, "(1:a1:a)", 8));
    ASSERT_TRUE(canon_equals("(a |YWJ=|)", 0, "(1:a2:ab)", 9));
    ASSERT_TRUE(canon_equals("(a |YWJjZ|)", 0, "(1:a3:abc)", 10));
    ASSERT_TRUE(canon_equals("(a |Y|)", 0, "(1:a0:)", 7));
    ASSERT_TRUE(canon_equals("(a |=|)", 0, "(1:a0:)", 7));
    ASSERT_TRUE(canon_equals("(a |====|)", 0, "(1:a0:)", 7));
    ASSERT_TRUE(canon_equals("(a |Y=Q=|)", 0, "(1:a1:`)", 8));
    s = (gcry_sexp_t)1;
    erroff = 999;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_sscan(&s, &erroff, "(a ||)", 6));
    ASSERT_NULL(s);
    ASSERT_EQ(999, erroff); /* No offset is reported for this one. */
}

TEST(extract_param_string_errors)
{
    gcry_sexp_t s = NULL;
    char *str = NULL;
    int iv = -5;
    unsigned int uv = 5;
    gcry_mpi_t m = NULL;
    gcry_buffer_t buf;

    ASSERT_OK(gcry_sexp_new(&s, "(x (a) (b ()) (c (d e)) (f \"\"))", 0, 1));

    /* %s, %d and %u want a non-empty string value. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%s a", &str, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%s b", &str, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%s c", &str, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%s f", &str, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%d a", &iv, NULL));
    ASSERT_EQ(-5, iv);
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%d c", &iv, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%d f", &iv, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_sexp_extract_param(s, NULL, "%u a", &uv, NULL));
    ASSERT_EQ(5, uv);

    /* MPIs and buffers report INV_OBJ, except that an empty string is a
     * perfectly good zero MPI. */
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "a", &m,
                                                        NULL));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "/a", &m,
                                                        NULL));
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "f", &m, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    memset(&buf, 0, sizeof buf);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "&f", &buf,
                                                        NULL));
    ASSERT_NULL(buf.data);

    gcry_sexp_release(s);
}

TEST(length_prefix_variants)
{
    size_t erroff = 0;
    gcry_sexp_t s = (gcry_sexp_t)1;

    /* A length prefix in front of a quoted, hex or base64 token is
     * ignored. */
    ASSERT_TRUE(canon_equals("(a 5\"hi\")", 0, "(1:a2:hi)", 9));
    ASSERT_TRUE(canon_equals("(a 3#0102#)", 0, "(1:a2:\x01\x02)", 9));
    ASSERT_TRUE(canon_equals("(a 2|AQ==|)", 0, "(1:a1:\x01)", 8));
    ASSERT_TRUE(canon_equals("(a 3:abc)", 0, "(1:a3:abc)", 10));
    ASSERT_ERR(GPG_ERR_SEXP_INV_LEN_SPEC,
               gcry_sexp_sscan(&s, &erroff, "(a 3x)", 6));
    ASSERT_EQ(4, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_INV_LEN_SPEC,
               gcry_sexp_sscan(&s, &erroff, "(a 3 :abc)", 10));
    ASSERT_EQ(4, erroff);
    /* A length that reaches exactly to the end eats the parenthesis. */
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_PAREN,
               gcry_sexp_sscan(&s, &erroff, "(a 4:abc)", 9));
}

TEST(display_hints_and_punctuation)
{
    size_t erroff = 0;
    gcry_sexp_t s = (gcry_sexp_t)1;

    /* Display hints are parsed and dropped. */
    ASSERT_TRUE(canon_equals("(a [text]b)", 0, "(1:a4:text1:b)", 14));
    ASSERT_TRUE(canon_equals("(a [text] b)", 0, "(1:a4:text1:b)", 14));
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_DH,
               gcry_sexp_sscan(&s, &erroff, "(a [text)", 9));
    ASSERT_EQ(8, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_DH,
               gcry_sexp_sscan(&s, &erroff, "([a)", 4));
    ASSERT_EQ(3, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_UNEXPECTED_PUNC,
               gcry_sexp_sscan(&s, &erroff, "(a &b)", 6));
    ASSERT_EQ(3, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_UNEXPECTED_PUNC,
               gcry_sexp_sscan(&s, &erroff, "(a \\b)", 6));
    ASSERT_EQ(3, erroff);

    /* Hex strings may contain whitespace and may be empty. */
    ASSERT_TRUE(canon_equals("(a #01 02# b)", 0, "(1:a2:\x01\x02" "1:b)",
                             12));
    ASSERT_TRUE(canon_equals("(a ## b)", 0, "(1:a0:1:b)", 10));
    ASSERT_TRUE(canon_equals("(a #0 1# #a b c d#)", 0,
                             "(1:a1:\x01" "2:\xab\xcd)", 12));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_HEX_CHAR,
               gcry_sexp_sscan(&s, &erroff, "(a #0102)", 9));
    ASSERT_EQ(8, erroff);

    /* A NUL byte is a valid token character. */
    ASSERT_TRUE(canon_equals("(a b\0c)", 7, "(1:a3:b\0c)", 10));
}

TEST(canon_len_errors)
{
    static const struct {
        const char *text;
        gcry_err_code_t code;
        size_t off;
        size_t len;
    } tv[] = {
        { "(3x)", GPG_ERR_SEXP_INV_LEN_SPEC, 2, 0 },
        { "([a)", GPG_ERR_SEXP_BAD_CHARACTER, 2, 0 },
        { "(a", GPG_ERR_SEXP_BAD_CHARACTER, 1, 0 },
        { "(0:)", GPG_ERR_SEXP_ZERO_PREFIX, 1, 0 },
        { "(&)", GPG_ERR_SEXP_UNEXPECTED_PUNC, 1, 0 },
        { "(3:ab)", GPG_ERR_SEXP_BAD_CHARACTER, 6, 0 },
        { "(2:ab)x", 0, 0, 6 },
        { "((1:a)(1:b))", 0, 0, 12 },
    };
    size_t i;
    size_t erroff;
    gcry_error_t err;
    size_t n;

    for (i = 0; i < sizeof tv / sizeof tv[0]; i++) {
        erroff = 99;
        err = 99;
        n = gcry_sexp_canon_len((const unsigned char *)tv[i].text, 0,
                                &erroff, &err);
        ASSERT_EQ(tv[i].len, n);
        ASSERT_ERR(tv[i].code, err);

        if (tv[i].code) {
            ASSERT_EQ(tv[i].off, erroff);
        }
    }

    /* With an explicit length the string may not run past it. */
    n = gcry_sexp_canon_len((const unsigned char *)"(3:abc)", 7, &erroff,
                            &err);
    ASSERT_EQ(7, n);
    ASSERT_OK(err);
    n = gcry_sexp_canon_len((const unsigned char *)"(3:abc)", 6, &erroff,
                            &err);
    ASSERT_EQ(0, n);
    ASSERT_ERR(GPG_ERR_SEXP_STRING_TOO_LONG, err);
    ASSERT_EQ(6, erroff);
    n = gcry_sexp_canon_len((const unsigned char *)"(3:abc)", 4, &erroff,
                            &err);
    ASSERT_ERR(GPG_ERR_SEXP_STRING_TOO_LONG, err);
    ASSERT_EQ(2, erroff);
    /* Display hints and multi-digit lengths. */
    ASSERT_EQ(10, gcry_sexp_canon_len((const unsigned char *)"([1:h]1:a)", 0,
                                      &erroff, &err));
    ASSERT_EQ(15, gcry_sexp_canon_len((const unsigned char *)"(10:abcdefghij)",
                                      0, &erroff, &err));
    ASSERT_EQ(0, gcry_sexp_canon_len((const unsigned char *)"(]", 0, &erroff,
                                     &err));
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_DH, err);
    ASSERT_EQ(1, erroff);
    ASSERT_EQ(0, gcry_sexp_canon_len((const unsigned char *)"([1:h)", 0,
                                     &erroff, &err));
    ASSERT_ERR(GPG_ERR_SEXP_UNMATCHED_DH, err);
    ASSERT_EQ(5, erroff);

    /* NULL is simply zero length; the optional outputs may be omitted. */
    ASSERT_EQ(0, gcry_sexp_canon_len(NULL, 0, NULL, NULL));
    ASSERT_EQ(5, gcry_sexp_canon_len((const unsigned char *)"(1:a)", 0,
                                     NULL, NULL));
}

TEST(build_edge_cases)
{
    gcry_sexp_t s = NULL;
    gcry_sexp_t inner = NULL;
    gcry_mpi_t opaque = gcry_mpi_set_opaque_copy(NULL, "\x01\x02\x03", 24);
    gcry_mpi_t zero = gcry_mpi_new(0);
    size_t erroff = 99;
    char *c;

    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_build(&s, &erroff, "(a %b)", -1,
                                                "x"));
    ASSERT_EQ(4, erroff);
    ASSERT_ERR(GPG_ERR_SEXP_INV_LEN_SPEC,
               gcry_sexp_build(&s, &erroff, "(a %%)"));
    ASSERT_EQ(4, erroff);

    /* A zero length %b may come with a NULL pointer. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a %b)", 0, (char *)NULL));
    c = canon(s);
    ASSERT_STR_EQ("(1:a0:)", c);
    free(c);
    gcry_sexp_release(s);

    /* A NULL %S inserts nothing. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a %S)", (gcry_sexp_t)NULL));
    c = canon(s);
    ASSERT_STR_EQ("(1:a)", c);
    free(c);
    gcry_sexp_release(s);

    /* Opaque MPIs are inserted as their raw bytes by %m and %M. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a %m %M)", opaque, opaque));
    c = canon(s);
    ASSERT_MEM_EQ("(1:a3:\x01\x02\x03" "3:\x01\x02\x03)", c, 15);
    free(c);
    gcry_sexp_release(s);

    /* Zero is the empty string in both formats. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a %m %M)", zero, zero));
    c = canon(s);
    ASSERT_STR_EQ("(1:a0:0:)", c);
    free(c);
    gcry_sexp_release(s);

    /* Integer extremes. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a %d %u)", -2147483647 - 1,
                              4294967295u));
    c = canon(s);
    ASSERT_STR_EQ("(1:a11:-214748364810:4294967295)", c);
    free(c);
    gcry_sexp_release(s);

    /* A lone string at the top level and nesting through the format. */
    ASSERT_OK(gcry_sexp_build(&s, NULL, "%s", ""));
    c = canon(s);
    ASSERT_STR_EQ("0:", c);
    free(c);
    gcry_sexp_release(s);
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a (b %s))", "x y"));
    c = canon(s);
    ASSERT_STR_EQ("(1:a(1:b3:x y))", c);
    free(c);
    gcry_sexp_release(s);

    /* %S of a list is spliced in as one element. */
    ASSERT_OK(gcry_sexp_build(&inner, NULL, "(k v)"));
    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a %S %S)", inner, inner));
    c = canon(s);
    ASSERT_STR_EQ("(1:a(1:k1:v)(1:k1:v))", c);
    free(c);
    gcry_sexp_release(s);
    gcry_sexp_release(inner);

    gcry_mpi_release(opaque);
    gcry_mpi_release(zero);
}

TEST(navigation_edges)
{
    gcry_sexp_t s = scan("(a (b c) #81# \"\" d)", 0);
    gcry_sexp_t one = scan("(a)", 0);
    gcry_sexp_t t;
    gcry_mpi_t m;
    const char *d;
    size_t n;
    char *c;

    ASSERT_NOT_NULL(s);
    ASSERT_NOT_NULL(one);

    /* nth wraps data elements in a list of their own. */
    t = gcry_sexp_nth(s, 3);
    c = canon(t);
    ASSERT_STR_EQ("(0:)", c);
    free(c);
    gcry_sexp_release(t);
    t = gcry_sexp_nth(s, 2);
    c = canon(t);
    ASSERT_MEM_EQ("(1:\x81)", c, 5);
    free(c);
    gcry_sexp_release(t);

    /* The data accessors refuse list elements and index overruns. */
    n = 99;
    ASSERT_NULL(gcry_sexp_nth_data(s, 1, &n));
    ASSERT_EQ(0, n);
    d = gcry_sexp_nth_data(s, 3, &n);
    ASSERT_NOT_NULL(d);
    ASSERT_EQ(0, n);
    ASSERT_NULL(gcry_sexp_nth_string(s, 1));
    ASSERT_NULL(gcry_sexp_nth_string(s, 3)); /* An empty value is NULL. */
    n = 77;
    ASSERT_NULL(gcry_sexp_nth_buffer(s, 1, &n));
    ASSERT_EQ(0, n);
    ASSERT_NULL(gcry_sexp_nth_buffer(s, 3, &n));
    ASSERT_NULL(gcry_sexp_nth_mpi(s, 1, GCRYMPI_FMT_USG));

    /* MPI format 0 means STD, so 0x81 is negative. */
    m = gcry_sexp_nth_mpi(s, 2, 0);
    ASSERT_NOT_NULL(m);
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    ASSERT_TRUE(gcry_mpi_cmp_ui(m, 0) < 0);
    gcry_mpi_abs(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x7f));
    gcry_mpi_release(m);
    m = gcry_sexp_nth_mpi(s, 3, GCRYMPI_FMT_USG);
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);

    /* car/cdr on degenerate lists. */
    ASSERT_NULL(gcry_sexp_car(NULL));
    ASSERT_NULL(gcry_sexp_cdr(NULL));
    ASSERT_NULL(gcry_sexp_cdr(one));
    ASSERT_NULL(gcry_sexp_cadr(one));
    t = gcry_sexp_car(one);
    c = canon(t);
    ASSERT_STR_EQ("(1:a)", c);
    free(c);
    gcry_sexp_release(t);

    gcry_sexp_release(s);
    gcry_sexp_release(one);

    /* find_token matches whole tokens at the head of sublists only. */
    s = scan("(a (bb x) (b y) ((c) z))", 0);
    ASSERT_NOT_NULL(s);
    t = gcry_sexp_find_token(s, "b", 0);
    ASSERT_NOT_NULL(t);
    c = canon(t);
    ASSERT_STR_EQ("(1:b1:y)", c);
    free(c);
    gcry_sexp_release(t);
    ASSERT_NULL(gcry_sexp_find_token(s, "bbb", 0));
    /* Nested lists are searched too. */
    t = gcry_sexp_find_token(s, "c", 0);
    ASSERT_NOT_NULL(t);
    c = canon(t);
    ASSERT_STR_EQ("(1:c)", c);
    free(c);
    gcry_sexp_release(t);
    ASSERT_NULL(gcry_sexp_find_token(s, "z", 0));
    /* An explicit length selects the prefix of the token string. */
    t = gcry_sexp_find_token(s, "bbx", 2);
    ASSERT_NOT_NULL(t);
    c = canon(t);
    ASSERT_STR_EQ("(2:bb1:x)", c);
    free(c);
    gcry_sexp_release(t);
    t = gcry_sexp_find_token(s, "a", 0);
    ASSERT_NOT_NULL(t);
    ASSERT_EQ(4, gcry_sexp_length(t));
    gcry_sexp_release(t);
    ASSERT_NULL(gcry_sexp_find_token(NULL, "a", 0));
    gcry_sexp_release(s);
}

TEST(create_and_new_edges)
{
    gcry_sexp_t s = NULL;
    char *buf;

    /* gcry_sexp_create hands the buffer to the release function. */
    buf = gcry_malloc(10);
    ASSERT_NOT_NULL(buf);
    memcpy(buf, "(1:a1:b)", 9);
    ASSERT_OK(gcry_sexp_create(&s, buf, 8, 0, gcry_free));
    ASSERT_EQ(2, gcry_sexp_length(s));
    gcry_sexp_release(s);
    s = NULL;
    buf = gcry_malloc(10);
    ASSERT_NOT_NULL(buf);
    memcpy(buf, "(1:a1:b)", 9);
    ASSERT_OK(gcry_sexp_create(&s, buf, 0, 0, gcry_free));
    ASSERT_EQ(2, gcry_sexp_length(s));
    gcry_sexp_release(s);
    s = NULL;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_create(&s, NULL, 0, 0, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_new(NULL, "(a)", 3, 1));

    /* Without autodetection a zero length means canonical input. */
    ASSERT_ERR(GPG_ERR_SEXP_BAD_CHARACTER, gcry_sexp_new(&s, "(a b", 0, 0));
    ASSERT_ERR(GPG_ERR_SEXP_NOT_CANONICAL, gcry_sexp_new(&s, "3:abc", 0, 0));
    ASSERT_ERR(GPG_ERR_SEXP_BAD_CHARACTER, gcry_sexp_new(&s, "(a b)", 0, 0));
    ASSERT_OK(gcry_sexp_new(&s, "  (a b)", 7, 1));
    ASSERT_EQ(2, gcry_sexp_length(s));
    gcry_sexp_release(s);
}

TEST(print_formats)
{
    gcry_sexp_t s = scan("(a \"q\\\"x\\\\y\\n\" #80# #01# 1:5 \"with space\""
                         " (\"\") #7f# abc \"\\t\\b\\v\\f\\r\" #7e# #00# (x))", 0);
    static const char expect_adv[] =
        "(a \"q\\\"x\\\\y\\n\" #80# #01# \"5\" \"with space\" \n"
        " (\"\")\n"
        " #7F# abc \"\\t\\b\\v\\f\\r\" \"~\" #00# \n"
        " (x)\n"
        " )\n";
    static const char expect_default[] =
        "(1:a6:q\"x\\y\n1:\x80" "1:\x01" "1:510:with space\n"
        " (0:)\n"
        " 1:\x7f" "3:abc5:\t\b\v\f\r1:~1:\0\n"
        " (1:x)\n"
        " )\n";
    char *a;
    char buf[128];
    size_t n;
    size_t i;

    ASSERT_NOT_NULL(s);
    a = advanced(s);
    ASSERT_STR_EQ(expect_adv, a);
    free(a);

    /* The default format is canonical data with advanced layout. */
    n = gcry_sexp_sprint(s, GCRYSEXP_FMT_DEFAULT, NULL, 0);
    ASSERT_EQ(sizeof expect_default, n);
    n = gcry_sexp_sprint(s, GCRYSEXP_FMT_DEFAULT, buf, sizeof buf);
    ASSERT_EQ(sizeof expect_default - 1, n);
    ASSERT_MEM_EQ(expect_default, buf, n);

    /* Every short buffer is refused, whatever the format. */
    for (i = 1; i < sizeof expect_adv; i++) {
        ASSERT_EQ(0, gcry_sexp_sprint(s, GCRYSEXP_FMT_ADVANCED, buf, i));
    }

    n = gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, NULL, 0);

    for (i = 1; i < n; i++) {
        ASSERT_EQ(0, gcry_sexp_sprint(s, GCRYSEXP_FMT_CANON, buf, i));
    }

    gcry_sexp_release(s);

    /* A single quote is escaped too. */
    s = scan("(a \"it's\")", 0);
    ASSERT_NOT_NULL(s);
    a = advanced(s);
    ASSERT_STR_EQ("(a \"it\\'s\")\n", a);
    free(a);
    gcry_sexp_release(s);

    /* A NULL list prints as the empty list. */
    ASSERT_EQ(3, gcry_sexp_sprint(NULL, GCRYSEXP_FMT_CANON, NULL, 0));
    n = gcry_sexp_sprint(NULL, GCRYSEXP_FMT_CANON, buf, sizeof buf);
    ASSERT_EQ(2, n);
    ASSERT_MEM_EQ("()", buf, 2);
    n = gcry_sexp_sprint(NULL, GCRYSEXP_FMT_ADVANCED, buf, sizeof buf);
    ASSERT_EQ(3, n);
    ASSERT_MEM_EQ("()\n", buf, 3);

    /* Dumping goes to the log; silence it for the duration. */
    s = scan("(a b)", 0);
    fflush(stderr);
    {
        int saved = dup(2);
        int devnull = open("/dev/null", O_WRONLY);

        if (saved >= 0 && devnull >= 0) {
            dup2(devnull, 2);
        }

        gcry_sexp_dump(s);
        gcry_sexp_dump(NULL);
        fflush(stderr);

        if (saved >= 0) {
            dup2(saved, 2);
            close(saved);
        }

        if (devnull >= 0) {
            close(devnull);
        }
    }
    gcry_sexp_release(s);
}

TEST(extract_param_edges)
{
    gcry_sexp_t s = scan("(k (n #81#) (e 3:257) (s \"hi there\")"
                         " (flags a (x y) b) (empty) (z \"\") (list (a b)))",
                         0);
    gcry_mpi_t m = NULL;
    gcry_mpi_t arr[21];
    int d = 5;
    long ld = 5;
    unsigned int u = 7;
    unsigned long lu = 7;
    size_t zu = 7;
    char *str = (char *)1;
    gcry_buffer_t buf = { 0, 0, 0, NULL };
    unsigned char raw[4];
    size_t i;

    ASSERT_NOT_NULL(s);

    /* Integer conversions in every width. */
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "%d'e'%ld'e'%u'e'%lu'e'%zu'e'",
                                      &d, &ld, &u, &lu, &zu, NULL));
    ASSERT_EQ(257, d);
    ASSERT_EQ(257, ld);
    ASSERT_EQ(257, u);
    ASSERT_EQ(257, lu);
    ASSERT_EQ(257, zu);

    /* Optional parameters that are missing get well defined values. */
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "%d'q'?%s'q'?%u'q'?&'q'?", &d,
                                      &str, &u, &buf, NULL));
    ASSERT_EQ(0, d);
    ASSERT_NULL(str);
    ASSERT_EQ(0, u);
    ASSERT_EQ(0, buf.len);
    m = (gcry_mpi_t)1;
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "+q?", &m, NULL));
    ASSERT_NULL(m);

    /* Sign handling and opaque extraction. */
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "-n", &m, NULL));
    ASSERT_TRUE(gcry_mpi_is_neg(m));
    gcry_mpi_release(m);
    m = NULL;
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "+n", &m, NULL));
    ASSERT_FALSE(gcry_mpi_is_neg(m));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0x81));
    gcry_mpi_release(m);
    m = NULL;
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "/n", &m, NULL));
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_OPAQUE));
    ASSERT_EQ(8, gcry_mpi_get_nbits(m));
    gcry_mpi_release(m);
    m = NULL;

    /* %#s joins all values, sublists become "()"; an empty list is "". */
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "%#s'flags'", &str, NULL));
    ASSERT_STR_EQ("a () b", str);
    gcry_free(str);
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "%#s'empty'", &str, NULL));
    ASSERT_STR_EQ("", str);
    gcry_free(str);

    /* Values that are not data cannot become MPIs or buffers. */
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "'list'",
                                                        &m, NULL));
    ASSERT_NULL(m);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "'empty'",
                                                        &m, NULL));
    ASSERT_NULL(m);
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "'z'", &m, NULL));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 0));
    gcry_mpi_release(m);
    m = NULL;

    /* Caller supplied buffers. */
    buf.size = sizeof raw;
    buf.off = 0;
    buf.len = 0;
    buf.data = raw;
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "&'n'", &buf, NULL));
    ASSERT_EQ(1, buf.len);
    ASSERT_EQ(0x81, raw[0]);
    buf.off = 3;
    buf.len = 0;
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT,
               gcry_sexp_extract_param(s, NULL, "&'s'", &buf, NULL));
    ASSERT_EQ(0, buf.len);
    buf.off = 0;
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "&'z'",
                                                        &buf, NULL));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "&'empty'",
                                                        &buf, NULL));
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_sexp_extract_param(s, NULL, "&'list'",
                                                        &buf, NULL));

    /* Malformed parameter lists and paths. */
    ASSERT_ERR(GPG_ERR_SYNTAX, gcry_sexp_extract_param(s, NULL,
                                                       "'unterminated", &m,
                                                       NULL));
    ASSERT_ERR(GPG_ERR_SYNTAX, gcry_sexp_extract_param(s, NULL, "''", &m,
                                                       NULL));
    ASSERT_ERR(GPG_ERR_MISSING_VALUE, gcry_sexp_extract_param(s, NULL, "n",
                                                              NULL, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_sexp_extract_param(s, NULL, "n", &m, &m,
                                                        NULL));
    gcry_mpi_release(m);
    m = NULL;
    ASSERT_ERR(GPG_ERR_NOT_FOUND, gcry_sexp_extract_param(s, "!k", "n", &m,
                                                          NULL));
    ASSERT_ERR(GPG_ERR_NOT_FOUND, gcry_sexp_extract_param(s, "k!nope", "n",
                                                          &m, NULL));
    ASSERT_OK(gcry_sexp_extract_param(s, "k", "n", &m, NULL));
    ASSERT_NOT_NULL(m);
    gcry_mpi_release(m);
    m = NULL;

    /* A NULL S-expression is an empty list. */
    ASSERT_OK(gcry_sexp_extract_param(NULL, NULL, "n?", &m, NULL));
    ASSERT_NULL(m);
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_sexp_extract_param(NULL, NULL, "n", &m,
                                                       NULL));

    /* Optional wide integers. */
    ld = 5;
    lu = 5;
    zu = 5;
    ASSERT_OK(gcry_sexp_extract_param(s, NULL, "%ld'q'?%lu'q'?%zu'q'?", &ld,
                                      &lu, &zu, NULL));
    ASSERT_EQ(0, ld);
    ASSERT_EQ(0, lu);
    ASSERT_EQ(0, zu);

    /* On failure everything extracted so far is released again. */
    buf.size = 0;
    buf.off = 0;
    buf.len = 0;
    buf.data = NULL;
    str = NULL;
    ASSERT_ERR(GPG_ERR_NO_OBJ,
               gcry_sexp_extract_param(s, NULL, "&'n'%s'e'+'nope'", &buf,
                                       &str, &m, NULL));
    ASSERT_NULL(buf.data);
    ASSERT_EQ(0, buf.size);
    ASSERT_EQ(0, buf.len);
    ASSERT_NULL(str);
    ASSERT_NULL(m);
    buf.size = sizeof raw;
    buf.data = raw;
    ASSERT_ERR(GPG_ERR_NO_OBJ, gcry_sexp_extract_param(s, NULL, "&'n''nope'",
                                                       &buf, &m, NULL));
    ASSERT_EQ(0, buf.len);

    /* At most 20 parameters. */
    memset(arr, 0, sizeof arr);
    ASSERT_ERR(GPG_ERR_LIMIT_REACHED,
               gcry_sexp_extract_param(s, NULL, "nnnnnnnnnnnnnnnnnnnnn",
                                       &arr[0], &arr[1], &arr[2], &arr[3],
                                       &arr[4], &arr[5], &arr[6], &arr[7],
                                       &arr[8], &arr[9], &arr[10], &arr[11],
                                       &arr[12], &arr[13], &arr[14], &arr[15],
                                       &arr[16], &arr[17], &arr[18], &arr[19],
                                       &arr[20], NULL));

    for (i = 0; i < sizeof arr / sizeof arr[0]; i++) {
        gcry_mpi_release(arr[i]);
    }

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
    RUN_TEST(quoted_string_escapes);
    RUN_TEST(base64_tokens);
    RUN_TEST(upstream_scanner_quirks);
    RUN_TEST(extract_param_string_errors);
    RUN_TEST(length_prefix_variants);
    RUN_TEST(display_hints_and_punctuation);
    RUN_TEST(canon_len_errors);
    RUN_TEST(build_edge_cases);
    RUN_TEST(navigation_edges);
    RUN_TEST(create_and_new_edges);
    RUN_TEST(print_formats);
    RUN_TEST(extract_param_edges);
    return TEST_RESULT();
}
