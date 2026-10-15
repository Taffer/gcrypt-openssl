/* Tests of the elliptic curve context API (gcry_mpi_ec_*). */
#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

static gcry_mpi_t
hex_mpi(const char *hex)
{
    gcry_mpi_t m = NULL;

    if (gcry_mpi_scan(&m, GCRYMPI_FMT_HEX, hex, 0, NULL)) {
        return NULL;
    }

    return m;
}

/* The bytes of HEX as an opaque MPI. */
static gcry_mpi_t
hex_opaque(const char *hex)
{
    size_t n = strlen(hex) / 2;
    unsigned char *buf = gcry_malloc(n);
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned int v;

        sscanf(hex + 2 * i, "%2x", &v);
        buf[i] = (unsigned char)v;
    }

    return gcry_mpi_set_opaque(NULL, buf, (unsigned int)n * 8);
}

static int
mpi_eq_hex(gcry_mpi_t m, const char *hex)
{
    gcry_mpi_t h = hex_mpi(hex);
    int eq = h && m && gcry_mpi_cmp(m, h) == 0;

    gcry_mpi_release(h);
    return eq;
}

static int
opaque_eq_hex(gcry_mpi_t m, const char *hex)
{
    gcry_mpi_t h = hex_opaque(hex);
    int eq = m && gcry_mpi_cmp(m, h) == 0;

    gcry_mpi_release(h);
    return eq;
}

TEST(p256_parameters)
{
    gcry_ctx_t ctx = NULL;
    gcry_mpi_t m;

    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));
    ASSERT_NOT_NULL(ctx);

    m = gcry_mpi_ec_get_mpi("p", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(m,
                           "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
    gcry_mpi_release(m);
    m = gcry_mpi_ec_get_mpi("a", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(m,
                           "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"));
    gcry_mpi_release(m);
    m = gcry_mpi_ec_get_mpi("b", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(m,
                           "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"));
    gcry_mpi_release(m);
    m = gcry_mpi_ec_get_mpi("n", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(m,
                           "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
    gcry_mpi_release(m);
    m = gcry_mpi_ec_get_mpi("g.x", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(m,
                           "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
    gcry_mpi_release(m);
    m = gcry_mpi_ec_get_mpi("g.y", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(m,
                           "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
    gcry_mpi_release(m);
    m = gcry_mpi_ec_get_mpi("h", ctx, 1);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(m, 1));
    gcry_mpi_release(m);

    /* Non-copied values are internal pointers; constants for "h". */
    m = gcry_mpi_ec_get_mpi("h", ctx, 0);
    ASSERT_TRUE(m == GCRYMPI_CONST_ONE);
    m = gcry_mpi_ec_get_mpi("p", ctx, 0);
    ASSERT_TRUE(m == gcry_mpi_ec_get_mpi("p", ctx, 0));

    /* "g" is the encoded generator. */
    m = gcry_mpi_ec_get_mpi("g", ctx, 1);
    ASSERT_NOT_NULL(m);
    ASSERT_TRUE(gcry_mpi_get_flag(m, GCRYMPI_FLAG_OPAQUE));
    ASSERT_TRUE(opaque_eq_hex(m,
                              "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
                              "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
    gcry_mpi_release(m);

    ASSERT_NULL(gcry_mpi_ec_get_mpi("d", ctx, 1));
    ASSERT_NULL(gcry_mpi_ec_get_mpi("q", ctx, 1));
    ASSERT_NULL(gcry_mpi_ec_get_mpi("zz", ctx, 1));
    gcry_ctx_release(ctx);

    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_mpi_ec_new(&ctx, NULL, "NIST P-999"));
    ASSERT_NULL(ctx);
}

/* RFC 6979 A.2.5 key on P-256. */
#define P256_D "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
#define P256_QX "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
#define P256_QY "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"

TEST(p256_scalar_multiplication)
{
    gcry_ctx_t ctx = NULL;
    gcry_mpi_t d = hex_mpi(P256_D);
    gcry_mpi_point_t G;
    gcry_mpi_point_t Q = gcry_mpi_point_new(0);
    gcry_mpi_point_t Q2;
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);
    gcry_mpi_t q;

    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));
    G = gcry_mpi_ec_get_point("g", ctx, 1);
    ASSERT_NOT_NULL(G);

    gcry_mpi_ec_mul(Q, d, G, ctx);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, Q, ctx));
    ASSERT_TRUE(mpi_eq_hex(x, P256_QX));
    ASSERT_TRUE(mpi_eq_hex(y, P256_QY));
    ASSERT_TRUE(gcry_mpi_ec_curve_point(Q, ctx));

    /* Setting d derives the same public key. */
    ASSERT_OK(gcry_mpi_ec_set_mpi("d", d, ctx));
    Q2 = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q2);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, Q2, ctx));
    ASSERT_TRUE(mpi_eq_hex(x, P256_QX));
    q = gcry_mpi_ec_get_mpi("q", ctx, 1);
    ASSERT_TRUE(opaque_eq_hex(q, "04" P256_QX P256_QY));
    gcry_mpi_release(q);
    q = gcry_mpi_ec_get_mpi("q.y", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(q, P256_QY));
    gcry_mpi_release(q);
    gcry_mpi_point_release(Q2);

    /* 2G == G + G, G - G == infinity. */
    {
        gcry_mpi_point_t A = gcry_mpi_point_new(0);
        gcry_mpi_point_t B = gcry_mpi_point_new(0);
        gcry_mpi_t ax = gcry_mpi_new(0);
        gcry_mpi_t bx = gcry_mpi_new(0);

        gcry_mpi_ec_dup(A, G, ctx);
        gcry_mpi_ec_add(B, G, G, ctx);
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(ax, NULL, A, ctx));
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(bx, NULL, B, ctx));
        ASSERT_EQ(0, gcry_mpi_cmp(ax, bx));
        gcry_mpi_ec_sub(B, G, G, ctx);
        ASSERT_EQ(-1, gcry_mpi_ec_get_affine(ax, NULL, B, ctx));
        gcry_mpi_point_get(NULL, NULL, ax, B);
        ASSERT_EQ(0, gcry_mpi_cmp_ui(ax, 0));
        /* Adding infinity is neutral. */
        gcry_mpi_ec_add(A, G, B, ctx);
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(ax, NULL, A, ctx));
        gcry_mpi_point_get(bx, NULL, NULL, G);
        ASSERT_EQ(0, gcry_mpi_cmp(ax, bx));
        gcry_mpi_point_release(A);
        gcry_mpi_point_release(B);
        gcry_mpi_release(ax);
        gcry_mpi_release(bx);
    }

    /* A point off the curve is rejected. */
    gcry_mpi_set_ui(x, 5);
    gcry_mpi_set_ui(y, 7);
    gcry_mpi_point_set(Q, x, y, GCRYMPI_CONST_ONE);
    ASSERT_FALSE(gcry_mpi_ec_curve_point(Q, ctx));

    gcry_mpi_point_release(G);
    gcry_mpi_point_release(Q);
    gcry_mpi_release(x);
    gcry_mpi_release(y);
    gcry_mpi_release(d);
    gcry_ctx_release(ctx);
}

TEST(point_encodings)
{
    gcry_ctx_t ctx = NULL;
    gcry_mpi_point_t P = gcry_mpi_point_new(0);
    gcry_mpi_t enc;
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);

    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));

    enc = hex_opaque("04" P256_QX P256_QY);
    ASSERT_OK(gcry_mpi_ec_decode_point(P, enc, ctx));
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, P, ctx));
    ASSERT_TRUE(mpi_eq_hex(x, P256_QX));
    ASSERT_TRUE(mpi_eq_hex(y, P256_QY));
    gcry_mpi_release(enc);

    /* Compressed, y is odd. */
    enc = hex_opaque("03" P256_QX);
    ASSERT_OK(gcry_mpi_ec_decode_point(P, enc, ctx));
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, P, ctx));
    ASSERT_TRUE(mpi_eq_hex(y, P256_QY));
    gcry_mpi_release(enc);

    /* The same encoding as a plain number works too. */
    enc = hex_mpi("04" P256_QX P256_QY);
    ASSERT_OK(gcry_mpi_ec_decode_point(P, enc, ctx));
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, P, ctx));
    ASSERT_TRUE(mpi_eq_hex(x, P256_QX));
    gcry_mpi_release(enc);

    enc = hex_opaque("05" P256_QX P256_QY);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_ec_decode_point(P, enc, ctx));
    gcry_mpi_release(enc);

    /* Setting "q" decodes; a bogus value clears it. */
    enc = hex_opaque("04" P256_QX P256_QY);
    ASSERT_OK(gcry_mpi_ec_set_mpi("q", enc, ctx));
    gcry_mpi_release(enc);
    enc = gcry_mpi_ec_get_mpi("q.x", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(enc, P256_QX));
    gcry_mpi_release(enc);
    enc = hex_opaque("0401");
    ASSERT_TRUE(gcry_mpi_ec_set_mpi("q", enc, ctx) != 0);
    ASSERT_NULL(gcry_mpi_ec_get_mpi("q", ctx, 1));
    gcry_mpi_release(enc);
    ASSERT_ERR(GPG_ERR_UNKNOWN_NAME, gcry_mpi_ec_set_mpi("zz", x, ctx));

    gcry_mpi_point_release(P);
    gcry_mpi_release(x);
    gcry_mpi_release(y);
    gcry_ctx_release(ctx);
}

TEST(context_from_key_and_get_sexp)
{
    gcry_sexp_t key = NULL;
    gcry_sexp_t out = NULL;
    gcry_ctx_t ctx = NULL;
    gcry_mpi_t d;
    gcry_mpi_t q;
    size_t n;
    char *buf;

    ASSERT_OK(gcry_sexp_build(&key, NULL,
                              "(private-key (ecc (curve \"NIST P-256\")"
                              " (q #04" P256_QX P256_QY "#) (d #" P256_D "#)))"));
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    d = gcry_mpi_ec_get_mpi("d", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(d, P256_D));
    gcry_mpi_release(d);
    q = gcry_mpi_ec_get_mpi("q.x", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(q, P256_QX));
    gcry_mpi_release(q);

    ASSERT_OK(gcry_pubkey_get_sexp(&out, GCRY_PK_GET_PUBKEY, ctx));
    n = gcry_sexp_sprint(out, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = malloc(n);
    gcry_sexp_sprint(out, GCRYSEXP_FMT_ADVANCED, buf, n);
    ASSERT_TRUE(strstr(buf, "(public-key") == buf);
    ASSERT_TRUE(strstr(buf, "(ecc") != NULL);
    ASSERT_TRUE(strstr(buf, "(d ") == NULL);
    ASSERT_TRUE(strstr(buf, "(q #04" P256_QX P256_QY "#)") != NULL);
    free(buf);
    gcry_sexp_release(out);

    ASSERT_OK(gcry_pubkey_get_sexp(&out, GCRY_PK_GET_SECKEY, ctx));
    n = gcry_sexp_sprint(out, GCRYSEXP_FMT_ADVANCED, NULL, 0);
    buf = malloc(n);
    gcry_sexp_sprint(out, GCRYSEXP_FMT_ADVANCED, buf, n);
    ASSERT_TRUE(strstr(buf, "(private-key") == buf);
    ASSERT_TRUE(strstr(buf, "(d #00" P256_D "#)") != NULL);
    free(buf);
    gcry_sexp_release(out);

    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_pubkey_get_sexp(&out, 7, ctx));
    ASSERT_ERR(GPG_ERR_NO_CRYPT_CTX, gcry_pubkey_get_sexp(&out, 0, NULL));
    gcry_ctx_release(ctx);

    /* A public key only context cannot give the secret key. */
    gcry_sexp_release(key);
    ASSERT_OK(gcry_sexp_build(&key, NULL,
                              "(public-key (ecc (curve secp256r1)"
                              " (q #04" P256_QX P256_QY "#)))"));
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    ASSERT_ERR(GPG_ERR_NO_SECKEY, gcry_pubkey_get_sexp(&out, GCRY_PK_GET_SECKEY,
                                                       ctx));
    gcry_ctx_release(ctx);
    gcry_sexp_release(key);

    /* Explicit parameters without a curve name. */
    ASSERT_OK(gcry_sexp_build(&key, NULL,
                              "(public-key (ecc"
                              " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
                              " (a #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC#)"
                              " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
                              " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                              "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
                              " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
                              " (h #01#)"
                              " (q #04" P256_QX P256_QY "#)))"));
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    q = gcry_mpi_ec_get_mpi("q.x", ctx, 1);
    ASSERT_TRUE(mpi_eq_hex(q, P256_QX));
    gcry_mpi_release(q);
    ASSERT_TRUE(gcry_mpi_ec_curve_point(gcry_mpi_ec_get_point("q", ctx, 1), ctx));
    gcry_ctx_release(ctx);
    gcry_sexp_release(key);
}

/* RFC 8032 section 7.1 test 1. */
#define ED25519_SK "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
#define ED25519_PK "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

TEST(ed25519_context)
{
    gcry_sexp_t key = NULL;
    gcry_ctx_t ctx = NULL;
    gcry_mpi_t q;
    gcry_mpi_point_t Q;
    gcry_mpi_point_t W = gcry_mpi_point_new(0);
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);

    ASSERT_OK(gcry_sexp_build(&key, NULL,
                              "(private-key (ecc (curve Ed25519) (flags eddsa)"
                              " (d #" ED25519_SK "#)))"));
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));

    q = gcry_mpi_ec_get_mpi("q@eddsa", ctx, 1);
    ASSERT_NOT_NULL(q);
    ASSERT_TRUE(opaque_eq_hex(q, ED25519_PK));
    gcry_mpi_release(q);

    /* The uncompressed "q" is 04 || X || Y; decoding it back must give the
     * same compressed form, and the point is on the curve. */
    q = gcry_mpi_ec_get_mpi("q", ctx, 1);
    ASSERT_NOT_NULL(q);
    ASSERT_OK(gcry_mpi_ec_decode_point(W, q, ctx));
    ASSERT_TRUE(gcry_mpi_ec_curve_point(W, ctx));
    gcry_mpi_release(q);
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, Q, ctx));
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(NULL, NULL, W, ctx));
    gcry_mpi_point_get(NULL, NULL, NULL, W);

    /* Decoding the compressed public key recovers X. */
    q = hex_opaque(ED25519_PK);
    ASSERT_OK(gcry_mpi_ec_decode_point(W, q, ctx));
    gcry_mpi_release(q);
    q = gcry_mpi_new(0);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(q, NULL, W, ctx));
    ASSERT_EQ(0, gcry_mpi_cmp(q, x));
    gcry_mpi_release(q);

    /* General point arithmetic is not available on Edwards curves. */
    gcry_mpi_ec_add(W, Q, Q, ctx);
    ASSERT_EQ(-1, gcry_mpi_ec_get_affine(x, y, W, ctx));

    gcry_mpi_point_release(Q);
    gcry_mpi_point_release(W);
    gcry_mpi_release(x);
    gcry_mpi_release(y);
    gcry_ctx_release(ctx);
    gcry_sexp_release(key);
}

/* RFC 7748 section 6.1. */
#define X25519_ALICE_SK "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
#define X25519_ALICE_PK "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
#define X25519_BOB_PK "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
#define X25519_SHARED "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

/* Little endian hex to a big endian number. */
static gcry_mpi_t
le_hex_mpi(const char *hex)
{
    gcry_mpi_t m = hex_opaque(hex);
    unsigned int nbits;
    unsigned char *p = gcry_mpi_get_opaque(m, &nbits);
    size_t n = (nbits + 7) / 8;
    size_t i;
    gcry_mpi_t r;

    for (i = 0; i < n / 2; i++) {
        unsigned char t = p[i];

        p[i] = p[n - 1 - i];
        p[n - 1 - i] = t;
    }

    gcry_mpi_scan(&r, GCRYMPI_FMT_USG, p, n, NULL);
    gcry_mpi_release(m);
    return r;
}

TEST(curve25519_context)
{
    gcry_ctx_t ctx = NULL;
    gcry_mpi_t k = le_hex_mpi(X25519_ALICE_SK);
    gcry_mpi_t u = le_hex_mpi(X25519_BOB_PK);
    gcry_mpi_t expected = le_hex_mpi(X25519_SHARED);
    gcry_mpi_t pub = le_hex_mpi(X25519_ALICE_PK);
    gcry_mpi_point_t G;
    gcry_mpi_point_t P = gcry_mpi_point_new(0);
    gcry_mpi_point_t W = gcry_mpi_point_new(0);
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t q;

    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "Curve25519"));
    G = gcry_mpi_ec_get_point("g", ctx, 1);
    ASSERT_NOT_NULL(G);
    gcry_mpi_point_get(x, NULL, NULL, G);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(x, 9));

    /* k * G is the public key, k * Bob is the shared secret. */
    gcry_mpi_ec_mul(W, k, G, ctx);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, NULL, W, ctx));
    ASSERT_EQ(0, gcry_mpi_cmp(x, pub));
    gcry_mpi_point_set(P, u, NULL, GCRYMPI_CONST_ONE);
    gcry_mpi_ec_mul(W, k, P, ctx);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, NULL, W, ctx));
    ASSERT_EQ(0, gcry_mpi_cmp(x, expected));
    ASSERT_TRUE(gcry_mpi_ec_curve_point(P, ctx));

    /* Public key derivation through the context: "q" is 40 || LE(u). */
    ASSERT_OK(gcry_mpi_ec_set_mpi("d", k, ctx));
    q = gcry_mpi_ec_get_mpi("q", ctx, 1);
    ASSERT_NOT_NULL(q);
    ASSERT_TRUE(opaque_eq_hex(q, "40" X25519_ALICE_PK));
    gcry_mpi_release(q);

    gcry_mpi_point_release(G);
    gcry_mpi_point_release(P);
    gcry_mpi_point_release(W);
    gcry_mpi_release(x);
    gcry_mpi_release(k);
    gcry_mpi_release(u);
    gcry_mpi_release(expected);
    gcry_mpi_release(pub);
    gcry_ctx_release(ctx);
}

TEST(curve_table_access)
{
    unsigned int nbits = 0;
    const char *name;
    int i;
    int found = 0;

    for (i = 0; (name = gcry_pk_get_curve(NULL, i, &nbits)); i++) {
        ASSERT_TRUE(nbits > 0);

        if (!strcmp(name, "brainpoolP256r1")) {
            found = 1;
            ASSERT_EQ(256, nbits);
        }
    }

    ASSERT_TRUE(found);
    ASSERT_TRUE(i >= 28);
    ASSERT_NULL(gcry_pk_get_curve(NULL, -1, NULL));
}

static gcry_sexp_t
sexp_of(const char *text)
{
    gcry_sexp_t s = NULL;

    gcry_sexp_sscan(&s, NULL, text, strlen(text));
    return s;
}

/* Points, parameters and contexts outside the normal key flow. */
TEST(context_edge_cases)
{
    gcry_ctx_t ctx = NULL;
    gcry_mpi_point_t G;
    gcry_mpi_point_t Q;
    gcry_mpi_point_t R;
    gcry_mpi_point_t inf;
    gcry_mpi_t m;
    gcry_mpi_t x;
    gcry_mpi_t y;
    gcry_mpi_t h;
    gcry_mpi_t enc;
    gcry_sexp_t sx = NULL;

    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_mpi_ec_new(&ctx, NULL, "bogus"));
    ASSERT_NULL(ctx);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));

    /* Cofactor, unknown names, and values a bare context does not have. */
    h = gcry_mpi_ec_get_mpi("h", ctx, 1);
    ASSERT_NOT_NULL(h);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(h, 1));
    gcry_mpi_release(h);
    ASSERT_NULL(gcry_mpi_ec_get_mpi("zz", ctx, 1));
    ASSERT_NULL(gcry_mpi_ec_get_mpi("q", ctx, 1));
    ASSERT_NULL(gcry_mpi_ec_get_mpi("d", ctx, 1));
    ASSERT_NULL(gcry_mpi_ec_get_point("q", ctx, 1));
    ASSERT_NULL(gcry_mpi_ec_get_point("zz", ctx, 1));
    ASSERT_ERR(GPG_ERR_NO_SECKEY, gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_SECKEY,
                                                       ctx));

    /* Setting the public point by point and by encoded MPI. */
    G = gcry_mpi_ec_get_point("g", ctx, 1);
    ASSERT_NOT_NULL(G);
    ASSERT_OK(gcry_mpi_ec_set_point("q", G, ctx));
    ASSERT_ERR(GPG_ERR_UNKNOWN_NAME, gcry_mpi_ec_set_point("zz", G, ctx));
    m = gcry_mpi_ec_get_mpi("q", ctx, 1);
    ASSERT_NOT_NULL(m);
    ASSERT_EQ(520, gcry_mpi_get_nbits(m)); /* 0x04 || x || y */
    gcry_mpi_release(m);
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q);
    gcry_mpi_point_release(Q);
    ASSERT_OK(gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_PUBKEY, ctx));
    gcry_sexp_release(sx);
    sx = NULL;

    m = gcry_mpi_set_ui(NULL, 5);
    ASSERT_OK(gcry_mpi_ec_set_mpi("d", m, ctx));
    ASSERT_ERR(GPG_ERR_UNKNOWN_NAME, gcry_mpi_ec_set_mpi("zz", m, ctx));
    ASSERT_OK(gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_SECKEY, ctx));
    {
        gcry_sexp_t l = gcry_sexp_find_token(sx, "d", 0);
        gcry_mpi_t d = gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG);

        ASSERT_EQ(0, gcry_mpi_cmp_ui(d, 5));
        gcry_mpi_release(d);
        gcry_sexp_release(l);
    }
    gcry_sexp_release(sx);
    sx = NULL;
    /* A plain integer is not a point encoding; the old q is kept. */
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_ec_set_mpi("q", m, ctx));
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q);
    gcry_mpi_point_release(Q);
    enc = hex_mpi("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                  "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    ASSERT_OK(gcry_mpi_ec_set_mpi("q", enc, ctx));
    gcry_mpi_release(enc);
    enc = hex_mpi("036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    ASSERT_OK(gcry_mpi_ec_set_mpi("q", enc, ctx));
    gcry_mpi_release(enc);
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q);
    x = gcry_mpi_new(0);
    y = gcry_mpi_new(0);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, Q, ctx));
    ASSERT_TRUE(mpi_eq_hex(x,
                           "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"));
    ASSERT_TRUE(mpi_eq_hex(y,
                           "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
    gcry_mpi_point_release(Q);
    enc = hex_opaque("0401");
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_ec_set_mpi("q", enc, ctx));
    gcry_mpi_release(enc);

    /* Re-setting the curve parameters to their own values keeps the
     * context usable. */
    {
        const char *names[4] = { "p", "a", "b", "n" };
        int i;

        for (i = 0; i < 4; i++) {
            gcry_mpi_t v = gcry_mpi_ec_get_mpi(names[i], ctx, 1);

            ASSERT_NOT_NULL(v);
            ASSERT_OK(gcry_mpi_ec_set_mpi(names[i], v, ctx));
            gcry_mpi_release(v);
        }
    }
    ASSERT_OK(gcry_mpi_ec_set_point("g", G, ctx));
    R = gcry_mpi_point_new(0);
    gcry_mpi_ec_mul(R, m, G, ctx);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, R, ctx));
    ASSERT_TRUE(mpi_eq_hex(x,
                           "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED"));

    /* The point at infinity as an operand. */
    inf = gcry_mpi_point_new(0);
    gcry_mpi_ec_add(R, G, inf, ctx);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, R, ctx));
    ASSERT_TRUE(mpi_eq_hex(x,
                           "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"));
    gcry_mpi_ec_add(R, inf, inf, ctx);
    ASSERT_EQ(-1, gcry_mpi_ec_get_affine(x, y, R, ctx));
    gcry_mpi_ec_dup(R, inf, ctx);
    ASSERT_EQ(-1, gcry_mpi_ec_get_affine(x, y, R, ctx));
    gcry_mpi_set_ui(m, 0);
    gcry_mpi_ec_mul(R, m, G, ctx);
    ASSERT_EQ(-1, gcry_mpi_ec_get_affine(x, y, R, ctx));
    ASSERT_EQ(1, gcry_mpi_ec_curve_point(G, ctx));

    /* A Jacobian representation with z != 1 is understood. */
    {
        gcry_mpi_t gx = gcry_mpi_new(0);
        gcry_mpi_t gy = gcry_mpi_new(0);
        gcry_mpi_t gz = gcry_mpi_new(0);
        gcry_mpi_t p = gcry_mpi_ec_get_mpi("p", ctx, 1);
        gcry_mpi_t two = gcry_mpi_set_ui(NULL, 2);
        gcry_mpi_t four = gcry_mpi_set_ui(NULL, 4);
        gcry_mpi_t eight = gcry_mpi_set_ui(NULL, 8);
        gcry_mpi_t ex = gcry_mpi_new(0);

        gcry_mpi_point_get(gx, gy, gz, G);
        gcry_mpi_mulm(gx, gx, four, p);   /* X = x * z^2 */
        gcry_mpi_mulm(gy, gy, eight, p);  /* Y = y * z^3 */
        gcry_mpi_point_set(R, gx, gy, two);
        ASSERT_EQ(1, gcry_mpi_ec_curve_point(R, ctx));
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, R, ctx));
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(ex, NULL, G, ctx));
        ASSERT_EQ(0, gcry_mpi_cmp(ex, x));
        gcry_mpi_ec_add(R, R, G, ctx);
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, NULL, R, ctx));
        gcry_mpi_set_ui(m, 2);
        gcry_mpi_ec_mul(R, m, G, ctx);
        ASSERT_EQ(0, gcry_mpi_ec_get_affine(ex, NULL, R, ctx));
        ASSERT_EQ(0, gcry_mpi_cmp(ex, x));
        gcry_mpi_release(gx);
        gcry_mpi_release(gy);
        gcry_mpi_release(gz);
        gcry_mpi_release(p);
        gcry_mpi_release(two);
        gcry_mpi_release(four);
        gcry_mpi_release(eight);
        gcry_mpi_release(ex);
    }

    gcry_mpi_point_release(inf);
    gcry_mpi_point_release(R);
    gcry_mpi_point_release(G);
    gcry_mpi_release(m);
    gcry_mpi_release(x);
    gcry_mpi_release(y);
    gcry_ctx_release(ctx);
}

TEST(montgomery_context_queries)
{
    gcry_ctx_t ctx = NULL;
    gcry_mpi_point_t G;
    gcry_mpi_point_t R;
    gcry_mpi_t m = gcry_mpi_set_ui(NULL, 3);
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t h;

    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "Curve25519"));
    G = gcry_mpi_ec_get_point("g", ctx, 1);
    ASSERT_NOT_NULL(G);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, NULL, G, ctx));
    ASSERT_EQ(0, gcry_mpi_cmp_ui(x, 9));
    R = gcry_mpi_point_new(0);
    gcry_mpi_ec_mul(R, m, G, ctx);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, NULL, R, ctx));
    ASSERT_EQ(1, gcry_mpi_ec_curve_point(G, ctx));
    h = gcry_mpi_ec_get_mpi("h", ctx, 1);
    ASSERT_EQ(0, gcry_mpi_cmp_ui(h, 8));
    gcry_mpi_release(h);
    gcry_mpi_point_release(R);
    gcry_mpi_point_release(G);
    gcry_mpi_release(m);
    gcry_mpi_release(x);
    gcry_ctx_release(ctx);
}

TEST(context_from_odd_keys)
{
    gcry_ctx_t ctx = NULL;
    gcry_sexp_t key;
    gcry_mpi_point_t Q;
    unsigned char out[64];
    unsigned char scalar[32] = { 9 };
    unsigned char point[32] = { 9 };

    /* A truncated q is accepted when the context is built; the error
     * surfaces later when the point is used. */
    key = NULL;
    key = sexp_of("(public-key (ecc (curve \"NIST P-256\") (q #04#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_ctx_release(ctx);
    ctx = NULL;
    gcry_sexp_release(key);

    key = NULL;
    key = sexp_of("(public-key (ecc (curve bogus) (q #04#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_mpi_ec_new(&ctx, key, NULL));
    ASSERT_NULL(ctx);
    gcry_sexp_release(key);

    /* "param" together with a curve name: the name wins. */
    key = NULL;
    key = sexp_of(
              "(public-key (ecc (curve \"NIST P-256\") (flags param) (p #0b#)))"
          );
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_ctx_release(ctx);
    ctx = NULL;
    gcry_sexp_release(key);

    /* Ed25519 secret scalars of unusual length still yield the public
     * point. */
    key = NULL;
    key = sexp_of(
              "(private-key (ecc (curve Ed25519) (flags eddsa) (d #01#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q);
    gcry_mpi_point_release(Q);
    gcry_ctx_release(ctx);
    ctx = NULL;
    gcry_sexp_release(key);
    key = NULL;
    key = sexp_of(
              "(private-key (ecc (curve Ed25519) (flags eddsa) (d #00"
              "0102030405060708091011121314151617181920212223242526272829303132#)))"
          );
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_ctx_release(ctx);
    ctx = NULL;
    gcry_sexp_release(key);
    key = NULL;
    key = sexp_of(
              "(private-key (ecc (curve Curve25519) (flags djb-tweak) (d #"
              "0102030405060708091011121314151617181920212223242526272829303132#)))"
          );
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_ctx_release(ctx);
    ctx = NULL;
    gcry_sexp_release(key);

    /* Raw scalar multiplication helpers. */
    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, out, scalar, point));
    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE448, out, scalar, point));
    ASSERT_OK(gcry_ecc_mul_point(GCRY_ECC_CURVE25519, out, scalar, NULL));
    ASSERT_ERR(GPG_ERR_UNKNOWN_CURVE, gcry_ecc_mul_point(999, out, scalar, point));
    ASSERT_EQ(32, gcry_ecc_get_algo_keylen(GCRY_ECC_CURVE25519));
    ASSERT_EQ(56, gcry_ecc_get_algo_keylen(GCRY_ECC_CURVE448));
    ASSERT_EQ(0, gcry_ecc_get_algo_keylen(999));
}

TEST(edwards_context_and_explicit_params)
{
    gcry_ctx_t ctx = NULL;
    gcry_sexp_t key;
    gcry_sexp_t sx = NULL;
    gcry_mpi_point_t Q;
    gcry_mpi_point_t G;
    gcry_mpi_t q;
    gcry_mpi_t x = gcry_mpi_new(0);
    gcry_mpi_t y = gcry_mpi_new(0);

    /* Broken key material is rejected when the context is built. */
    key = sexp_of("(public-key (ecc (curve \"NIST P-256\") (q)))");
    ASSERT_NOT_NULL(key);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_sexp_release(key);
    key = sexp_of("(private-key (ecc (curve Ed25519) (flags eddsa) (d #0000"
                  "0102030405060708091011121314151617181920212223242526272829303132"
                  "#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_ERR(GPG_ERR_INV_OBJ, gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_sexp_release(key);
    ASSERT_NULL(ctx);

    /* A bare Edwards context: nothing to export until q or d is set. */
    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "Ed25519"));
    ASSERT_ERR(GPG_ERR_NO_SECKEY, gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_SECKEY,
                                                       ctx));
    ASSERT_ERR(GPG_ERR_BAD_CRYPT_CTX, gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_PUBKEY,
                                                           ctx));
    ASSERT_NULL(sx);
    /* The public key as the plain 32-byte encoding or with a 0x40 prefix
     * in an opaque MPI. */
    q = hex_mpi("1FA2E99AB1F89DB74F47B649B8C280659E25E4DA32B87BCF8BB5EF7AB6007D87");
    ASSERT_OK(gcry_mpi_ec_set_mpi("q", q, ctx));
    gcry_mpi_release(q);
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, Q, ctx));
    gcry_mpi_point_release(Q);
    q = hex_opaque("401FA2E99AB1F89DB74F47B649B8C280659E25E4DA32B87BCF8BB5EF7AB6007D87");
    ASSERT_OK(gcry_mpi_ec_set_mpi("q", q, ctx));
    gcry_mpi_release(q);
    ASSERT_OK(gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_PUBKEY, ctx));
    {
        gcry_sexp_t l = gcry_sexp_find_token(sx, "q", 0);
        size_t n = 0;
        const unsigned char *d = (const unsigned char *)gcry_sexp_nth_data(l, 1, &n);

        ASSERT_EQ(32, n);
        ASSERT_EQ(0x1F, d[0]);
        ASSERT_EQ(0x87, d[31]);
        gcry_sexp_release(l);
    }
    gcry_sexp_release(sx);
    sx = NULL;
    gcry_ctx_release(ctx);
    ctx = NULL;

    /* Explicit parameters without a curve name are recognised. */
    key = sexp_of("(public-key (ecc"
                  " (p #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF#)"
                  " (a #00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC#)"
                  " (b #5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B#)"
                  " (g #046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                  "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5#)"
                  " (n #00FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551#)"
                  " (h #01#)"
                  " (q #04" P256_QX P256_QY "#)))");
    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_mpi_ec_new(&ctx, key, NULL));
    gcry_sexp_release(key);
    q = gcry_mpi_ec_get_mpi("p", ctx, 1);
    ASSERT_EQ(256, gcry_mpi_get_nbits(q));
    gcry_mpi_release(q);
    gcry_ctx_release(ctx);
    ctx = NULL;

    /* A public point that is not on the curve is still exported. */
    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));
    Q = gcry_mpi_point_new(0);
    gcry_mpi_set_ui(x, 1);
    gcry_mpi_set_ui(y, 1);
    gcry_mpi_point_set(Q, x, y, y);
    ASSERT_EQ(0, gcry_mpi_ec_curve_point(Q, ctx));
    ASSERT_OK(gcry_mpi_ec_set_point("q", Q, ctx));
    ASSERT_OK(gcry_pubkey_get_sexp(&sx, GCRY_PK_GET_PUBKEY, ctx));
    gcry_sexp_release(sx);
    sx = NULL;
    gcry_mpi_point_release(Q);
    gcry_ctx_release(ctx);
    ctx = NULL;

    /* The public key is computed from d on demand. */
    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));
    gcry_mpi_set_ui(x, 5);
    ASSERT_OK(gcry_mpi_ec_set_mpi("d", x, ctx));
    q = gcry_mpi_ec_get_mpi("q", ctx, 1);
    ASSERT_NOT_NULL(q);
    gcry_mpi_release(q);
    Q = gcry_mpi_ec_get_point("q", ctx, 1);
    ASSERT_NOT_NULL(Q);
    ASSERT_EQ(0, gcry_mpi_ec_get_affine(x, y, Q, ctx));
    ASSERT_TRUE(mpi_eq_hex(x,
                           "51590B7A515140D2D784C85608668FDFEF8C82FD1F5BE52421554A0DC3D033ED"));
    gcry_mpi_point_release(Q);

    /* Debug output of points must cope with and without a context. */
    G = gcry_mpi_ec_get_point("g", ctx, 1);
    gcry_log_debugpnt("G", G, ctx);
    gcry_log_debugpnt("G", G, NULL);
    gcry_log_debugpnt("none", NULL, ctx);
    gcry_mpi_point_release(G);
    gcry_ctx_release(ctx);

    gcry_mpi_release(x);
    gcry_mpi_release(y);
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(p256_parameters);
    RUN_TEST(p256_scalar_multiplication);
    RUN_TEST(point_encodings);
    RUN_TEST(context_from_key_and_get_sexp);
    RUN_TEST(ed25519_context);
    RUN_TEST(curve25519_context);
    RUN_TEST(curve_table_access);
    RUN_TEST(context_edge_cases);
    RUN_TEST(montgomery_context_queries);
    RUN_TEST(context_from_odd_keys);
    RUN_TEST(edwards_context_and_explicit_params);
    return TEST_RESULT();
}
