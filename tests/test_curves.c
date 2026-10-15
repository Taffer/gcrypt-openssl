/* Internal consistency check of the curve table: every Weierstrass curve
 * must yield an EC_GROUP whose parameters match the table, and the NIST
 * OpenSSL groups must agree with our constants. */
#include "../src/gcrypt-int.h"

#include <openssl/ec.h>

#include "test_common.h"

TEST(lookup)
{
    const struct gcry_ecc_curve *c = _gcry_ecc_curve_find("NIST P-256");

    ASSERT_NOT_NULL(c);
    ASSERT_TRUE(_gcry_ecc_curve_find("prime256v1") == c);
    ASSERT_TRUE(_gcry_ecc_curve_find("secp256r1") == c);
    ASSERT_TRUE(_gcry_ecc_curve_find("1.2.840.10045.3.1.7") == c);
    ASSERT_TRUE(_gcry_ecc_curve_find("nistp256") == c);
    ASSERT_EQ(256, c->nbits);
    ASSERT_TRUE(_gcry_ecc_curve_by_nbits(384) ==
                _gcry_ecc_curve_find("NIST P-384"));
    ASSERT_NULL(_gcry_ecc_curve_find("no-such-curve"));
    ASSERT_NULL(_gcry_ecc_curve_find(NULL));
    c = _gcry_ecc_curve_find("X25519");
    ASSERT_NOT_NULL(c);
    ASSERT_STR_EQ("Curve25519", c->name);
    ASSERT_EQ(GCRY_ECC_MODEL_MONTGOMERY, c->model);
    ASSERT_STR_EQ("X25519", c->keytype);
    c = _gcry_ecc_curve_find("1.3.101.112");
    ASSERT_STR_EQ("Ed25519", c->name);
    ASSERT_EQ(GCRY_ECC_MODEL_EDWARDS, c->model);
    ASSERT_STR_EQ("brainpoolP256r1", _gcry_ecc_curve_find("bp256")->name);
    ASSERT_STR_EQ("GOST2001-CryptoPro-A",
                  _gcry_ecc_curve_find("GOST2012-256-tc26-B")->name);
}

TEST(groups_match_table)
{
    size_t i;
    BN_CTX *ctx = BN_CTX_new();
    int weierstrass = 0;

    for (i = 0; i < _gcry_ecc_curve_count(); i++) {
        const struct gcry_ecc_curve *c = _gcry_ecc_curve_by_index(i);
        EC_GROUP *g;
        BIGNUM *p = BN_new();
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        gcry_mpi_t tp;
        gcry_mpi_t ta;
        gcry_mpi_t tb;
        gcry_mpi_t tn;
        gcry_mpi_t th;
        unsigned int nbits;

        if (c->model != GCRY_ECC_MODEL_WEIERSTRASS) {
            ASSERT_NULL(_gcry_ecc_curve_group(c));
            BN_free(p);
            BN_free(a);
            BN_free(b);
            continue;
        }

        weierstrass++;
        g = _gcry_ecc_curve_group(c);

        if (!g) {
            TEST_FAIL_("no EC_GROUP for %s", c->name);
            return;
        }

        ASSERT_TRUE(EC_GROUP_get_curve(g, p, a, b, ctx));
        tp = _gcry_ecc_curve_param(c, "p");
        ta = _gcry_ecc_curve_param(c, "a");
        tb = _gcry_ecc_curve_param(c, "b");
        tn = _gcry_ecc_curve_param(c, "n");
        th = _gcry_ecc_curve_param(c, "h");
        ASSERT_EQ(0, BN_cmp(p, _gcry_mpi_bn(tp)));
        ASSERT_EQ(0, BN_cmp(a, _gcry_mpi_bn(ta)));
        ASSERT_EQ(0, BN_cmp(b, _gcry_mpi_bn(tb)));
        ASSERT_EQ(0, BN_cmp(EC_GROUP_get0_order(g), _gcry_mpi_bn(tn)));
        ASSERT_EQ(0, BN_cmp(EC_GROUP_get0_cofactor(g), _gcry_mpi_bn(th)));
        nbits = (unsigned int)EC_GROUP_get_degree(g);
        ASSERT_EQ(c->nbits, nbits);
        ASSERT_TRUE(_gcry_ecc_curve_from_group(g) == c);
        gcry_mpi_release(tp);
        gcry_mpi_release(ta);
        gcry_mpi_release(tb);
        gcry_mpi_release(tn);
        gcry_mpi_release(th);
        EC_GROUP_free(g);
        BN_free(p);
        BN_free(a);
        BN_free(b);
    }

    ASSERT_EQ(23, weierstrass);
    BN_CTX_free(ctx);
}

TEST(negative_parameter_is_reduced)
{
    const struct gcry_ecc_curve *c = _gcry_ecc_curve_find("Ed25519");
    gcry_mpi_t a = _gcry_ecc_curve_param(c, "a");
    gcry_mpi_t p = _gcry_ecc_curve_param(c, "p");

    ASSERT_FALSE(gcry_mpi_is_neg(a));
    gcry_mpi_add_ui(a, a, 1);
    ASSERT_EQ(0, gcry_mpi_cmp(a, p)); /* -1 mod p == p - 1 */
    gcry_mpi_release(a);
    gcry_mpi_release(p);
    ASSERT_NULL(_gcry_ecc_curve_param(c, "zz"));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(lookup);
    RUN_TEST(groups_match_table);
    RUN_TEST(negative_parameter_is_reduced);
    return TEST_RESULT();
}
