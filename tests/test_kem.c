#include <gcrypt.h>

#include <stdlib.h>

#include "kem-vectors.h"
#include "test_common.h"

/* Decode a hex string into a malloc'd buffer; returns the length. */
static size_t
unhex(const char *hex, unsigned char **out)
{
    size_t n = strlen(hex) / 2;
    size_t i;
    unsigned char *buf = malloc(n ? n : 1);

    for (i = 0; i < n; i++) {
        unsigned int v;

        sscanf(hex + 2 * i, "%2x", &v);
        buf[i] = (unsigned char)v;
    }

    *out = buf;
    return n;
}

#define ASSERT_HEX_EQ(hex, buf, len)                       \
    do {                                                   \
        unsigned char *exp_;                               \
        size_t explen_ = unhex((hex), &exp_);              \
        int ok_ = explen_ == (len) && !memcmp(exp_, (buf), (len)); \
        free(exp_);                                        \
        if (!ok_) {                                        \
            TEST_FAIL_("%s", "mismatch: " #buf);           \
            return;                                        \
        }                                                  \
    } while (0)

/* ------------------------------------------------------------------ */
/* ML-KEM                                                              */
/* ------------------------------------------------------------------ */

struct mlkem_vectors {
    int algo;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
    const unsigned char *gen_z;
    const unsigned char *gen_d;
    const unsigned char *gen_ek;
    const unsigned char *gen_dk;
    const unsigned char *enc_ek;
    const unsigned char *enc_m;
    const unsigned char *enc_c;
    const unsigned char *enc_k;
    const unsigned char *dec_dk;
    const unsigned char *dec_c;
    const unsigned char *dec_k;
};

static const struct mlkem_vectors mlkem_sets[] = {
    {
        GCRY_KEM_MLKEM512, GCRY_KEM_MLKEM512_PUBKEY_LEN,
        GCRY_KEM_MLKEM512_SECKEY_LEN, GCRY_KEM_MLKEM512_CIPHER_LEN,
        mlkem512_gen_z, mlkem512_gen_d, mlkem512_gen_ek, mlkem512_gen_dk,
        mlkem512_enc_ek, mlkem512_enc_m, mlkem512_enc_c, mlkem512_enc_k,
        mlkem512_dec_dk, mlkem512_dec_c, mlkem512_dec_k
    },
    {
        GCRY_KEM_MLKEM768, GCRY_KEM_MLKEM768_PUBKEY_LEN,
        GCRY_KEM_MLKEM768_SECKEY_LEN, GCRY_KEM_MLKEM768_CIPHER_LEN,
        mlkem768_gen_z, mlkem768_gen_d, mlkem768_gen_ek, mlkem768_gen_dk,
        mlkem768_enc_ek, mlkem768_enc_m, mlkem768_enc_c, mlkem768_enc_k,
        mlkem768_dec_dk, mlkem768_dec_c, mlkem768_dec_k
    },
    {
        GCRY_KEM_MLKEM1024, GCRY_KEM_MLKEM1024_PUBKEY_LEN,
        GCRY_KEM_MLKEM1024_SECKEY_LEN, GCRY_KEM_MLKEM1024_CIPHER_LEN,
        mlkem1024_gen_z, mlkem1024_gen_d, mlkem1024_gen_ek, mlkem1024_gen_dk,
        mlkem1024_enc_ek, mlkem1024_enc_m, mlkem1024_enc_c, mlkem1024_enc_k,
        mlkem1024_dec_dk, mlkem1024_dec_c, mlkem1024_dec_k
    },
};

static void
mlkem_kat(const struct mlkem_vectors *v)
{
    unsigned char *pk = malloc(v->pk_len);
    unsigned char *sk = malloc(v->sk_len);
    unsigned char *ct = malloc(v->ct_len);
    unsigned char ss[GCRY_KEM_MLKEM512_SHARED_LEN];
    unsigned char ss2[GCRY_KEM_MLKEM512_SHARED_LEN];
    unsigned char coins[2 * GCRY_KEM_MLKEM_RANDOM_LEN];

    /* Key generation from seed d || z. */
    memcpy(coins, v->gen_d, 32);
    memcpy(coins + 32, v->gen_z, 32);
    ASSERT_OK(gcry_kem_genkey(v->algo, pk, v->pk_len, sk, v->sk_len, coins,
                              sizeof coins));
    ASSERT_MEM_EQ(v->gen_ek, pk, v->pk_len);
    ASSERT_MEM_EQ(v->gen_dk, sk, v->sk_len);

    /* Encapsulation with known randomness m. */
    ASSERT_OK(gcry_kem_encap(v->algo, v->enc_ek, v->pk_len, ct, v->ct_len, ss,
                             sizeof ss, v->enc_m, 32));
    ASSERT_MEM_EQ(v->enc_c, ct, v->ct_len);
    ASSERT_MEM_EQ(v->enc_k, ss, sizeof ss);

    /* Decapsulation vector. */
    ASSERT_OK(gcry_kem_decap(v->algo, v->dec_dk, v->sk_len, v->dec_c,
                             v->ct_len, ss, sizeof ss, NULL, 0));
    ASSERT_MEM_EQ(v->dec_k, ss, sizeof ss);

    /* Random round trip plus implicit rejection on a damaged ciphertext. */
    ASSERT_OK(gcry_kem_keypair(v->algo, pk, v->pk_len, sk, v->sk_len));
    ASSERT_OK(gcry_kem_encap(v->algo, pk, v->pk_len, ct, v->ct_len, ss,
                             sizeof ss, NULL, 0));
    ASSERT_OK(gcry_kem_decap(v->algo, sk, v->sk_len, ct, v->ct_len, ss2,
                             sizeof ss2, NULL, 0));
    ASSERT_MEM_EQ(ss, ss2, sizeof ss);
    ct[5] ^= 0x01;
    ASSERT_OK(gcry_kem_decap(v->algo, sk, v->sk_len, ct, v->ct_len, ss2,
                             sizeof ss2, NULL, 0));
    ASSERT_TRUE(memcmp(ss, ss2, sizeof ss) != 0);

    /* Length and argument checks. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(v->algo, pk, v->pk_len - 1, ct, v->ct_len, ss,
                              sizeof ss, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(v->algo, sk, v->sk_len, ct, v->ct_len, ss,
                              sizeof ss - 1, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_genkey(v->algo, pk, v->pk_len, sk, v->sk_len, coins,
                               33));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(v->algo, pk, v->pk_len, ct, v->ct_len, ss,
                              sizeof ss, coins, 31));

    free(pk);
    free(sk);
    free(ct);
}

TEST(mlkem512)
{
    mlkem_kat(&mlkem_sets[0]);
}

TEST(mlkem768)
{
    mlkem_kat(&mlkem_sets[1]);
}

TEST(mlkem1024)
{
    mlkem_kat(&mlkem_sets[2]);
}

/* ------------------------------------------------------------------ */
/* RAW ECC KEMs                                                        */
/* ------------------------------------------------------------------ */

TEST(raw_x25519)
{
    unsigned char pk[GCRY_KEM_ECC_X25519_PUBKEY_LEN];
    unsigned char sk[GCRY_KEM_ECC_X25519_SECKEY_LEN];
    unsigned char ct[GCRY_KEM_ECC_X25519_ENCAPS_LEN];
    unsigned char ss1[GCRY_KEM_RAW_X25519_SHARED_LEN];
    unsigned char ss2[GCRY_KEM_RAW_X25519_SHARED_LEN];
    unsigned char *alice_sk;
    unsigned char *bob_pk;
    unsigned char zero[32] = { 0 };

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_RAW_X25519, pk, sizeof pk, sk,
                               sizeof sk));
    /* The generated scalar is clamped like the reference implementation. */
    ASSERT_EQ(0, sk[0] & 0x07);
    ASSERT_EQ(0x40, sk[31] & 0xc0);
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, sizeof pk, ct, sizeof ct,
                             ss1, sizeof ss1, NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_RAW_X25519, sk, sizeof sk, ct, sizeof ct,
                             ss2, sizeof ss2, NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, sizeof ss1);

    /* RFC 7748 section 6.1: decapsulation is plain X25519. */
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
          &alice_sk);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
          &bob_pk);
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_RAW_X25519, alice_sk, 32, bob_pk, 32,
                             ss1, sizeof ss1, NULL, 0));
    ASSERT_HEX_EQ("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                  ss1, 32);

    /* A small order point gives an all-zero secret and is rejected. */
    ASSERT_ERR(GPG_ERR_INV_DATA,
               gcry_kem_decap(GCRY_KEM_RAW_X25519, alice_sk, 32, zero, 32, ss1,
                              sizeof ss1, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, sizeof pk, ct, 31, ss1,
                              sizeof ss1, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, sizeof pk, ct, sizeof ct,
                              ss1, sizeof ss1, zero, 32));
    free(alice_sk);
    free(bob_pk);
}

TEST(raw_x448)
{
    unsigned char pk[GCRY_KEM_ECC_X448_PUBKEY_LEN];
    unsigned char sk[GCRY_KEM_ECC_X448_SECKEY_LEN];
    unsigned char ct[GCRY_KEM_ECC_X448_ENCAPS_LEN];
    unsigned char ss1[GCRY_KEM_RAW_X448_SHARED_LEN];
    unsigned char ss2[GCRY_KEM_RAW_X448_SHARED_LEN];

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_RAW_X448, pk, sizeof pk, sk,
                               sizeof sk));
    ASSERT_EQ(0, sk[0] & 0x03);
    ASSERT_EQ(0x80, sk[55] & 0x80);
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_RAW_X448, pk, sizeof pk, ct, sizeof ct,
                             ss1, sizeof ss1, NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_RAW_X448, sk, sizeof sk, ct, sizeof ct,
                             ss2, sizeof ss2, NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, sizeof ss1);
}

static void
raw_weierstrass_roundtrip(int algo, size_t nbytes)
{
    size_t ptlen = 1 + 2 * nbytes;
    unsigned char *pk = malloc(ptlen);
    unsigned char *sk = malloc(nbytes);
    unsigned char *ct = malloc(ptlen);
    unsigned char *ss1 = malloc(ptlen);
    unsigned char *ss2 = malloc(ptlen);

    ASSERT_OK(gcry_kem_keypair(algo, pk, ptlen, sk, nbytes));
    ASSERT_EQ(0x04, pk[0]);
    ASSERT_OK(gcry_kem_encap(algo, pk, ptlen, ct, ptlen, ss1, ptlen, NULL, 0));
    ASSERT_EQ(0x04, ct[0]);
    ASSERT_EQ(0x04, ss1[0]);
    ASSERT_OK(gcry_kem_decap(algo, sk, nbytes, ct, ptlen, ss2, ptlen, NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, ptlen);

    /* A point that is not on the curve is rejected. */
    ct[ptlen - 1] ^= 0x01;
    ASSERT_ERR(GPG_ERR_INV_DATA,
               gcry_kem_decap(algo, sk, nbytes, ct, ptlen, ss2, ptlen, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_keypair(algo, pk, ptlen, sk, nbytes + 1));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(algo, sk, nbytes, ct, ptlen, ss2, ptlen - 1,
                              NULL, 0));
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
}

TEST(raw_weierstrass)
{
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_P256R1, 32);
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_P384R1, 48);
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_P521R1, 66);
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_BP256, 32);
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_BP384, 48);
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_BP512, 64);
    raw_weierstrass_roundtrip(GCRY_KEM_RAW_P256K1, 32);
}

TEST(raw_p256_low_y_key)
{
    /* Generated keys use the point with y < p - y, as upstream does. */
    unsigned char pk[65];
    unsigned char sk[32];
    gcry_mpi_t y = NULL;
    gcry_mpi_t p = NULL;
    gcry_mpi_t negy = gcry_mpi_new(0);
    int i;

    gcry_mpi_scan(&p, GCRYMPI_FMT_HEX,
                  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                  0, NULL);

    for (i = 0; i < 8; i++) {
        ASSERT_OK(gcry_kem_keypair(GCRY_KEM_RAW_P256R1, pk, sizeof pk, sk,
                                   sizeof sk));
        gcry_mpi_release(y);
        ASSERT_OK(gcry_mpi_scan(&y, GCRYMPI_FMT_USG, pk + 33, 32, NULL));
        gcry_mpi_sub(negy, p, y);
        ASSERT_TRUE(gcry_mpi_cmp(y, negy) <= 0);
    }

    gcry_mpi_release(y);
    gcry_mpi_release(p);
    gcry_mpi_release(negy);
}

/* ------------------------------------------------------------------ */
/* DHKEM                                                               */
/* ------------------------------------------------------------------ */

TEST(dhkem_x25519)
{
    unsigned char pk[GCRY_KEM_DHKEM25519_PUBKEY_LEN];
    unsigned char sk[GCRY_KEM_DHKEM25519_SECKEY_LEN];
    unsigned char ct[GCRY_KEM_DHKEM25519_ENCAPS_LEN];
    unsigned char ss1[GCRY_KEM_DHKEM25519_SHARED_LEN];
    unsigned char ss2[GCRY_KEM_DHKEM25519_SHARED_LEN];
    unsigned char *skR;
    unsigned char *pkR;
    unsigned char *enc;

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_DHKEM25519, pk, sizeof pk, sk,
                               sizeof sk));
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_DHKEM25519, pk, sizeof pk, ct, sizeof ct,
                             ss1, sizeof ss1, NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEM25519, sk, sizeof sk, ct, sizeof ct,
                             ss2, sizeof ss2, NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, sizeof ss1);
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEM25519, sk, sizeof sk, ct, sizeof ct,
                             ss2, sizeof ss2, pk, sizeof pk));
    ASSERT_MEM_EQ(ss1, ss2, sizeof ss1);
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(GCRY_KEM_DHKEM25519, sk, sizeof sk, ct, sizeof ct,
                              ss2, sizeof ss2, pk, 31));

    /* RFC 9180 appendix A.1 (DHKEM(X25519, HKDF-SHA256), base mode). */
    unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
          &skR);
    unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
          &pkR);
    unhex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
          &enc);
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEM25519, skR, 32, enc, 32, ss1,
                             sizeof ss1, pkR, 32));
    ASSERT_HEX_EQ("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
                  ss1, 32);
    free(skR);
    free(pkR);
    free(enc);
}

TEST(dhkem_x448)
{
    unsigned char pk[GCRY_KEM_DHKEM448_PUBKEY_LEN];
    unsigned char sk[GCRY_KEM_DHKEM448_SECKEY_LEN];
    unsigned char ct[GCRY_KEM_DHKEM448_ENCAPS_LEN];
    unsigned char ss1[64];
    unsigned char ss2[GCRY_KEM_DHKEM448_SHARED_LEN];

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_DHKEM448, pk, sizeof pk, sk,
                               sizeof sk));
    /* The full 64 byte RFC 9180 secret and the header's 56 byte length are
     * both accepted; the shorter one is a prefix of the longer. */
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_DHKEM448, pk, sizeof pk, ct, sizeof ct,
                             ss1, sizeof ss1, NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEM448, sk, sizeof sk, ct, sizeof ct,
                             ss2, sizeof ss2, NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, sizeof ss2);
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(GCRY_KEM_DHKEM448, pk, sizeof pk, ct, sizeof ct,
                              ss1, 48, NULL, 0));
}

TEST(dhkem_p256)
{
    unsigned char pk[65];
    unsigned char sk[32];
    unsigned char ct[65];
    unsigned char ss1[32];
    unsigned char ss2[32];

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_DHKEMP256R1, pk, sizeof pk, sk,
                               sizeof sk));
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_DHKEMP256R1, pk, sizeof pk, ct,
                             sizeof ct, ss1, sizeof ss1, NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEMP256R1, sk, sizeof sk, ct,
                             sizeof ct, ss2, sizeof ss2, NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, sizeof ss1);
}

/* ------------------------------------------------------------------ */
/* Unsupported and unknown algorithms                                  */
/* ------------------------------------------------------------------ */

TEST(unsupported)
{
    unsigned char pk[GCRY_KEM_SNTRUP761_PUBKEY_LEN];
    unsigned char sk[GCRY_KEM_SNTRUP761_SECKEY_LEN];

    ASSERT_ERR(GPG_ERR_UNSUPPORTED_ALGORITHM,
               gcry_kem_keypair(GCRY_KEM_SNTRUP761, pk, sizeof pk, sk,
                                sizeof sk));
    ASSERT_ERR(GPG_ERR_UNSUPPORTED_ALGORITHM,
               gcry_kem_keypair(GCRY_KEM_CM6688128F, pk, sizeof pk, sk,
                                sizeof sk));
    ASSERT_ERR(GPG_ERR_UNKNOWN_ALGORITHM,
               gcry_kem_keypair(999, pk, sizeof pk, sk, sizeof sk));
    ASSERT_ERR(GPG_ERR_UNKNOWN_ALGORITHM,
               gcry_kem_encap(GCRY_KEM_NONE, pk, sizeof pk, sk, sizeof sk, pk,
                              32, NULL, 0));
}

TEST(dhkem_p384_p521)
{
    unsigned char pk[133];
    unsigned char sk[66];
    unsigned char ct[133];
    unsigned char ss1[64];
    unsigned char ss2[64];

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_DHKEMP384R1, pk, 97, sk, 48));
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_DHKEMP384R1, pk, 97, ct, 97, ss1, 48,
                             NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEMP384R1, sk, 48, ct, 97, ss2, 48,
                             NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, 48);
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEMP384R1, sk, 48, ct, 97, ss2, 48,
                             pk, 97));
    ASSERT_MEM_EQ(ss1, ss2, 48);

    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_DHKEMP521R1, pk, 133, sk, 66));
    ASSERT_OK(gcry_kem_encap(GCRY_KEM_DHKEMP521R1, pk, 133, ct, 133, ss1, 64,
                             NULL, 0));
    ASSERT_OK(gcry_kem_decap(GCRY_KEM_DHKEMP521R1, sk, 66, ct, 133, ss2, 64,
                             NULL, 0));
    ASSERT_MEM_EQ(ss1, ss2, 64);
}

TEST(argument_validation)
{
    unsigned char pk[GCRY_KEM_MLKEM512_PUBKEY_LEN];
    unsigned char sk[GCRY_KEM_MLKEM512_SECKEY_LEN];
    unsigned char ct[GCRY_KEM_MLKEM512_CIPHER_LEN];
    unsigned char ss[65];

    /* Buffer lengths must match the algorithm exactly. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_keypair(GCRY_KEM_RAW_X25519, pk, 31, sk, 32));
    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_RAW_X25519, pk, 32, sk, 32));
    ASSERT_ERR(GPG_ERR_INV_VALUE, /* raw ECC: ciphertext is a public key */
               gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, 32, ct, 31, ss, 32, NULL,
                              0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, 32, ct, 32, ss, 31, NULL,
                              0));
    ASSERT_ERR(GPG_ERR_INV_ARG, /* no optional input for raw ECC */
               gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, 32, ct, 32, ss, 32, pk,
                              32));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(GCRY_KEM_RAW_X25519, sk, 32, ct, 32, ss, 31, NULL,
                              0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(GCRY_KEM_RAW_X25519, sk, 32, ct, 32, ss, 32, pk,
                              32));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_genkey(GCRY_KEM_RAW_X25519, pk, 32, sk, 32, pk, 32));
    ASSERT_ERR(GPG_ERR_INV_ARG, /* ML-KEM seed is d || z, 64 bytes */
               gcry_kem_genkey(GCRY_KEM_MLKEM512, pk, sizeof pk, sk, sizeof sk,
                               pk, 10));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(GCRY_KEM_MLKEM512, pk, sizeof pk, ct, sizeof ct,
                              ss, 32, pk, 10));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(GCRY_KEM_MLKEM512, sk, sizeof sk, ct, sizeof ct,
                              ss, 32, pk, 10));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_keypair(GCRY_KEM_MLKEM512, pk, sizeof pk, sk, 100));

    /* A point that is not on the curve is rejected. */
    ASSERT_OK(gcry_kem_keypair(GCRY_KEM_RAW_P256R1, pk, 65, sk, 32));
    memset(pk, 0, 65);
    pk[0] = 4;
    ASSERT_ERR(GPG_ERR_INV_DATA,
               gcry_kem_decap(GCRY_KEM_RAW_P256R1, sk, 32, pk, 65, ss, 65, NULL,
                              0));
    ASSERT_ERR(GPG_ERR_INV_DATA,
               gcry_kem_encap(GCRY_KEM_RAW_P256R1, pk, 65, ct, 65, ss, 65, NULL,
                              0));

    /* Unsupported and unknown algorithms through every entry point. */
    ASSERT_ERR(GPG_ERR_UNSUPPORTED_ALGORITHM,
               gcry_kem_encap(GCRY_KEM_SNTRUP761, pk, 32, ct, 32, ss, 32, NULL,
                              0));
    ASSERT_ERR(GPG_ERR_UNSUPPORTED_ALGORITHM,
               gcry_kem_decap(GCRY_KEM_SNTRUP761, sk, 32, ct, 32, ss, 32, NULL,
                              0));
    ASSERT_ERR(GPG_ERR_UNKNOWN_ALGORITHM,
               gcry_kem_decap(999, sk, 32, ct, 32, ss, 32, NULL, 0));

    /* NULL buffers: the reference library crashes, we return an error. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_keypair(GCRY_KEM_RAW_X25519, NULL, 32, sk, 32));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_encap(GCRY_KEM_RAW_X25519, pk, 32, NULL, 32, ss, 32,
                              NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_kem_decap(GCRY_KEM_RAW_X25519, sk, 32, ct, 32, NULL, 32,
                              NULL, 0));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(mlkem512);
    RUN_TEST(mlkem768);
    RUN_TEST(mlkem1024);
    RUN_TEST(raw_x25519);
    RUN_TEST(raw_x448);
    RUN_TEST(raw_weierstrass);
    RUN_TEST(raw_p256_low_y_key);
    RUN_TEST(dhkem_x25519);
    RUN_TEST(dhkem_x448);
    RUN_TEST(dhkem_p256);
    RUN_TEST(unsupported);
    RUN_TEST(dhkem_p384_p521);
    RUN_TEST(argument_validation);
    return TEST_RESULT();
}
