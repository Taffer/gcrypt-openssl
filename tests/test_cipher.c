#include <gcrypt.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdlib.h>
#include <string.h>

#include "test_common.h"

/* Decode a hex string into BUF; returns the byte count. */
static size_t
unhex(const char *hex, unsigned char *buf, size_t bufsize)
{
    size_t n = 0;

    while (hex[0] && hex[1] && n < bufsize) {
        unsigned int v;

        if (hex[0] == ' ') {
            hex++;
            continue;
        }

        sscanf(hex, "%2x", &v);
        buf[n++] = (unsigned char)v;
        hex += 2;
    }

    return n;
}

/* Skip an algorithm OpenSSL does not provide, reporting it. */
static int
algo_available(int algo)
{
    if (gcry_cipher_test_algo(algo)) {
        printf("  (skipping %s: not available)\n", gcry_cipher_algo_name(algo));
        return 0;
    }

    return 1;
}

/* The error for opening a non-FIPS algorithm in a mode it cannot do: the
 * algorithm check precedes the mode check, so FIPS mode reports the
 * algorithm, as the reference library does. */
static gcry_err_code_t
bad_mode_err(void)
{
    return gcry_fips_mode_active() ? GPG_ERR_CIPHER_ALGO
           : GPG_ERR_INV_CIPHER_MODE;
}

/* One-shot encrypt and decrypt check for a block or stream cipher. */
static void
check_vector(int algo, int mode, const char *keyhex, const char *ivhex,
             const char *pthex, const char *cthex)
{
    gcry_cipher_hd_t hd;
    unsigned char key[64];
    unsigned char iv[32];
    unsigned char pt[128];
    unsigned char ct[128];
    unsigned char out[128];
    size_t keylen = unhex(keyhex, key, sizeof key);
    size_t ivlen = ivhex ? unhex(ivhex, iv, sizeof iv) : 0;
    size_t ptlen = unhex(pthex, pt, sizeof pt);
    size_t ctlen = unhex(cthex, ct, sizeof ct);

    if (!algo_available(algo)) {
        return;
    }

    if (getenv("TEST_VERBOSE")) {
        printf("  vector %s mode %d\n", gcry_cipher_algo_name(algo), mode);
    }

    ASSERT_EQ(ptlen, ctlen);
    ASSERT_OK(gcry_cipher_open(&hd, algo, mode, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, keylen));

    if (ivhex) {
        if (mode == GCRY_CIPHER_MODE_CTR) {
            ASSERT_OK(gcry_cipher_setctr(hd, iv, ivlen));
        } else {
            ASSERT_OK(gcry_cipher_setiv(hd, iv, ivlen));
        }
    }

    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, pt, ptlen));
    ASSERT_MEM_EQ(ct, out, ctlen);

    gcry_cipher_reset(hd);

    if (ivhex) {
        if (mode == GCRY_CIPHER_MODE_CTR) {
            ASSERT_OK(gcry_cipher_setctr(hd, iv, ivlen));
        } else {
            ASSERT_OK(gcry_cipher_setiv(hd, iv, ivlen));
        }
    }

    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, ct, ctlen));
    ASSERT_MEM_EQ(pt, out, ptlen);

    /* In place. */
    gcry_cipher_reset(hd);

    if (ivhex) {
        if (mode == GCRY_CIPHER_MODE_CTR) {
            ASSERT_OK(gcry_cipher_setctr(hd, iv, ivlen));
        } else {
            ASSERT_OK(gcry_cipher_setiv(hd, iv, ivlen));
        }
    }

    memcpy(out, pt, ptlen);
    ASSERT_OK(gcry_cipher_encrypt(hd, out, ptlen, NULL, 0));
    ASSERT_MEM_EQ(ct, out, ctlen);
    gcry_cipher_close(hd);
}

#define AES128_KEY "2b7e151628aed2a6abf7158809cf4f3c"
#define AES_PT1 "6bc1bee22e409f96e93d7e117393172a"
#define AES_PT2 "ae2d8a571e03ac9c9eb76fac45af8e51"
#define AES_IV "000102030405060708090a0b0c0d0e0f"

TEST(aes_sp800_38a)
{
    check_vector(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_ECB, AES128_KEY, NULL,
                 AES_PT1 AES_PT2,
                 "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf");
    check_vector(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, AES128_KEY, AES_IV,
                 AES_PT1 AES_PT2,
                 "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2");
    check_vector(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB, AES128_KEY, AES_IV,
                 AES_PT1 AES_PT2,
                 "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b");
    check_vector(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OFB, AES128_KEY, AES_IV,
                 AES_PT1 AES_PT2,
                 "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825");
    check_vector(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR, AES128_KEY,
                 "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", AES_PT1 AES_PT2,
                 "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");
    check_vector(GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_ECB,
                 "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", NULL,
                 AES_PT1, "bd334f1d6e45f25ff712a214571fa5cc");
    check_vector(GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB,
                 "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                 NULL, AES_PT1, "f3eed1bdb5d2a03c064b5a7e3db181f8");
}

TEST(other_block_ciphers)
{
    /* DES, and 3DES with three equal keys (equivalent to single DES). */
    check_vector(GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, "0123456789abcdef",
                 NULL, "4e6f772069732074", "3fa40e8a984d4815");
    check_vector(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB,
                 "0123456789abcdef0123456789abcdef0123456789abcdef", NULL,
                 "4e6f772069732074", "3fa40e8a984d4815");
    /* CAST5, RFC 2144 B.1. */
    check_vector(GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB,
                 "0123456712345678234567893456789a", NULL,
                 "0123456789abcdef", "238b4fe5847e44b2");
    /* Blowfish, Schneier's vector. */
    check_vector(GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB,
                 "0000000000000000", NULL, "0000000000000000",
                 "4ef997456198dd78");
    /* IDEA. */
    check_vector(GCRY_CIPHER_IDEA, GCRY_CIPHER_MODE_ECB,
                 "00010002000300040005000600070008", NULL,
                 "0000000100020003", "11fbed2b01986de5");
    /* RC2, RFC 2268 (64 bit key, 64 effective bits). */
    check_vector(GCRY_CIPHER_RFC2268_128, GCRY_CIPHER_MODE_ECB,
                 "ffffffffffffffff", NULL, "ffffffffffffffff",
                 "278b27e42e2f0d49");
    /* SM4, GB/T 32907. */
    check_vector(GCRY_CIPHER_SM4, GCRY_CIPHER_MODE_ECB,
                 "0123456789abcdeffedcba9876543210", NULL,
                 "0123456789abcdeffedcba9876543210",
                 "681edf34d206965e86b3e94f536e4246");
    /* Camellia-128, RFC 3713. */
    check_vector(GCRY_CIPHER_CAMELLIA128, GCRY_CIPHER_MODE_ECB,
                 "0123456789abcdeffedcba9876543210", NULL,
                 "0123456789abcdeffedcba9876543210",
                 "67673138549669730857065648eabe43");
    /* ARIA-128, RFC 5794. */
    check_vector(GCRY_CIPHER_ARIA128, GCRY_CIPHER_MODE_ECB,
                 "000102030405060708090a0b0c0d0e0f", NULL,
                 "00112233445566778899aabbccddeeff",
                 "d718fbd6ab644c739da95f3be6451778");
    /* SEED, RFC 4269 B.3. */
    check_vector(GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_ECB,
                 "4706480851e61be85d74bfb3fd956185", NULL,
                 "83a2f8a288641fb9a4e9a5cc2f131c7d",
                 "ee54d13ebcae706d226bc3142cd40d4a");

    /* CTR with a 64 bit block cipher exercises the composed CTR. */
    if (algo_available(GCRY_CIPHER_CAST5)) {
        gcry_cipher_hd_t hd;
        unsigned char key[16];
        unsigned char ctr[8] = { 0, 0, 0, 0, 0, 0, 0, 0xff };
        unsigned char pt[21];
        unsigned char ct[21];
        unsigned char ecb[24];
        unsigned char counter[24];
        size_t i;

        unhex("0123456712345678234567893456789a", key, sizeof key);

        for (i = 0; i < sizeof pt; i++) {
            pt[i] = (unsigned char)i;
        }

        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_CTR, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
        ASSERT_OK(gcry_cipher_setctr(hd, ctr, sizeof ctr));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 5, pt, 5));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct + 5, 16, pt + 5, 16));
        gcry_cipher_close(hd);

        /* Reference: ECB encrypt the three counter blocks ff, 0100, 0101. */
        memset(counter, 0, sizeof counter);
        counter[7] = 0xff;
        counter[14] = 0x01;
        counter[22] = 0x01;
        counter[23] = 0x01;
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CAST5, GCRY_CIPHER_MODE_ECB, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
        ASSERT_OK(gcry_cipher_encrypt(hd, ecb, sizeof ecb, counter, sizeof counter));
        gcry_cipher_close(hd);

        for (i = 0; i < sizeof pt; i++) {
            ASSERT_EQ(pt[i] ^ ecb[i], ct[i]);
        }
    }
}

TEST(stream_ciphers)
{
    /* RC4: "Key" / "Plaintext". */
    check_vector(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, "536563726574",
                 NULL, "41747461636b206174206461776e",
                 "45a01f645fc35b383552544b9bf5");
    /* ChaCha20, RFC 7539 A.2 #1 (zero key, zero nonce, counter 0). */
    check_vector(GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM,
                 "0000000000000000000000000000000000000000000000000000000000000000",
                 "000000000000000000000000",
                 "0000000000000000000000000000000000000000000000000000000000000000"
                 "0000000000000000000000000000000000000000000000000000000000000000",
                 "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                 "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    /* The same keystream with an 8 byte nonce (original variant). */
    check_vector(GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_STREAM,
                 "0000000000000000000000000000000000000000000000000000000000000000",
                 "0000000000000000", "00000000000000000000000000000000",
                 "76b8e0ada0f13d90405d6ae55386bd28");
}

TEST(aes_gcm)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16] = { 0 };
    unsigned char iv[12] = { 0 };
    unsigned char pt[16] = { 0 };
    unsigned char ct[16];
    unsigned char tag[16];
    unsigned char expect_ct[16];
    unsigned char expect_tag[16];
    size_t taglen = 0;

    unhex("0388dace60b6a392f328c2b971b2fe78", expect_ct, sizeof expect_ct);
    unhex("ab6e47d42cec13bdf53a67b21257bddf", expect_tag, sizeof expect_tag);

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen));
    ASSERT_EQ(16, taglen);
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, sizeof ct, pt, sizeof pt));
    ASSERT_MEM_EQ(expect_ct, ct, 16);
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_tag, tag, 16);
    {
        unsigned char scratch[16];

        ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, scratch, 16, pt, 16));
    }

    /* Decrypt in two pieces, then verify. */
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt, 7, ct, 7));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt + 7, 9, ct + 7, 9));
    {
        unsigned char zeros[16] = { 0 };

        ASSERT_MEM_EQ(zeros, pt, 16);
    }
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));

    /* Wrong tag, and a truncated tag. */
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt, 16, ct, 16));
    tag[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    tag[0] ^= 1;
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt, 16, ct, 16));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));

    /* GMAC: no data at all (test case 1 of the GCM spec). */
    unhex("58e2fccefa7e3061367f1d57a4e7455a", expect_tag, sizeof expect_tag);
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_tag, tag, 16);

    /* AAD before data, round trip with a 16 byte IV. */
    {
        unsigned char iv16[16];
        unsigned char aad[20];
        unsigned char data[33];
        unsigned char enc[33];
        unsigned char dec[33];
        size_t i;

        for (i = 0; i < sizeof iv16; i++) {
            iv16[i] = (unsigned char)(i * 7);
        }

        for (i = 0; i < sizeof aad; i++) {
            aad[i] = (unsigned char)(i + 1);
        }

        for (i = 0; i < sizeof data; i++) {
            data[i] = (unsigned char)(i * 3);
        }

        ASSERT_OK(gcry_cipher_setiv(hd, iv16, sizeof iv16));
        ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
        ASSERT_OK(gcry_cipher_encrypt(hd, enc, sizeof enc, data, sizeof data));
        ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, aad, 1));
        ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));

        ASSERT_OK(gcry_cipher_setiv(hd, iv16, sizeof iv16));
        ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
        ASSERT_OK(gcry_cipher_decrypt(hd, dec, sizeof dec, enc, sizeof enc));
        ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
        ASSERT_MEM_EQ(data, dec, sizeof data);

        /* Tampered AAD. */
        aad[0] ^= 0x80;
        ASSERT_OK(gcry_cipher_setiv(hd, iv16, sizeof iv16));
        ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
        ASSERT_OK(gcry_cipher_decrypt(hd, dec, sizeof dec, enc, sizeof enc));
        ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    }

    gcry_cipher_close(hd);
}

TEST(chacha20_poly1305_rfc8439)
{
    gcry_cipher_hd_t hd;
    unsigned char key[32];
    unsigned char nonce[12];
    unsigned char aad[12];
    unsigned char expect_ct[114];
    unsigned char expect_tag[16];
    unsigned char ct[114];
    unsigned char pt[114];
    unsigned char tag[16];
    const char *msg = "Ladies and Gentlemen of the class of '99: If I could "
                      "offer you only one tip for the future, sunscreen would "
                      "be it.";

    unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
          key, sizeof key);
    unhex("070000004041424344454647", nonce, sizeof nonce);
    unhex("50515253c0c1c2c3c4c5c6c7", aad, sizeof aad);
    unhex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
          "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
          "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
          "3ff4def08e4b7a9de576d26586cec64b6116", expect_ct, sizeof expect_ct);
    unhex("1ae10b594f09e26a7e902ecbd0600691", expect_tag, sizeof expect_tag);
    ASSERT_EQ(114, strlen(msg));

    if (gcry_fips_mode_active()) {
        /* ChaCha20 is not a FIPS algorithm. */
        ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                   gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                    GCRY_CIPHER_MODE_POLY1305, 0));
        return;
    }

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305,
                               0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, sizeof ct, msg, 114));
    ASSERT_MEM_EQ(expect_ct, ct, 114);
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_tag, tag, 16);

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt, sizeof pt, ct, sizeof ct));
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 16));
    ASSERT_MEM_EQ(msg, pt, 114);
    gcry_cipher_close(hd);
}

TEST(aes_ccm_rfc3610)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char nonce[13];
    unsigned char aad[8];
    unsigned char pt[23];
    unsigned char expect_ct[23];
    unsigned char expect_tag[8];
    unsigned char ct[23];
    unsigned char dec[23];
    unsigned char tag[8];
    unsigned long long lengths[3] = { 23, 8, 8 };
    size_t taglen = 0;

    unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", key, sizeof key);
    unhex("00000003020100a0a1a2a3a4a5", nonce, sizeof nonce);
    unhex("0001020304050607", aad, sizeof aad);
    unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", pt, sizeof pt);
    unhex("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384", expect_ct,
          sizeof expect_ct);
    unhex("17e8d12cfdf926e0", expect_tag, sizeof expect_tag);

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen));
    ASSERT_EQ(8, taglen);
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 10, pt, 10));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct + 10, 13, pt + 10, 13));
    ASSERT_MEM_EQ(expect_ct, ct, 23);
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_tag, tag, 8);

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_decrypt(hd, dec, sizeof dec, ct, sizeof ct));
    ASSERT_MEM_EQ(pt, dec, 23);
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 8));

    /* Decryption in several chunks. */
    memset(dec, 0, sizeof dec);
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_decrypt(hd, dec, 10, ct, 10));
    ASSERT_OK(gcry_cipher_decrypt(hd, dec + 10, 13, ct + 10, 13));
    ASSERT_MEM_EQ(pt, dec, 23);
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 8));

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_decrypt(hd, dec, sizeof dec, ct, sizeof ct));
    tag[7] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 8));

    /* Bad tag lengths and unfinished data. */
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    lengths[2] = 7;
    ASSERT_ERR(GPG_ERR_INV_LENGTH,
               gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof lengths));
    lengths[2] = 8;
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 10, pt, 10));
    ASSERT_ERR(GPG_ERR_UNFINISHED, gcry_cipher_gettag(hd, tag, 8));
    gcry_cipher_close(hd);
}

TEST(aes_ocb_rfc7253)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char nonce[12];
    unsigned char data[8];
    unsigned char expect[24];
    unsigned char out[8];
    unsigned char tag[16];
    size_t taglen = 0;

    unhex("000102030405060708090a0b0c0d0e0f", key, sizeof key);
    unhex("bbaa99887766554433221100", nonce, sizeof nonce);
    unhex("785407bfffc8ad9edcc5520ac9111ee6", expect, 16);

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OCB, 0));
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen));
    ASSERT_EQ(16, taglen);
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    /* No tag until the data has been finalized, even if there is none. */
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_OK(gcry_cipher_final(hd));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 0, data, 0));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect, tag, 16);
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, 8, data, 8));

    /* N=...01, A=P=0001020304050607. */
    nonce[11] = 1;
    unhex("0001020304050607", data, sizeof data);
    unhex("6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009", expect, 24);
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, data, sizeof data));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(hd, out, 8, data, 8));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, data, sizeof data));
    ASSERT_OK(gcry_cipher_final(hd));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 8, data, 8));
    ASSERT_MEM_EQ(expect, out, 8);
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect + 8, tag, 16);

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_final(hd));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 8, expect, 8));
    ASSERT_OK(gcry_cipher_authenticate(hd, data, sizeof data));
    ASSERT_MEM_EQ(data, out, 8);
    ASSERT_OK(gcry_cipher_checktag(hd, expect + 8, 16));

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_final(hd));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 8, expect, 8));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, expect + 8, 16));

    /* A 12 byte tag. */
    {
        int tl = 12;

        ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_TAGLEN, &tl, sizeof tl));
        ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen));
        ASSERT_EQ(12, taglen);
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_encrypt(hd, out, 8, data, 8));
        ASSERT_OK(gcry_cipher_gettag(hd, tag, 12));
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_decrypt(hd, out, 8, out, 8));
        ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));
        ASSERT_MEM_EQ(data, out, 8);
        tl = 9;
        ASSERT_ERR(GPG_ERR_INV_LENGTH,
                   gcry_cipher_ctl(hd, GCRYCTL_SET_TAGLEN, &tl, sizeof tl));
    }

    /* Decrypting without gcry_cipher_final() leaves no tag to check. */
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 0, expect, 0));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_checktag(hd, tag, 12));

    /* The tag length is a handle setting: it survives a new key, and a
     * multi-chunk message with a partial last block round-trips. */
    {
        int tl = 8;
        unsigned char big[37];
        unsigned char enc[37];
        unsigned char dec[37];

        memset(big, 0x5a, sizeof big);
        ASSERT_OK(gcry_cipher_reset(hd));
        ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_TAGLEN, &tl, sizeof tl));
        ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
        ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen));
        ASSERT_EQ(8, taglen);
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_authenticate(hd, data, sizeof data));
        ASSERT_OK(gcry_cipher_encrypt(hd, enc, 16, big, 16));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_encrypt(hd, enc + 16, 21, big + 16, 21));
        ASSERT_OK(gcry_cipher_gettag(hd, tag, 8));
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_decrypt(hd, dec, 32, enc, 32));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_decrypt(hd, dec + 32, 5, enc + 32, 5));
        ASSERT_OK(gcry_cipher_authenticate(hd, data, sizeof data));
        ASSERT_OK(gcry_cipher_checktag(hd, tag, 8));
        ASSERT_MEM_EQ(big, dec, sizeof big);
    }

    gcry_cipher_close(hd);
}

TEST(aes_gcm_siv_rfc8452)
{
    gcry_cipher_hd_t hd;
    unsigned char key[32] = { 1 };
    unsigned char nonce[12] = { 3 };
    unsigned char pt[8] = { 1 };
    unsigned char expect_ct[8];
    unsigned char expect_tag[16];
    unsigned char out[8];
    unsigned char tag[16];

    unhex("b5d839330ac7b786", expect_ct, sizeof expect_ct);
    unhex("578782fff6013b815b287c22493a364c", expect_tag, sizeof expect_tag);

    if (gcry_fips_mode_active()) {
        /* The FIPS provider has no AES-GCM-SIV; the mode is refused at
         * open for every AES variant. */
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES192,
                                    GCRY_CIPHER_MODE_GCM_SIV, 0));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
                                    GCRY_CIPHER_MODE_GCM_SIV, 0));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES,
                                    GCRY_CIPHER_MODE_GCM_SIV, 0));
        return;
    }

    /* RFC 8452 only defines 128 and 256 bit keys. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES192,
                               GCRY_CIPHER_MODE_GCM_SIV, 0));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 24));
    gcry_cipher_close(hd);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
                               GCRY_CIPHER_MODE_GCM_SIV, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 32));
    gcry_cipher_close(hd);

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM_SIV,
                               0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 16));

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, pt, sizeof pt));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_ct, out, 8);
    ASSERT_MEM_EQ(expect_tag, tag, 16);

    /* A finished message must be reset before a new nonce is accepted. */
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, sizeof tag));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, expect_ct, 8));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(pt, out, 8);

    gcry_cipher_close(hd);
}

TEST(aes_xts_ieee1619)
{
    gcry_cipher_hd_t hd;
    unsigned char key[32];
    unsigned char tweak[16] = { 0x33, 0x33, 0x33, 0x33, 0x33, 0 };
    unsigned char pt[32];
    unsigned char expect[32];
    unsigned char out[32];

    unhex("1111111111111111111111111111111122222222222222222222222222222222",
          key, sizeof key);
    memset(pt, 0x44, sizeof pt);
    unhex("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
          expect, sizeof expect);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_XTS, 0));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 16));

    /* Two equal keys are weak; FIPS mode refuses them at setkey. */
    {
        unsigned char same[32];

        memset(same, 0x11, sizeof same);

        if (gcry_fips_mode_active()) {
            ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_cipher_setkey(hd, same, sizeof same));
        } else {
            ASSERT_OK(gcry_cipher_setkey(hd, same, sizeof same));
        }
    }

    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, pt, sizeof pt));
    ASSERT_MEM_EQ(expect, out, 32);
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, expect, sizeof expect));
    ASSERT_MEM_EQ(pt, out, 32);
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 8, pt, 8));
    gcry_cipher_close(hd);
}

TEST(aes_keywrap)
{
    gcry_cipher_hd_t hd;
    unsigned char kek[24];
    unsigned char data[20];
    unsigned char expect[32];
    unsigned char out[32];
    unsigned char plen[4];
    size_t n = 0;

    /* RFC 3394 4.1. */
    unhex("000102030405060708090a0b0c0d0e0f", kek, 16);
    unhex("00112233445566778899aabbccddeeff", data, 16);
    unhex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", expect, 24);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, kek, 16));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 16, data,
                                                             16));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_encrypt(hd, out, 32, data, 12));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 24, data, 16));
    ASSERT_MEM_EQ(expect, out, 24);
    memset(out, 0, sizeof out);
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 16, expect, 24));
    ASSERT_MEM_EQ(data, out, 16);
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_KEYLEN, plen, &n));
    ASSERT_EQ(4, n);
    ASSERT_EQ(0, plen[0] | plen[1] | plen[2] | plen[3]);
    expect[3] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_decrypt(hd, out, 16, expect, 24));
    gcry_cipher_close(hd);

    /* RFC 5649 (padded). */
    unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", kek, 24);
    unhex("c37b7e6492584340bed12207808941155068f738", data, 20);
    unhex("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
          expect, 32);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_AESWRAP,
                               GCRY_CIPHER_EXTENDED));
    ASSERT_OK(gcry_cipher_setkey(hd, kek, 24));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 32, data, 20));
    ASSERT_MEM_EQ(expect, out, 32);
    memset(out, 0xaa, sizeof out);
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 24, expect, 32));
    ASSERT_MEM_EQ(data, out, 20);
    ASSERT_EQ(0, out[20] | out[21] | out[22] | out[23]);
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_KEYLEN, plen, &n));
    ASSERT_EQ(20, plen[3]);
    gcry_cipher_close(hd);
}

TEST(cbc_cts_rfc3962)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char iv[16] = { 0 };
    unsigned char expect[64];
    unsigned char out[64];
    const char *msg = "I would like the General Gau's Chicken, please, and "
                      "wonton soup.";

    memcpy(key, "chicken teriyaki", 16);
    ASSERT_EQ(64, strlen(msg));
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
                               GCRY_CIPHER_CBC_CTS));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));

    /* 17 bytes. */
    unhex("c6353568f2bf8cb4d8a580362da7ff7f97", expect, 17);
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, msg, 17));
    ASSERT_MEM_EQ(expect, out, 17);
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, expect, 17));
    ASSERT_MEM_EQ(msg, out, 17);

    /* 64 bytes: the last two blocks are swapped. */
    unhex("97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a8"
          "4807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
          expect, 64);
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, msg, 64));
    ASSERT_MEM_EQ(expect, out, 64);
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, expect, 64));
    ASSERT_MEM_EQ(msg, out, 64);

    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(hd, out, sizeof out, msg,
                                                       5));
    ASSERT_ERR(GPG_ERR_INV_FLAG, gcry_cipher_ctl(hd, GCRYCTL_SET_CBC_MAC, NULL, 1));
    gcry_cipher_close(hd);
}

TEST(cbc_mac_and_cfb_sync)
{
    gcry_cipher_hd_t cbc;
    gcry_cipher_hd_t mac;
    unsigned char key[16];
    unsigned char iv[16] = { 0 };
    unsigned char data[48];
    unsigned char ct[48];
    unsigned char tag[16];
    size_t i;

    unhex(AES128_KEY, key, sizeof key);

    for (i = 0; i < sizeof data; i++) {
        data[i] = (unsigned char)(i * 5 + 1);
    }

    /* CBC-MAC equals the last block of the CBC ciphertext. */
    ASSERT_OK(gcry_cipher_open(&cbc, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0));
    ASSERT_OK(gcry_cipher_open(&mac, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
                               GCRY_CIPHER_CBC_MAC));
    ASSERT_OK(gcry_cipher_setkey(cbc, key, sizeof key));
    ASSERT_OK(gcry_cipher_setkey(mac, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(cbc, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_setiv(mac, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(cbc, ct, sizeof ct, data, sizeof data));
    ASSERT_OK(gcry_cipher_encrypt(mac, tag, sizeof tag, data, sizeof data));
    ASSERT_MEM_EQ(ct + 32, tag, 16);
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(mac, tag, 16, data, 7));
    gcry_cipher_close(cbc);
    gcry_cipher_close(mac);

    /* OpenPGP CFB resync: after sync, the state equals a fresh CFB context
     * whose IV is the last 16 bytes of ciphertext produced so far. */
    {
        gcry_cipher_hd_t a;
        gcry_cipher_hd_t b;
        unsigned char ct_a[48];
        unsigned char ct_b[48];

        ASSERT_OK(gcry_cipher_open(&a, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB,
                                   GCRY_CIPHER_ENABLE_SYNC));
        ASSERT_OK(gcry_cipher_open(&b, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB, 0));
        ASSERT_OK(gcry_cipher_setkey(a, key, sizeof key));
        ASSERT_OK(gcry_cipher_setkey(b, key, sizeof key));
        ASSERT_OK(gcry_cipher_setiv(a, iv, sizeof iv));
        ASSERT_OK(gcry_cipher_encrypt(a, ct_a, 18, data, 18));
        ASSERT_OK(gcry_cipher_sync(a));
        ASSERT_OK(gcry_cipher_encrypt(a, ct_a + 18, 30, data + 18, 30));

        ASSERT_OK(gcry_cipher_setiv(b, ct_a + 2, 16));
        ASSERT_OK(gcry_cipher_encrypt(b, ct_b, 30, data + 18, 30));
        ASSERT_MEM_EQ(ct_b, ct_a + 18, 30);

        /* And decryption with sync recovers the plaintext. */
        ASSERT_OK(gcry_cipher_setiv(a, iv, sizeof iv));
        ASSERT_OK(gcry_cipher_decrypt(a, ct_b, 18, ct_a, 18));
        ASSERT_OK(gcry_cipher_sync(a));
        ASSERT_OK(gcry_cipher_decrypt(a, ct_b + 18, 30, ct_a + 18, 30));
        ASSERT_MEM_EQ(data, ct_b, 48);
        gcry_cipher_close(a);
        gcry_cipher_close(b);
    }
}

TEST(names_and_info)
{
    size_t n = 0;

    ASSERT_EQ(GCRY_CIPHER_AES, gcry_cipher_map_name("aes"));
    ASSERT_EQ(GCRY_CIPHER_AES, gcry_cipher_map_name("AES128"));
    ASSERT_EQ(GCRY_CIPHER_AES, gcry_cipher_map_name("Rijndael"));
    ASSERT_EQ(GCRY_CIPHER_AES192, gcry_cipher_map_name("aes-192"));
    ASSERT_EQ(GCRY_CIPHER_AES256, gcry_cipher_map_name("2.16.840.1.101.3.4.1.42"));
    ASSERT_EQ(GCRY_CIPHER_AES, gcry_cipher_map_name("oid.2.16.840.1.101.3.4.1.2"));
    ASSERT_EQ(GCRY_CIPHER_3DES, gcry_cipher_map_name("1.2.840.113549.3.7"));
    ASSERT_EQ(GCRY_CIPHER_CHACHA20, gcry_cipher_map_name("chacha20"));
    ASSERT_EQ(GCRY_CIPHER_TWOFISH, gcry_cipher_map_name("TWOFISH"));
    ASSERT_EQ(0, gcry_cipher_map_name("nope"));
    ASSERT_EQ(0, gcry_cipher_map_name(NULL));

    ASSERT_STR_EQ("AES256", gcry_cipher_algo_name(GCRY_CIPHER_AES256));
    ASSERT_STR_EQ("3DES", gcry_cipher_algo_name(GCRY_CIPHER_3DES));
    ASSERT_STR_EQ("ARCFOUR", gcry_cipher_algo_name(GCRY_CIPHER_ARCFOUR));
    ASSERT_STR_EQ("?", gcry_cipher_algo_name(12345));
    ASSERT_STR_EQ("?", gcry_cipher_algo_name(GCRY_CIPHER_SAFER_SK128));

    ASSERT_EQ(GCRY_CIPHER_MODE_CBC,
              gcry_cipher_mode_from_oid("2.16.840.1.101.3.4.1.2"));
    ASSERT_EQ(GCRY_CIPHER_MODE_GCM,
              gcry_cipher_mode_from_oid("2.16.840.1.101.3.4.1.46"));
    ASSERT_EQ(GCRY_CIPHER_MODE_CTR,
              gcry_cipher_mode_from_oid("1.2.156.10197.1.104.7"));
    ASSERT_EQ(0, gcry_cipher_mode_from_oid("1.2.3"));
    ASSERT_EQ(0, gcry_cipher_mode_from_oid(NULL));

    ASSERT_EQ(16, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES));
    ASSERT_EQ(32, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256));
    ASSERT_EQ(24, gcry_cipher_get_algo_keylen(GCRY_CIPHER_3DES));
    ASSERT_EQ(5, gcry_cipher_get_algo_keylen(GCRY_CIPHER_RFC2268_40));
    ASSERT_EQ(32, gcry_cipher_get_algo_keylen(GCRY_CIPHER_TWOFISH));
    ASSERT_EQ(0, gcry_cipher_get_algo_keylen(9999));
    ASSERT_EQ(16, gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES));
    ASSERT_EQ(8, gcry_cipher_get_algo_blklen(GCRY_CIPHER_BLOWFISH));
    ASSERT_EQ(1, gcry_cipher_get_algo_blklen(GCRY_CIPHER_ARCFOUR));
    ASSERT_EQ(16, gcry_cipher_get_algo_blklen(GCRY_CIPHER_SERPENT256));
    ASSERT_EQ(0, gcry_cipher_get_algo_blklen(9999));
    ASSERT_OK(gcry_cipher_algo_info(GCRY_CIPHER_AES, GCRYCTL_GET_KEYLEN, NULL, &n));
    ASSERT_EQ(16, n);
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_cipher_algo_info(GCRY_CIPHER_AES, 999, NULL,
                                                     NULL));

    ASSERT_OK(gcry_cipher_test_algo(GCRY_CIPHER_AES));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(GCRY_CIPHER_TWOFISH));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(GCRY_CIPHER_SERPENT128));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(GCRY_CIPHER_SALSA20));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(GCRY_CIPHER_GOST28147));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(GCRY_CIPHER_SAFER_SK128));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(0));
}

TEST(errors)
{
    gcry_cipher_hd_t hd = NULL;
    unsigned char key[32] = { 1 };
    unsigned char buf[32];
    unsigned char weak[8];

    ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
               gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, 0));
    ASSERT_NULL(hd);
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_STREAM, 0));
    ASSERT_ERR(bad_mode_err(),
               gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_ERR(bad_mode_err(),
               gcry_cipher_open(&hd, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_CBC, 0));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_POLY1305, 0));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_NONE, 0));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, 77, 0));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_EAX, 0));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
                                GCRY_CIPHER_CBC_CTS | GCRY_CIPHER_CBC_MAC));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
               gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0x100));

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
                               GCRY_CIPHER_SECURE));
    ASSERT_ERR(GPG_ERR_MISSING_KEY, gcry_cipher_encrypt(hd, buf, 16, buf, 16));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 15));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 16));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(hd, buf, 32, buf, 15));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, buf, 16, buf, 32));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE, gcry_cipher_authenticate(hd, buf, 4));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE, gcry_cipher_gettag(hd, buf, 16));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE, gcry_cipher_checktag(hd, buf, 16));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_cipher_ctl(hd, 9999, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
    gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &(size_t) {
        0
    }));
    {
        char sbox[] = "1.2.3";
        gcry_error_t e = gcry_cipher_set_sbox(hd, sbox)

                         ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, e);
    }
    gcry_cipher_close(hd);

    /* Weak DES keys are rejected unless explicitly allowed. */
    if (algo_available(GCRY_CIPHER_DES)) {
        unhex("0101010101010101", weak, sizeof weak);
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB, 0));
        ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_cipher_setkey(hd, weak, 8));
        ASSERT_ERR(GPG_ERR_MISSING_KEY, gcry_cipher_encrypt(hd, buf, 8, buf, 8));
        ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_ALLOW_WEAK_KEY, NULL, 1));
        ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_cipher_setkey(hd, weak, 8));
        ASSERT_OK(gcry_cipher_encrypt(hd, buf, 8, buf, 8));
        gcry_cipher_close(hd);
    }

    /* Variable key lengths. */
    if (algo_available(GCRY_CIPHER_ARCFOUR)) {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM,
                                   0));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 4));
        ASSERT_OK(gcry_cipher_setkey(hd, key, 5));
        ASSERT_OK(gcry_cipher_setkey(hd, key, 32));
        gcry_cipher_close(hd);
    }

    if (algo_available(GCRY_CIPHER_BLOWFISH)) {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_BLOWFISH, GCRY_CIPHER_MODE_ECB, 0));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 4));
        ASSERT_OK(gcry_cipher_setkey(hd, key, 32));
        gcry_cipher_close(hd);
    }

    gcry_cipher_close(NULL);
}

TEST(geniv)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16] = { 0 };
    unsigned char fixed[4] = { 1, 2, 3, 4 };
    unsigned char dyn[8] = { 0, 0, 0, 0, 0, 0, 0, 0xff };
    unsigned char iv[12];
    unsigned char expect[12] = { 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0xff };

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_geniv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_setup_geniv(hd, GCRY_CIPHER_GENIV_METHOD_CONCAT, fixed,
                                      sizeof fixed, dyn, sizeof dyn));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_geniv(hd, iv, 8));
    ASSERT_OK(gcry_cipher_geniv(hd, iv, sizeof iv));
    ASSERT_MEM_EQ(expect, iv, 12);
    ASSERT_OK(gcry_cipher_geniv(hd, iv, sizeof iv));
    expect[11] = 0;
    expect[10] = 1;
    ASSERT_MEM_EQ(expect, iv, 12);
    gcry_cipher_close(hd);
}

TEST(aes_cfb8_sp800_38a)
{
    /* SP 800-38A F.3.7, CFB8-AES128. */
    check_vector(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB8, AES128_KEY,
                 "000102030405060708090a0b0c0d0e0f",
                 "6bc1bee22e409f96e93d7e117393172aae2d",
                 "3b79424c9c0dd436bace9e0ed4586a4f32b9");
}

TEST(aes_siv_rfc5297)
{
    gcry_cipher_hd_t hd;
    unsigned char key[32];
    unsigned char ad[24];
    unsigned char pt[14];
    unsigned char expect_ct[14];
    unsigned char expect_tag[16];
    unsigned char out[14];
    unsigned char tag[16];
    size_t taglen = 0;

    /* RFC 5297 A.1: deterministic authenticated encryption. */
    unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
          key, sizeof key);
    unhex("101112131415161718191a1b1c1d1e1f2021222324252627", ad, sizeof ad);
    unhex("112233445566778899aabbccddee", pt, sizeof pt);
    unhex("40c02b9690c4dc04daef7f6afe5c", expect_ct, sizeof expect_ct);
    unhex("85632d07c6e8f37f950acd320a2ecc93", expect_tag, sizeof expect_tag);

    if (gcry_fips_mode_active()) {
        /* The FIPS provider has no AES-SIV. */
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_SIV, 0));
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_SIV,
                                    0));
        ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                   gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_SIV, 0));
        return;
    }

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_SIV, 0));
    /* SIV needs two AES keys. */
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 16));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 32));
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &taglen));
    ASSERT_EQ(16, taglen);

    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, pt, sizeof pt));
    ASSERT_MEM_EQ(expect_ct, out, sizeof out);
    /* The message is complete: no more associated data or plaintext. */
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_tag, tag, 16);
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, sizeof out, pt,
                                                      sizeof pt));

    /* Decryption needs the tag up front. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, sizeof out,
                                                      expect_ct, sizeof expect_ct));
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, expect_tag, 16));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    memset(out, 0, sizeof out);
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, expect_ct,
                                  sizeof expect_ct));
    ASSERT_MEM_EQ(pt, out, sizeof pt);
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 16));
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 16));
    tag[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    gcry_cipher_close(hd);

    /* SIV needs a 128 bit block cipher. */
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_SIV, 0));
}

TEST(aes_gcm_siv_states)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16] = { 1 };
    unsigned char nonce[12] = { 3 };
    unsigned char ad[1] = { 1 };
    unsigned char pt[8] = { 2 };
    unsigned char expect_ct[8];
    unsigned char expect_tag[16];
    unsigned char out[8];
    unsigned char tag[16];

    /* RFC 8452 C.1, 8 byte plaintext with one byte of AAD. */
    unhex("1e6daba35669f427", expect_ct, sizeof expect_ct);
    unhex("3b0a1a2560969cdf790d99759abd1508", expect_tag, sizeof expect_tag);

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM_SIV,
                                    0));
        return;
    }

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM_SIV,
                               0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, pt, sizeof pt));
    ASSERT_MEM_EQ(expect_ct, out, 8);
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(expect_tag, tag, 16);
    /* Single shot: nothing more may follow the plaintext. */
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, sizeof out, pt,
                                                      sizeof pt));

    /* The plaintext must come in one call. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 4, pt, 4));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out + 4, 4, pt + 4,
                                                      4));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));

    /* A tag for the empty message, and no encryption without a nonce. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, sizeof out, pt,
                                                      sizeof pt));

    /* Decryption: nonce, AAD, expected tag, data, check. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, sizeof out,
                                                      expect_ct, sizeof expect_ct));
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, expect_tag, 16));
    memset(out, 0, sizeof out);
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, expect_ct,
                                  sizeof expect_ct));
    ASSERT_MEM_EQ(pt, out, 8);
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 16));
    ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, sizeof out,
                                                      expect_ct, sizeof expect_ct));
    gcry_cipher_close(hd);
}

/* A CCM handle keyed with KEY, a 12 byte nonce and, optionally, lengths. */
static gcry_cipher_hd_t
ccm_handle(const unsigned char *key, const unsigned char *nonce,
           int with_lengths, unsigned long long datalen,
           unsigned long long aadlen, unsigned long long taglen)
{
    gcry_cipher_hd_t hd = NULL;
    unsigned long long lengths[3];

    gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0);
    gcry_cipher_setkey(hd, key, 16);
    gcry_cipher_setiv(hd, nonce, 12);

    if (with_lengths) {
        lengths[0] = datalen;
        lengths[1] = aadlen;
        lengths[2] = taglen;
        gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof lengths);
    }

    return hd;
}

TEST(aes_ccm_states)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char nonce[13];
    unsigned char ad[4];
    unsigned char pt[5];
    unsigned char ct[5];
    unsigned char out[5];
    unsigned char scratch[8];
    unsigned char tag[8];
    unsigned char expect_tag[8];
    unsigned long long lengths[3] = { 5, 4, 8 };

    unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", key, sizeof key);
    unhex("00000003020100a0a1a2a3a4a5", nonce, sizeof nonce);
    unhex("00112233", ad, sizeof ad);
    unhex("7468697320", pt, sizeof pt);
    unhex("6ecdcbfdb6d4b696", expect_tag, sizeof expect_tag);

    /* Nonce and length validation. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_setiv(hd, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_setiv(hd, nonce, 6));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_setiv(hd, nonce, 14));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS,
                                                  lengths, sizeof lengths));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    lengths[2] = 7;
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS,
                                                   lengths, sizeof lengths));
    lengths[2] = 8;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS,
                                                lengths, 8));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, scratch, sizeof scratch,
                                                      pt, sizeof pt));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS,
                                                  lengths, sizeof lengths));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_authenticate(hd, pt, 5));
    gcry_cipher_close(hd);

    /* Call order: AAD, then data, then the tag. */
    hd = ccm_handle(key, nonce, 1, 5, 4, 8);
    ASSERT_NOT_NULL(hd);
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_gettag(hd, tag, 8));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, scratch, sizeof scratch,
                                                      pt, sizeof pt));
    gcry_cipher_close(hd);

    hd = ccm_handle(key, nonce, 1, 5, 4, 8);
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_ERR(GPG_ERR_UNFINISHED, gcry_cipher_gettag(hd, tag, 8));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 3, pt, 3));
    ASSERT_ERR(GPG_ERR_UNFINISHED, gcry_cipher_gettag(hd, tag, 8));
    /* More data than announced; a failed call fills the output with 0x42
     * so that nothing sensitive leaks. */
    memset(scratch, 0, sizeof scratch);
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(hd, scratch,
                                                       sizeof scratch, pt + 2, 3));
    ASSERT_EQ(0x42, scratch[0]);
    ASSERT_EQ(0x42, scratch[7]);
    ASSERT_OK(gcry_cipher_encrypt(hd, ct + 3, 2, pt + 3, 2));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_gettag(hd, tag, 0));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_gettag(hd, tag, 4));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 8));
    ASSERT_MEM_EQ(expect_tag, tag, 8);
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 8));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, scratch, sizeof scratch,
                                                      pt, sizeof pt));
    gcry_cipher_close(hd);

    /* Decryption with the AAD delivered in two pieces. */
    hd = ccm_handle(key, nonce, 1, 5, 4, 8);
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, 2));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad + 2, 2));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, ct, sizeof ct));
    ASSERT_MEM_EQ(pt, out, 5);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_checktag(hd, tag, 0));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_checktag(hd, tag, 4));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 8));
    gcry_cipher_close(hd);

    /* No AAD at all, and a wrong tag. */
    hd = ccm_handle(key, nonce, 1, 5, 0, 8);
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, 0));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, sizeof ct, pt, sizeof pt));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 8));
    gcry_cipher_close(hd);

    ASSERT_ERR(bad_mode_err(),
               gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CCM, 0));
}

TEST(aes_gcm_states)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char iv[12] = { 1 };
    unsigned char ad[4] = { 1, 2, 3, 4 };
    unsigned char pt[5] = { 5, 6, 7, 8, 9 };
    unsigned char ct[5];
    unsigned char out[5];
    unsigned char tag[16];
    unsigned char tag2[16];
    unsigned char big[17];
    unsigned long long lengths[3] = { 5, 4, 8 };
    int tl = 12;

    unhex(AES128_KEY, key, sizeof key);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_setiv(hd, iv, 0));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, sizeof ct, pt, sizeof pt));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_gettag(hd, tag, 3));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    /* Reading the tag again gives the same tag; longer buffers are fine. */
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_MEM_EQ(tag, tag2, 16);
    ASSERT_OK(gcry_cipher_gettag(hd, big, sizeof big));
    ASSERT_MEM_EQ(tag, big, 16);
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, sizeof out, pt,
                                                      sizeof pt));

    /* Controls that belong to other modes. */
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE, gcry_cipher_ctl(hd, GCRYCTL_SET_TAGLEN,
                                                        &tl, sizeof tl));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                               sizeof lengths));

    /* Decrypt and verify, with truncated and full tags. */
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_authenticate(hd, ad, sizeof ad));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, ct, sizeof ct));
    ASSERT_MEM_EQ(pt, out, 5);
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));
    tag2[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag2, 16));

    /* Missing AAD: the verdict is repeated for the same tag. */
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, sizeof out, ct, sizeof ct));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    gcry_cipher_close(hd);
}

TEST(xts_and_keywrap_lengths)
{
    gcry_cipher_hd_t hd;
    unsigned char key[32];
    unsigned char tweak[16] = { 0 };
    unsigned char data[32];
    unsigned char out[32];
    unsigned char back[32];
    unsigned char expect[16];
    unsigned char short_in[8] = { 0 };
    unsigned char plen[4];
    size_t n = 0;
    size_t i;

    for (i = 0; i < sizeof data; i++) {
        data[i] = (unsigned char)i;
    }

    unhex("1111111111111111111111111111111122222222222222222222222222222222",
          key, sizeof key);

    /* XTS: one data unit per call, at least one block. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_XTS, 0));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, key, 16));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 32));
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 16, data,
                                                             15));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 15, data,
                                                             16));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 17, data, 17));
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_decrypt(hd, back, 17, out, 17));
    ASSERT_MEM_EQ(data, back, 17);
    gcry_cipher_close(hd);
    ASSERT_ERR(bad_mode_err(),
               gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_XTS, 0));

    /* RFC 3394 wrap needs at least two whole semiblocks. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, 8));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_encrypt(hd, out, sizeof out, data, 8));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_decrypt(hd, out, sizeof out, data,
                                                    12));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_decrypt(hd, out, sizeof out,
                                                             data, 16));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_decrypt(hd, out, 8, data,
                                                             24));
    gcry_cipher_close(hd);

    /* RFC 5649 padded wrap of a short input with the default AIV. */
    unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", key, 24);
    unhex("0260b112f2eaf24d763305e6c1ffd6bb", expect, sizeof expect);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_AESWRAP,
                               GCRY_CIPHER_EXTENDED));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 24));
    unhex("746869", short_in, 3);
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 16, short_in, 3));
    ASSERT_MEM_EQ(expect, out, 16);
    ASSERT_OK(gcry_cipher_decrypt(hd, back, 8, out, 16));
    /* The padding bytes come back as zeros. */
    ASSERT_MEM_EQ(short_in, back, 8);
    ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_KEYLEN, plen, &n));
    ASSERT_EQ(4, n);
    ASSERT_EQ(3, plen[3]);
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 16, data, 0));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 16, data,
                                                             9));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 24, data, 9));
    ASSERT_OK(gcry_cipher_decrypt(hd, back, 16, out, 24));
    ASSERT_MEM_EQ(data, back, 9);
    gcry_cipher_close(hd);
}

TEST(ocb_generic_block_ciphers)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char nonce[12];
    unsigned char data[40];
    unsigned char expect[40];
    unsigned char expect_tag[16];
    unsigned char out[40];
    unsigned char tag[16];
    size_t i;
    int tl = 12;

    unhex("000102030405060708090a0b0c0d0e0f", key, sizeof key);
    unhex("bbaa99887766554433221100", nonce, sizeof nonce);

    for (i = 0; i < sizeof data; i++) {
        data[i] = (unsigned char)i;
    }

    /* OCB over Camellia runs through the generic OCB driver; the expected
     * values were produced by the reference library. */
    if (algo_available(GCRY_CIPHER_CAMELLIA128)) {
        unhex("c0de2ec305f2d025569d4394fbc01907e1b2aa01ef35edc2ae9e4dd730f3f7af"
              "82e4f3cab40cc68a", expect, sizeof expect);
        unhex("4dc054c156b18e2bdc325eea6b70d69f", expect_tag, sizeof expect_tag);
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CAMELLIA128,
                                   GCRY_CIPHER_MODE_OCB, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_authenticate(hd, data, 20));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out, data, sizeof data));
        ASSERT_MEM_EQ(expect, out, sizeof out);
        ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
        ASSERT_MEM_EQ(expect_tag, tag, 16);

        /* Chunked decryption, AAD after the data. */
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_decrypt(hd, out, 16, expect, 16));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_decrypt(hd, out + 16, 24, expect + 16, 24));
        ASSERT_OK(gcry_cipher_authenticate(hd, data, 20));
        ASSERT_OK(gcry_cipher_checktag(hd, expect_tag, 16));
        ASSERT_MEM_EQ(data, out, sizeof data);

        /* Partial blocks need the finalize marker; so does the tag. */
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(hd, out, 15, data, 15));
        ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_gettag(hd, tag, 16));

        /* A 12 byte tag over the empty message. */
        unhex("26f257c73dc8eae830311661", expect_tag, 12);
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_TAGLEN, &tl, sizeof tl));
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_encrypt(hd, out, 0, data, 0));
        ASSERT_OK(gcry_cipher_gettag(hd, tag, 12));
        ASSERT_MEM_EQ(expect_tag, tag, 12);
        gcry_cipher_close(hd);
    }

    if (algo_available(GCRY_CIPHER_SEED)) {
        unhex("0da3db21849fea91fc74f6cb39305d8a405be94a", expect, 20);
        unhex("85230e7d020ff7a7ab5024af8ad905a5", expect_tag, sizeof expect_tag);
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_OCB, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
        ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
        ASSERT_OK(gcry_cipher_final(hd));
        ASSERT_OK(gcry_cipher_encrypt(hd, out, 20, data, 20));
        ASSERT_MEM_EQ(expect, out, 20);
        ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
        ASSERT_MEM_EQ(expect_tag, tag, 16);
        gcry_cipher_close(hd);
    }

    /* OCB needs a 128 bit block cipher and a key before the nonce. */
    ASSERT_ERR(bad_mode_err(),
               gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_OCB, 0));
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OCB, 0));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_setiv(hd, data, 16));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_setiv(hd, data, 7));
    ASSERT_OK(gcry_cipher_setiv(hd, data, 8));
    gcry_cipher_close(hd);
}

TEST(controls_and_misc)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char iv[16] = { 0 };
    unsigned char data[48];
    unsigned char out[48];
    unsigned char out2[48];
    unsigned char expect[48];
    size_t n = 0;
    size_t i;
    int tl = 12;

    for (i = 0; i < sizeof data; i++) {
        data[i] = (unsigned char)(i * 5 + 1);
    }

    /* Switching CTS on an existing handle, and the CTS/MAC conflict. */
    memcpy(key, "chicken teriyaki", 16);
    unhex("c6353568f2bf8cb4d8a580362da7ff7f97", expect, 17);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_cts(hd, 1));
    ASSERT_ERR(GPG_ERR_INV_FLAG, gcry_cipher_ctl(hd, GCRYCTL_SET_CBC_MAC, NULL, 1));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, sizeof out,
                                  "I would like the General Gau's Chicken",
                                  17));
    ASSERT_MEM_EQ(expect, out, 17);
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 16, data, 0));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 16, data,
                                                             20));
    ASSERT_OK(gcry_cipher_cts(hd, 0));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CBC_MAC, NULL, 1));
    ASSERT_ERR(GPG_ERR_INV_FLAG, gcry_cipher_cts(hd, 1));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_encrypt(hd, out, 8, data,
                                                             16));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CBC_MAC, NULL, 0));

    /* Controls and queries that do not apply to CBC. */
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE, gcry_cipher_info(hd, GCRYCTL_GET_KEYLEN,
                                                         out, &n));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_cipher_info(hd, 999, NULL, &n));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_set_decryption_tag(hd, out, 16));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE, gcry_cipher_ctl(hd, GCRYCTL_SET_TAGLEN,
                                                        &tl, sizeof tl));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
               gcry_cipher_ctl(hd, GCRYCTL_SET_ALLOW_WEAK_KEY, out, 1));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
               gcry_cipher_ctl(hd, GCRYCTL_SET_ALLOW_WEAK_KEY, NULL, 2));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_ctl(hd, GCRYCTL_FINALIZE, out, 1));
    /* Sync is a no-op outside OpenPGP CFB. */
    ASSERT_OK(gcry_cipher_sync(hd));
    gcry_cipher_close(hd);

    /* Algorithm queries with bad arguments. */
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_algo_info(GCRY_CIPHER_AES,
                                                          GCRYCTL_GET_KEYLEN, out, &n));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_algo_info(9999, GCRYCTL_GET_KEYLEN,
                                                          NULL, &n));
    ASSERT_OK(gcry_cipher_algo_info(GCRY_CIPHER_AES, GCRYCTL_GET_BLKLEN, NULL,
                                    &n));
    ASSERT_EQ(16, n);
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_algo_info(9999, GCRYCTL_GET_BLKLEN,
                                                          NULL, &n));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_algo_info(GCRY_CIPHER_AES,
                                                          GCRYCTL_GET_BLKLEN, NULL, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_algo_info(GCRY_CIPHER_AES,
                                                      GCRYCTL_TEST_ALGO, NULL, &n));
    ASSERT_ERR(bad_mode_err(),
               gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_CBC,
                                0));

    /* CTR: a NULL counter resets to zero, odd lengths are refused. */
    unhex(AES128_KEY, key, sizeof key);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CTR, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setctr(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 16, data, 16));
    iv[15] = 9;
    ASSERT_OK(gcry_cipher_setctr(hd, iv, sizeof iv));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_setctr(hd, iv, 15));
    ASSERT_OK(gcry_cipher_setctr(hd, NULL, 0));
    ASSERT_OK(gcry_cipher_encrypt(hd, out2, 16, data, 16));
    ASSERT_MEM_EQ(out, out2, 16);
    ASSERT_OK(gcry_cipher_encrypt(hd, out2, 5, data, 5));
    ASSERT_OK(gcry_cipher_setctr(hd, NULL, 0));
    ASSERT_OK(gcry_cipher_encrypt(hd, out2, 16, data, 16));
    ASSERT_MEM_EQ(out, out2, 16);
    iv[15] = 0;
    gcry_cipher_close(hd);

    /* IV rules of the stream ciphers. */
    if (algo_available(GCRY_CIPHER_ARCFOUR)) {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_ARCFOUR,
                                   GCRY_CIPHER_MODE_STREAM, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
        ASSERT_OK(gcry_cipher_setiv(hd, NULL, 0));
        gcry_cipher_close(hd);
    }

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                   gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                    GCRY_CIPHER_MODE_STREAM, 0));
        ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                   gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                    GCRY_CIPHER_MODE_POLY1305, 0));
    } else {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                   GCRY_CIPHER_MODE_STREAM, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, data, 32));
        ASSERT_OK(gcry_cipher_setiv(hd, iv, 16));
        ASSERT_OK(gcry_cipher_setiv(hd, iv, 8));
        gcry_cipher_close(hd);
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                   GCRY_CIPHER_MODE_POLY1305, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, data, 32));
        ASSERT_OK(gcry_cipher_setiv(hd, iv, 8));
        ASSERT_OK(gcry_cipher_info(hd, GCRYCTL_GET_TAGLEN, NULL, &n));
        ASSERT_EQ(16, n);
        gcry_cipher_close(hd);
    }

    /* OpenPGP CFB sync after partial blocks; the ciphertext comes from the
     * reference library. */
    unhex("7cf1601c0fa28697cdee07e0ef9ce9a641cd2161f10f8427cf77404e25ea044e"
          "529b748e20e618f06568464af2fed51e", expect, 48);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB,
                               GCRY_CIPHER_ENABLE_SYNC));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 5, data, 5));
    ASSERT_OK(gcry_cipher_encrypt(hd, out + 5, 3, data + 5, 3));
    ASSERT_OK(gcry_cipher_sync(hd));
    ASSERT_OK(gcry_cipher_encrypt(hd, out + 8, 20, data + 8, 20));
    ASSERT_OK(gcry_cipher_sync(hd));
    ASSERT_OK(gcry_cipher_encrypt(hd, out + 28, 20, data + 28, 20));
    ASSERT_MEM_EQ(expect, out, 48);
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_decrypt(hd, out2, 5, out, 5));
    ASSERT_OK(gcry_cipher_decrypt(hd, out2 + 5, 3, out + 5, 3));
    ASSERT_OK(gcry_cipher_sync(hd));
    ASSERT_OK(gcry_cipher_decrypt(hd, out2 + 8, 20, out + 8, 20));
    ASSERT_OK(gcry_cipher_sync(hd));
    ASSERT_OK(gcry_cipher_decrypt(hd, out2 + 28, 20, out + 28, 20));
    ASSERT_MEM_EQ(data, out2, 48);
    gcry_cipher_close(hd);
}

/* Disabling an algorithm is process wide, so this runs last. */
/* Behaviour checked against the reference library (libgcrypt 1.12.2) with
 * probe programs: the expected bytes and error codes below are what it
 * produces for key = 00 01 02 .., IV = 10 11 12 .., AAD = 30 31 32 .. and
 * plaintext = a0 a1 a2 ...
 */
static unsigned char cmp_key[64];
static unsigned char cmp_iv[32];
static unsigned char cmp_pt[64];
static unsigned char cmp_aad[16];

static void
compat_fill(void)
{
    size_t i;

    for (i = 0; i < 64; i++) {
        cmp_key[i] = (unsigned char)i;
        cmp_pt[i] = (unsigned char)(0xa0 + i);
    }

    for (i = 0; i < 32; i++) {
        cmp_iv[i] = (unsigned char)(0x10 + i);
    }

    for (i = 0; i < 16; i++) {
        cmp_aad[i] = (unsigned char)(0x30 + i);
    }
}

static int
hex_eq(const unsigned char *buf, const char *hex)
{
    unsigned char expect[80];
    size_t n = unhex(hex, expect, sizeof expect);

    return memcmp(buf, expect, n) == 0;
}

/* NIST GCM test case 6: a 60-byte IV (J0 from GHASH, arbitrary counter
 * low word), chunked decryption, and the decryption side reading its tag
 * before and after checks; stock libgcrypt produces the same output. */
TEST(gcm_long_iv_decrypt_tag)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char iv[60];
    unsigned char aad[20];
    unsigned char ct[60];
    unsigned char pt[60];
    unsigned char tag[16];

    unhex("feffe9928665731c6d6a8f9467308308", key, sizeof key);
    unhex("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
          "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
          iv, sizeof iv);
    unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof aad);
    unhex("8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
          "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
          ct, sizeof ct);

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, sizeof aad));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt, 17, ct, 17));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt + 17, 43, ct + 17, 43));
    ASSERT_TRUE(hex_eq(pt, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da"
                       "2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16a"
                       "edf5aa0de657ba637b39"));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_TRUE(hex_eq(tag, "619cc5aefffe0bfa462af43c1699d050"));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));
    tag[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    tag[0] ^= 1;
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 8));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_TRUE(hex_eq(tag, "619cc5aefffe0bfa462af43c1699d050"));

    /* The handle keeps working in both directions afterwards and both
     * directions agree on the tag. */
    ASSERT_OK(gcry_cipher_setiv(hd, iv, 12));
    ASSERT_OK(gcry_cipher_decrypt(hd, pt, sizeof pt, ct, sizeof ct));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_TRUE(hex_eq(tag, "ed73409ea070c994381d65d3b7073d8b"));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, 12));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, sizeof ct, pt, sizeof pt));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_TRUE(hex_eq(tag, "ed73409ea070c994381d65d3b7073d8b"));
    gcry_cipher_close(hd);
}

TEST(upstream_gcm_tags)
{
    gcry_cipher_hd_t hd;
    unsigned char ct[32];
    unsigned char out[32];
    unsigned char tag[16];
    unsigned char tag2[17];
    const char *tag_hex = "6483275bdb74a33f55392be0fa49e958";

    compat_fill();
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(tag, tag_hex));

    /* The encryption side can check its own tag. */
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));
    memcpy(tag2, tag, 16);
    tag2[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag2, 16));

    /* A decryption handle yields the computed tag, before and after a
     * check, and checks may be repeated with any allowed length. */
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_MEM_EQ(cmp_pt, out, 32);
    memset(tag2, 0, sizeof tag2);
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_TRUE(hex_eq(tag2, tag_hex));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 12));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 15));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_checktag(hd, tag, 3));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_checktag(hd, tag, 11));
    memcpy(tag2, tag, 16);
    tag2[16] = 0;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag2, 17));
    memset(tag2, 0, sizeof tag2);
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_TRUE(hex_eq(tag2, tag_hex));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, 32, ct, 32));

    /* gettag copies a prefix for the allowed short lengths. */
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    memset(tag2, 0xee, sizeof tag2);
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 15));
    ASSERT_TRUE(hex_eq(tag2, "28505a54e2655f378557b48bb01d99"));
    ASSERT_EQ(0xee, tag2[15]);
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 17));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_gettag(hd, tag2, 5));
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 4));
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 8));

    /* IVs of any non-zero length, including ones longer than a block. */
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_setiv(hd, cmp_iv, 0));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 32));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(tag, "7f8923f7d0245f6ebd46bd5498d62450"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 32));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_MEM_EQ(cmp_pt, out, 32);
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 1));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(tag, "a89c0f41a40d04df2e9256a1a6350caa"));

    /* The tag of an empty message is available without any data call. */
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(tag, "0ed7259add1011e159d00e61b1925410"));
    gcry_cipher_close(hd);
}

TEST(upstream_siv_states)
{
    gcry_cipher_hd_t hd;
    unsigned char ct[32];
    unsigned char out[64];
    unsigned char tag[16];
    unsigned char tag2[16];
    const char *ct_hex = "4de06d4ec7c0c4895d745153a063f144"
                         "60962d618731bf5350235a151c041004";
    const char *tag_hex = "08348491cf6aa22075b4bdadf2d6738e";

    compat_fill();

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_SIV, 0));
        return;
    }

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_SIV, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));

    /* Associated data first, the nonce last, then the single data call. */
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(ct, ct_hex));
    ASSERT_TRUE(hex_eq(tag, tag_hex));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 15));
    memset(tag2, 0xee, 16);
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 15));
    ASSERT_MEM_EQ(tag, tag2, 15);
    ASSERT_EQ(0xee, tag2[15]);
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_setiv(hd, cmp_iv, 12));

    /* A nonce set first makes later associated data an error, and the
     * message proceeds with the nonce alone. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_TRUE(hex_eq(tag2, "afafb98fbdb235160f964cdd30eabe22"));

    /* Decryption: the tag may be set before or after the components. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_MEM_EQ(cmp_pt, out, 32);
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    memcpy(tag2, tag, 16);
    tag2[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag2, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 15));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_set_decryption_tag(hd, tag, 16));

    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_MEM_EQ(cmp_pt, out, 32);

    /* A wrong tag is reported by the data call, the output is cleared
     * and every later check fails. */
    memcpy(tag2, tag, 16);
    tag2[0] ^= 1;
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag2, 16));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    memset(out, 0x11, sizeof out);
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_decrypt(hd, out, 64, ct, 32));
    {
        unsigned char zeros[32] = { 0 };

        ASSERT_MEM_EQ(zeros, out, 32);
        ASSERT_EQ(0x11, out[32]);
    }
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag2, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, 32, ct, 32));

    /* No tag: the state is kept until one is set. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_MEM_EQ(cmp_pt, out, 32);

    /* Tag lengths; a tag turns the handle into a decryption handle. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_set_decryption_tag(hd, tag, 15));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_set_decryption_tag(hd, tag, 17));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, 32, cmp_pt, 32));

    /* Nothing at all is a valid message; asking for the tag closes it. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_encrypt(hd, out, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_TRUE(hex_eq(tag2, "a56a7fa513c4b1b97596bf328f70dfa3"));
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_TRUE(hex_eq(tag2, "6890e5685ed0253753a2121dab850fdf"));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_setiv(hd, cmp_iv, 12));

    /* Two AES-192 or AES-256 keys are fine on the AES id, singles not. */
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 48));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 64));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, cmp_key, 16));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, cmp_key, 24));
    gcry_cipher_close(hd);
}

TEST(upstream_gcm_siv_states)
{
    gcry_cipher_hd_t hd;
    unsigned char ct[32];
    unsigned char out[64];
    unsigned char tag[16];
    unsigned char tag2[16];
    const char *tag_hex = "49ea9de2bd470ea3fbe567d7cb22e2bf";

    compat_fill();

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
                   gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM_SIV,
                                    0));
        return;
    }

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM_SIV,
                               0));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));

    /* Nonce, associated data, data. */
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, ct, 16, cmp_pt, 16));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_setiv(hd, cmp_iv, 11));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_setiv(hd, cmp_iv, 13));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_setiv(hd, cmp_iv, 0));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, 32, cmp_pt, 32));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(ct, "b7d70b02a652f82e509e5f5def98f55c"
                       "a33f7428f7064a5aff789d47e980470a"));
    ASSERT_TRUE(hex_eq(tag, tag_hex));
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 15));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_setiv(hd, cmp_iv, 12));

    /* Decryption: nonce, associated data, then the tag closes the AAD. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, out, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
    ASSERT_MEM_EQ(cmp_pt, out, 32);
    ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
    memset(tag2, 0, 16);
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_MEM_EQ(tag, tag2, 16);

    /* The tag may also come before the nonce. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_decrypt(hd, out, 32, ct, 32));

    /* A wrong tag: reported by the data call, output cleared, and the
     * handle keeps answering for the tag it was given. */
    memcpy(tag2, tag, 16);
    tag2[3] ^= 1;
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_set_decryption_tag(hd, tag2, 16));
    memset(out, 0x11, sizeof out);
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_decrypt(hd, out, 64, ct, 32));
    {
        unsigned char zeros[32] = { 0 };

        ASSERT_MEM_EQ(zeros, out, 32);
        ASSERT_EQ(0x11, out[32]);
    }
    ASSERT_OK(gcry_cipher_checktag(hd, tag2, 16));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 16));
    memset(out, 0, 16);
    ASSERT_OK(gcry_cipher_gettag(hd, out, 16));
    ASSERT_MEM_EQ(tag2, out, 16);
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, 32, ct, 32));

    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_set_decryption_tag(hd, tag, 15));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_decrypt(hd, out, 32, ct, 32));

    /* Empty message tag without a data call. */
    ASSERT_OK(gcry_cipher_reset(hd));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 12));
    ASSERT_OK(gcry_cipher_gettag(hd, tag2, 16));
    ASSERT_TRUE(hex_eq(tag2, "fdec3e54464cc76e7a8130f928589f50"));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_encrypt(hd, ct, 0, cmp_pt, 0));

    /* Key lengths: 128 and 256 bit keys on any AES id. */
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, cmp_key, 24));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));
    gcry_cipher_close(hd);
}

TEST(upstream_key_lengths)
{
    static const int ids[3] = {
        GCRY_CIPHER_AES, GCRY_CIPHER_AES192, GCRY_CIPHER_AES256
    };
    static const char *const first4[3] = { "67896c75", "98a9222e", "965fe30b" };
    gcry_cipher_hd_t hd;
    unsigned char ct[32];
    unsigned char out[32];
    int i;
    int k;

    compat_fill();

    /* The key length selects the AES variant, whatever the id says. */
    for (i = 0; i < 3; i++) {
        for (k = 0; k < 3; k++) {
            ASSERT_OK(gcry_cipher_open(&hd, ids[i], GCRY_CIPHER_MODE_CBC, 0));
            ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16 + 8 * (size_t)k));
            ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
            ASSERT_OK(gcry_cipher_encrypt(hd, ct, 16, cmp_pt, 16));
            ASSERT_TRUE(hex_eq(ct, first4[k]));
            gcry_cipher_close(hd);
        }

        ASSERT_OK(gcry_cipher_open(&hd, ids[i], GCRY_CIPHER_MODE_XTS, 0));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, cmp_key, 16));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_cipher_setkey(hd, cmp_key, 24));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 64));
        /* AES-192 XTS has no OpenSSL cipher; it is composed from ECB. */
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 48));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, "f6c96d1df29d43c7c43cd640f549f706"
                           "cba1ed0fcff99dbe0945071539d1a065"));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
        ASSERT_OK(gcry_cipher_decrypt(hd, out, 32, ct, 32));
        ASSERT_MEM_EQ(cmp_pt, out, 32);
        gcry_cipher_close(hd);
    }

    if (algo_available(GCRY_CIPHER_CAMELLIA128)) {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CAMELLIA128,
                                   GCRY_CIPHER_MODE_CBC, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 24));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));
        gcry_cipher_close(hd);
    }

    /* DES: the 64 weak, semi-weak and possibly weak keys are refused in
     * every position of a 3DES key; parity bits do not matter. */
    {
        static const unsigned char weak[][8] = {
            { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
            { 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe },
            { 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01 },
            { 0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1 },
            { 0x1f, 0x01, 0xfe, 0xe0, 0x0e, 0x01, 0xfe, 0xf1 },
            { 0xe0, 0x1f, 0x01, 0xfe, 0xf1, 0x0e, 0x01, 0xfe },
            { 0xfe, 0x01, 0x1f, 0xe0, 0xfe, 0x01, 0x0e, 0xf1 },
            { 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe },
        };
        unsigned char k3[24];
        size_t w;

        if (gcry_fips_mode_active()) {
            /* Neither DES nor 3DES is a FIPS algorithm. */
            ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                       gcry_cipher_open(&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB,
                                        0));
            ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                       gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB,
                                        0));
            return;
        }

        for (w = 0; w < sizeof weak / sizeof weak[0]; w++) {
            ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_ECB,
                                       0));
            ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_cipher_setkey(hd, weak[w], 8));
            memcpy(k3, weak[w], 8);
            k3[0] ^= 1; /* Parity bit. */
            ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_cipher_setkey(hd, k3, 8));
            k3[3] ^= 0x20;
            ASSERT_OK(gcry_cipher_setkey(hd, k3, 8));
            gcry_cipher_close(hd);
        }

        memset(k3, 0x23, sizeof k3);
        memcpy(k3 + 8, weak[1], 8);
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_ECB,
                                   0));
        ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_cipher_setkey(hd, k3, 24));
        memset(k3, 0x23, sizeof k3);
        ASSERT_OK(gcry_cipher_setkey(hd, k3, 24));
        gcry_cipher_close(hd);
    }
}

TEST(upstream_iv_conventions)
{
    gcry_cipher_hd_t hd;
    unsigned char ct[32];
    unsigned char tag[16];
    unsigned char zero[16] = { 0 };
    const char *zero_nonce = "b819e09209430076bbc8f6ca03eee088"
                             "480041465518edeb544146a99688cbe3";

    compat_fill();

    /* ChaCha20: 8, 12 and 16 byte IVs select the variant; anything else
     * is a warning and an all zero IV. */
    if (algo_available(GCRY_CIPHER_CHACHA20)) {
        const char *other = "995c89de7d60bfcd2514a9dc1471e4e6"
                            "3a846adc086bdc7b0a75c7f764579a2d";

        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                   GCRY_CIPHER_MODE_STREAM, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 8));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, "2a49ef411d0782d6989e4c43a8a80235"
                           "58a60f0e71bbc8c359f3f7a31266a8dd"));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 7));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, other));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 13));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, other));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 17));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, other));
        gcry_cipher_close(hd);

        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20,
                                   GCRY_CIPHER_MODE_POLY1305, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 7));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
        ASSERT_TRUE(hex_eq(ct, zero_nonce));
        ASSERT_TRUE(hex_eq(tag, "740287ca3494214808b3f69e9dac9eb8"));
        /* A 16 byte IV is counter||nonce; with a zero counter it equals
         * the 12 byte nonce. */
        memcpy(zero + 4, cmp_iv + 4, 12);
        ASSERT_OK(gcry_cipher_setiv(hd, zero, 16));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, "8a5b214119a5c0164898affa173ea2c6"
                           "1de09bf9138507ce20d2740c84612c51"));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv + 4, 12));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
        ASSERT_TRUE(hex_eq(ct, "8a5b214119a5c0164898affa173ea2c6"
                           "1de09bf9138507ce20d2740c84612c51"));
        /* Tag lengths. */
        ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_gettag(hd, tag, 15));
        ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
        ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_checktag(hd, tag, 15));
        ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, tag, 17));
        ASSERT_OK(gcry_cipher_checktag(hd, tag, 16));
        gcry_cipher_close(hd);
    }

    /* XTS: the tweak is zero padded or truncated to a block. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_XTS, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 32));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 15));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 16, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "730955487b54dd6bc39f3fef19ec4f11"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 0));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 16, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "f9d68ea4b1e397c918297aa9c8098abf"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 17));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 16, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "b6c63bc43c01d673a51e45a59c8e5c5d"));
    gcry_cipher_close(hd);

    /* ARCFOUR takes and ignores an IV. */
    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                   gcry_cipher_open(&hd, GCRY_CIPHER_ARCFOUR,
                                    GCRY_CIPHER_MODE_STREAM, 0));
    } else {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_ARCFOUR,
                                   GCRY_CIPHER_MODE_STREAM, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 8));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 16, cmp_pt, 16));
        ASSERT_TRUE(hex_eq(ct, "493de25ae347bf6bae723d6da27084e0"));
        gcry_cipher_close(hd);
    }

    /* CBC-MAC handles decrypt as plain CBC. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC,
                               GCRY_CIPHER_CBC_MAC));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
    ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT, gcry_cipher_decrypt(hd, ct, 16, cmp_pt,
                                                             32));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
    ASSERT_OK(gcry_cipher_decrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_TRUE(hex_eq(ct, "3cd93f0477dc098aaef64a27300ab412"
                       "abe10fb4914bfd322142c03a25305087"));
    gcry_cipher_close(hd);
}

TEST(upstream_keywrap_and_ccm)
{
    gcry_cipher_hd_t hd;
    unsigned char ct[32];
    unsigned char out[32];
    unsigned char tag[16];
    unsigned long long lengths[3];

    compat_fill();

    /* Plain wrap: the IV is zero padded or truncated to 8 bytes; a NULL
     * IV means the default, an empty one eight zero bytes. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP,
                               0));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "7c98f3e4d60636d4aef4977d12dbfe75611dbd03e54dffef"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 4));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "9fe10555c714baf27cc2b06abf1006d39c963ccc9f1da250"));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 16, ct, 24));
    ASSERT_MEM_EQ(cmp_pt, out, 16);
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 9));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "59b3f9a6a987e26a64232a35dfa8b27f7bc43d6131bc97b9"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "59b3f9a6a987e26a64232a35dfa8b27f7bc43d6131bc97b9"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 0));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "bd9b64172b7b2c69058fe980deb217d26cc8161adae210c2"));
    ASSERT_OK(gcry_cipher_setiv(hd, NULL, 0));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
    ASSERT_TRUE(hex_eq(ct, "7c98f3e4d60636d4aef4977d12dbfe75611dbd03e54dffef"));
    gcry_cipher_close(hd);

    /* Padded wrap ignores the IV altogether. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP,
                               GCRY_CIPHER_EXTENDED));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 9));
    ASSERT_TRUE(hex_eq(ct, "e6e76afcf1f71f43634b96919c1e36a95bf7b0260f519b4b"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 4));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 9));
    ASSERT_TRUE(hex_eq(ct, "e6e76afcf1f71f43634b96919c1e36a95bf7b0260f519b4b"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 7));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 16));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, 24, ct, 24));
    ASSERT_MEM_EQ(cmp_pt, out, 9);
    gcry_cipher_close(hd);

    /* Other 128 bit block ciphers wrap through the generic driver; 64 bit
     * block ciphers open but cannot wrap. */
    if (algo_available(GCRY_CIPHER_CAMELLIA128)) {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_CAMELLIA128,
                                   GCRY_CIPHER_MODE_AESWRAP, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
        ASSERT_TRUE(hex_eq(ct, "63e43993864ae54fa16e1732452cbe55072bd05e95776062"));
        ASSERT_OK(gcry_cipher_decrypt(hd, out, 16, ct, 24));
        ASSERT_MEM_EQ(cmp_pt, out, 16);
        gcry_cipher_close(hd);
    }

    if (algo_available(GCRY_CIPHER_SEED)) {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_SEED, GCRY_CIPHER_MODE_AESWRAP,
                                   GCRY_CIPHER_EXTENDED));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
        ASSERT_OK(gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 9));
        ASSERT_TRUE(hex_eq(ct, "20ba8665bf09ab8c13f82772f9da9c65517a9a13119a78db"));
        ASSERT_OK(gcry_cipher_decrypt(hd, out, 24, ct, 24));
        ASSERT_MEM_EQ(cmp_pt, out, 9);
        gcry_cipher_close(hd);
    }

    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                   gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_AESWRAP,
                                    0));
    } else {
        ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_AESWRAP,
                                   0));
        ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 24));
        ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 8));
        ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_encrypt(hd, ct, 24, cmp_pt, 16));
        ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_decrypt(hd, out, 16, ct, 24));
        gcry_cipher_close(hd);
    }

    /* CCM: lengths are not checked against the L field, and the tag calls
     * before the lengths are set report a length problem. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, cmp_key, 16));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_gettag(hd, tag, 16));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_cipher_checktag(hd, tag, 16));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 13));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_authenticate(hd, cmp_aad, 16));
    lengths[0] = 1ULL << 20;
    lengths[1] = 0;
    lengths[2] = 16;
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS,
                                                  lengths, sizeof lengths));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 13));
    lengths[0] = 32;
    lengths[1] = 16;
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, cmp_aad, 16));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(tag, "4d6ea00fcf4a3d53495435a0bc86df56"));
    ASSERT_OK(gcry_cipher_setiv(hd, cmp_iv, 7));
    lengths[1] = 0;
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 32, cmp_pt, 32));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, 16));
    ASSERT_TRUE(hex_eq(tag, "3e4053728b63bfe765fdbafbffc4d82d"));
    gcry_cipher_close(hd);
}

/* Multiply a 128-bit XTS tweak by alpha in GF(2^128), IEEE 1619 style:
 * little-endian shift left by one with the reduction polynomial 0x87. */
static void
xts_ref_mul_alpha(unsigned char t[16])
{
    unsigned char carry = 0;
    size_t i;

    for (i = 0; i < 16; i++) {
        unsigned char next = (unsigned char)(t[i] >> 7);

        t[i] = (unsigned char)((t[i] << 1) | carry);
        carry = next;
    }

    if (carry) {
        t[0] ^= 0x87;
    }
}

/* One XTS block: OUT = E(IN xor T) xor T through the ECB context. */
static int
xts_ref_block(EVP_CIPHER_CTX *ctx, const unsigned char t[16],
              const unsigned char *in, unsigned char *out)
{
    unsigned char blk[16];
    int outl = 0;
    size_t i;

    for (i = 0; i < 16; i++) {
        blk[i] = (unsigned char)(in[i] ^ t[i]);
    }

    if (!EVP_CipherUpdate(ctx, blk, &outl, blk, 16) || outl != 16) {
        return 0;
    }

    for (i = 0; i < 16; i++) {
        out[i] = (unsigned char)(blk[i] ^ t[i]);
    }

    return 1;
}

/* IEEE 1619 XTS with ciphertext stealing, built in the test from
 * OpenSSL's ECB cipher ECB_NAME and two half keys.  It is the reference
 * for ciphers whose XTS mode the library composes itself.  Returns 0 if
 * the ECB cipher is not available or fails. */
static int
xts_reference(const char *ecb_name, const unsigned char *key, size_t keylen,
              const unsigned char tweak[16], int enc, unsigned char *out,
              const unsigned char *in, size_t len)
{
    EVP_CIPHER *ecb = EVP_CIPHER_fetch(NULL, ecb_name, NULL);
    EVP_CIPHER_CTX *data = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *tw = EVP_CIPHER_CTX_new();
    unsigned char t[16];
    unsigned char t2[16];
    size_t m = len / 16;
    size_t tail = len % 16;
    size_t plain = tail ? m - 1 : m;
    size_t i;
    int outl = 0;
    int ok = 0;

    if (!ecb) {
        /* SEED lives in the legacy provider; load it as the library does,
         * keeping the default provider as the fallback. */
        ERR_clear_error();

        if (OSSL_PROVIDER_try_load(NULL, "legacy", 1)) {
            ecb = EVP_CIPHER_fetch(NULL, ecb_name, NULL);
        }
    }

    if (!ecb || !data || !tw || len < 16) {
        goto done;
    }

    if (!EVP_CipherInit_ex2(data, ecb, key, NULL, enc, NULL)
        || !EVP_CIPHER_CTX_set_padding(data, 0)
        || !EVP_EncryptInit_ex2(tw, ecb, key + keylen / 2, NULL, NULL)
        || !EVP_CIPHER_CTX_set_padding(tw, 0)
        || !EVP_EncryptUpdate(tw, t, &outl, tweak, 16)) {
        goto done;
    }

    for (i = 0; i < plain; i++) {
        if (!xts_ref_block(data, t, in + i * 16, out + i * 16)) {
            goto done;
        }

        xts_ref_mul_alpha(t);
    }

    if (tail) {
        /* The last full block uses the earlier tweak when encrypting and
         * the later one when decrypting; the completed block the other. */
        const unsigned char *first = enc ? t : t2;
        const unsigned char *second = enc ? t2 : t;
        unsigned char cc[16];
        unsigned char pp[16];

        memcpy(t2, t, 16);
        xts_ref_mul_alpha(t2);

        if (!xts_ref_block(data, first, in + plain * 16, cc)) {
            goto done;
        }

        memcpy(pp, in + m * 16, tail);
        memcpy(pp + tail, cc + tail, 16 - tail);
        memcpy(out + m * 16, cc, tail);

        if (!xts_ref_block(data, second, pp, out + plain * 16)) {
            goto done;
        }
    }

    ok = 1;
done:
    EVP_CIPHER_CTX_free(data);
    EVP_CIPHER_CTX_free(tw);
    EVP_CIPHER_free(ecb);
    return ok;
}

#define XTS_MAX_LEN 1100

/* Encrypt and decrypt LEN bytes (not a multiple of the block size) with
 * ALGO in XTS mode, in place and out of place, and compare against the
 * reference built on ECB_NAME. */
static void
check_xts_stealing(int algo, const char *ecb_name, size_t keylen, size_t len)
{
    gcry_cipher_hd_t hd;
    unsigned char key[64];
    unsigned char tweak[16];
    unsigned char pt[XTS_MAX_LEN];
    unsigned char ct[XTS_MAX_LEN];
    unsigned char ref[XTS_MAX_LEN];
    unsigned char buf[XTS_MAX_LEN];
    size_t m = (len + 15) / 16;   /* Blocks, the last one partial. */
    size_t tail = len % 16;
    size_t prefix = (m - 2) * 16; /* Bytes unaffected by the stealing. */
    size_t i;

    if (getenv("TEST_VERBOSE")) {
        printf("  XTS stealing %s, %zu bytes\n", gcry_cipher_algo_name(algo),
               len);
    }

    for (i = 0; i < sizeof key; i++) {
        key[i] = (unsigned char)(0x5a ^ (i * 13));
    }

    for (i = 0; i < sizeof tweak; i++) {
        tweak[i] = (unsigned char)(0xc3 - i);
    }

    for (i = 0; i < len; i++) {
        pt[i] = (unsigned char)(i * 7 + 3);
    }

    ASSERT_OK(gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_XTS, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 2 * keylen));

    /* Out of place, then in place: the same ciphertext. */
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, len, pt, len));
    memcpy(buf, pt, len);
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_encrypt(hd, buf, len, NULL, 0));
    ASSERT_MEM_EQ(ct, buf, len);

    /* The IEEE 1619 construction from the ECB primitive. */
    ASSERT_TRUE(xts_reference(ecb_name, key, 2 * keylen, tweak, 1, ref, pt,
                              len));
    ASSERT_MEM_EQ(ref, ct, len);
    ASSERT_TRUE(xts_reference(ecb_name, key, 2 * keylen, tweak, 0, ref, ct,
                              len));
    ASSERT_MEM_EQ(pt, ref, len);

    /* Stealing only touches the last two blocks: the blocks before them
     * are the ciphertext of the truncated message. */
    if (prefix) {
        ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
        ASSERT_OK(gcry_cipher_encrypt(hd, buf, prefix, pt, prefix));
        ASSERT_MEM_EQ(ct, buf, prefix);
    }

    /* Round trips, out of place and in place. */
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_decrypt(hd, buf, len, ct, len));
    ASSERT_MEM_EQ(pt, buf, len);
    memcpy(buf, ct, len);
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_decrypt(hd, buf, len, NULL, 0));
    ASSERT_MEM_EQ(pt, buf, len);

    /* A tampered stolen (last full) block spoils both final blocks and
     * nothing before them. */
    memcpy(ref, ct, len);
    ref[prefix + 5] ^= 0x10;
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_decrypt(hd, buf, len, ref, len));
    ASSERT_MEM_EQ(pt, buf, prefix);
    ASSERT_TRUE(memcmp(pt + prefix, buf + prefix, 16) != 0);
    ASSERT_TRUE(memcmp(pt + prefix + 16, buf + prefix + 16, tail) != 0);

    /* A tampered partial block spoils only the last full block: the
     * partial plaintext is carved from the full ciphertext block. */
    memcpy(ref, ct, len);
    ref[len - 1] ^= 0x80;
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_decrypt(hd, buf, len, ref, len));
    ASSERT_MEM_EQ(pt, buf, prefix);
    ASSERT_TRUE(memcmp(pt + prefix, buf + prefix, 16) != 0);
    ASSERT_MEM_EQ(pt + prefix + 16, buf + prefix + 16, tail);

    gcry_cipher_close(hd);
}

/* The library's own XTS ciphertext stealing, used for ciphers OpenSSL has
 * no native XTS for (AES-192 and the other 128 bit block ciphers), checked
 * against the IEEE 1619 construction built here from the ECB primitive;
 * the construction itself is pinned to the standard's partial-block
 * vectors through the native AES-128 path. */
TEST(xts_ciphertext_stealing)
{
    static const struct {
        int algo;
        const char *ecb;
        size_t keylen;
    } variants[] = {
        { GCRY_CIPHER_AES192, "AES-192-ECB", 24 },
        { GCRY_CIPHER_CAMELLIA128, "CAMELLIA-128-ECB", 16 },
        { GCRY_CIPHER_CAMELLIA256, "CAMELLIA-256-ECB", 32 },
        { GCRY_CIPHER_SM4, "SM4-ECB", 16 },
        { GCRY_CIPHER_ARIA128, "ARIA-128-ECB", 16 },
        { GCRY_CIPHER_SEED, "SEED-ECB", 16 },
    };
    /* 17 and 31: two blocks, both involved in the stealing; 33 and 47:
     * one untouched block before them; 100: several; 1057: a full batch
     * of 64 blocks and one more before the stolen pair. */
    static const size_t lengths[] = { 17, 31, 33, 47, 100, 1057 };
    gcry_cipher_hd_t hd;
    unsigned char key[64];
    unsigned char tweak[16] = { 0 };
    unsigned char pt[32];
    unsigned char ct[32];
    unsigned char ref[32];
    unsigned char expect[32];
    size_t i;
    size_t j;

    /* IEEE 1619 vectors 15 and 18 (17 and 20 bytes) through OpenSSL's
     * native AES-128 XTS and through the reference construction. */
    unhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0",
          key, 32);
    unhex("9a78563412", tweak, 5);
    unhex("000102030405060708090a0b0c0d0e0f10111213", pt, 20);
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_XTS, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 32));
    unhex("6c1625db4671522d3d7599601de7ca09ed", expect, 17);
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 17, pt, 17));
    ASSERT_MEM_EQ(expect, ct, 17);
    ASSERT_TRUE(xts_reference("AES-128-ECB", key, 32, tweak, 1, ref, pt, 17));
    ASSERT_MEM_EQ(expect, ref, 17);
    ASSERT_TRUE(xts_reference("AES-128-ECB", key, 32, tweak, 0, ref, expect,
                              17));
    ASSERT_MEM_EQ(pt, ref, 17);
    unhex("9d84c813f719aa2c7be3f66171c7c5c2edbf9dac", expect, 20);
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 20, pt, 20));
    ASSERT_MEM_EQ(expect, ct, 20);
    ASSERT_TRUE(xts_reference("AES-128-ECB", key, 32, tweak, 1, ref, pt, 20));
    ASSERT_MEM_EQ(expect, ref, 20);
    gcry_cipher_close(hd);

    /* The native AES-256 path agrees with the construction as well; this
     * one uses 31 bytes, more than the vectors above initialised. */
    for (i = 0; i < sizeof key; i++) {
        key[i] = (unsigned char)(0x80 | i);
    }

    for (i = 0; i < sizeof pt; i++) {
        pt[i] = (unsigned char)(0xa0 + i);
    }

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_XTS,
                               0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, 64));
    ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, 31, pt, 31));
    ASSERT_TRUE(xts_reference("AES-256-ECB", key, 64, tweak, 1, ref, pt, 31));
    ASSERT_MEM_EQ(ref, ct, 31);
    gcry_cipher_close(hd);

    /* The generic path: AES-192 everywhere, the other ciphers only
     * outside FIPS mode, where they are not available at all. */
    for (i = 0; i < sizeof variants / sizeof variants[0]; i++) {
        int algo = variants[i].algo;

        if (algo != GCRY_CIPHER_AES192 && gcry_fips_mode_active()) {
            ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
                       gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_XTS, 0));
            continue;
        }

        if (!algo_available(algo)) {
            continue;
        }

        for (j = 0; j < sizeof lengths / sizeof lengths[0]; j++) {
            check_xts_stealing(algo, variants[i].ecb, variants[i].keylen,
                               lengths[j]);
        }

        /* Less than one block cannot be stolen from. */
        ASSERT_OK(gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_XTS, 0));
        ASSERT_OK(gcry_cipher_setkey(hd, key, 2 * variants[i].keylen));
        ASSERT_OK(gcry_cipher_setiv(hd, tweak, sizeof tweak));
        ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT,
                   gcry_cipher_encrypt(hd, ct, sizeof ct, pt, 15));
        ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT,
                   gcry_cipher_encrypt(hd, ct, sizeof ct, pt, 1));
        ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT,
                   gcry_cipher_decrypt(hd, ct, sizeof ct, pt, 15));
        ASSERT_ERR(GPG_ERR_BUFFER_TOO_SHORT,
                   gcry_cipher_decrypt(hd, ct, 8, NULL, 0));
        gcry_cipher_close(hd);
    }
}

/* AES-128-CCM through OpenSSL's native EVP cipher: the reference for the
 * library's composed CCM.  Returns 0 if the cipher is not available. */
static int
ccm_reference(const unsigned char *key, const unsigned char *nonce,
              size_t noncelen, const unsigned char *aad, size_t aadlen,
              const unsigned char *pt, size_t ptlen, unsigned char *ct,
              unsigned char *tag, size_t taglen)
{
    EVP_CIPHER *ccm = EVP_CIPHER_fetch(NULL, "AES-128-CCM", NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char scratch[16];
    int outl = 0;
    int ok = 0;

    if (!ccm || !ctx) {
        goto done;
    }

    if (!EVP_EncryptInit_ex2(ctx, ccm, NULL, NULL, NULL)
        || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)noncelen,
                                NULL)
        || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)taglen, NULL)
        || !EVP_EncryptInit_ex2(ctx, NULL, key, nonce, NULL)
        || !EVP_EncryptUpdate(ctx, NULL, &outl, NULL, (int)ptlen)
        || !EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aadlen)) {
        goto done;
    }

    if (ptlen && !EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)ptlen)) {
        goto done;
    }

    if (!EVP_EncryptFinal_ex(ctx, scratch, &outl)
        || !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)taglen, tag)) {
        goto done;
    }

    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(ccm);
    return ok;
}

/* AES-CCM with AADLEN bytes of associated data, delivered in two pieces,
 * and PTLEN bytes of data: ciphertext and tag against the EVP reference,
 * then the decryption side. */
static void
check_ccm_long_aad(const unsigned char *aad, size_t aadlen, size_t ptlen)
{
    gcry_cipher_hd_t hd;
    unsigned char key[16];
    unsigned char nonce[13];
    unsigned char pt[40];
    unsigned char ct[40];
    unsigned char ref_ct[40];
    unsigned char out[40];
    unsigned char tag[16];
    unsigned char ref_tag[16];
    unsigned long long lengths[3];
    size_t split = aadlen / 3;
    size_t i;

    if (getenv("TEST_VERBOSE")) {
        printf("  CCM with %zu bytes of AAD, %zu of data\n", aadlen, ptlen);
    }

    for (i = 0; i < sizeof key; i++) {
        key[i] = (unsigned char)(0x40 + i);
    }

    for (i = 0; i < sizeof nonce; i++) {
        nonce[i] = (unsigned char)(0x10 + i);
    }

    for (i = 0; i < sizeof pt; i++) {
        pt[i] = (unsigned char)(0x20 + i);
    }

    ASSERT_TRUE(ptlen <= sizeof pt);
    ASSERT_TRUE(ccm_reference(key, nonce, sizeof nonce, aad, aadlen, pt, ptlen,
                              ref_ct, ref_tag, sizeof ref_tag));

    lengths[0] = ptlen;
    lengths[1] = aadlen;
    lengths[2] = sizeof tag;
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CCM, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, split));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad + split, aadlen - split));
    ASSERT_OK(gcry_cipher_encrypt(hd, ct, ptlen, pt, ptlen));
    ASSERT_OK(gcry_cipher_gettag(hd, tag, sizeof tag));
    ASSERT_MEM_EQ(ref_ct, ct, ptlen);
    ASSERT_MEM_EQ(ref_tag, tag, sizeof tag);

    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, aadlen));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, ptlen, ct, ptlen));
    ASSERT_MEM_EQ(pt, out, ptlen);
    ASSERT_OK(gcry_cipher_checktag(hd, ref_tag, sizeof ref_tag));

    /* One AAD byte changed: the tag no longer verifies. */
    ASSERT_OK(gcry_cipher_setiv(hd, nonce, sizeof nonce));
    ASSERT_OK(gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, lengths,
                              sizeof lengths));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad + 1, aadlen - 1));
    ASSERT_OK(gcry_cipher_authenticate(hd, aad, 1));
    ASSERT_OK(gcry_cipher_decrypt(hd, out, ptlen, ct, ptlen));
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_cipher_checktag(hd, ref_tag,
                                                      sizeof ref_tag));
    gcry_cipher_close(hd);
}

/* CCM associated data of 0xff00 bytes and more is length-prefixed with
 * the six byte 0xfffe encoding (RFC 3610 section 2.2) instead of the two
 * byte one; the AES-only test runs in FIPS mode as well. */
TEST(ccm_long_aad)
{
    size_t aadlen = 70000;
    unsigned char *aad = malloc(aadlen);
    size_t i;

    ASSERT_NOT_NULL(aad);

    for (i = 0; i < aadlen; i++) {
        aad[i] = (unsigned char)(i * 31 + (i >> 8));
    }

    check_ccm_long_aad(aad, 0xfeff, 40); /* Last two byte length. */
    check_ccm_long_aad(aad, 0xff00, 40); /* First six byte length. */
    check_ccm_long_aad(aad, 0xff01, 23);
    check_ccm_long_aad(aad, 70000, 40);
    check_ccm_long_aad(aad, 0xff00, 0);  /* Authentication only. */
    check_ccm_long_aad(aad, 70000, 0);
    free(aad);
}

TEST(disable_algo)
{
    gcry_cipher_hd_t hd = NULL;
    /* FIPS mode has already rejected CAST5; disable an AES variant there. */
    int fips = gcry_fips_mode_active();
    int algo = fips ? GCRY_CIPHER_AES192 : GCRY_CIPHER_CAST5;
    const char *name = fips ? "AES192" : "CAST5";
    size_t keylen = fips ? 24 : 16;

    if (!algo_available(algo)) {
        return;
    }

    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_ctl(NULL, GCRYCTL_DISABLE_ALGO,
                                                    &algo, 2));
    ASSERT_OK(gcry_cipher_ctl(NULL, GCRYCTL_DISABLE_ALGO, &algo, sizeof algo));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO, gcry_cipher_test_algo(algo));
    ASSERT_ERR(GPG_ERR_CIPHER_ALGO,
               gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CBC, 0));
    ASSERT_NULL(hd);
    /* The tables still know the algorithm. */
    ASSERT_EQ(keylen, gcry_cipher_get_algo_keylen(algo));
    ASSERT_STR_EQ(name, gcry_cipher_algo_name(algo));
    ASSERT_EQ(algo, gcry_cipher_map_name(name));
}

TEST(null_buffer_arguments)
{
    gcry_cipher_hd_t hd = NULL;
    unsigned char key[16] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char buf[32] = { 0 };

    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0));
    ASSERT_OK(gcry_cipher_setkey(hd, key, sizeof key));
    /* A NULL buffer with a non-zero length is refused. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_setiv(hd, NULL, sizeof iv));
    ASSERT_OK(gcry_cipher_setiv(hd, iv, sizeof iv));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_encrypt(hd, NULL, 16, buf, 16));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_encrypt(hd, buf, 16, NULL, 16));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_decrypt(hd, NULL, 16, buf, 16));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_cipher_decrypt(hd, buf, 16, NULL, 16));
    /* In-place operation (NULL input, zero length) still works. */
    ASSERT_OK(gcry_cipher_encrypt(hd, buf, 16, NULL, 0));
    ASSERT_OK(gcry_cipher_decrypt(hd, buf, 16, NULL, 0));
    /* A zero-length call with no buffers at all is a no-op. */
    ASSERT_OK(gcry_cipher_encrypt(hd, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_cipher_encrypt(NULL, buf, 16, buf, 16));
    gcry_cipher_close(hd);
}

int
main(void)
{
    gcry_check_version(NULL);

    if (getenv("TEST_VERBOSE")) {
        gcry_control(GCRYCTL_SET_VERBOSITY, 2);
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    RUN_TEST(aes_sp800_38a);
    RUN_TEST(other_block_ciphers);
    RUN_TEST(stream_ciphers);
    RUN_TEST(aes_gcm);
    RUN_TEST(chacha20_poly1305_rfc8439);
    RUN_TEST(aes_ccm_rfc3610);
    RUN_TEST(aes_ocb_rfc7253);
    RUN_TEST(aes_gcm_siv_rfc8452);
    RUN_TEST(aes_xts_ieee1619);
    RUN_TEST(aes_keywrap);
    RUN_TEST(cbc_cts_rfc3962);
    RUN_TEST(cbc_mac_and_cfb_sync);
    RUN_TEST(names_and_info);
    RUN_TEST(errors);
    RUN_TEST(geniv);
    RUN_TEST(aes_cfb8_sp800_38a);
    RUN_TEST(aes_siv_rfc5297);
    RUN_TEST(aes_gcm_siv_states);
    RUN_TEST(aes_ccm_states);
    RUN_TEST(aes_gcm_states);
    RUN_TEST(xts_and_keywrap_lengths);
    RUN_TEST(ocb_generic_block_ciphers);
    RUN_TEST(controls_and_misc);
    RUN_TEST(gcm_long_iv_decrypt_tag);
    RUN_TEST(upstream_gcm_tags);
    RUN_TEST(upstream_siv_states);
    RUN_TEST(upstream_gcm_siv_states);
    RUN_TEST(upstream_key_lengths);
    RUN_TEST(upstream_iv_conventions);
    RUN_TEST(upstream_keywrap_and_ccm);
    RUN_TEST(xts_ciphertext_stealing);
    RUN_TEST(ccm_long_aad);
    RUN_TEST(disable_algo);
    RUN_TEST(null_buffer_arguments);
    return TEST_RESULT();
}
