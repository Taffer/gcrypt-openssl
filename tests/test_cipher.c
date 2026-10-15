#include <gcrypt.h>

#include <stdlib.h>

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
    {
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
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
               gcry_cipher_open(&hd, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_GCM, 0));
    ASSERT_ERR(GPG_ERR_INV_CIPHER_MODE,
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
    return TEST_RESULT();
}
