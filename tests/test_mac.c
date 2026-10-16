#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

static size_t
unhex(const char *hex, unsigned char *buf, size_t bufsize)
{
    size_t n = 0;

    while (hex[0] && hex[1] && n < bufsize) {
        unsigned int v;

        sscanf(hex, "%2x", &v);
        buf[n++] = (unsigned char)v;
        hex += 2;
    }

    return n;
}

/* Whether a MAC the library's tables list is not offered: always in FIPS
 * mode (every use of this asks about a non-approved algorithm), and under
 * a strict provider whenever the provider lacks it. */
static int
mac_unavailable(int algo)
{
    return gcry_fips_mode_active()
           || (TEST_STRICT_PROVIDER && gcry_mac_test_algo(algo) != 0);
}

/* Compute the MAC of DATA under KEY (and IV if given) and compare. */
static int
check_mac(int algo, const char *keyhex, const char *ivhex, const void *data,
          size_t datalen, const char *hex)
{
    unsigned char key[64];
    unsigned char iv[16];
    unsigned char expect[64];
    unsigned char got[64];
    size_t keylen = unhex(keyhex, key, sizeof key);
    size_t ivlen = ivhex ? unhex(ivhex, iv, sizeof iv) : 0;
    size_t n = unhex(hex, expect, sizeof expect);
    size_t gotlen = sizeof got;
    gcry_mac_hd_t hd;
    gcry_error_t err;

    err = gcry_mac_open(&hd, algo, 0, NULL);

    if (err) {
        fprintf(stderr, "mac %d (%s): open: %s\n", algo, gcry_mac_algo_name(algo),
                gcry_strerror(err));
        return 0;
    }

    err = gcry_mac_setkey(hd, key, keylen);

    if (!err && ivlen) {
        err = gcry_mac_setiv(hd, iv, ivlen);
    }

    if (!err) {
        err = gcry_mac_write(hd, data, datalen);
    }

    if (!err) {
        err = gcry_mac_read(hd, got, &gotlen);
    }

    if (err) {
        fprintf(stderr, "mac %d (%s): %s\n", algo, gcry_mac_algo_name(algo),
                gcry_strerror(err));
        gcry_mac_close(hd);
        return 0;
    }

    if (gotlen != n || memcmp(got, expect, n)) {
        size_t i;

        fprintf(stderr, "mac %d (%s): mismatch (len %zu)\n  got ", algo,
                gcry_mac_algo_name(algo), gotlen);

        for (i = 0; i < gotlen; i++) {
            fprintf(stderr, "%02x", got[i]);
        }

        fprintf(stderr, "\n");
        gcry_mac_close(hd);
        return 0;
    }

    /* verify agrees, and a reset recomputes the same tag. */
    err = gcry_mac_verify(hd, expect, n);

    if (!err) {
        err = gcry_mac_reset(hd);
    }

    if (!err && ivlen) {
        err = gcry_mac_setiv(hd, iv, ivlen);
    }

    if (!err) {
        err = gcry_mac_write(hd, data, datalen);
    }

    if (!err) {
        err = gcry_mac_verify(hd, expect, n);
    }

    gcry_mac_close(hd);

    if (err) {
        fprintf(stderr, "mac %d (%s): verify/reset: %s\n", algo,
                gcry_mac_algo_name(algo), gcry_strerror(err));
        return 0;
    }

    return 1;
}

TEST(hmac_rfc4231)
{
    const char *jefe = "4a656665";
    const char *key0b = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const char *data = "what do ya want for nothing?";
    const char *sha256_hi_there =
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    const char *sha3_msg = "Sample message for keylen<blocklen";

    /* RFC 4231 case 1 (20 byte 0x0b key, "Hi There"), the same key and
     * data as RFC 2202 case 1 for SHA-1, and the NIST HMAC-SHA3-256
     * sample with a 32 byte key.  All keys reach the 112 bit minimum
     * FIPS mode insists on, so these run in both modes. */
    ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA224, key0b, NULL, "Hi There", 8,
                          "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"));
    ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA256, key0b, NULL, "Hi There", 8,
                          sha256_hi_there));
    ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA384, key0b, NULL, "Hi There", 8,
                          "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
                          "faea9ea9076ede7f4af152e8b2fa9cb6"));
    ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA512, key0b, NULL, "Hi There", 8,
                          "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                          "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"));
    ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA1, key0b, NULL, "Hi There", 8,
                          "b617318655057264e28bc0b6fb378c8ef146be00"));
    ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA3_256,
                          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                          NULL, sha3_msg, strlen(sha3_msg),
                          "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205"));

    /* RFC 4231 case 2 uses the four byte key "Jefe", which is below the
     * FIPS minimum; HMAC-MD5 is not offered in FIPS mode at all. */
    if (gcry_fips_mode_active()) {
        gcry_mac_hd_t hd;
        unsigned char key[20];
        unsigned char expect[32];
        unsigned char got[32];
        size_t len = sizeof got;

        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0, NULL));
        unhex(jefe, key, sizeof key);
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 4));
        /* The refused key leaves the handle unkeyed and still usable. */
        ASSERT_ERR(GPG_ERR_INV_STATE, gcry_mac_write(hd, data, 28));
        unhex(key0b, key, sizeof key);
        ASSERT_OK(gcry_mac_setkey(hd, key, 20));
        ASSERT_OK(gcry_mac_write(hd, "Hi There", 8));
        ASSERT_OK(gcry_mac_read(hd, got, &len));
        ASSERT_EQ(32, len);
        unhex(sha256_hi_there, expect, sizeof expect);
        ASSERT_MEM_EQ(expect, got, 32);
        gcry_mac_close(hd);

        ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_HMAC_MD5));
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_HMAC_MD5, 0, NULL));
        ASSERT_NULL(hd);
    } else {
        ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA224, jefe, NULL, data, 28,
                              "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44"));
        ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA256, jefe, NULL, data, 28,
                              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
        ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA384, jefe, NULL, data, 28,
                              "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
                              "8e2240ca5e69e2c78b3239ecfab21649"));
        ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA512, jefe, NULL, data, 28,
                              "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                              "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
        ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_MD5, jefe, NULL, data, 28,
                              "750c783e6ab0b503eaa86e310a5db738"));
        ASSERT_TRUE(check_mac(GCRY_MAC_HMAC_SHA1, jefe, NULL, data, 28,
                              "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));
    }
}

TEST(cmac_rfc4493)
{
    const char *key = "2b7e151628aed2a6abf7158809cf4f3c";
    unsigned char m[40];

    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411", m, sizeof m);
    ASSERT_TRUE(check_mac(GCRY_MAC_CMAC_AES, key, NULL, "", 0,
                          "bb1d6929e95937287fa37d129b756746"));
    ASSERT_TRUE(check_mac(GCRY_MAC_CMAC_AES, key, NULL, m, 16,
                          "070a16b46b4d4144f79bdd9dd04a287c"));
    ASSERT_TRUE(check_mac(GCRY_MAC_CMAC_AES, key, NULL, m, 40,
                          "dfa66747de9ae63030ca32611497c827"));
    /* AES-256 CMAC (NIST SP 800-38B D.3, empty message). */
    ASSERT_TRUE(check_mac(GCRY_MAC_CMAC_AES,
                          "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
                          NULL, "", 0, "028962f61b7bf89efc6b551f4667d983"));

    /* 3DES CMAC (NIST SP 800-38B D.4, empty message).  Triple-DES is not
     * an approved MAC cipher, so FIPS mode refuses to open it; a strict
     * provider may not have it at all. */
    if (mac_unavailable(GCRY_MAC_CMAC_3DES)) {
        gcry_mac_hd_t hd = NULL;

        ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_CMAC_3DES));
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_CMAC_3DES, 0, NULL));
        ASSERT_NULL(hd);
    } else {
        ASSERT_TRUE(check_mac(GCRY_MAC_CMAC_3DES,
                              "8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5",
                              NULL, "", 0, "b7a688e122ffaf95"));
    }
}

TEST(gmac_and_poly1305)
{
    /* GMAC is not approved in FIPS mode: the reference library refuses
     * it there whatever the provider offers. */
    if (mac_unavailable(GCRY_MAC_GMAC_AES)) {
        gcry_mac_hd_t hd = NULL;

        ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_GMAC_AES));
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_GMAC_AES, 0, NULL));
        ASSERT_NULL(hd);
    } else {
        gcry_mac_hd_t hd;
        unsigned char tag1[16];
        unsigned char tag2[16];
        unsigned char zero_iv_tag[16];
        size_t len = 16;
        unsigned char key[16] = { 0 };
        unsigned char iv[12] = { 0 };

        /* NIST GCM test case 1: zero key and IV, no data. */
        ASSERT_TRUE(check_mac(GCRY_MAC_GMAC_AES,
                              "00000000000000000000000000000000",
                              "000000000000000000000000", "", 0,
                              "58e2fccefa7e3061367f1d57a4e7455a"));
        /* GCM test case with AAD only: key/IV from test case 2 with 16
         * bytes of zero AAD; value derived from the GHASH definition and
         * cross-checked against OpenSSL. */
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_GMAC_AES, 0, NULL));
        ASSERT_OK(gcry_mac_setkey(hd, key, 16));
        /* Data before any IV is authenticated under a 16 byte zero IV,
         * as in the reference library (value cross-checked with it). */
        ASSERT_OK(gcry_mac_write(hd, key, 16));
        ASSERT_OK(gcry_mac_read(hd, tag1, &len));
        ASSERT_EQ(16, len);
        unhex("9103a01f968fd51aaf65695d40cf88d8", zero_iv_tag, 16);
        ASSERT_MEM_EQ(zero_iv_tag, tag1, 16);
        ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_mac_setiv(hd, iv, 0));
        /* A new IV starts a fresh message under that IV. */
        ASSERT_OK(gcry_mac_setiv(hd, iv, 12));
        ASSERT_OK(gcry_mac_write(hd, key, 16));
        ASSERT_OK(gcry_mac_read(hd, tag1, &len));
        ASSERT_EQ(16, len);
        ASSERT_TRUE(memcmp(zero_iv_tag, tag1, 16) != 0);
        /* A reset forgets the IV along with the data, as in the
         * reference: the next message runs under the zero IV again. */
        ASSERT_OK(gcry_mac_reset(hd));
        ASSERT_OK(gcry_mac_write(hd, key, 8));
        ASSERT_OK(gcry_mac_write(hd, key, 8));
        ASSERT_OK(gcry_mac_read(hd, tag2, &len));
        ASSERT_MEM_EQ(zero_iv_tag, tag2, 16);
        /* Setting the IV again after a reset brings its tag back. */
        ASSERT_OK(gcry_mac_reset(hd));
        ASSERT_OK(gcry_mac_setiv(hd, iv, 12));
        ASSERT_OK(gcry_mac_write(hd, key, 16));
        ASSERT_OK(gcry_mac_read(hd, tag2, &len));
        ASSERT_MEM_EQ(tag1, tag2, 16);
        /* A reset in the middle of a message drops data and IV alike. */
        ASSERT_OK(gcry_mac_setiv(hd, iv, 12));
        ASSERT_OK(gcry_mac_write(hd, key, 8));
        ASSERT_OK(gcry_mac_reset(hd));
        ASSERT_OK(gcry_mac_write(hd, key, 16));
        ASSERT_OK(gcry_mac_read(hd, tag2, &len));
        ASSERT_MEM_EQ(zero_iv_tag, tag2, 16);
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 15));
        gcry_mac_close(hd);
    }

    /* RFC 8439 section 2.5.2.  Poly1305 is not a FIPS algorithm and the
     * FIPS provider does not offer it. */
    if (mac_unavailable(GCRY_MAC_POLY1305)) {
        gcry_mac_hd_t hd = NULL;

        ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_POLY1305));
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_POLY1305, 0, NULL));
        ASSERT_NULL(hd);
    } else {
        gcry_mac_hd_t hd;
        unsigned char key[32] = { 0 };

        ASSERT_TRUE(check_mac(GCRY_MAC_POLY1305,
                              "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
                              NULL, "Cryptographic Forum Research Group", 34,
                              "a8061dc1305136c6c22b8baf0c0127a9"));
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_POLY1305, 0, NULL));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 16));
        ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_setiv(hd, key, 16));
        gcry_mac_close(hd);
    }
}

TEST(legacy_cmacs)
{
    gcry_mac_hd_t hd;
    const int algos[] = {
        GCRY_MAC_CMAC_CAMELLIA, GCRY_MAC_CMAC_CAST5, GCRY_MAC_CMAC_BLOWFISH,
        GCRY_MAC_CMAC_SEED, GCRY_MAC_CMAC_RFC2268, GCRY_MAC_CMAC_IDEA,
        GCRY_MAC_CMAC_SM4, GCRY_MAC_CMAC_ARIA
    };
    size_t i;

    /* These must at least be usable and deterministic; none of the
     * ciphers is FIPS-approved, so FIPS mode refuses them all, and a
     * strict provider may lack any of them. */
    for (i = 0; i < sizeof algos / sizeof algos[0]; i++) {
        unsigned char key[17] = "0123456789abcdef";
        unsigned char t1[16];
        unsigned char t2[16];
        size_t l1 = sizeof t1;
        size_t l2 = sizeof t2;

        if (mac_unavailable(algos[i])) {
            hd = NULL;
            ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(algos[i]));
            ASSERT_ERR(GPG_ERR_MAC_ALGO,
                       gcry_mac_open(&hd, algos[i], 0, NULL));
            ASSERT_NULL(hd);
            continue;
        }

        ASSERT_OK(gcry_mac_test_algo(algos[i]));
        ASSERT_OK(gcry_mac_open(&hd, algos[i], 0, NULL));
        ASSERT_OK(gcry_mac_setkey(hd, key, 16));
        ASSERT_OK(gcry_mac_write(hd, "hello", 5));
        ASSERT_OK(gcry_mac_read(hd, t1, &l1));
        ASSERT_EQ(gcry_mac_get_algo_maclen(algos[i]), l1);
        ASSERT_OK(gcry_mac_reset(hd));
        ASSERT_OK(gcry_mac_write(hd, "hello", 5));
        ASSERT_OK(gcry_mac_read(hd, t2, &l2));
        ASSERT_MEM_EQ(t1, t2, l1);
        gcry_mac_close(hd);
    }
}

TEST(truncation_and_errors)
{
    gcry_mac_hd_t hd;
    unsigned char full[32];
    unsigned char part[8];
    size_t len;

    ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0, NULL));
    ASSERT_EQ(GCRY_MAC_HMAC_SHA256, gcry_mac_get_algo(hd));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_mac_write(hd, "x", 1)); /* no key */

    /* Any key length goes, except that FIPS mode wants 112 bits. */
    if (gcry_fips_mode_active()) {
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, "key", 3));
        ASSERT_ERR(GPG_ERR_INV_STATE, gcry_mac_write(hd, "x", 1));
        ASSERT_OK(gcry_mac_setkey(hd, "key of 16 bytes!", 16));
    } else {
        ASSERT_OK(gcry_mac_setkey(hd, "key", 3));
    }

    ASSERT_OK(gcry_mac_write(hd, "message", 7));
    len = sizeof full;
    ASSERT_OK(gcry_mac_read(hd, full, &len));
    ASSERT_EQ(32, len);
    len = 8;
    ASSERT_OK(gcry_mac_read(hd, part, &len));
    ASSERT_EQ(8, len);
    ASSERT_MEM_EQ(full, part, 8);
    ASSERT_OK(gcry_mac_verify(hd, full, 32));
    ASSERT_OK(gcry_mac_verify(hd, full, 8));
    full[0] ^= 1;
    ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_mac_verify(hd, full, 32));
    ASSERT_ERR(GPG_ERR_INV_LENGTH, gcry_mac_verify(hd, full, 33));
    ASSERT_ERR(GPG_ERR_INV_STATE, gcry_mac_write(hd, "more", 4));
    len = 0;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_read(hd, full, &len));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_read(hd, full, NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_verify(hd, NULL, 4));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_setiv(hd, "iv", 2));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_mac_ctl(hd, 9999, NULL, 0));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_mac_ctl(hd, GCRYCTL_SET_SBOX, NULL, 0));
    gcry_mac_close(hd);
    gcry_mac_close(NULL);

    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0x10,
                                              NULL));
    ASSERT_NULL(hd);

    /* Secure handle. */
    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA1, GCRY_MAC_FLAG_SECURE, NULL));
    ASSERT_TRUE(gcry_is_secure(hd));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, "k", 1));
    ASSERT_OK(gcry_mac_setkey(hd, "key of 16 bytes!", 16));
    ASSERT_OK(gcry_mac_write(hd, "message", 7));
    len = sizeof full;
    ASSERT_OK(gcry_mac_read(hd, full, &len));
    ASSERT_EQ(20, len);
    gcry_mac_close(hd);
}

TEST(algorithm_tables)
{
    size_t n = 0;

    ASSERT_EQ(32, gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA256));
    ASSERT_EQ(64, gcry_mac_get_algo_keylen(GCRY_MAC_HMAC_SHA256));
    ASSERT_EQ(128, gcry_mac_get_algo_keylen(GCRY_MAC_HMAC_SHA512));
    ASSERT_EQ(16, gcry_mac_get_algo_maclen(GCRY_MAC_CMAC_AES));
    ASSERT_EQ(16, gcry_mac_get_algo_keylen(GCRY_MAC_CMAC_AES));
    ASSERT_EQ(8, gcry_mac_get_algo_maclen(GCRY_MAC_CMAC_3DES));
    ASSERT_EQ(24, gcry_mac_get_algo_keylen(GCRY_MAC_CMAC_3DES));
    ASSERT_EQ(16, gcry_mac_get_algo_maclen(GCRY_MAC_GMAC_AES));
    ASSERT_EQ(16, gcry_mac_get_algo_maclen(GCRY_MAC_POLY1305));
    ASSERT_EQ(32, gcry_mac_get_algo_keylen(GCRY_MAC_POLY1305));
    ASSERT_EQ(0, gcry_mac_get_algo_maclen(4711));
    ASSERT_EQ(0, gcry_mac_get_algo_keylen(4711));

    ASSERT_STR_EQ("HMAC_SHA256", gcry_mac_algo_name(GCRY_MAC_HMAC_SHA256));
    ASSERT_STR_EQ("HMAC_RIPEMD160", gcry_mac_algo_name(GCRY_MAC_HMAC_RMD160));
    ASSERT_STR_EQ("CMAC_AES", gcry_mac_algo_name(GCRY_MAC_CMAC_AES));
    ASSERT_STR_EQ("GMAC_AES", gcry_mac_algo_name(GCRY_MAC_GMAC_AES));
    ASSERT_STR_EQ("POLY1305", gcry_mac_algo_name(GCRY_MAC_POLY1305));
    ASSERT_STR_EQ("?", gcry_mac_algo_name(4711));
    ASSERT_EQ(GCRY_MAC_HMAC_SHA256, gcry_mac_map_name("HMAC_SHA256"));
    ASSERT_EQ(GCRY_MAC_HMAC_SHA256, gcry_mac_map_name("hmac_sha256"));
    ASSERT_EQ(GCRY_MAC_CMAC_AES, gcry_mac_map_name("CMAC_AES"));
    ASSERT_EQ(GCRY_MAC_POLY1305, gcry_mac_map_name("POLY1305"));
    ASSERT_EQ(0, gcry_mac_map_name("nope"));
    ASSERT_EQ(0, gcry_mac_map_name(NULL));

    ASSERT_OK(gcry_mac_test_algo(GCRY_MAC_HMAC_SHA3_256));
    ASSERT_OK(gcry_mac_test_algo(GCRY_MAC_HMAC_SHA512_256));
    ASSERT_OK(gcry_mac_test_algo(GCRY_MAC_CMAC_AES));
    /* GMAC is refused in FIPS mode, as the reference library does. */
    ASSERT_OK_UNLESS(mac_unavailable(GCRY_MAC_GMAC_AES), GPG_ERR_MAC_ALGO,
                     gcry_mac_test_algo(GCRY_MAC_GMAC_AES));
    /* BLAKE2, SM3 and Whirlpool are not FIPS-approved, so HMAC over them
     * is refused in FIPS mode, and a strict provider may lack the digests
     * outside it; TEST_ALGO is the probe, so these are only consistent
     * with themselves. */
    ASSERT_OK_UNLESS(mac_unavailable(GCRY_MAC_HMAC_BLAKE2B_512),
                     GPG_ERR_MAC_ALGO,
                     gcry_mac_test_algo(GCRY_MAC_HMAC_BLAKE2B_512));
    ASSERT_OK_UNLESS(mac_unavailable(GCRY_MAC_HMAC_SM3), GPG_ERR_MAC_ALGO,
                     gcry_mac_test_algo(GCRY_MAC_HMAC_SM3));
    ASSERT_OK_UNLESS(mac_unavailable(GCRY_MAC_HMAC_WHIRLPOOL),
                     GPG_ERR_MAC_ALGO,
                     gcry_mac_test_algo(GCRY_MAC_HMAC_WHIRLPOOL));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_HMAC_TIGER1));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_HMAC_STRIBOG256));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_HMAC_BLAKE2B_256));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_CMAC_TWOFISH));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_CMAC_SERPENT));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_CMAC_GOST28147));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_GMAC_CAMELLIA));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_POLY1305_AES));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(GCRY_MAC_GOST28147_IMIT));
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_test_algo(4711));
    {
        gcry_mac_hd_t hd;

        ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_open(&hd, GCRY_MAC_CMAC_TWOFISH, 0,
                                                   NULL));
        ASSERT_NULL(hd);
    }

    ASSERT_OK(gcry_mac_algo_info(GCRY_MAC_CMAC_AES, GCRYCTL_GET_KEYLEN, NULL, &n));
    ASSERT_EQ(16, n);
    ASSERT_ERR(GPG_ERR_MAC_ALGO, gcry_mac_algo_info(4711, GCRYCTL_GET_KEYLEN, NULL,
                                                    &n));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_algo_info(GCRY_MAC_CMAC_AES,
                                                   GCRYCTL_GET_KEYLEN, NULL, NULL));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_mac_algo_info(GCRY_MAC_CMAC_AES, 9999, NULL,
                                                  NULL));
}

TEST(key_and_state_rules)
{
    gcry_mac_hd_t hd;
    unsigned char key[128];
    unsigned char tag[16];
    size_t len;

    memset(key, 7, sizeof key);

    /* CMAC key lengths follow the underlying cipher. */
    ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_CMAC_AES, 0, NULL));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 20));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_setkey(hd, NULL, 5));
    ASSERT_OK(gcry_mac_setkey(hd, key, 24));
    ASSERT_OK(gcry_mac_setkey(hd, key, 32)); /* re-keying is allowed */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_write(hd, NULL, 3));
    ASSERT_OK(gcry_mac_write(hd, "abc", 3));
    len = sizeof tag;
    ASSERT_OK(gcry_mac_read(hd, tag, &len));
    ASSERT_EQ(16, len);
    gcry_mac_close(hd);

    /* Triple-DES CMAC takes three-key material only, and refuses weak or
     * semi-weak subkeys like the cipher does.  FIPS mode does not offer
     * it at all, nor may a strict provider. */
    if (mac_unavailable(GCRY_MAC_CMAC_3DES)) {
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_CMAC_3DES, 0, NULL));
    } else {
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_CMAC_3DES, 0, NULL));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 20));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 16));
        ASSERT_OK(gcry_mac_setkey(hd, key, 24));
        memset(key + 8, 0x01, 8);
        ASSERT_ERR(GPG_ERR_WEAK_KEY, gcry_mac_setkey(hd, key, 24));
        memset(key, 7, sizeof key);
        gcry_mac_close(hd);
    }

    /* The variable-length legacy ciphers; none of them in FIPS mode, and
     * a strict provider may lack each of them. */
    if (mac_unavailable(GCRY_MAC_CMAC_BLOWFISH)) {
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_CMAC_BLOWFISH, 0, NULL));
    } else {
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_CMAC_BLOWFISH, 0, NULL));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 57));
        ASSERT_OK(gcry_mac_setkey(hd, key, 5));
        gcry_mac_close(hd);
    }

    if (mac_unavailable(GCRY_MAC_CMAC_CAST5)) {
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_CMAC_CAST5, 0, NULL));
    } else {
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_CMAC_CAST5, 0, NULL));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 4));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 17));
        ASSERT_OK(gcry_mac_setkey(hd, key, 10));
        gcry_mac_close(hd);
    }

    if (mac_unavailable(GCRY_MAC_CMAC_RFC2268)) {
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_CMAC_RFC2268, 0, NULL));
    } else {
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_CMAC_RFC2268, 0, NULL));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 0));
        ASSERT_OK(gcry_mac_setkey(hd, key, 128));
        gcry_mac_close(hd);
    }

    /* HMAC takes any key length, but FIPS mode draws the line at 112
     * bits (SP 800-131A). */
    ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0, NULL));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 13));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 0));
    ASSERT_OK(gcry_mac_setkey(hd, key, 14));
    ASSERT_OK(gcry_mac_write(hd, "abc", 3));
    len = sizeof tag;
    ASSERT_OK(gcry_mac_read(hd, tag, &len));
    ASSERT_EQ(16, len);
    gcry_mac_close(hd);

    /* GMAC keeps the key across a reset, but not the IV.  FIPS mode has
     * no GMAC (see gmac_and_poly1305 for that). */
    if (!mac_unavailable(GCRY_MAC_GMAC_AES)) {
        gcry_mac_hd_t fresh;
        unsigned char tag2[16];
        size_t len2 = sizeof tag2;

        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_GMAC_AES, 0, NULL));
        ASSERT_OK(gcry_mac_setkey(hd, key, 16));
        ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_setiv(hd, NULL, 12));
        ASSERT_OK(gcry_mac_setiv(hd, key, 12));
        ASSERT_OK(gcry_mac_write(hd, "abc", 3));
        len = sizeof tag;
        ASSERT_OK(gcry_mac_read(hd, tag, &len));
        ASSERT_OK(gcry_mac_ctl(hd, GCRYCTL_RESET, NULL, 0));
        ASSERT_OK(gcry_mac_setiv(hd, key, 12));
        ASSERT_OK(gcry_mac_write(hd, "abc", 3));
        ASSERT_OK(gcry_mac_verify(hd, tag, len));
        /* Without a new IV the reset handle authenticates under the
         * all-zero IV, exactly like a fresh handle that never had one;
         * the reference library behaves the same. */
        ASSERT_OK(gcry_mac_ctl(hd, GCRYCTL_RESET, NULL, 0));
        ASSERT_OK(gcry_mac_write(hd, "abc", 3));
        ASSERT_OK(gcry_mac_read(hd, tag2, &len2));
        ASSERT_EQ(16, len2);
        ASSERT_TRUE(memcmp(tag, tag2, 16) != 0);
        ASSERT_ERR(GPG_ERR_CHECKSUM, gcry_mac_verify(hd, tag, len));
        ASSERT_OK(gcry_mac_open(&fresh, GCRY_MAC_GMAC_AES, 0, NULL));
        ASSERT_OK(gcry_mac_setkey(fresh, key, 16));
        ASSERT_OK(gcry_mac_write(fresh, "abc", 3));
        ASSERT_OK(gcry_mac_verify(fresh, tag2, len2));
        gcry_mac_close(fresh);
        gcry_mac_close(hd);
    }

    /* Poly1305 takes exactly 32 key bytes; FIPS mode has no Poly1305. */
    if (mac_unavailable(GCRY_MAC_POLY1305)) {
        ASSERT_ERR(GPG_ERR_MAC_ALGO,
                   gcry_mac_open(&hd, GCRY_MAC_POLY1305, 0, NULL));
    } else {
        ASSERT_OK(gcry_mac_open(&hd, GCRY_MAC_POLY1305, 0, NULL));
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_mac_setkey(hd, key, 16));
        len = sizeof tag;
        ASSERT_ERR(GPG_ERR_INV_STATE, gcry_mac_read(hd, tag, &len));
        gcry_mac_close(hd);
    }

    /* TEST_ALGO takes no output arguments. */
    len = 0;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_algo_info(GCRY_MAC_CMAC_AES,
                                                   GCRYCTL_TEST_ALGO, NULL, &len));
    ASSERT_OK(gcry_mac_algo_info(GCRY_MAC_CMAC_AES, GCRYCTL_TEST_ALGO, NULL,
                                 NULL));

    /* NULL handles are rejected instead of dereferenced. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_open(NULL, GCRY_MAC_HMAC_SHA256, 0,
                                              NULL));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_setkey(NULL, key, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_setiv(NULL, key, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_write(NULL, key, 1));
    len = sizeof tag;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_read(NULL, tag, &len));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_verify(NULL, tag, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_mac_ctl(NULL, GCRYCTL_RESET, NULL, 0));
    ASSERT_EQ(0, gcry_mac_get_algo(NULL));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(hmac_rfc4231);
    RUN_TEST(cmac_rfc4493);
    RUN_TEST(gmac_and_poly1305);
    RUN_TEST(legacy_cmacs);
    RUN_TEST(truncation_and_errors);
    RUN_TEST(algorithm_tables);
    RUN_TEST(key_and_state_rules);
    return TEST_RESULT();
}
