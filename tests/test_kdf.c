#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

/* Derive through the handle based API (open/compute/final/close). */
static gcry_error_t
kdf_derive_hd(int algo, int subalgo, const unsigned long *param,
              unsigned int paramlen, const void *pass, size_t passlen,
              const void *salt, size_t saltlen, const void *key,
              size_t keylen, const void *ad, size_t adlen, size_t outlen,
              void *out)
{
    gcry_kdf_hd_t hd;
    gcry_error_t err = gcry_kdf_open(&hd, algo, subalgo, param, paramlen,
                                     pass, passlen, salt, saltlen, key,
                                     keylen, ad, adlen);

    if (err) {
        return err;
    }

    err = gcry_kdf_compute(hd, NULL);

    if (!err) {
        err = gcry_kdf_final(hd, outlen, out);
    }

    gcry_kdf_close(hd);
    return err;
}

TEST(s2k_vectors)
{
    /* Derived keys produced by GnuPG 1.4 (the reference library's own
     * published test data). */
    static const struct {
        const char *p;
        size_t plen;
        int algo;
        int hashalgo;
        const char *salt;
        unsigned long c;
        size_t dklen;
        const char *dk;
    } tv[] = {
        {
            "a", 1, GCRY_KDF_SIMPLE_S2K, GCRY_MD_MD5, NULL, 0, 16,
            "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61"
        },
        {
            "abcdefghi", 9, GCRY_KDF_SIMPLE_S2K, GCRY_MD_MD5, NULL, 0, 16,
            "\x8a\xa9\x9b\x1f\x43\x9f\xf7\x12\x93\xe9\x53\x57\xba\xc6\xfd\x94"
        },
        {
            "abcdefg", 7, GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA1,
            "\x40\x57\xb2\x9d\x5f\xbb\x11\x4f", 1024, 16,
            "\xad\xa2\x33\xd9\xdd\xe0\xfb\x94\x8e\xcc\xec\xcc\xb3\xa8\x3a\x9e"
        },
        {
            "abcdefghijklmnopqrstu", 21, GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA1,
            "\x4c\xf1\x10\x11\x04\x70\xd3\x6e", 1024, 16,
            "\x2c\x50\x79\x8d\x83\x23\xac\xd6\x22\x29\x37\xaf\x15\x0d\xdd\x8f"
        },
        {
            "Long_sentence_used_as_passphrase", 32, GCRY_KDF_ITERSALTED_S2K,
            GCRY_MD_SHA1, "\x95\xd6\x72\x4e\xfb\xe1\xc3\x1a", 102400, 16,
            "\xf2\x3f\x36\x7f\xb4\x6a\xd0\x3a\x31\x9e\x65\x11\x8e\x2b\x99\x9b"
        },
        /* Key longer than the digest: a second pass with a zero prefix. */
        {
            "a", 1, GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA1,
            "\x6d\x69\x15\x18\xe4\x13\x42\x82", 1024, 24,
            "\x28\x0c\x7e\xf2\x31\xf6\x1c\x6b\x5c\xef\x6a\xd5\x22\x64\x97\x91"
            "\xe3\x5e\x37\xfd\x50\xe2\xfc\x6c"
        },
        {
            "abcdefghi", 9, GCRY_KDF_ITERSALTED_S2K, GCRY_MD_SHA1,
            "\x5d\x41\x3d\xa3\xa7\xfc\x5d\x0c", 1024, 32,
            "\x4c\x7a\x86\xed\x81\x8a\x94\x99\x7d\x4a\xc4\xf7\x1c\xf8\x08\xdb"
            "\x09\x35\xd9\xa3\x2d\x22\xde\x32\x2d\x74\x38\xe5\xc8\xf2\x50\x6e"
        },
        {
            "Long_sentence_used_as_passphrase", 32, GCRY_KDF_SIMPLE_S2K,
            GCRY_MD_SHA256, NULL, 0, 16,
            "\x88\x36\x78\x6b\xd9\x5a\x62\xff\x47\xd3\xfb\x79\xc9\x08\x70\x56"
        },
        {
            "Long_sentence_used_as_passphrase", 32, GCRY_KDF_SALTED_S2K,
            GCRY_MD_SHA256, "\x05\x8b\xfe\x31\xaa\xf3\x29\x11", 0, 16,
            "\xb2\x42\xfe\x5e\x09\x02\xd9\x62\xb9\x35\xf3\xa8\x43\x80\x9f\xb1"
        },
        {
            "Long_sentence_used_as_passphrase", 32, GCRY_KDF_ITERSALTED_S2K,
            GCRY_MD_SHA256, "\x5e\x71\xbd\x00\x5f\x96\xc4\x23", 10240, 16,
            "\xa1\x6a\xee\xba\xde\x73\x25\x25\xd1\xab\xa0\xc5\x7e\xc6\x39\xa7"
        },
        {
            "Long_sentence_used_as_passphrase", 32, GCRY_KDF_ITERSALTED_S2K,
            GCRY_MD_SHA384, "\xc3\x08\xeb\x17\x62\x08\x89\xef", 1024, 16,
            "\x9b\x7f\x0c\x81\x6f\x71\x59\x9b\xd5\xf6\xbf\x3a\x86\x20\x16\x33"
        },
        {
            "Long_sentence_used_as_passphrase", 32, GCRY_KDF_ITERSALTED_S2K,
            GCRY_MD_SHA512, "\xed\x7d\x30\x47\xe4\xc3\xf8\xb6", 1024, 32,
            "\x89\x7a\xef\x70\x97\xe7\x10\xdb\x75\xcc\x20\x22\xab\x7b\xf3\x05"
            "\x4b\xb6\x2e\x17\x11\x9f\xd6\xeb\xbf\xdf\x4d\x70\x59\xf0\xf9\xe5"
        },
    };
    size_t i;
    unsigned char out[32];

    for (i = 0; i < sizeof tv / sizeof tv[0]; i++) {
        ASSERT_OK(gcry_kdf_derive(tv[i].p, tv[i].plen, tv[i].algo,
                                  tv[i].hashalgo, tv[i].salt,
                                  tv[i].salt ? 8 : 0, tv[i].c, tv[i].dklen,
                                  out));
        ASSERT_MEM_EQ(tv[i].dk, out, tv[i].dklen);
    }

    /* Salted modes insist on an 8 byte salt. */
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("a", 1, GCRY_KDF_SALTED_S2K, GCRY_MD_SHA1,
                               "short", 5, 0, 16, out));
    ASSERT_ERR(GPG_ERR_INV_DATA,
               gcry_kdf_derive("", 0, GCRY_KDF_SIMPLE_S2K, GCRY_MD_SHA1,
                               NULL, 0, 0, 16, out));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_kdf_derive("a", 1, GCRY_KDF_SIMPLE_S2K, GCRY_MD_TIGER,
                               NULL, 0, 0, 16, out));
}

TEST(pbkdf2_vectors)
{
    /* RFC 6070 (SHA-1) and RFC 7914, section 11 (SHA-256). */
    static const struct {
        const char *p;
        size_t plen;
        const char *salt;
        size_t saltlen;
        int hashalgo;
        unsigned long c;
        size_t dklen;
        const char *dk;
    } tv[] = {
        {
            "password", 8, "salt", 4, GCRY_MD_SHA1, 1, 20,
            "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06"
            "\x2f\xe0\x37\xa6"
        },
        {
            "password", 8, "salt", 4, GCRY_MD_SHA1, 1, 10,
            "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9"
        },
        {
            "password", 8, "salt", 4, GCRY_MD_SHA1, 2, 20,
            "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0"
            "\xd8\xde\x89\x57"
        },
        {
            "password", 8, "salt", 4, GCRY_MD_SHA1, 4096, 20,
            "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0"
            "\x65\xa4\x29\xc1"
        },
        {
            "passwordPASSWORDpassword", 24,
            "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, GCRY_MD_SHA1, 4096, 25,
            "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a"
            "\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38"
        },
        {
            "pass\0word", 9, "sa\0lt", 5, GCRY_MD_SHA1, 4096, 16,
            "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3"
        },
        {
            "", 0, "salt", 4, GCRY_MD_SHA1, 2, 20,
            "\x13\x3a\x4c\xe8\x37\xb4\xd2\x52\x1e\xe2\xbf\x03\xe1\x1c\x71\xca"
            "\x79\x4e\x07\x97"
        },
        {
            "passwd", 6, "salt", 4, GCRY_MD_SHA256, 1, 64,
            "\x55\xac\x04\x6e\x56\xe3\x08\x9f\xec\x16\x91\xc2\x25\x44\xb6\x05"
            "\xf9\x41\x85\x21\x6d\xde\x04\x65\xe6\x8b\x9d\x57\xc2\x0d\xac\xbc"
            "\x49\xca\x9c\xcc\xf1\x79\xb6\x45\x99\x16\x64\xb3\x9d\x77\xef\x31"
            "\x7c\x71\xb8\x45\xb1\xe3\x0b\xd5\x09\x11\x20\x41\xd3\xa1\x97\x83"
        },
        {
            "Password", 8, "NaCl", 4, GCRY_MD_SHA256, 80000, 64,
            "\x4d\xdc\xd8\xf6\x0b\x98\xbe\x21\x83\x0c\xee\x5e\xf2\x27\x01\xf9"
            "\x64\x1a\x44\x18\xd0\x4c\x04\x14\xae\xff\x08\x87\x6b\x34\xab\x56"
            "\xa1\xd4\x25\xa1\x22\x58\x33\x54\x9a\xdb\x84\x1b\x51\xc9\xb3\x17"
            "\x6a\x27\x2b\xde\xbb\xa1\xd0\x78\x47\x8f\x62\xb3\x97\xf3\x3c\x8d"
        },
    };
    size_t i;
    unsigned char out[64];

    for (i = 0; i < sizeof tv / sizeof tv[0]; i++) {
        ASSERT_OK(gcry_kdf_derive(tv[i].p, tv[i].plen, GCRY_KDF_PBKDF2,
                                  tv[i].hashalgo, tv[i].salt, tv[i].saltlen,
                                  tv[i].c, tv[i].dklen, out));
        ASSERT_MEM_EQ(tv[i].dk, out, tv[i].dklen);
    }

    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
                               "salt", 4, 0, 20, out));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
                               NULL, 0, 1, 20, out));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF2, 9999,
                               "salt", 4, 1, 20, out));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
                               "salt", 4, 1, 0, out));
    ASSERT_ERR(GPG_ERR_INV_DATA,
               gcry_kdf_derive(NULL, 0, GCRY_KDF_PBKDF2, GCRY_MD_SHA1, "salt",
                               4, 1, 20, out));
    ASSERT_ERR(GPG_ERR_UNSUPPORTED_ALGORITHM,
               gcry_kdf_derive("password", 8, GCRY_KDF_PBKDF1, GCRY_MD_SHA1,
                               "salt", 4, 1, 20, out));
    ASSERT_ERR(GPG_ERR_UNKNOWN_ALGORITHM,
               gcry_kdf_derive("password", 8, GCRY_KDF_ARGON2, 0, "salt", 4,
                               1, 20, out));
    ASSERT_ERR(GPG_ERR_UNKNOWN_ALGORITHM,
               gcry_kdf_derive("password", 8, 1234, 0, "salt", 4, 1, 20,
                               out));
}

TEST(scrypt_vectors)
{
    /* RFC 7914, section 12.  The first uses r = 1 through the undocumented
     * algorithm id 41, as the reference test suite does. */
    static const unsigned char dk1[] =
        "\x77\xd6\x57\x62\x38\x65\x7b\x20\x3b\x19\xca\x42\xc1\x8a\x04\x97"
        "\xf1\x6b\x48\x44\xe3\x07\x4a\xe8\xdf\xdf\xfa\x3f\xed\xe2\x14\x42"
        "\xfc\xd0\x06\x9d\xed\x09\x48\xf8\x32\x6a\x75\x3a\x0f\xc8\x1f\x17"
        "\xe8\xd3\xe0\xfb\x2e\x0d\x36\x28\xcf\x35\xe2\x0c\x38\xd1\x89\x06";
    static const unsigned char dk2[] =
        "\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe"
        "\x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62"
        "\x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda"
        "\xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40";
    static const unsigned char dk3[] =
        "\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46\x1c\x06\xcd\x81\xfd\x38\xeb"
        "\xfd\xa8\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43\xf6\x54\x5d\xa1\xf2"
        "\xd5\x43\x29\x55\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24\x2a\x9a\xf9"
        "\xe6\x1e\x85\xdc\x0d\x65\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58\x87";
    unsigned char out[64];

    ASSERT_OK(gcry_kdf_derive("", 0, 41, 16, "", 0, 1, 64, out));
    ASSERT_MEM_EQ(dk1, out, 64);
    ASSERT_OK(gcry_kdf_derive("password", 8, GCRY_KDF_SCRYPT, 1024, "NaCl",
                              4, 16, 64, out));
    ASSERT_MEM_EQ(dk2, out, 64);
    ASSERT_OK(gcry_kdf_derive("pleaseletmein", 13, GCRY_KDF_SCRYPT, 16384,
                              "SodiumChloride", 14, 1, 64, out));
    ASSERT_MEM_EQ(dk3, out, 64);

    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("x", 1, GCRY_KDF_SCRYPT, 0, "s", 1, 1, 64,
                               out));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("x", 1, GCRY_KDF_SCRYPT, 16, "s", 1, 0, 64,
                               out));
    /* N must be a power of two. */
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_derive("x", 1, GCRY_KDF_SCRYPT, 15, "s", 1, 1, 64,
                               out));
}

TEST(argon2_vectors)
{
    /* RFC 9106, sections 5.1 to 5.3, plus two empty-password cases. */
    static const unsigned char pass[] =
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
    static const unsigned char salt[] =
        "\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02";
    static const unsigned char secret[] = "\x03\x03\x03\x03\x03\x03\x03\x03";
    static const unsigned char ad[] =
        "\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04";
    static const unsigned char salt2[] =
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    static const struct {
        int subalgo;
        unsigned long param[4];
        int empty_pass;
        const unsigned char *salt;
        int with_secret_ad;
        const char *dk;
    } tv[] = {
        {
            GCRY_KDF_ARGON2D, { 32, 3, 32, 4 }, 0, salt, 1,
            "\x51\x2b\x39\x1b\x6f\x11\x62\x97\x53\x71\xd3\x09\x19\x73\x42\x94"
            "\xf8\x68\xe3\xbe\x39\x84\xf3\xc1\xa1\x3a\x4d\xb9\xfa\xbe\x4a\xcb"
        },
        {
            GCRY_KDF_ARGON2I, { 32, 3, 32, 4 }, 0, salt, 1,
            "\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
            "\xc8\xde\x6b\x01\x6d\xd3\x88\xd2\x99\x52\xa4\xc4\x67\x2b\x6c\xe8"
        },
        {
            GCRY_KDF_ARGON2ID, { 32, 3, 32, 4 }, 0, salt, 1,
            "\x0d\x64\x0d\xf5\x8d\x78\x76\x6c\x08\xc0\x37\xa3\x4a\x8b\x53\xc9"
            "\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e\xb5\x25\x20\xe9\x6b\x01\xe6\x59"
        },
        {
            GCRY_KDF_ARGON2I, { 32, 3, 128, 1 }, 1, salt2, 0,
            "\xbb\x1f\xf2\xb9\x9f\xd4\x4a\xd9\xdf\x7f\xb9\x54\x55\x9e\xb8\xeb"
            "\xb5\x9d\xab\xce\x2e\x62\x9f\x9b\x89\x09\xfe\xde\x57\xcc\x63\x86"
        },
        {
            GCRY_KDF_ARGON2ID, { 32, 3, 128, 1 }, 1, salt2, 0,
            "\x09\x2f\x38\x35\xac\xb2\x43\x92\x93\xeb\xcd\xe8\x04\x16\x6a\x31"
            "\xce\x14\xd4\x55\xdb\xd8\xf7\xe6\xb4\xf5\x9d\x64\x8e\xd0\x3a\xdb"
        },
    };
    size_t i;
    unsigned char out[32];
    gcry_kdf_hd_t hd;
    unsigned long bad[4] = { 32, 3, 32, 0 };

    for (i = 0; i < sizeof tv / sizeof tv[0]; i++) {
        ASSERT_OK(kdf_derive_hd(GCRY_KDF_ARGON2, tv[i].subalgo, tv[i].param,
                                4, tv[i].empty_pass ? NULL : pass,
                                tv[i].empty_pass ? 0 : 32,
                                tv[i].salt, 16,
                                tv[i].with_secret_ad ? secret : NULL,
                                tv[i].with_secret_ad ? 8 : 0,
                                tv[i].with_secret_ad ? ad : NULL,
                                tv[i].with_secret_ad ? 12 : 0, 32,
                                out));
        ASSERT_MEM_EQ(tv[i].dk, out, 32);
    }

    /* Three parameters imply a parallelism of one. */
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID, tv[4].param,
                            3, NULL, 0, salt2, 16, NULL, 0, NULL, 0, 32,
                            out));
    ASSERT_MEM_EQ(tv[4].dk, out, 32);

    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID,
                             tv[0].param, 4, pass, 32, NULL, 0, NULL, 0, NULL,
                             0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_ARGON2, 7, tv[0].param, 4, pass,
                             32, salt, 16, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID,
                             tv[0].param, 2, pass, 32, salt, 16, NULL, 0,
                             NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID, bad, 4,
                             pass, 32, salt, 16, NULL, 0, NULL, 0));

    /* Wrong result length at final time. */
    ASSERT_OK(gcry_kdf_open(&hd, GCRY_KDF_ARGON2, GCRY_KDF_ARGON2ID,
                            tv[0].param, 4, pass, 32, salt, 16, NULL, 0, NULL,
                            0));
    ASSERT_OK(gcry_kdf_compute(hd, NULL));
    ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_kdf_final(hd, 16, out));
    ASSERT_OK(gcry_kdf_final(hd, 32, out));
    gcry_kdf_close(hd);
    gcry_kdf_close(NULL);
}

TEST(balloon_unsupported)
{
    gcry_kdf_hd_t hd;
    unsigned long param[2] = { 1024, 3 };
    static const unsigned char salt[32] = { 0 };

    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_kdf_open(&hd, GCRY_KDF_BALLOON, GCRY_MD_SHA256, param, 2,
                             "pw", 2, salt, sizeof salt, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_BALLOON, GCRY_MD_SHA256, param, 2,
                             "pw", 2, NULL, 0, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_UNKNOWN_ALGORITHM,
               gcry_kdf_open(&hd, 777, 0, param, 2, "pw", 2, salt, 32, NULL,
                             0, NULL, 0));
}

TEST(onestep_kdf_vectors)
{
    /* NIST CAVP SSKDF vectors as used by the reference test suite. */
    static const unsigned char z1[] =
        "\x3f\x89\x2b\xd8\xb8\x4d\xae\x64\xa7\x82\xa3\x5f\x6e\xaa\x8f\x00";
    static const unsigned char info1[] =
        "\xec\x3f\x1c\xd8\x73\xd2\x88\x58\xa5\x8c\xc3\x9e";
    static const unsigned char dk1[] =
        "\xa7\xc0\x66\x52\x98\x25\x25\x31\xe0\xdb\x37\x73\x7a\x37\x46\x51"
        "\xb3\x68\x27\x5f\x20\x48\x28\x4d\x16\xa1\x66\xc6\xd8\xa9\x0a\x91"
        "\xa4\x91\xc1\x6f\x49\x64";
    static const unsigned char z2[] =
        "\xe6\x5b\x19\x05\x87\x8b\x95\xf6\x8b\x55\x35\xbd\x3b\x2b\x10\x13";
    static const unsigned char info2[] =
        "\x83\x02\x21\xb1\x73\x0d\x91\x76\xf8\x07\xd4\x07";
    static const unsigned char dk2[] =
        "\xb8\xc4\x4b\xdf\x0b\x85\xa6\x4b\x6a\x51\xc1\x2a\x06\x71\x0e\x37"
        "\x3d\x82\x9b\xb1\xfd\xa5\xb4\xe1\xa2\x07\x95\xc6\x19\x95\x94\xf6"
        "\xfa\x65\x19\x8a\x72\x12\x57\xf7\xd5\x8c\xb2\xf6\xf6\xdb\x9b\xb5"
        "\x69\x9f\x73\x86\x30\x45\x90\x90\x54\xb2\x38\x9e\x06\xec\x00\xfe"
        "\x31\x8c\xab\xd9";
    static const unsigned char z3[] =
        "\x02\xb4\x0d\x33\xe3\xf6\x85\xae\xae\x67\x7a\xc3\x44\xee\xaf\x77";
    static const unsigned char info3[] =
        "\xc6\x7c\x38\x95\x80\x12\x8f\x18\xf6\xcf\x85\x92";
    static const unsigned char salt3[] =
        "\x0a\xd5\x2c\x93\x57\xc8\x5e\x47\x81\x29\x6a\x36\xca\x72\x03\x9c";
    static const unsigned char dk3[] =
        "\xbe\x32\xe7\xd3\x06\xd8\x91\x02\x8b\xe0\x88\xf2\x13\xf9\xf9\x47"
        "\xc5\x04\x20\xd9\xb5\xa1\x2c\xa6\x98\x18\xdd\x99\x95\xde\xdd\x8e"
        "\x61\x37\xc7\x10\x4d\x67\xf2\xca\x90\x91\x5d\xda";
    static const unsigned char z4[] =
        "\x8e\x5c\xd5\xf6\xae\x55\x8f\xfa\x04\xcd\xa2\xfa\xd9\x4d\xd6\x16";
    static const unsigned char info4[] =
        "\x4a\x43\x30\x18\xe5\x1c\x09\xbb\xd6\x13\x26\xbb";
    static const unsigned char salt4[] =
        "\x6e\xd9\x3b\x6f\xe5\xb3\x50\x2b\xb4\x2b\x4c\x0f\xcb\x13\x36\x62";
    static const unsigned char dk4[] =
        "\x29\x5d\xfb\xeb\x54\xec\x0f\xe2\x4e\xce\x32\xf5\xb8\x7c\x85\x3e"
        "\x69\x9a\x62\xe3\x9d\x9c\x9e\xe6\xee\x78\xf8\xb9\xa0\xee\x50\xa3"
        "\x6a\x82\xe6\x06\x2c\x95\xed\x53\xbc\x36\x67\x00\xe2\xd0\xe0\x93"
        "\xbf\x75\x2e\xea\x42\x99\x47\x2e";
    unsigned long param[1];
    unsigned char out[68];
    gcry_kdf_hd_t hd;

    param[0] = 38;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_ONESTEP_KDF, GCRY_MD_SHA256, param, 1,
                            z1, 16, NULL, 0, NULL, 0, info1, 12, 38, out));
    ASSERT_MEM_EQ(dk1, out, 38);
    param[0] = 68;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_ONESTEP_KDF, GCRY_MD_SHA512, param, 1,
                            z2, 16, NULL, 0, NULL, 0, info2, 12, 68, out));
    ASSERT_MEM_EQ(dk2, out, 68);
    param[0] = 44;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_ONESTEP_KDF_MAC, GCRY_MAC_HMAC_SHA256,
                            param, 1, z3, 16, NULL, 0, salt3, 16, info3, 12,
                            44, out));
    ASSERT_MEM_EQ(dk3, out, 44);
    param[0] = 56;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_ONESTEP_KDF_MAC, GCRY_MAC_HMAC_SHA512,
                            param, 1, z4, 16, NULL, 0, salt4, 16, info4, 12,
                            56, out));
    ASSERT_MEM_EQ(dk4, out, 56);

    /* Parameter validation. */
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_ONESTEP_KDF, GCRY_MD_SHA256, param,
                             1, z1, 16, NULL, 0, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_kdf_open(&hd, GCRY_KDF_ONESTEP_KDF, GCRY_MD_TIGER, param,
                             1, z1, 16, NULL, 0, NULL, 0, info1, 12));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_ONESTEP_KDF_MAC,
                             GCRY_MAC_HMAC_SHA256, param, 1, z3, 16, NULL, 0,
                             NULL, 0, info3, 12));
    ASSERT_ERR(GPG_ERR_MAC_ALGO,
               gcry_kdf_open(&hd, GCRY_KDF_ONESTEP_KDF_MAC, GCRY_MAC_CMAC_AES,
                             param, 1, z3, 16, NULL, 0, salt3, 16, info3,
                             12));
    /* Thread callbacks are refused for the single-threaded KDFs. */
    ASSERT_OK(gcry_kdf_open(&hd, GCRY_KDF_ONESTEP_KDF, GCRY_MD_SHA256, param,
                            1, z1, 16, NULL, 0, NULL, 0, info1, 12));
    {
        gcry_kdf_thread_ops_t ops = { NULL, NULL, NULL };

        ASSERT_ERR(GPG_ERR_INV_VALUE, gcry_kdf_compute(hd, &ops));
    }
    gcry_kdf_close(hd);
}

TEST(hkdf_vectors)
{
    /* RFC 5869 test cases 1 to 3 and RFC 9580 A.8.2. */
    static const unsigned char ikm1[] =
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b\x0b\x0b\x0b";
    static const unsigned char salt1[] =
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c";
    static const unsigned char info1[] =
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9";
    static const unsigned char okm1[] =
        "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a"
        "\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf"
        "\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65";
    static const unsigned char okm3[] =
        "\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31"
        "\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d"
        "\x9d\x20\x13\x95\xfa\xa4\xb6\x1a\x96\xc8";
    static const unsigned char ikm4[] =
        "\x87\xcf\x18\xd5\xf1\xb5\x3f\x81\x7c\xce\x5a\x00\x4c\xf3\x93\xcc"
        "\x89\x58\xbd\xdc\x06\x5f\x25\xf8\x4a\xf5\x09\xb1\x7d\xd3\x67\x64"
        "\x86\x93\x24\x83\x67\xf9\xe5\x01\x5d\xb9\x22\xf8\xf4\x80\x95\xdd"
        "\xa7\x84\x98\x7f\x2d\x59\x85\xb1\x2f\xba\xd1\x6c\xaf\x5e\x44\x35"
        "\x67\xe3\x0e\x69\xcd\xc7\xba\xb2\xa2\x68\x0d\x78\xac\xa4\x6a\x2f"
        "\x8b\x6e\x2a\xe4\x4d\x39\x8b\xdc\x6f\x92\xc5\xad\x4a\x49\x25\x14";
    static const unsigned char okm4[] =
        "\xf6\x6d\xad\xcf\xf6\x45\x92\x23\x9b\x25\x45\x39\xb6\x4f\xf6\x07";
    unsigned char ikm2[80];
    unsigned char salt2[80];
    unsigned char info2[80];
    static const unsigned char okm2[] =
        "\xb1\x1e\x39\x8d\xc8\x03\x27\xa1\xc8\xe7\xf7\x8c\x59\x6a\x49\x34"
        "\x4f\x01\x2e\xda\x2d\x4e\xfa\xd8\xa0\x50\xcc\x4c\x19\xaf\xa9\x7c"
        "\x59\x04\x5a\x99\xca\xc7\x82\x72\x71\xcb\x41\xc6\x5e\x59\x0e\x09"
        "\xda\x32\x75\x60\x0c\x2f\x09\xb8\x36\x77\x93\xa9\xac\xa3\xdb\x71"
        "\xcc\x30\xc5\x81\x79\xec\x3e\x87\xc1\x4c\x01\xd5\xc1\xf3\x43\x4f"
        "\x1d\x87";
    unsigned long param[2];
    unsigned char out[82];
    gcry_kdf_hd_t hd;
    int i;

    for (i = 0; i < 80; i++) {
        ikm2[i] = (unsigned char)i;
        salt2[i] = (unsigned char)(0x60 + i);
        info2[i] = (unsigned char)(0xb0 + i);
    }

    param[0] = 42;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 1,
                            ikm1, 22, NULL, 0, salt1, 13, info1, 10, 42,
                            out));
    ASSERT_MEM_EQ(okm1, out, 42);
    param[0] = 82;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 1,
                            ikm2, 80, NULL, 0, salt2, 80, info2, 80, 82,
                            out));
    ASSERT_MEM_EQ(okm2, out, 82);
    param[0] = 42;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 1,
                            ikm1, 22, NULL, 0, NULL, 0, NULL, 0, 42, out));
    ASSERT_MEM_EQ(okm3, out, 42);
    param[0] = 16;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 1,
                            ikm4, 96, NULL, 0, NULL, 0, "OpenPGP X25519", 14,
                            16, out));
    ASSERT_MEM_EQ(okm4, out, 16);

    /* A second parameter (mode) is accepted. */
    param[0] = 42;
    param[1] = 0;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param, 2,
                            ikm1, 22, NULL, 0, salt1, 13, info1, 10, 42,
                            out));
    ASSERT_MEM_EQ(okm1, out, 42);

    param[0] = 255 * 32 + 1;
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param,
                             1, ikm1, 22, NULL, 0, NULL, 0, NULL, 0));
    param[0] = 42;
    ASSERT_ERR(GPG_ERR_MAC_ALGO,
               gcry_kdf_open(&hd, GCRY_KDF_HKDF, GCRY_MAC_CMAC_AES, param, 1,
                             ikm1, 22, NULL, 0, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param,
                             1, NULL, 0, NULL, 0, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_HKDF, GCRY_MAC_HMAC_SHA256, param,
                             3, ikm1, 22, NULL, 0, NULL, 0, NULL, 0));
}

TEST(x963_vectors)
{
    /* ANSI X9.63 KDF with SHA-256: the first case is simply SHA-256(Z || 1)
     * truncated to 16 bytes, the second is a CAVP vector with shared info. */
    static const unsigned char z1[] =
        "\x96\xc0\x5b\xfe\xea\x4b\x7f\x4a\x3e\x9f\x11\x67\x66\x6b\x45\xb5"
        "\x7b\xa0\xa5\x1e\x8a\xd5\xc9\x8d";
    static const unsigned char dk1[] =
        "\xf2\x7c\x2a\xf2\x89\x15\xc4\x88\x37\x90\x8a\xa1\xe3\xb5\x14\xd9";
    static const unsigned char z2[] =
        "\x22\x51\x8b\x10\xe7\x0f\x2a\x3f\x24\x38\x10\xae\x32\x54\x13\x9e"
        "\xfb\xee\x04\xaa\x57\xc7\xaf\x7d";
    static const unsigned char info2[] =
        "\x75\xee\xf8\x1a\xa3\x04\x1e\x33\xb8\x09\x71\x20\x3d\x2c\x0c\x52";
    /* The concatenation of SHA-256(Z || counter || info) for counters 1..4,
     * each block verified by hand against the X9.63 definition. */
    static const unsigned char dk2[] =
        "\xc4\x98\xaf\x77\x16\x1c\xc5\x9f\x29\x62\xb9\xa7\x13\xe2\xb2\x15"
        "\x15\x2d\x13\x97\x66\xce\x34\xa7\x76\xdf\x11\x86\x6a\x69\xbf\x2e"
        "\x52\xa1\x3d\x9c\x7c\x6f\xc8\x78\xc5\x0c\x5e\xa0\xbc\x7b\x00\xe0"
        "\xda\x24\x47\xcf\xd8\x74\xf6\xcf\x92\xf3\x0d\x00\x97\x11\x14\x85"
        "\x50\x0c\x90\xc3\xaf\x8b\x48\x78\x72\xd0\x46\x85\xd1\x4c\x8d\x1d"
        "\xc8\xd7\xfa\x08\xbe\xb0\xce\x0a\xba\xbc\x11\xf0\xbd\x49\x62\x69"
        "\x14\x2d\x43\x52\x5a\x78\xe5\xbc\x79\xa1\x7f\x59\x67\x6a\x57\x06"
        "\xdc\x54\xd5\x4d\x4d\x1f\x0b\xd7\xe3\x86\x12\x8e\xc2\x6a\xfc\x21";
    unsigned long param[1];
    unsigned char out[128];
    gcry_kdf_hd_t hd;

    param[0] = 16;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_X963_KDF, GCRY_MD_SHA256, param, 1, z1,
                            24, NULL, 0, NULL, 0, NULL, 0, 16, out));
    ASSERT_MEM_EQ(dk1, out, 16);
    param[0] = 128;
    ASSERT_OK(kdf_derive_hd(GCRY_KDF_X963_KDF, GCRY_MD_SHA256, param, 1, z2,
                            24, NULL, 0, NULL, 0, info2, 16, 128, out));
    ASSERT_MEM_EQ(dk2, out, 128);

    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_kdf_open(&hd, GCRY_KDF_X963_KDF, 9999, param, 1, z1, 24,
                             NULL, 0, NULL, 0, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_VALUE,
               gcry_kdf_open(&hd, GCRY_KDF_X963_KDF, GCRY_MD_SHA256, param, 0,
                             z1, 24, NULL, 0, NULL, 0, NULL, 0));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(s2k_vectors);
    RUN_TEST(pbkdf2_vectors);
    RUN_TEST(scrypt_vectors);
    RUN_TEST(argon2_vectors);
    RUN_TEST(balloon_unsupported);
    RUN_TEST(onestep_kdf_vectors);
    RUN_TEST(hkdf_vectors);
    RUN_TEST(x963_vectors);
    return TEST_RESULT();
}
