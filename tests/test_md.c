#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

/* Decode a hex string into BUF; returns the number of bytes. */
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

/* Hash DATA with ALGO through a handle and compare with the hex digest. */
static int
check_digest(int algo, const void *data, size_t len, const char *hex)
{
    unsigned char expect[64];
    unsigned char got[64];
    size_t n = unhex(hex, expect, sizeof expect);
    gcry_md_hd_t hd;
    gcry_error_t err;
    unsigned int dlen = gcry_md_get_algo_dlen(algo);

    if (dlen != n) {
        fprintf(stderr, "algo %d (%s): dlen %u, vector %zu\n", algo,
                gcry_md_algo_name(algo), dlen, n);
        return 0;
    }

    err = gcry_md_open(&hd, algo, 0);

    if (err) {
        fprintf(stderr, "algo %d (%s): open failed: %s\n", algo,
                gcry_md_algo_name(algo), gcry_strerror(err));
        return 0;
    }

    gcry_md_write(hd, data, len);
    memcpy(got, gcry_md_read(hd, algo), n);
    gcry_md_close(hd);

    if (memcmp(got, expect, n)) {
        size_t i;

        fprintf(stderr, "algo %d (%s): mismatch\n  got ", algo,
                gcry_md_algo_name(algo));

        for (i = 0; i < n; i++) {
            fprintf(stderr, "%02x", got[i]);
        }

        fprintf(stderr, "\n");
        return 0;
    }

    /* The one-shot function must agree. */
    memset(got, 0, sizeof got);
    gcry_md_hash_buffer(algo, got, data, len);

    if (memcmp(got, expect, n)) {
        fprintf(stderr, "algo %d (%s): hash_buffer mismatch\n", algo,
                gcry_md_algo_name(algo));
        return 0;
    }

    return 1;
}

#define CHECK(algo, data, hex) \
    ASSERT_TRUE(check_digest(algo, data, strlen(data), hex))

/* One million 'a' bytes, fed in chunks. */
static int
check_million_a(int algo, const char *hex)
{
    unsigned char expect[64];
    size_t n = unhex(hex, expect, sizeof expect);
    unsigned char chunk[1000];
    gcry_md_hd_t hd;
    int i;

    memset(chunk, 'a', sizeof chunk);

    if (gcry_md_open(&hd, algo, 0)) {
        return 0;
    }

    for (i = 0; i < 1000; i++) {
        gcry_md_write(hd, chunk, sizeof chunk);
    }

    i = memcmp(gcry_md_read(hd, algo), expect, n) == 0;
    gcry_md_close(hd);
    return i;
}

static const char msg56[] =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

TEST(md5_sha1_sha2)
{
    CHECK(GCRY_MD_MD5, "", "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(GCRY_MD_MD5, "abc", "900150983cd24fb0d6963f7d28e17f72");
    CHECK(GCRY_MD_MD5, "message digest", "f96b697d7cb7938d525a2f31aaf161d0");
    CHECK(GCRY_MD_SHA1, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    CHECK(GCRY_MD_SHA1, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    CHECK(GCRY_MD_SHA224, "abc",
          "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    CHECK(GCRY_MD_SHA224, msg56,
          "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    CHECK(GCRY_MD_SHA256, "abc",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(GCRY_MD_SHA256, msg56,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(GCRY_MD_SHA384, "abc",
          "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
          "8086072ba1e7cc2358baeca134c825a7");
    CHECK(GCRY_MD_SHA512, "abc",
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    CHECK(GCRY_MD_SHA512_224, "abc",
          "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    CHECK(GCRY_MD_SHA512_256, "abc",
          "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
}

TEST(sha3_and_shake)
{
    gcry_md_hd_t hd;
    unsigned char a[64];
    unsigned char b[64];
    unsigned char expect[64];

    CHECK(GCRY_MD_SHA3_224, "abc",
          "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    CHECK(GCRY_MD_SHA3_256, "abc",
          "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    CHECK(GCRY_MD_SHA3_384, "abc",
          "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
          "98d88cea927ac7f539f1edf228376d25");
    CHECK(GCRY_MD_SHA3_512, "abc",
          "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
          "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    /* SHAKE128("abc"), first 32 bytes, via extract. */
    unhex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
          expect, sizeof expect);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHAKE128, 0));
    gcry_md_write(hd, "abc", 3);
    ASSERT_OK(gcry_md_extract(hd, GCRY_MD_SHAKE128, a, 16));
    ASSERT_OK(gcry_md_extract(hd, 0, a + 16, 16));
    ASSERT_MEM_EQ(expect, a, 32);
    gcry_md_close(hd);

    /* The same through one extract and through gcry_md_read (which yields
     * the first dlen bytes). */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHAKE128, 0));
    gcry_md_write(hd, "abc", 3);
    ASSERT_OK(gcry_md_extract(hd, GCRY_MD_SHAKE128, b, 32));
    ASSERT_MEM_EQ(expect, b, 32);
    gcry_md_close(hd);
    ASSERT_EQ(32, gcry_md_get_algo_dlen(GCRY_MD_SHAKE128));
    ASSERT_TRUE(check_digest(GCRY_MD_SHAKE128, "abc", 3,
                             "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f"
                             "97b83351940f2cc8"));
    ASSERT_TRUE(check_digest(GCRY_MD_SHAKE256, "abc", 3,
                             "483366601360a8771c6863080cc4114d8db44530f8f1e1ee"
                             "4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa"
                             "9f8726e462a12a4feb06bd8801e751e4"));

    /* Extract from a fixed-length hash is refused. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_extract(hd, GCRY_MD_SHA256, a, 8));
    gcry_md_close(hd);

    /* hash_buffers_ext with a longer XOF output. */
    {
        gcry_buffer_t iov;
        unsigned char out[48];
        char abc[] = "abc";

        iov.data = abc;
        iov.off = 0;
        iov.len = 3;
        iov.size = 0;
        ASSERT_OK(gcry_md_hash_buffers_ext(GCRY_MD_SHAKE128, 0, out, 48, &iov, 1));
        ASSERT_MEM_EQ(expect, out, 32);
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
                   gcry_md_hash_buffers_ext(GCRY_MD_SHA256, 0, out, 48, &iov, 1));
    }
}

TEST(cshake)
{
    gcry_md_hd_t hd;
    struct gcry_cshake_customization cust;
    unsigned char out[32];
    unsigned char expect[32];
    unsigned char data[4] = { 0, 1, 2, 3 };

    /* NIST SP 800-185 sample: cSHAKE128, N = "", S = "Email Signature". */
    unhex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
          expect, sizeof expect);
    cust.n = NULL;
    cust.n_len = 0;
    cust.s = "Email Signature";
    cust.s_len = 15;
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_CSHAKE128, 0));
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_write(hd, data, sizeof data);
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, 3));
    gcry_md_close(hd);

    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_close(hd);
}

TEST(legacy_and_other_hashes)
{
    CHECK(GCRY_MD_RMD160, "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    CHECK(GCRY_MD_MD4, "abc", "a448017aaf21d8525fc10ae87aa6729d");
    CHECK(GCRY_MD_WHIRLPOOL, "abc",
          "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
          "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
    CHECK(GCRY_MD_SM3, "abc",
          "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
}

TEST(blake2)
{
    CHECK(GCRY_MD_BLAKE2B_512, "abc",
          "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
          "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    CHECK(GCRY_MD_BLAKE2S_256, "abc",
          "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    CHECK(GCRY_MD_BLAKE2B_384, "abc",
          "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
          "c66ba83be64b302d7cba6ce15bb556f4");
    CHECK(GCRY_MD_BLAKE2B_256, "abc",
          "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    CHECK(GCRY_MD_BLAKE2B_160, "abc", "384264f676f39536840523f284921cdc68b6846b");
    CHECK(GCRY_MD_BLAKE2S_224, "abc",
          "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55");
    CHECK(GCRY_MD_BLAKE2S_160, "abc", "5ae3b99be29b01834c3b508521ede60438f8de17");
    CHECK(GCRY_MD_BLAKE2S_128, "abc", "aa4938119b1dc7b87cbad0ffd200d0ae");

    /* Keyed BLAKE2 through gcry_md_setkey (RFC 7693 style: BLAKE2b with a
     * 64 byte key over a 3 byte message, from the official test vectors).
     * Value cross-checked against OpenSSL's BLAKE2BMAC. */
    {
        gcry_md_hd_t hd;
        unsigned char key[64];
        unsigned char expect[64];
        size_t i;

        for (i = 0; i < 64; i++) {
            key[i] = (unsigned char)i;
        }

        unhex("33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5"
              "a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1",
              expect, sizeof expect);
        ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0));
        ASSERT_OK(gcry_md_setkey(hd, key, sizeof key));
        gcry_md_write(hd, "\x00\x01\x02", 3);
        ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 64);
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 65));
        gcry_md_close(hd);

        ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_setkey(hd, key, 16));
        gcry_md_close(hd);
    }
}

TEST(crc)
{
    CHECK(GCRY_MD_CRC32, "", "00000000");
    CHECK(GCRY_MD_CRC32, "foo", "8c736521");
    CHECK(GCRY_MD_CRC32, "123456789", "cbf43926");
    ASSERT_TRUE(check_million_a(GCRY_MD_CRC32, "dc25bfbc"));
    CHECK(GCRY_MD_CRC32_RFC1510, "", "00000000");
    CHECK(GCRY_MD_CRC32_RFC1510, "foo", "7332bc33");
    CHECK(GCRY_MD_CRC32_RFC1510, "test0123456789", "b83e88d6");
    CHECK(GCRY_MD_CRC32_RFC1510, "123456789", "2dfd2d88");
    ASSERT_TRUE(check_digest(GCRY_MD_CRC32_RFC1510, "\x80\x00", 2, "3b83984b"));
    ASSERT_TRUE(check_digest(GCRY_MD_CRC32_RFC1510, "\x80", 1, "edb88320"));
    ASSERT_TRUE(check_digest(GCRY_MD_CRC32_RFC1510, "\x00\x00\x00\x01", 4,
                             "77073096"));
    CHECK(GCRY_MD_CRC24_RFC2440, "", "b704ce");
    CHECK(GCRY_MD_CRC24_RFC2440, "foo", "4fc255");
    CHECK(GCRY_MD_CRC24_RFC2440, "123456789", "21cf02");
    ASSERT_TRUE(check_million_a(GCRY_MD_CRC24_RFC2440, "a5cb6b"));
    ASSERT_TRUE(check_million_a(GCRY_MD_CRC32_RFC1510, "ce5c7422"));

    /* Chunked and unaligned writes must agree with a single write, which
     * exercises the head, wide and tail loops of the table-driven CRCs. */
    {
        static const int algos[] = { GCRY_MD_CRC32, GCRY_MD_CRC32_RFC1510,
                                     GCRY_MD_CRC24_RFC2440
                                   };
        static const size_t chunks[] = { 1, 3, 7, 8, 13, 64, 1000 };
        unsigned char data[1000 + 8];
        size_t i;
        size_t j;

        for (i = 0; i < sizeof data; i++) {
            data[i] = (unsigned char)(i * 131 + 7);
        }

        for (i = 0; i < sizeof algos / sizeof algos[0]; i++) {
            unsigned char want[4];
            gcry_md_hd_t hd;
            unsigned int dlen = gcry_md_get_algo_dlen(algos[i]);

            gcry_md_hash_buffer(algos[i], want, data, 1000);

            for (j = 0; j < sizeof chunks / sizeof chunks[0]; j++) {
                size_t off;
                size_t start;

                /* Both an aligned and an unaligned start offset. */
                for (start = 0; start < 2; start++) {
                    gcry_md_hash_buffer(algos[i], want, data + start, 1000);
                    ASSERT_OK(gcry_md_open(&hd, algos[i], 0));

                    for (off = 0; off < 1000; off += chunks[j]) {
                        size_t n = chunks[j];

                        if (n > 1000 - off) {
                            n = 1000 - off;
                        }

                        gcry_md_write(hd, data + start + off, n);
                    }

                    ASSERT_MEM_EQ(want, gcry_md_read(hd, algos[i]), dlen);
                    gcry_md_close(hd);
                }
            }
        }
    }
    ASSERT_TRUE(check_million_a(GCRY_MD_SHA1,
                                "34aa973cd4c4daa4f61eeb2bdbad27316534016f"));
}

static int
check_hmac(int algo, void *key, size_t keylen, void *data, size_t datalen,
           const char *hex)
{
    unsigned char expect[64];
    unsigned char got[64];
    size_t n = unhex(hex, expect, sizeof expect);
    gcry_md_hd_t hd;
    gcry_buffer_t iov[2];

    if (gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC)) {
        return 0;
    }

    if (gcry_md_setkey(hd, key, keylen)) {
        gcry_md_close(hd);
        return 0;
    }

    gcry_md_write(hd, data, datalen);
    memcpy(got, gcry_md_read(hd, algo), n);
    gcry_md_close(hd);

    if (memcmp(got, expect, n)) {
        fprintf(stderr, "HMAC algo %d mismatch\n", algo);
        return 0;
    }

    iov[0].data = key;
    iov[0].off = 0;
    iov[0].len = keylen;
    iov[0].size = 0;
    iov[1].data = data;
    iov[1].off = 0;
    iov[1].len = datalen;
    iov[1].size = 0;
    memset(got, 0, sizeof got);

    if (gcry_md_hash_buffers(algo, GCRY_MD_FLAG_HMAC, got, iov, 2)) {
        return 0;
    }

    return memcmp(got, expect, n) == 0;
}

TEST(hmac)
{
    char key[] = "Jefe";
    char data[] = "what do ya want for nothing?";
    char bigmsg[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    unsigned char bigkey[131];
    gcry_md_hd_t hd;

    ASSERT_TRUE(check_hmac(GCRY_MD_SHA256, key, 4, data, 28,
                           "5bdcc146bf60754e6a042426089575c75a003f089d2739839d"
                           "ec58b964ec3843"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA224, key, 4, data, 28,
                           "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008f"
                           "d05e44"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA384, key, 4, data, 28,
                           "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e4"
                           "2ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA512, key, 4, data, 28,
                           "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610"
                           "270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaea"
                           "b1a34d4a6b4b636e070a38bce737"));
    ASSERT_TRUE(check_hmac(GCRY_MD_MD5, key, 4, data, 28,
                           "750c783e6ab0b503eaa86e310a5db738"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA1, key, 4, data, 28,
                           "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));

    /* RFC 4231 test case 6: key longer than the block size. */
    memset(bigkey, 0xaa, sizeof bigkey);
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA256, bigkey, sizeof bigkey, bigmsg, 54,
                           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546"
                           "040f0ee37f54"));

    /* HMAC handles refuse XOFs, CRCs and need a key for setkey-less use. */
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_open(&hd, GCRY_MD_SHAKE128,
                                                 GCRY_MD_FLAG_HMAC));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_open(&hd, GCRY_MD_CRC32,
                                                 GCRY_MD_FLAG_HMAC));
    ASSERT_OK(gcry_md_open(&hd, 0, GCRY_MD_FLAG_HMAC));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_setkey(hd, key, 4));
    gcry_md_close(hd);

    /* hash_buffers with HMAC flag needs at least the key buffer. */
    {
        unsigned char out[32];
        gcry_buffer_t iov;

        iov.data = key;
        iov.off = 0;
        iov.len = 4;
        iov.size = 0;
        ASSERT_ERR(GPG_ERR_INV_ARG,
                   gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, out, &iov, 0));
        ASSERT_ERR(GPG_ERR_INV_ARG,
                   gcry_md_hash_buffers(GCRY_MD_SHA256, 0x80, out, &iov, 1));
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
                   gcry_md_hash_buffers(GCRY_MD_TIGER, 0, out, &iov, 1));
    }
}

TEST(multi_algo_handle)
{
    gcry_md_hd_t hd;
    unsigned char sha1[20];
    unsigned char sha256[32];
    unsigned char md5[16];

    unhex("a9993e364706816aba3e25717850c26c9cd0d89d", sha1, sizeof sha1);
    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          sha256, sizeof sha256);
    unhex("900150983cd24fb0d6963f7d28e17f72", md5, sizeof md5);

    ASSERT_OK(gcry_md_open(&hd, 0, 0));
    ASSERT_EQ(0, gcry_md_get_algo(hd));
    ASSERT_OK(gcry_md_enable(hd, GCRY_MD_SHA1));
    ASSERT_OK(gcry_md_enable(hd, GCRY_MD_SHA256));
    ASSERT_OK(gcry_md_enable(hd, GCRY_MD_SHA256)); /* twice is fine */
    ASSERT_OK(gcry_md_enable(hd, GCRY_MD_MD5));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, GCRY_MD_TIGER));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, 12345));
    ASSERT_TRUE(gcry_md_is_enabled(hd, GCRY_MD_SHA1));
    ASSERT_TRUE(gcry_md_is_enabled(hd, GCRY_MD_MD5));
    ASSERT_FALSE(gcry_md_is_enabled(hd, GCRY_MD_SHA512));
    ASSERT_FALSE(gcry_md_is_secure(hd));

    gcry_md_write(hd, "a", 1);
    gcry_md_write(hd, "bc", 2);
    ASSERT_MEM_EQ(sha1, gcry_md_read(hd, GCRY_MD_SHA1), 20);
    ASSERT_MEM_EQ(sha256, gcry_md_read(hd, GCRY_MD_SHA256), 32);
    ASSERT_MEM_EQ(md5, gcry_md_read(hd, GCRY_MD_MD5), 16);
    /* Reading again returns the same digest. */
    ASSERT_MEM_EQ(sha1, gcry_md_read(hd, GCRY_MD_SHA1), 20);
    /* The most recently enabled algorithm is the "first" one. */
    ASSERT_EQ(GCRY_MD_MD5, gcry_md_get_algo(hd));
    ASSERT_MEM_EQ(md5, gcry_md_read(hd, 0), 16);

    /* Reset and hash something else. */
    gcry_md_reset(hd);
    gcry_md_write(hd, "", 0);
    unhex("da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1, sizeof sha1);
    ASSERT_MEM_EQ(sha1, gcry_md_read(hd, GCRY_MD_SHA1), 20);
    gcry_md_close(hd);
    gcry_md_close(NULL);
}

TEST(putc_buffering_and_copy)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t copy;
    unsigned char expect[32];
    unsigned char data[3000];
    size_t i;

    for (i = 0; i < sizeof data; i++) {
        data[i] = (unsigned char)(i * 7 + 3);
    }

    gcry_md_hash_buffer(GCRY_MD_SHA256, expect, data, sizeof data);

    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    ASSERT_TRUE(hd->bufsize >= 512);

    /* Byte at a time crosses the internal buffer boundary repeatedly. */
    for (i = 0; i < sizeof data; i++) {
        gcry_md_putc(hd, data[i]);
    }

    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);

    /* Mixed putc and write, with a copy taken mid-way. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));

    for (i = 0; i < 1500; i++) {
        gcry_md_putc(hd, data[i]);
    }

    ASSERT_OK(gcry_md_copy(&copy, hd));
    gcry_md_write(hd, data + 1500, sizeof data - 1500);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);

    gcry_md_write(copy, data + 1500, sizeof data - 1500);
    ASSERT_MEM_EQ(expect, gcry_md_read(copy, 0), 32);
    gcry_md_close(copy);

    /* Copying a finalised handle keeps the digest. */
    ASSERT_OK(gcry_md_copy(&copy, hd));
    ASSERT_MEM_EQ(expect, gcry_md_read(copy, GCRY_MD_SHA256), 32);
    gcry_md_close(copy);
    gcry_md_close(hd);

    /* Copy of an HMAC handle keeps the key. */
    {
        unsigned char ref[32];
        gcry_buffer_t iov[2];
        char jefe[] = "Jefe";

        iov[0].data = jefe;
        iov[0].off = 0;
        iov[0].len = 4;
        iov[0].size = 0;
        iov[1].data = data;
        iov[1].off = 0;
        iov[1].len = 100;
        iov[1].size = 0;
        ASSERT_OK(gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, ref, iov, 2));
        ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
        ASSERT_OK(gcry_md_setkey(hd, "Jefe", 4));
        gcry_md_write(hd, data, 50);
        ASSERT_OK(gcry_md_copy(&copy, hd));
        gcry_md_write(copy, data + 50, 50);
        ASSERT_MEM_EQ(ref, gcry_md_read(copy, 0), 32);
        gcry_md_reset(copy);
        gcry_md_write(copy, data, 100);
        ASSERT_MEM_EQ(ref, gcry_md_read(copy, 0), 32);
        gcry_md_close(copy);
        gcry_md_close(hd);
    }
}

TEST(secure_handle)
{
    gcry_md_hd_t hd;
    unsigned char expect[20];

    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    unhex("a9993e364706816aba3e25717850c26c9cd0d89d", expect, sizeof expect);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_SECURE));
    ASSERT_TRUE(gcry_md_is_secure(hd));
    ASSERT_TRUE(gcry_is_secure(hd));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 20);
    gcry_md_close(hd);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_open(&hd, GCRY_MD_SHA1, 0x40));
}

TEST(algorithm_info)
{
    unsigned char oid[32];
    size_t n = sizeof oid;
    unsigned char expect[19];

    ASSERT_OK(gcry_md_test_algo(GCRY_MD_SHA256));
    ASSERT_OK(gcry_md_test_algo(GCRY_MD_CRC32));
    ASSERT_OK(gcry_md_test_algo(GCRY_MD_BLAKE2S_128));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(GCRY_MD_TIGER));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(GCRY_MD_HAVAL));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(GCRY_MD_STRIBOG512));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(GCRY_MD_GOSTR3411_94));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(0));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_algo_info(GCRY_MD_SHA1, GCRYCTL_TEST_ALGO,
                                                  oid, NULL));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_md_algo_info(GCRY_MD_SHA1, 9999, NULL, NULL));

    unhex("3031300d060960864801650304020105000420", expect, sizeof expect);
    ASSERT_OK(gcry_md_get_asnoid(GCRY_MD_SHA256, oid, &n));
    ASSERT_EQ(19, n);
    ASSERT_MEM_EQ(expect, oid, 19);
    n = 0;
    ASSERT_OK(gcry_md_get_asnoid(GCRY_MD_SHA256, NULL, &n));
    ASSERT_EQ(19, n);
    n = 5;
    ASSERT_ERR(GPG_ERR_TOO_SHORT, gcry_md_get_asnoid(GCRY_MD_SHA256, oid, &n));
    n = sizeof oid;
    ASSERT_OK(gcry_md_get_asnoid(GCRY_MD_SHA1, oid, &n));
    ASSERT_EQ(15, n);
    ASSERT_OK(gcry_md_get_asnoid(GCRY_MD_WHIRLPOOL, NULL, &n));
    ASSERT_EQ(0, n);

    ASSERT_STR_EQ("SHA256", gcry_md_algo_name(GCRY_MD_SHA256));
    ASSERT_STR_EQ("RIPEMD160", gcry_md_algo_name(GCRY_MD_RMD160));
    ASSERT_STR_EQ("TIGER", gcry_md_algo_name(GCRY_MD_TIGER1));
    ASSERT_STR_EQ("CRC24RFC2440", gcry_md_algo_name(GCRY_MD_CRC24_RFC2440));
    ASSERT_STR_EQ("?", gcry_md_algo_name(4711));
    ASSERT_EQ(GCRY_MD_SHA256, gcry_md_map_name("SHA256"));
    ASSERT_EQ(GCRY_MD_SHA256, gcry_md_map_name("sha256"));
    ASSERT_EQ(GCRY_MD_SHA256, gcry_md_map_name("2.16.840.1.101.3.4.2.1"));
    ASSERT_EQ(GCRY_MD_SHA256, gcry_md_map_name("oid.1.2.840.113549.1.1.11"));
    ASSERT_EQ(GCRY_MD_SHA1, gcry_md_map_name("1.3.14.3.2.26"));
    ASSERT_EQ(GCRY_MD_RMD160, gcry_md_map_name("RIPEMD160"));
    ASSERT_EQ(GCRY_MD_SHA3_256, gcry_md_map_name("SHA3-256"));
    ASSERT_EQ(GCRY_MD_SHA512_256, gcry_md_map_name("SHA512_256"));
    ASSERT_EQ(GCRY_MD_BLAKE2B_512, gcry_md_map_name("BLAKE2B_512"));
    ASSERT_EQ(GCRY_MD_BLAKE2S_128, gcry_md_map_name("1.3.6.1.4.1.1722.12.2.2.4"));
    ASSERT_EQ(GCRY_MD_SM3, gcry_md_map_name("SM3"));
    ASSERT_EQ(GCRY_MD_TIGER1, gcry_md_map_name("TIGER"));
    ASSERT_EQ(0, gcry_md_map_name("nope"));
    ASSERT_EQ(0, gcry_md_map_name(NULL));
    ASSERT_EQ(64, gcry_md_get_algo_dlen(GCRY_MD_SHA512));
    ASSERT_EQ(3, gcry_md_get_algo_dlen(GCRY_MD_CRC24_RFC2440));
    ASSERT_EQ(24, gcry_md_get_algo_dlen(GCRY_MD_TIGER));
    ASSERT_EQ(0, gcry_md_get_algo_dlen(4711));
}

int
main(void)
{
    gcry_check_version(NULL);
    RUN_TEST(md5_sha1_sha2);
    RUN_TEST(sha3_and_shake);
    RUN_TEST(cshake);
    RUN_TEST(legacy_and_other_hashes);
    RUN_TEST(blake2);
    RUN_TEST(crc);
    RUN_TEST(hmac);
    RUN_TEST(multi_algo_handle);
    RUN_TEST(putc_buffering_and_copy);
    RUN_TEST(secure_handle);
    RUN_TEST(algorithm_info);
    return TEST_RESULT();
}
