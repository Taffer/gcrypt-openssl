#define _POSIX_C_SOURCE 200809L

#include <gcrypt.h>

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

/* The upstream header marks gcry_set_log_handler and gcry_md_info
 * deprecated; the former is still the only way to observe the logger. */
#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* --- log capture ------------------------------------------------------ */

static char logbuf[4096];
static size_t loglen;
static int logcalls;
static int loglevel;

static void
capture_log(void *opaque, int level, const char *fmt, va_list ap)
{
    int n;

    (void)opaque;
    logcalls++;
    loglevel = level;

    if (loglen < sizeof logbuf - 1) {
        n = vsnprintf(logbuf + loglen, sizeof logbuf - loglen, fmt, ap);

        if (n > 0) {
            loglen += (size_t)n;

            if (loglen > sizeof logbuf - 1) {
                loglen = sizeof logbuf - 1;
            }
        }
    }
}

static void
log_reset(void)
{
    loglen = 0;
    logbuf[0] = 0;
    logcalls = 0;
    loglevel = -1;
}

/* Run FN in a child and report how it ended: its exit code, or 1000 plus
 * the signal number.  The fatal paths abort, so they cannot run in the
 * test process itself. */
static int
run_child(void (*fn)(void))
{
    pid_t pid;
    int status = 0;

    fflush(NULL); /* The child's exit() must not replay our buffers. */
    pid = fork();

    if (pid == 0) {
        if (!freopen("/dev/null", "w", stderr)) {
            test_child_exit(99);
        }

        fn();
        test_child_exit(0);
    }

    if (pid < 0) {
        return -1;
    }

    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        return 1000 + WTERMSIG(status);
    }

    return -1;
}

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

/* In FIPS mode OpenSSL's provider offers only the approved digests.  Every
 * entry point must then report ALGO as an unknown algorithm, never as an
 * internal error, and the one-shot function must zero the digest. */
static int
check_unavailable(int algo)
{
    const char *name = gcry_md_algo_name(algo);
    gcry_md_hd_t hd = NULL;
    gcry_error_t err;
    unsigned char buf[65];
    unsigned char zero[64];
    gcry_buffer_t iov;
    char abc[] = "abc";
    size_t n = sizeof buf;
    unsigned int dlen = gcry_md_get_algo_dlen(algo);

#define EXPECT_DIGEST_ALGO(expr)                                           \
    do {                                                                   \
        if (gcry_err_code(expr) != GPG_ERR_DIGEST_ALGO) {                  \
            fprintf(stderr, "%s: %s did not report an unknown algorithm\n", \
                    name, #expr);                                          \
            return 0;                                                      \
        }                                                                  \
    } while (0)

    EXPECT_DIGEST_ALGO(gcry_md_test_algo(algo));
    EXPECT_DIGEST_ALGO(gcry_md_algo_info(algo, GCRYCTL_SELFTEST, NULL, NULL));
    EXPECT_DIGEST_ALGO(gcry_md_get_asnoid(algo, NULL, &n));
    EXPECT_DIGEST_ALGO(gcry_md_open(&hd, algo, 0));

    if (hd) {
        fprintf(stderr, "%s: open handed out a handle\n", name);
        return 0;
    }

    EXPECT_DIGEST_ALGO(gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC));

    if (hd) {
        fprintf(stderr, "%s: HMAC open handed out a handle\n", name);
        return 0;
    }

    if (gcry_md_open(&hd, 0, 0)) {
        return 0;
    }

    err = gcry_md_enable(hd, algo);
    gcry_md_close(hd);
    EXPECT_DIGEST_ALGO(err);

    memset(buf, 0xaa, sizeof buf);
    memset(zero, 0, sizeof zero);
    gcry_md_hash_buffer(algo, buf, abc, 3);

    if (dlen == 0 || dlen > sizeof zero || memcmp(buf, zero, dlen)
        || buf[dlen] != 0xaa) {
        fprintf(stderr, "%s: hash_buffer did not zero the digest\n", name);
        return 0;
    }

    iov.data = abc;
    iov.off = 0;
    iov.len = 3;
    iov.size = 0;
    EXPECT_DIGEST_ALGO(gcry_md_hash_buffers(algo, 0, buf, &iov, 1));
    EXPECT_DIGEST_ALGO(gcry_md_hash_buffers(algo, GCRY_MD_FLAG_HMAC, buf, &iov,
                                            1));
#undef EXPECT_DIGEST_ALGO
    return 1;
}

/* Whether a digest the library's tables list is not offered: always in
 * FIPS mode (every use of this asks about a non-approved digest), and
 * under a strict provider whenever the provider lacks it. */
static int
md_unavailable(int algo)
{
    return gcry_fips_mode_active()
           || (TEST_STRICT_PROVIDER && gcry_md_test_algo(algo) != 0);
}

/* CHECK, except that an algorithm that is not offered must be reported as
 * unknown everywhere instead. */
#define CHECK_OR_UNAVAILABLE(algo, data, hex)     \
    do {                                          \
        if (md_unavailable(algo)) {               \
            ASSERT_TRUE(check_unavailable(algo)); \
        } else {                                  \
            CHECK(algo, data, hex);               \
        }                                         \
    } while (0)

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
    CHECK_OR_UNAVAILABLE(GCRY_MD_MD5, "", "d41d8cd98f00b204e9800998ecf8427e");
    CHECK_OR_UNAVAILABLE(GCRY_MD_MD5, "abc", "900150983cd24fb0d6963f7d28e17f72");
    CHECK_OR_UNAVAILABLE(GCRY_MD_MD5, "message digest",
                         "f96b697d7cb7938d525a2f31aaf161d0");
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
#ifdef GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT

    /* Chainguard's strict FIPS provider has no SHA-512/224 even though
     * FIPS approves it; the algorithm is then reported as unavailable. */
    if (gcry_md_test_algo(GCRY_MD_SHA512_224)) {
        gcry_md_hd_t hd = NULL;

        ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(GCRY_MD_SHA512_224));
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
                   gcry_md_open(&hd, GCRY_MD_SHA512_224, 0));
        ASSERT_NULL(hd);
    } else {
        CHECK(GCRY_MD_SHA512_224, "abc",
              "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    }

#else
    CHECK(GCRY_MD_SHA512_224, "abc",
          "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
#endif
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

    /* A function name N is reserved for NIST-defined functions and OpenSSL
     * refuses other values; the reference library computes it.  The call
     * fails cleanly and the handle keeps working. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_CSHAKE128, 0));
    cust.n = "fn";
    cust.n_len = 2;
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    cust.n = NULL;
    cust.n_len = 0;
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_write(hd, data, sizeof data);
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    gcry_md_close(hd);

    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    /* A plain handle has nothing to key, whatever the arguments. */
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_setkey(hd, NULL, 16));
    gcry_md_close(hd);
}

TEST(legacy_and_other_hashes)
{
    /* None of these is a FIPS-approved digest: in FIPS mode they are
     * reported as unavailable and no handle can be opened for them. */
    CHECK_OR_UNAVAILABLE(GCRY_MD_RMD160, "abc",
                         "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    CHECK_OR_UNAVAILABLE(GCRY_MD_MD4, "abc", "a448017aaf21d8525fc10ae87aa6729d");
    CHECK_OR_UNAVAILABLE(GCRY_MD_WHIRLPOOL, "abc",
                         "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c"
                         "7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
    CHECK_OR_UNAVAILABLE(GCRY_MD_SM3, "abc",
                         "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
}

TEST(blake2)
{
    /* BLAKE2 is not FIPS-approved: unavailable in FIPS mode. */
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2B_512, "abc",
                         "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                         "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2S_256, "abc",
                         "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2B_384, "abc",
                         "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6"
                         "c66ba83be64b302d7cba6ce15bb556f4");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2B_256, "abc",
                         "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2B_160, "abc",
                         "384264f676f39536840523f284921cdc68b6846b");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2S_224, "abc",
                         "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2S_160, "abc",
                         "5ae3b99be29b01834c3b508521ede60438f8de17");
    CHECK_OR_UNAVAILABLE(GCRY_MD_BLAKE2S_128, "abc",
                         "aa4938119b1dc7b87cbad0ffd200d0ae");

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

        if (!gcry_fips_mode_active()) {
            ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0));
            ASSERT_OK(gcry_md_setkey(hd, key, sizeof key));
            gcry_md_write(hd, "\x00\x01\x02", 3);
            ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 64);
            ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 65));
            gcry_md_close(hd);
        }

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
    gcry_error_t err;
    gcry_buffer_t iov[2];
    /* The FIPS provider insists on HMAC keys of at least 112 bits. */
    int short_key = gcry_fips_mode_active() && keylen < 14;

    iov[0].data = key;
    iov[0].off = 0;
    iov[0].len = keylen;
    iov[0].size = 0;
    iov[1].data = data;
    iov[1].off = 0;
    iov[1].len = datalen;
    iov[1].size = 0;

    if (gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC)) {
        fprintf(stderr, "HMAC algo %d: open failed\n", algo);
        return 0;
    }

    err = gcry_md_setkey(hd, key, keylen);

    if (short_key) {
        gcry_md_close(hd);

        if (gcry_err_code(err) != GPG_ERR_INV_KEYLEN) {
            fprintf(stderr, "HMAC algo %d: short key: %s\n", algo,
                    gcry_strerror(err));
            return 0;
        }

        err = gcry_md_hash_buffers(algo, GCRY_MD_FLAG_HMAC, got, iov, 2);

        if (gcry_err_code(err) != GPG_ERR_INV_KEYLEN) {
            fprintf(stderr, "HMAC algo %d: short key (hash_buffers): %s\n",
                    algo, gcry_strerror(err));
            return 0;
        }

        return 1;
    }

    if (err) {
        fprintf(stderr, "HMAC algo %d: setkey: %s\n", algo, gcry_strerror(err));
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

    memset(got, 0, sizeof got);
    err = gcry_md_hash_buffers(algo, GCRY_MD_FLAG_HMAC, got, iov, 2);

    if (err) {
        fprintf(stderr, "HMAC algo %d: hash_buffers: %s\n", algo,
                gcry_strerror(err));
        return 0;
    }

    return memcmp(got, expect, n) == 0;
}

TEST(hmac)
{
    char key[] = "Jefe";
    char data[] = "what do ya want for nothing?";
    char bigmsg[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    char hi[] = "Hi There";
    unsigned char bigkey[131];
    unsigned char key0b[20];
    gcry_md_hd_t hd;

    /* RFC 4231 test case 1 and RFC 2202 test case 1: a 20 (16 for MD5)
     * byte key, long enough for FIPS mode. */
    memset(key0b, 0x0b, sizeof key0b);
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA224, key0b, 20, hi, 8,
                           "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53"
                           "684b22"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA256, key0b, 20, hi, 8,
                           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726"
                           "e9376c2e32cff7"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA384, key0b, 20, hi, 8,
                           "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682"
                           "aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA512, key0b, 20, hi, 8,
                           "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787a"
                           "d0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d"
                           "914eeb61f1702e696c203a126854"));
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA1, key0b, 20, hi, 8,
                           "b617318655057264e28bc0b6fb378c8ef146be00"));

    /* RFC 4231 test case 2: the 4 byte key "Jefe" is below the 112 bits
     * the FIPS provider requires, so in FIPS mode these must be refused
     * with an invalid key length (check_hmac verifies that). */
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
    ASSERT_TRUE(check_hmac(GCRY_MD_SHA1, key, 4, data, 28,
                           "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"));

    /* HMAC over a digest the FIPS provider lacks is an unknown algorithm
     * however long the key is. */
    if (gcry_fips_mode_active()) {
        unsigned char out[16];
        gcry_buffer_t iov[2];

        iov[0].data = key0b;
        iov[0].off = 0;
        iov[0].len = 16;
        iov[0].size = 0;
        iov[1].data = hi;
        iov[1].off = 0;
        iov[1].len = 8;
        iov[1].size = 0;
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_open(&hd, GCRY_MD_MD5,
                                                     GCRY_MD_FLAG_HMAC));
        ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
                   gcry_md_hash_buffers(GCRY_MD_MD5, GCRY_MD_FLAG_HMAC, out,
                                        iov, 2));
    } else {
        ASSERT_TRUE(check_hmac(GCRY_MD_MD5, key, 4, data, 28,
                               "750c783e6ab0b503eaa86e310a5db738"));
        ASSERT_TRUE(check_hmac(GCRY_MD_MD5, key0b, 16, hi, 8,
                               "9294727a3638bb1c13f48ef8158bfc9d"));
    }

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
    /* MD5 is not offered in FIPS mode; the handle keeps its other
     * algorithms when enabling it fails. */
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, GCRY_MD_MD5));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, GCRY_MD_TIGER));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, 12345));
    ASSERT_TRUE(gcry_md_is_enabled(hd, GCRY_MD_SHA1));
    ASSERT_EQ(!gcry_fips_mode_active(), gcry_md_is_enabled(hd, GCRY_MD_MD5));
    ASSERT_FALSE(gcry_md_is_enabled(hd, GCRY_MD_SHA512));
    ASSERT_FALSE(gcry_md_is_secure(hd));

    gcry_md_write(hd, "a", 1);
    gcry_md_write(hd, "bc", 2);
    ASSERT_MEM_EQ(sha1, gcry_md_read(hd, GCRY_MD_SHA1), 20);
    ASSERT_MEM_EQ(sha256, gcry_md_read(hd, GCRY_MD_SHA256), 32);

    if (gcry_fips_mode_active()) {
        /* Reading again returns the same digest. */
        ASSERT_MEM_EQ(sha1, gcry_md_read(hd, GCRY_MD_SHA1), 20);
        /* The most recently enabled algorithm is the "first" one. */
        ASSERT_EQ(GCRY_MD_SHA256, gcry_md_get_algo(hd));
        ASSERT_MEM_EQ(sha256, gcry_md_read(hd, 0), 32);
    } else {
        ASSERT_MEM_EQ(md5, gcry_md_read(hd, GCRY_MD_MD5), 16);
        /* Reading again returns the same digest. */
        ASSERT_MEM_EQ(sha1, gcry_md_read(hd, GCRY_MD_SHA1), 20);
        /* The most recently enabled algorithm is the "first" one. */
        ASSERT_EQ(GCRY_MD_MD5, gcry_md_get_algo(hd));
        ASSERT_MEM_EQ(md5, gcry_md_read(hd, 0), 16);
    }

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

    /* Copy of an HMAC handle keeps the key (16 bytes: long enough for
     * FIPS mode). */
    {
        unsigned char ref[32];
        gcry_buffer_t iov[2];
        char hmackey[] = "0123456789abcdef";

        iov[0].data = hmackey;
        iov[0].off = 0;
        iov[0].len = 16;
        iov[0].size = 0;
        iov[1].data = data;
        iov[1].off = 0;
        iov[1].len = 100;
        iov[1].size = 0;
        ASSERT_OK(gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, ref, iov, 2));
        ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
        ASSERT_OK(gcry_md_setkey(hd, hmackey, 16));
        gcry_md_write(hd, data, 50);
        ASSERT_OK(gcry_md_copy(&copy, hd));
        gcry_md_write(copy, data + 50, 50);
        ASSERT_MEM_EQ(ref, gcry_md_read(copy, 0), 32);
        gcry_md_reset(copy);
        gcry_md_write(copy, data, 100);
        ASSERT_MEM_EQ(ref, gcry_md_read(copy, 0), 32);
        gcry_md_close(copy);
        gcry_md_close(hd);

        /* A copy taken before the key is set is keyed on its own. */
        ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
        ASSERT_OK(gcry_md_copy(&copy, hd));
        ASSERT_OK(gcry_md_setkey(copy, hmackey, 16));
        gcry_md_write(copy, data, 100);
        ASSERT_MEM_EQ(ref, gcry_md_read(copy, 0), 32);
        gcry_md_close(copy);
        ASSERT_OK(gcry_md_setkey(hd, hmackey, 16));
        gcry_md_write(hd, data, 100);
        ASSERT_MEM_EQ(ref, gcry_md_read(hd, 0), 32);
        /* Copying a finalised HMAC handle keeps its MAC too. */
        ASSERT_OK(gcry_md_copy(&copy, hd));
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
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_DIGEST_ALGO,
                          gcry_md_test_algo(GCRY_MD_BLAKE2S_128));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_test_algo(GCRY_MD_TIGER));
    /* An unavailable algorithm must not abort gcry_md_hash_buffer(); the
     * digest is zeroed instead. */
    memset(oid, 0xaa, sizeof oid);
    gcry_md_hash_buffer(GCRY_MD_TIGER, oid, "abc", 3);
    memset(expect, 0, sizeof expect);
    ASSERT_MEM_EQ(expect, oid, 19);
    ASSERT_EQ(0xaa, oid[24]);
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
    /* Whirlpool has no DigestInfo prefix; where the algorithm itself is
     * unavailable (FIPS mode, a strict provider) that is reported first. */
    ASSERT_OK_UNLESS(md_unavailable(GCRY_MD_WHIRLPOOL), GPG_ERR_DIGEST_ALGO,
                     gcry_md_get_asnoid(GCRY_MD_WHIRLPOOL, NULL, &n));

    if (!md_unavailable(GCRY_MD_WHIRLPOOL)) {
        ASSERT_EQ(0, n);
    }

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

TEST(handle_api_edges)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t copy;
    unsigned char out[32];
    unsigned char expect[32];

    /* Plain handles reject keys and controls meant for other kinds. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_setkey(hd, "0123456789abcdef", 16));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_md_ctl(hd, 9999, NULL, 0));
    ASSERT_TRUE(gcry_md_is_enabled(hd, GCRY_MD_SHA256));
    ASSERT_FALSE(gcry_md_is_enabled(hd, GCRY_MD_SHA1));
    ASSERT_FALSE(gcry_md_is_secure(hd));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_extract(hd, 0, out, 32));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_extract(hd, GCRY_MD_SHA256, out, 32));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, 9999));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, GCRY_MD_TIGER));
    /* Explicit finalisation through the control interface. */
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_FINALIZE, NULL, 0));
    unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          expect, sizeof expect);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);

    /* NULL handles are rejected or ignored, never dereferenced. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_enable(NULL, GCRY_MD_SHA1));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_setkey(NULL, "k", 1));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_ctl(NULL, GCRYCTL_FINALIZE, NULL, 0));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_extract(NULL, 0, out, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_open(NULL, GCRY_MD_SHA1, 0));
    copy = hd;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_copy(&copy, NULL));
    ASSERT_NULL(copy);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_copy(NULL, NULL));
    ASSERT_EQ(0, gcry_md_get_algo(NULL));
    ASSERT_FALSE(gcry_md_is_enabled(NULL, GCRY_MD_SHA1));
    ASSERT_TRUE(gcry_md_is_secure(NULL)); /* "secure" when in doubt */
    gcry_md_write(NULL, "x", 1);
    gcry_md_reset(NULL);
    gcry_md_close(NULL);
    gcry_md_debug(NULL, "x");

    /* Algorithm information edge cases. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_algo_info(GCRY_MD_SHA256,
                                                  GCRYCTL_GET_ASNOID, NULL, NULL));
    ASSERT_OK(gcry_md_algo_info(GCRY_MD_SHA256, GCRYCTL_SELFTEST, NULL, NULL));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_algo_info(4711, GCRYCTL_SELFTEST, NULL, NULL));
}

TEST(keyed_blake2_limits)
{
    gcry_md_hd_t hd;
    unsigned char key[65];
    unsigned char expect[32];

    memset(key, 7, sizeof key);

    if (gcry_fips_mode_active()) {
        /* No BLAKE2 at all in FIPS mode, keyed or not. */
        ASSERT_TRUE(check_unavailable(GCRY_MD_BLAKE2B_512));
        ASSERT_TRUE(check_unavailable(GCRY_MD_BLAKE2S_256));
        return;
    }

    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 65));
    ASSERT_OK(gcry_md_setkey(hd, key, 64));
    gcry_md_close(hd);

    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0));
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 33));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_setkey(hd, NULL, 5));
    ASSERT_OK(gcry_md_setkey(hd, key, 32));
    gcry_md_write(hd, "abc", 3);
    /* Reference value from the stock library. */
    unhex("a7bcf1900a3f3b084ad27e6aa74771ed66ac3e94d7489967d692118532d2fc2a",
          expect, sizeof expect);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);
}

TEST(hmac_reset_and_rekey)
{
    gcry_md_hd_t hd;
    unsigned char expect[32];
    unsigned char first[32];
    unsigned char key0b[20];
    unsigned char keyaa[20];
    unsigned char dd50[50];

    memset(key0b, 0x0b, sizeof key0b);
    memset(keyaa, 0xaa, sizeof keyaa);
    memset(dd50, 0xdd, sizeof dd50);

    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));

    if (gcry_fips_mode_active()) {
        /* Keys shorter than 112 bits are refused by the FIPS provider;
         * the handle stays usable. */
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, "key", 3));
    } else {
        ASSERT_OK(gcry_md_setkey(hd, "key", 3));
        gcry_md_write(hd, "abc", 3);
        unhex("9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab",
              expect, sizeof expect);
        memcpy(first, gcry_md_read(hd, 0), 32);
        ASSERT_MEM_EQ(expect, first, 32);
        /* A reset keeps the key. */
        gcry_md_reset(hd);
        gcry_md_write(hd, "abc", 3);
        ASSERT_MEM_EQ(first, gcry_md_read(hd, 0), 32);
        /* A second setkey replaces it. */
        ASSERT_OK(gcry_md_setkey(hd, "key2", 4));
        gcry_md_write(hd, "abc", 3);
        unhex("69ba1f142a63bb0e8f3f74bf55018364bf680b75d35e290918a34d6576861736",
              expect, sizeof expect);
        ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    }

    /* The same with FIPS-sized keys: RFC 4231 test case 1 ... */
    ASSERT_OK(gcry_md_setkey(hd, key0b, sizeof key0b));
    gcry_md_write(hd, "Hi There", 8);
    unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          expect, sizeof expect);
    memcpy(first, gcry_md_read(hd, 0), 32);
    ASSERT_MEM_EQ(expect, first, 32);
    /* A reset keeps the key. */
    gcry_md_reset(hd);
    gcry_md_write(hd, "Hi There", 8);
    ASSERT_MEM_EQ(first, gcry_md_read(hd, 0), 32);
    /* ... and test case 3 after a second setkey. */
    ASSERT_OK(gcry_md_setkey(hd, keyaa, sizeof keyaa));
    gcry_md_write(hd, dd50, sizeof dd50);
    unhex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
          expect, sizeof expect);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);

    if (gcry_fips_mode_active()) {
        /* A refused key leaves the previous one in place. */
        ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, "key", 3));
        gcry_md_write(hd, dd50, sizeof dd50);
        ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    }

    gcry_md_close(hd);
}

TEST(hmac_unkeyed_and_key_lengths)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t copy;
    unsigned char key[20];
    unsigned char expect[32];
    unsigned char tc1[32];
    gcry_buffer_t iov[2];
    char hi[] = "Hi There";

    memset(key, 0x0b, sizeof key);
    unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          tc1, sizeof tc1);

    /* Setting the key resets the handle: data written before it does not
     * count, in either mode. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
    gcry_md_write(hd, "garbage", 7);
    ASSERT_OK(gcry_md_setkey(hd, key, sizeof key));
    gcry_md_write(hd, hi, 8);
    ASSERT_MEM_EQ(tc1, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);

    /* A copy taken before the key is set can be keyed independently. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
    gcry_md_write(hd, "garbage", 7);
    ASSERT_OK(gcry_md_copy(&copy, hd));
    ASSERT_OK(gcry_md_setkey(copy, key, sizeof key));
    gcry_md_write(copy, hi, 8);
    ASSERT_MEM_EQ(tc1, gcry_md_read(copy, 0), 32);
    gcry_md_close(copy);
    ASSERT_OK(gcry_md_setkey(hd, key, sizeof key));
    gcry_md_write(hd, hi, 8);
    ASSERT_MEM_EQ(tc1, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);

    /* Without setkey the reference library computes with an empty key.
     * The FIPS provider refuses an empty key, so there such a handle has
     * nothing to return and hands out zeros. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
    gcry_md_write(hd, "abc", 3);

    if (gcry_fips_mode_active()) {
        memset(expect, 0, sizeof expect);
    } else {
        unhex("fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351",
              expect, sizeof expect);
    }

    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    /* Keying afterwards makes it a proper HMAC handle. */
    ASSERT_OK(gcry_md_setkey(hd, key, sizeof key));
    gcry_md_write(hd, hi, 8);
    ASSERT_MEM_EQ(tc1, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);

    /* The FIPS boundary is 112 bits: 13 byte keys are refused, 14 byte
     * keys accepted.  Outside FIPS mode any length goes. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 13));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 0));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, NULL, 0));
    ASSERT_OK(gcry_md_setkey(hd, key, 14));
    gcry_md_close(hd);

    /* gcry_md_hash_buffers takes the key from the first entry and must
     * agree. */
    iov[0].data = key;
    iov[0].off = 0;
    iov[0].len = 13;
    iov[0].size = 0;
    iov[1].data = hi;
    iov[1].off = 0;
    iov[1].len = 8;
    iov[1].size = 0;
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN,
                          gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC,
                                               expect, iov, 2));
    iov[0].len = 14;
    ASSERT_OK(gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, expect,
                                   iov, 2));
    iov[0].len = 20;
    ASSERT_OK(gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, expect,
                                   iov, 2));
    ASSERT_MEM_EQ(tc1, expect, 32);
}

TEST(cshake_copy)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t copy;
    struct gcry_cshake_customization cust;
    unsigned char out[32];
    unsigned char expect[32];
    unsigned char data[4] = { 0, 1, 2, 3 };

    /* The customisation string travels with gcry_md_copy. */
    unhex("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
          expect, sizeof expect);
    cust.n = NULL;
    cust.n_len = 0;
    cust.s = "Email Signature";
    cust.s_len = 15;
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_CSHAKE128, 0));
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_write(hd, data, 2);
    ASSERT_OK(gcry_md_copy(&copy, hd));
    gcry_md_write(hd, data + 2, 2);
    gcry_md_write(copy, data + 2, 2);
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    memset(out, 0, sizeof out);
    ASSERT_OK(gcry_md_extract(copy, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    gcry_md_close(copy);
    /* Customising again resets the state and applies the new strings. */
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_write(hd, data, 4);
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    gcry_md_close(hd);
}

TEST(debug_dump)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t copy;
    unsigned char expect[20];
    char suffix[] = "ctl";
    FILE *f;

    /* The dump files are written to the current directory with a running
     * index; this is the first use in the process, so the names are
     * predictable. */
    unhex("a9993e364706816aba3e25717850c26c9cd0d89d", expect, sizeof expect);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA1, 0));
    gcry_md_debug(hd, "covtest");
    gcry_md_debug(hd, "covtest"); /* already started: ignored */
    gcry_md_write(hd, "ab", 2);
    gcry_md_putc(hd, 'c');
    ASSERT_OK(gcry_md_copy(&copy, hd)); /* copies get their own dump */
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 20);
    ASSERT_MEM_EQ(expect, gcry_md_read(copy, 0), 20);
    gcry_md_debug(hd, NULL);
    gcry_md_close(copy);
    f = fopen("dbgmd-00001.covtest", "rb");
    ASSERT_NOT_NULL(f);
    fseek(f, 0, SEEK_END);
    ASSERT_EQ(3, ftell(f));
    fclose(f);
    remove("dbgmd-00001.covtest");
    remove("dbgmd-00002.unknown");

    /* The same through the control interface. */
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_START_DUMP, suffix, 0));
    gcry_md_reset(hd);
    gcry_md_write(hd, "abc", 3);
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_STOP_DUMP, NULL, 0));
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 20);
    remove("dbgmd-00003.ctl");
    gcry_md_close(hd);
}

TEST(hash_buffers_edges)
{
    gcry_buffer_t iov[2];
    unsigned char out[32];
    unsigned char expect[32];
    char key[] = "key";
    char msg[] = "abc";

    memset(iov, 0, sizeof iov);
    iov[0].data = key;
    iov[0].len = 3;
    iov[1].data = msg;
    iov[1].len = 3;

    /* A fixed-length digest must be asked for with its exact length. */
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_hash_buffers_ext(GCRY_MD_SHA256, 0, out, 20, iov + 1, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers_ext(GCRY_MD_SHA256, 0, out, 32, NULL, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers_ext(GCRY_MD_SHA256, 0, out, 32, iov + 1, -1));
    /* HMAC over a BLAKE2 digest (not offered in FIPS mode) and an XOF at
     * its default length. */
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_DIGEST_ALGO,
                          gcry_md_hash_buffers(GCRY_MD_BLAKE2S_256,
                                               GCRY_MD_FLAG_HMAC, out, iov, 2));

    if (!gcry_fips_mode_active()) {
        unhex("0018bfddc0c878b3e270c6e59b35af01e164a42d89499c9447a90b58a4d60eb3",
              expect, sizeof expect);
        ASSERT_MEM_EQ(expect, out, 32);
    }

    ASSERT_OK(gcry_md_hash_buffers(GCRY_MD_SHAKE128, 0, out, iov + 1, 1));
    unhex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
          expect, sizeof expect);
    ASSERT_MEM_EQ(expect, out, 32);
}

TEST(buffer_argument_checks)
{
    gcry_md_hd_t hd = NULL;
    gcry_buffer_t iov[2];
    unsigned char out[32];
    unsigned char expect[32];
    char key[] = "key";
    char msg[] = "abc";

    /* gcry_md_extract: a NULL output buffer is only fine for no bytes. */
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHAKE128, 0));
    gcry_md_write(hd, NULL, 0);
    gcry_md_write(hd, msg, 3);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_extract(hd, 0, NULL, 16));
    ASSERT_OK(gcry_md_extract(hd, 0, NULL, 0));
    ASSERT_OK(gcry_md_extract(hd, 0, out, 16));
    unhex("5881092dd818bf5cf8a3ddb793fbcba7", expect, sizeof expect);
    ASSERT_MEM_EQ(expect, out, 16);
    gcry_md_close(hd);

    /* gcry_md_hash_buffers_ext: the digest buffer and every iov entry. */
    memset(iov, 0, sizeof iov);
    iov[0].data = key;
    iov[0].len = 3;
    iov[1].data = msg;
    iov[1].len = 3;
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers_ext(GCRY_MD_SHA256, 0, NULL, 32, iov + 1, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers(GCRY_MD_SHA256, 0, NULL, iov + 1, 1));
    iov[1].data = NULL;
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers(GCRY_MD_SHA256, 0, out, iov + 1, 1));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC, out, iov,
                                    2));
    /* A NULL entry without data contributes nothing. */
    iov[1].len = 0;
    ASSERT_OK(gcry_md_hash_buffers(GCRY_MD_SHA256, 0, out, iov + 1, 1));
    unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          expect, sizeof expect);
    ASSERT_MEM_EQ(expect, out, 32);
    /* The NULL key of an HMAC is likewise an empty key, which the FIPS
     * provider refuses as too short. */
    iov[0].data = NULL;
    iov[0].len = 0;
    iov[1].data = msg;
    iov[1].len = 3;
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN,
                          gcry_md_hash_buffers(GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC,
                                               out, iov, 2));

    if (!gcry_fips_mode_active()) {
        unhex("fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351",
              expect, sizeof expect);
        ASSERT_MEM_EQ(expect, out, 32);
    }
    /* No XOF output bytes may be requested into no buffer. */
    ASSERT_OK(gcry_md_hash_buffers_ext(GCRY_MD_SHAKE128, 0, NULL, 0, iov + 1,
                                       1));
    /* NULL iov with no entries was always rejected (reference behaviour). */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               gcry_md_hash_buffers(GCRY_MD_SHA256, 0, out, NULL, 0));
}

TEST(hmac_never_keyed)
{
    gcry_md_hd_t hd;
    unsigned char expect[32];
    unsigned char tc1[32];
    unsigned char key[20];
    int fips = gcry_fips_mode_active();

    memset(key, 0x0b, sizeof key);
    unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
          tc1, sizeof tc1);

    if (fips) {
        /* The provider refuses the empty key the reference library would
         * compute with, so a handle that was never keyed has nothing to
         * hand out: all zeros, with an error on the log. */
        memset(expect, 0, sizeof expect);
    } else {
        /* HMAC-SHA256 with the empty key, as the reference library has
         * it. */
        unhex("fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351",
              expect, sizeof expect);
    }

    log_reset();
    gcry_set_log_handler(capture_log, NULL);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    ASSERT_EQ(fips ? 1 : 0, logcalls);

    if (fips) {
        ASSERT_EQ(GCRY_LOG_ERROR, loglevel);
        ASSERT_NOT_NULL(strstr(logbuf, "HMAC-SHA256 handle was never keyed"));
    }

    /* An explicit empty key, as NULL or as an empty buffer, is the same
     * thing: outside FIPS mode it is the key the handle computed with
     * anyway, inside it is refused and the handle stays unkeyed. */
    log_reset();
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, NULL, 0));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    ASSERT_EQ(fips ? 1 : 0, logcalls);
    log_reset();
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, "", 0));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    ASSERT_EQ(fips ? 1 : 0, logcalls);

    /* A NULL key with a length is an argument error in both modes. */
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_setkey(hd, NULL, 5));

    /* A real key ends the unkeyed state. */
    log_reset();
    ASSERT_OK(gcry_md_setkey(hd, key, sizeof key));
    gcry_md_write(hd, "Hi There", 8);
    ASSERT_MEM_EQ(tc1, gcry_md_read(hd, 0), 32);
    ASSERT_EQ(0, logcalls);
    gcry_set_log_handler(NULL, NULL);
    gcry_md_close(hd);
}

TEST(keyed_blake2_reset_and_rekey)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t fresh;
    unsigned char key[64];
    unsigned char expect[64];
    unsigned char first[64];
    size_t i;

    if (gcry_fips_mode_active()) {
        return; /* No BLAKE2 at all; see keyed_blake2_limits. */
    }

    for (i = 0; i < sizeof key; i++) {
        key[i] = (unsigned char)i;
    }

    /* The official keyed BLAKE2b-512 KAT (key 00..3f, empty message). */
    unhex("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786"
          "b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
          expect, sizeof expect);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0));
    ASSERT_OK(gcry_md_setkey(hd, key, 64));
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 64);
    /* The key survives a reset ... */
    gcry_md_reset(hd);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 64);
    /* ... with data as well (the KAT entry for the message 00).  Note
     * that the stock library forgets a BLAKE2 key on reset and would
     * return the unkeyed digest here. */
    unhex("961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4"
          "187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
          expect, sizeof expect);
    gcry_md_reset(hd);
    gcry_md_write(hd, "\x00", 1);
    memcpy(first, gcry_md_read(hd, 0), 64);
    ASSERT_MEM_EQ(expect, first, 64);
    gcry_md_reset(hd);
    gcry_md_write(hd, "\x00", 1);
    ASSERT_MEM_EQ(first, gcry_md_read(hd, 0), 64);
    /* An empty key is refused (OpenSSL's BLAKE2 MAC insists on one) and
     * the current key stays in place. */
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 0));
    gcry_md_write(hd, "\x00", 1);
    ASSERT_MEM_EQ(first, gcry_md_read(hd, 0), 64);
    gcry_md_close(hd);

    /* Keying a handle that has already produced a digest starts afresh:
     * the next digest is the keyed one, the same as from a fresh handle
     * (plain BLAKE2b-512 of "abc" first). */
    unhex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
          "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
          expect, sizeof expect);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2B_512, 0));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 64);
    ASSERT_OK(gcry_md_setkey(hd, key, 64));
    gcry_md_write(hd, "abc", 3);
    ASSERT_OK(gcry_md_open(&fresh, GCRY_MD_BLAKE2B_512, 0));
    ASSERT_OK(gcry_md_setkey(fresh, key, 64));
    gcry_md_write(fresh, "abc", 3);
    memcpy(first, gcry_md_read(fresh, 0), 64);
    ASSERT_TRUE(memcmp(expect, first, 64) != 0);
    ASSERT_MEM_EQ(first, gcry_md_read(hd, 0), 64);
    gcry_md_close(fresh);
    gcry_md_close(hd);

    /* The same for BLAKE2s-256 (key 00..1f). */
    unhex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
          expect, 32);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0));
    ASSERT_OK(gcry_md_setkey(hd, key, 32));
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_reset(hd);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    unhex("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
          expect, 32);
    gcry_md_reset(hd);
    gcry_md_write(hd, "\x00", 1);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    ASSERT_ERR(GPG_ERR_INV_KEYLEN, gcry_md_setkey(hd, key, 0));
    gcry_md_write(hd, "\x00", 1);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);

    /* The truncated variants keep their key through a reset as well
     * (reference values from the stock library, without a reset). */
    unhex("dff38c978666dff5631db35ca15535520d134f5c8060ea569c6a178ad393719f",
          expect, 32);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2B_256, 0));
    ASSERT_OK(gcry_md_setkey(hd, key, 64));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_reset(hd);
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);
    unhex("61ba5f165c194692e09d12520cc4c74a", expect, 16);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_BLAKE2S_128, 0));
    ASSERT_OK(gcry_md_setkey(hd, key, 32));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 16);
    gcry_md_reset(hd);
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 16);
    gcry_md_close(hd);
}

/* Feed HD the KMAC128 framing for the NIST sample key (40..5f, 256 bits):
 * bytepad(encode_string(K), 168).  The message and right_encode(L) follow
 * separately. */
static void
kmac128_prefix(gcry_md_hd_t hd)
{
    unsigned char block[168];
    size_t i;

    memset(block, 0, sizeof block);
    block[0] = 0x01; /* left_encode(168) */
    block[1] = 0xa8;
    block[2] = 0x02; /* left_encode(256) */
    block[3] = 0x01;
    block[4] = 0x00;

    for (i = 0; i < 32; i++) {
        block[5 + i] = (unsigned char)(0x40 + i);
    }

    gcry_md_write(hd, block, sizeof block);
}

TEST(cshake_function_name)
{
    gcry_md_hd_t hd;
    gcry_md_hd_t copy;
    struct gcry_cshake_customization cust;
    unsigned char data[200];
    unsigned char out[32];
    unsigned char expect[32];
    size_t i;

    for (i = 0; i < sizeof data; i++) {
        data[i] = (unsigned char)i;
    }

    /* The function name N is reserved for NIST-defined constructions and
     * OpenSSL knows only those, so "KMAC" goes through: a cSHAKE128
     * handle with N = "KMAC" computes KMAC128 when given the KMAC framing.
     * NIST KMAC sample 1: N only, a 4 byte message, 256 output bits. */
    unhex("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
          expect, sizeof expect);
    cust.n = "KMAC";
    cust.n_len = 4;
    cust.s = NULL;
    cust.s_len = 0;
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_CSHAKE128, 0));
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    kmac128_prefix(hd);
    gcry_md_write(hd, data, 4);
    gcry_md_write(hd, "\x01\x00\x02", 3); /* right_encode(256) */
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);

    /* Sample 2 adds S; a copy taken midway carries both strings. */
    unhex("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5",
          expect, sizeof expect);
    cust.s = "My Tagged Application";
    cust.s_len = 21;
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    kmac128_prefix(hd);
    gcry_md_write(hd, data, 2);
    ASSERT_OK(gcry_md_copy(&copy, hd));
    gcry_md_write(hd, data + 2, 2);
    gcry_md_write(hd, "\x01\x00\x02", 3);
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    gcry_md_write(copy, data + 2, 2);
    gcry_md_write(copy, "\x01\x00\x02", 3);
    memset(out, 0, sizeof out);
    ASSERT_OK(gcry_md_extract(copy, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    /* The copy can be customised again on its own (sample 3: 200 bytes). */
    unhex("1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230",
          expect, sizeof expect);
    ASSERT_OK(gcry_md_ctl(copy, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    kmac128_prefix(copy);
    gcry_md_write(copy, data, sizeof data);
    gcry_md_write(copy, "\x01\x00\x02", 3);
    ASSERT_OK(gcry_md_extract(copy, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    gcry_md_close(copy);

    /* Any other function name is refused.  The customisation is dropped
     * altogether, S included, and the handle reset: it now computes plain
     * cSHAKE128 without strings, which is SHAKE128. */
    unhex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
          expect, sizeof expect);
    cust.n = "ABC";
    cust.n_len = 3;
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_write(hd, "abc", 3);
    ASSERT_OK(gcry_md_copy(&copy, hd)); /* Nothing left to carry over. */
    ASSERT_OK(gcry_md_extract(hd, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    memset(out, 0, sizeof out);
    ASSERT_OK(gcry_md_extract(copy, 0, out, 32));
    ASSERT_MEM_EQ(expect, out, 32);
    gcry_md_close(copy);
    gcry_md_close(hd);
}

TEST(hmac_blake2_and_misc_edges)
{
    gcry_md_hd_t hd;
    struct gcry_cshake_customization cust;
    gcry_buffer_t iov;
    unsigned char out[32];
    unsigned char expect[32];
    char abc[] = "abc";
    size_t n;
    int algo;

    /* HMAC over a truncated BLAKE2 digest cannot be expressed with
     * OpenSSL's HMAC (and in FIPS mode BLAKE2 is unavailable anyway). */
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_open(&hd, GCRY_MD_BLAKE2B_160, GCRY_MD_FLAG_HMAC));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_open(&hd, GCRY_MD_BLAKE2S_128, GCRY_MD_FLAG_HMAC));
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_enable(hd, GCRY_MD_BLAKE2B_384));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_DIGEST_ALGO,
                          gcry_md_enable(hd, GCRY_MD_BLAKE2B_512));
    gcry_md_close(hd);

    /* A customisation needs an algorithm on the handle. */
    cust.n = NULL;
    cust.n_len = 0;
    cust.s = "x";
    cust.s_len = 1;
    ASSERT_OK(gcry_md_open(&hd, 0, 0));
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO,
               gcry_md_ctl(hd, GCRYCTL_MD_CUSTOMIZE, &cust, sizeof cust));
    gcry_md_close(hd);

    /* The one-shot helpers with an unknown algorithm: gcry_md_hash_buffer
     * leaves the digest alone, gcry_md_hash_buffers reports it. */
    memset(out, 0xaa, sizeof out);
    memset(expect, 0xaa, sizeof expect);
    gcry_md_hash_buffer(4711, out, abc, 3);
    ASSERT_MEM_EQ(expect, out, 32);
    iov.size = 0;
    iov.off = 0;
    iov.len = 3;
    iov.data = abc;
    ASSERT_ERR(GPG_ERR_DIGEST_ALGO, gcry_md_hash_buffers(4711, 0, out, &iov,
                                                         1));

    /* Zero length writes and a repeated finalisation change nothing. */
    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          expect, sizeof expect);
    ASSERT_OK(gcry_md_open(&hd, GCRY_MD_SHA256, 0));
    gcry_md_write(hd, "", 0);
    gcry_md_write(hd, "ab", 2);
    gcry_md_write(hd, NULL, 0);
    gcry_md_write(hd, "c", 1);
    gcry_md_write(hd, "", 0);
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_FINALIZE, NULL, 0));
    ASSERT_OK(gcry_md_ctl(hd, GCRYCTL_FINALIZE, NULL, 0));
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, GCRY_MD_SHA256), 32);

    /* gcry_md_info, the deprecated query interface. */
    n = 99;
    ASSERT_OK(gcry_md_info(hd, GCRYCTL_IS_SECURE, NULL, &n));
    ASSERT_EQ(0, n);
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_info(hd, GCRYCTL_IS_SECURE, NULL,
                                             NULL));
    algo = GCRY_MD_SHA256;
    n = sizeof algo;
    ASSERT_OK(gcry_md_info(hd, GCRYCTL_IS_ALGO_ENABLED, &algo, &n));
    ASSERT_EQ(1, n);
    algo = GCRY_MD_SHA1;
    n = sizeof algo;
    ASSERT_OK(gcry_md_info(hd, GCRYCTL_IS_ALGO_ENABLED, &algo, &n));
    ASSERT_EQ(0, n);
    n = 1;
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_info(hd, GCRYCTL_IS_ALGO_ENABLED,
                                             &algo, &n));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_info(hd, GCRYCTL_IS_ALGO_ENABLED,
                                             NULL, &n));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_md_info(hd, 9999, NULL, &n));
    ASSERT_ERR(GPG_ERR_INV_ARG, gcry_md_info(NULL, GCRYCTL_IS_SECURE, NULL,
                                             &n));

    /* A dump file that cannot be created is noted on the log, and the
     * handle carries on undisturbed. */
    log_reset();
    gcry_set_log_handler(capture_log, NULL);
    gcry_md_reset(hd);
    gcry_md_debug(hd, "nodir/x");
    gcry_set_log_handler(NULL, NULL);
    ASSERT_EQ(1, logcalls);
    ASSERT_EQ(GCRY_LOG_DEBUG, loglevel);
    ASSERT_NOT_NULL(strstr(logbuf, "can't open"));
    gcry_md_write(hd, "abc", 3);
    ASSERT_MEM_EQ(expect, gcry_md_read(hd, 0), 32);
    gcry_md_close(hd);
}

/* Leave the child with a code that tells which error was raised.  The
 * fatal error handler is honoured outside FIPS mode only; there the
 * child exits here instead of aborting. */
static void
fatal_exit_handler(void *opaque, int rc, const char *text)
{
    (void)opaque;
    (void)text;
    test_child_exit(rc == GPG_ERR_INV_ARG ? 42
                    : rc == GPG_ERR_DIGEST_ALGO ? 43 : 44);
}

static void
fatal_md_read_null(void)
{
    gcry_set_fatalerror_handler(fatal_exit_handler, NULL);
    gcry_md_read(NULL, 0);
}

static void
fatal_md_read_missing(void)
{
    gcry_md_hd_t hd;

    gcry_set_fatalerror_handler(fatal_exit_handler, NULL);

    if (gcry_md_open(&hd, GCRY_MD_SHA256, 0)) {
        return;
    }

    gcry_md_write(hd, "abc", 3);
    gcry_md_read(hd, GCRY_MD_SHA1);
}

static void
fatal_md_write_null(void)
{
    gcry_md_hd_t hd;

    gcry_set_fatalerror_handler(fatal_exit_handler, NULL);

    if (gcry_md_open(&hd, GCRY_MD_SHA256, 0)) {
        return;
    }

    gcry_md_write(hd, NULL, 3);
}

static void
fatal_md_hash_buffer_null(void)
{
    gcry_set_fatalerror_handler(fatal_exit_handler, NULL);
    gcry_md_hash_buffer(GCRY_MD_SHA256, NULL, "abc", 3);
}

static void
fatal_md_read_null_unhandled(void)
{
    gcry_md_read(NULL, 0);
}

TEST(fatal_arguments)
{
    int fips = gcry_fips_mode_active();

    /* Caller bugs the reference library treats as fatal: the fatal error
     * handler is called (outside FIPS mode) and the process aborts if it
     * returns, so each runs in a child of its own. */
    ASSERT_EQ(fips ? 1000 + SIGABRT : 42, run_child(fatal_md_read_null));
    ASSERT_EQ(fips ? 1000 + SIGABRT : 43, run_child(fatal_md_read_missing));
    ASSERT_EQ(fips ? 1000 + SIGABRT : 42, run_child(fatal_md_write_null));
    ASSERT_EQ(fips ? 1000 + SIGABRT : 42,
              run_child(fatal_md_hash_buffer_null));
    ASSERT_EQ(1000 + SIGABRT, run_child(fatal_md_read_null_unhandled));
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
    RUN_TEST(handle_api_edges);
    RUN_TEST(keyed_blake2_limits);
    RUN_TEST(hmac_reset_and_rekey);
    RUN_TEST(hmac_unkeyed_and_key_lengths);
    RUN_TEST(cshake_copy);
    RUN_TEST(debug_dump);
    RUN_TEST(hash_buffers_edges);
    RUN_TEST(buffer_argument_checks);
    RUN_TEST(hmac_never_keyed);
    RUN_TEST(keyed_blake2_reset_and_rekey);
    RUN_TEST(cshake_function_name);
    RUN_TEST(hmac_blake2_and_misc_edges);
    RUN_TEST(fatal_arguments);
    return TEST_RESULT();
}
