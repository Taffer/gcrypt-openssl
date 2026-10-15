/*
 * gcry_control commands, the configuration report, the logging and
 * progress handlers and the version parser: everything in global.c and
 * misc.c that is reachable through the public API without changing the
 * process-wide memory allocator (see test_secmem.c for that).
 *
 * Expected values were checked against the reference library; where the
 * two libraries format debug output differently only the parts they agree
 * on are asserted.
 */
#define _POSIX_C_SOURCE 200809L

#include <gcrypt.h>

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_common.h"

/* The upstream header marks the log handler setter deprecated; it is
 * still the only way to observe the logger. */
#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* --- log capture ------------------------------------------------------ */

static char logbuf[8192];
static size_t loglen;
static int logcalls;
static int loglevel_seen[8];

static void
capture_log(void *opaque, int level, const char *fmt, va_list ap)
{
    int n;

    (void)opaque;

    if (logcalls < (int)(sizeof loglevel_seen / sizeof loglevel_seen[0])) {
        loglevel_seen[logcalls] = level;
    }

    logcalls++;

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
}

/* Hex digits found in S after PREFIX, ignoring the layout characters the
 * printers insert (spaces, newlines, continuation backslashes). */
static size_t
hex_after(const char *s, const char *prefix, char *out, size_t outsize)
{
    const char *p = strstr(s, prefix);
    size_t n = 0;

    if (!p) {
        return 0;
    }

    for (p += strlen(prefix); *p && n + 1 < outsize; p++) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')) {
            out[n++] = *p;
        }
    }

    out[n] = 0;
    return n;
}

/* Send stderr to /dev/null while the default (handler-less) logger runs. */
static int
silence_stderr(void)
{
    int saved = dup(2);
    int devnull = open("/dev/null", O_WRONLY);

    fflush(stderr);

    if (devnull >= 0) {
        dup2(devnull, 2);
        close(devnull);
    }

    return saved;
}

static void
restore_stderr(int saved)
{
    fflush(stderr);

    if (saved >= 0) {
        dup2(saved, 2);
        close(saved);
    }
}

/* --- tests -------------------------------------------------------------- */

TEST(version_parser)
{
    ASSERT_NULL(gcry_check_version(""));
    ASSERT_NULL(gcry_check_version("1.12"));
    ASSERT_NOT_NULL(gcry_check_version("1.12.")); /* Missing micro is 0. */
    ASSERT_NOT_NULL(gcry_check_version("1..0")); /* Empty minor is 0. */
    ASSERT_NOT_NULL(gcry_check_version("0.0.0"));
    ASSERT_NOT_NULL(gcry_check_version("1.0.0"));
    ASSERT_NOT_NULL(gcry_check_version("1.0.0trailing"));
}

TEST(control_noops)
{
    ASSERT_OK(gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM));
    ASSERT_OK(gcry_control(GCRYCTL_DUMP_RANDOM_STATS));
    ASSERT_OK(gcry_control(GCRYCTL_DUMP_MEMORY_STATS));
    ASSERT_OK(gcry_control(GCRYCTL_DUMP_SECMEM_STATS));
    ASSERT_OK(gcry_control(GCRYCTL_DROP_PRIVS));
    ASSERT_OK(gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN));
    ASSERT_OK(gcry_control(GCRYCTL_RESUME_SECMEM_WARN));
    ASSERT_OK(gcry_control(GCRYCTL_DISABLE_LOCKED_SECMEM));
    ASSERT_OK(gcry_control(GCRYCTL_DISABLE_PRIV_DROP));
    ASSERT_OK(gcry_control(GCRYCTL_AUTO_EXPAND_SECMEM, 65536u));
    ASSERT_OK(gcry_control(GCRYCTL_USE_SECURE_RNDPOOL));
    ASSERT_OK(gcry_control(GCRYCTL_DISABLE_INTERNAL_LOCKING));
    ASSERT_OK(gcry_control(GCRYCTL_SET_THREAD_CBS, NULL));
    ASSERT_OK(gcry_control(GCRYCTL_FAST_POLL));
    ASSERT_OK(gcry_control(GCRYCTL_CLOSE_RANDOM_DEVICE));
    ASSERT_OK(gcry_control(GCRYCTL_DISABLE_HWF, "intel-aesni"));
    ASSERT_OK(gcry_control(GCRYCTL_SET_ENFORCED_FIPS_FLAG));
    ASSERT_OK(gcry_control(GCRYCTL_REINIT_SYSCALL_CLAMP));
    ASSERT_OK(gcry_control(GCRYCTL_SET_VERBOSITY, 0));
    ASSERT_OK(gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 1u));
    ASSERT_OK(gcry_control(GCRYCTL_CLEAR_DEBUG_FLAGS, 1u));
}

TEST(control_unsupported)
{
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_SET_RNDEGD_SOCKET, "/nonexistent"));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_SET_RANDOM_DAEMON_SOCKET, "/nonexistent"));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_control(GCRYCTL_USE_RANDOM_DAEMON, 1));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_control(GCRYCTL_ENABLE_M_GUARD));
    ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED,
               gcry_control(GCRYCTL_INACTIVATE_FIPS_FLAG));
    ASSERT_ERR(GPG_ERR_NOT_IMPLEMENTED,
               gcry_control(GCRYCTL_REACTIVATE_FIPS_FLAG));
    /* Cipher handle commands are not global commands. */
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_control(GCRYCTL_SET_CCM_LENGTHS));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_control(GCRYCTL_SET_TAGLEN));
}

TEST(fips_mode_off)
{
    /* This test suite does not run in FIPS mode. */
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_MODE_P));
    ASSERT_FALSE(gcry_fips_mode_active());
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS, 0u));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS,
                           (unsigned int)GCRY_FIPS_FLAG_REJECT_DEFAULT));
    /* Too late to leave FIPS mode once initialisation has finished. */
    ASSERT_ERR(GPG_ERR_GENERAL, gcry_control(GCRYCTL_NO_FIPS_MODE));
    ASSERT_TRUE(gcry_control(GCRYCTL_OPERATIONAL_P));
}

TEST(fips_service_indicators)
{
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER,
                           GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER,
                           GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER,
                           GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_GCM));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER,
                            GCRY_CIPHER_AES, GCRY_CIPHER_MODE_OCB));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER,
                            GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER,
                            GCRY_CIPHER_AES, 9999));

    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MD, GCRY_MD_SHA1));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MD, GCRY_MD_SHA256));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MD,
                           GCRY_MD_SHA3_256));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MD,
                           GCRY_MD_SHAKE128));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MD, GCRY_MD_MD5));

    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MAC,
                           GCRY_MAC_HMAC_SHA1));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MAC,
                           GCRY_MAC_HMAC_SHA256));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MAC,
                           GCRY_MAC_HMAC_SHA3_256));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MAC,
                           GCRY_MAC_CMAC_AES));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_MAC,
                            GCRY_MAC_HMAC_MD5));

    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_KDF, GCRY_KDF_PBKDF2));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_KDF,
                            GCRY_KDF_SCRYPT));

    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_FUNCTION,
                            "gcry_pk_sign"));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_FUNCTION,
                            "gcry_pk_encrypt"));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_FUNCTION,
                           "gcry_pk_hash_sign"));

    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_PK_FLAGS, "pkcs1"));
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_PK_FLAGS, "pss"));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED,
               gcry_control(GCRYCTL_FIPS_SERVICE_INDICATOR_PK_FLAGS, "oaep"));
}

TEST(selftest)
{
    ASSERT_OK(gcry_control(GCRYCTL_SELFTEST));
}

TEST(rng_type)
{
    int type = -1;

    ASSERT_OK(gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &type));
    ASSERT_EQ(GCRY_RNG_TYPE_STANDARD, type);
    ASSERT_OK(gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE,
                           GCRY_RNG_TYPE_STANDARD));
    ASSERT_OK(gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, 0));
    type = -1;
    ASSERT_OK(gcry_control(GCRYCTL_GET_CURRENT_RNG_TYPE, &type));
    ASSERT_EQ(GCRY_RNG_TYPE_STANDARD, type);
}

TEST(config_items)
{
    static const char *const items[] = {
        "version", "cc", "ciphers", "pubkeys", "digests", "rnd-mod",
        "cpu-arch", "mpi-asm", "mpi-pow", "hwflist", "fips-mode", "rng-type",
        "compliance"
    };
    size_t i;

    for (i = 0; i < sizeof items / sizeof items[0]; i++) {
        char *line = gcry_get_config(0, items[i]);

        ASSERT_NOT_NULL(line);
        ASSERT_TRUE(strncmp(line, items[i], strlen(items[i])) == 0);
        ASSERT_NULL(strchr(line, '\n'));
        gcry_free(line);
    }

    {
        char *line = gcry_get_config(0, "fips-mode");

        ASSERT_NOT_NULL(line);
        ASSERT_TRUE(strncmp(line, "fips-mode:n:", 12) == 0);
        gcry_free(line);
        line = gcry_get_config(0, "rng-type");
        ASSERT_NOT_NULL(line);
        ASSERT_TRUE(strncmp(line, "rng-type:standard:1:", 20) == 0);
        gcry_free(line);
    }
}

TEST(print_config)
{
    FILE *fp = tmpfile();
    char head[16];
    long size;

    ASSERT_NOT_NULL(fp);
    ASSERT_OK(gcry_control(GCRYCTL_PRINT_CONFIG, fp));
    size = ftell(fp);
    ASSERT_TRUE(size > 40);
    rewind(fp);
    ASSERT_EQ(sizeof head, fread(head, 1, sizeof head, fp));
    ASSERT_TRUE(memcmp(head, "version:", 8) == 0);
    fclose(fp);

    /* Without a stream the report goes through the logger at info level. */
    log_reset();
    gcry_set_log_handler(capture_log, NULL);
    ASSERT_OK(gcry_control(GCRYCTL_PRINT_CONFIG, NULL));
    gcry_set_log_handler(NULL, NULL);
    ASSERT_TRUE(logcalls >= 1);
    ASSERT_EQ(GCRY_LOG_INFO, loglevel_seen[0]);
    ASSERT_NOT_NULL(strstr(logbuf, "version:"));
}

TEST(log_handler_text)
{
    static const unsigned char bytes[3] = { 1, 2, 3 };
    unsigned char big[40];
    char hex[256];

    gcry_set_log_handler(capture_log, NULL);

    log_reset();
    gcry_log_debug("hello %d%s", 42, "\n");
    ASSERT_EQ(1, logcalls);
    ASSERT_EQ(GCRY_LOG_DEBUG, loglevel_seen[0]);
    ASSERT_STR_EQ("hello 42\n", logbuf);

    log_reset();
    gcry_log_debughex("buf", bytes, sizeof bytes);
    ASSERT_STR_EQ("buf: 010203\n", logbuf);

    memset(big, 0xab, sizeof big);
    log_reset();
    gcry_log_debughex("big", big, sizeof big);
    ASSERT_TRUE(strncmp(logbuf, "big: ", 5) == 0);
    ASSERT_EQ(80, hex_after(logbuf, "big: ", hex, sizeof hex));
    {
        size_t i;

        for (i = 0; i < 80; i += 2) {
            ASSERT_TRUE(hex[i] == 'a' && hex[i + 1] == 'b');
        }
    }

    gcry_set_log_handler(NULL, NULL);
}

TEST(log_handler_mpi)
{
    gcry_mpi_t m = gcry_mpi_set_ui(NULL, 0x1234);
    gcry_mpi_t o;
    static const unsigned char opaque[2] = { 0xaa, 0xbb };

    gcry_set_log_handler(capture_log, NULL);

    log_reset();
    gcry_log_debugmpi("m", m);
    ASSERT_STR_EQ("m:+1234\n", logbuf);

    gcry_mpi_set_ui(m, 0);
    log_reset();
    gcry_log_debugmpi("z", m);
    ASSERT_STR_EQ("z:+00\n", logbuf);

    gcry_mpi_set_ui(m, 5);
    gcry_mpi_neg(m, m);
    log_reset();
    gcry_log_debugmpi("neg", m);
    ASSERT_STR_EQ("neg:-05\n", logbuf);

    log_reset();
    gcry_log_debugmpi("null", NULL);
    ASSERT_STR_EQ("null: (null)\n", logbuf);

    o = gcry_mpi_set_opaque_copy(NULL, opaque, 16);
    ASSERT_NOT_NULL(o);
    log_reset();
    gcry_log_debugmpi("op", o);
    ASSERT_NOT_NULL(strstr(logbuf, "op: [16 bit]"));
    ASSERT_NOT_NULL(strstr(logbuf, "aabb"));
    log_reset();
    gcry_log_debugmpi(NULL, o);
    ASSERT_NOT_NULL(strstr(logbuf, "[16 bit]"));
    ASSERT_NOT_NULL(strstr(logbuf, "aabb"));

    gcry_mpi_release(o);
    gcry_mpi_release(m);
    gcry_set_log_handler(NULL, NULL);
}

TEST(log_handler_sexp_and_point)
{
    gcry_sexp_t s = NULL;
    gcry_ctx_t ctx = NULL;
    gcry_mpi_point_t pt;
    gcry_mpi_t one = gcry_mpi_set_ui(NULL, 1);
    gcry_mpi_t two = gcry_mpi_set_ui(NULL, 2);

    ASSERT_OK(gcry_sexp_build(&s, NULL, "(a (b 1:x))"));
    gcry_set_log_handler(capture_log, NULL);

    log_reset();
    gcry_log_debugsxp("sx", s);
    ASSERT_TRUE(strncmp(logbuf, "sx: (a ", 7) == 0);
    ASSERT_NOT_NULL(strstr(logbuf, "(b x)"));
    ASSERT_EQ('\n', logbuf[loglen - 1]);

    log_reset();
    gcry_log_debugsxp("two\nlines", s);
    ASSERT_TRUE(strncmp(logbuf, "two\nlines", 9) == 0);
    ASSERT_NOT_NULL(strstr(logbuf, "(b x)"));

    log_reset();
    gcry_log_debugsxp(NULL, s);
    ASSERT_TRUE(strncmp(logbuf, "(a ", 3) == 0);

    log_reset();
    gcry_log_debugsxp("nosexp", NULL);
    ASSERT_STR_EQ("nosexp: \n", logbuf);

    log_reset();
    gcry_log_debugsxp(NULL, NULL);
    ASSERT_EQ(0, logcalls);

    ASSERT_OK(gcry_mpi_ec_new(&ctx, NULL, "NIST P-256"));
    pt = gcry_mpi_point_set(NULL, one, two, one);
    ASSERT_NOT_NULL(pt);

    log_reset();
    gcry_log_debugpnt("pt", pt, ctx);
    ASSERT_TRUE(strncmp(logbuf, "pt", 2) == 0);
    ASSERT_NOT_NULL(strstr(logbuf, "x:+01"));
    ASSERT_NOT_NULL(strstr(logbuf, "y:+02"));

    /* Without a context the projective coordinates are printed; the
     * reference library labels them X/Y/Z. */
    log_reset();
    gcry_log_debugpnt("pt", pt, NULL);
    ASSERT_TRUE(strstr(logbuf, "x:+01") || strstr(logbuf, "X:+01"));
    ASSERT_TRUE(strstr(logbuf, "y:+02") || strstr(logbuf, "Y:+02"));
    ASSERT_TRUE(strstr(logbuf, "z:+01") || strstr(logbuf, "Z:+01"));

    log_reset();
    gcry_log_debugpnt("nullpt", NULL, ctx);
    ASSERT_TRUE(strncmp(logbuf, "nullpt", 6) == 0);
    ASSERT_NOT_NULL(strstr(logbuf, "(null)"));

    gcry_set_log_handler(NULL, NULL);
    gcry_mpi_point_release(pt);
    gcry_ctx_release(ctx);
    gcry_mpi_release(one);
    gcry_mpi_release(two);
    gcry_sexp_release(s);
}

TEST(default_logger)
{
    /* No handler installed: the messages go to stderr, which is parked on
     * /dev/null while they are produced. */
    int saved = silence_stderr();
    unsigned char b[2] = { 0xde, 0xad };

    gcry_log_debug("debug line %d\n", 1);
    gcry_log_debughex("hex", b, sizeof b);
    gcry_control(GCRYCTL_PRINT_CONFIG, NULL);
    restore_stderr(saved);
    ASSERT_TRUE(1);
}

static int progress_calls;
static char progress_what[32];

static void
progress_cb(void *opaque, const char *what, int printchar, int current,
            int total)
{
    (void)printchar;
    (void)current;
    (void)total;
    *(int *)opaque += 1;
    progress_calls++;

    if (what) {
        strncpy(progress_what, what, sizeof progress_what - 1);
    }
}

TEST(progress_handler)
{
    int opaque_hits = 0;
    gcry_mpi_t prime = NULL;

    gcry_set_progress_handler(progress_cb, &opaque_hits);
    ASSERT_OK(gcry_prime_generate(&prime, 256, 0, NULL, NULL, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    gcry_mpi_release(prime);
    prime = NULL;
    ASSERT_TRUE(progress_calls >= 1);
    ASSERT_EQ(progress_calls, opaque_hits);
    ASSERT_STR_EQ("primegen", progress_what);

    gcry_set_progress_handler(NULL, NULL);
    progress_calls = 0;
    ASSERT_OK(gcry_prime_generate(&prime, 256, 0, NULL, NULL, NULL,
                                  GCRY_WEAK_RANDOM, 0));
    gcry_mpi_release(prime);
    ASSERT_EQ(0, progress_calls);
}

static const char *
identity_gettext(const char *s)
{
    return s;
}

TEST(gettext_handler)
{
    gcry_set_gettext_handler(identity_gettext);
    ASSERT_STR_EQ("Invalid argument", gcry_strerror(gcry_error(GPG_ERR_INV_ARG)));
    gcry_set_gettext_handler(NULL);
}

int
main(void)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    RUN_TEST(version_parser);
    RUN_TEST(control_noops);
    RUN_TEST(control_unsupported);
    RUN_TEST(fips_mode_off);
    RUN_TEST(fips_service_indicators);
    RUN_TEST(selftest);
    RUN_TEST(rng_type);
    RUN_TEST(config_items);
    RUN_TEST(print_config);
    RUN_TEST(log_handler_text);
    RUN_TEST(log_handler_mpi);
    RUN_TEST(log_handler_sexp_and_point);
    RUN_TEST(default_logger);
    RUN_TEST(progress_handler);
    RUN_TEST(gettext_handler);
    return TEST_RESULT();
}
