/*
 * Internal helpers of global.c, misc.c, memory.c, error.c and pk-rsa.c
 * that the public API does not reach directly: context objects, OpenSSL
 * error translation, errno capture, debug and FIPS flags, the low level
 * log and progress hooks, the fatal paths (run in forked children), and
 * the PKCS#1 v1.5 frame check with implicit rejection that stands in for
 * a provider's.
 */
#include "../src/gcrypt-int.h"

#include <errno.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

/* The upstream header marks the log handler setter deprecated; it is
 * still the only way to observe the logger. */
#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

static char logbuf[1024];
static size_t loglen;
static int loglevel;

static void
capture_log(void *opaque, int level, const char *fmt, va_list ap)
{
    int n;

    (void)opaque;
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
    loglevel = -1;
}

static int
run_child(void (*fn)(void))
{
    pid_t pid;
    int status = 0;

    fflush(NULL); /* The child's exit() must not replay our buffers. */
    pid = fork();

    if (pid == 0) {
        fclose(stderr);
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

TEST(syserror)
{
    errno = 0;
    ASSERT_EQ(GPG_ERR_MISSING_ERRNO, _gcry_err_code_from_syserror());
    errno = ENOENT;
    ASSERT_EQ(GPG_ERR_ENOENT, _gcry_err_code_from_syserror());
    errno = 0;
}

TEST(openssl_errors)
{
    /* Nothing queued: the fallback is returned. */
    ERR_clear_error();
    ASSERT_EQ(GPG_ERR_INTERNAL, _gcry_err_from_openssl(GPG_ERR_INTERNAL));

    /* Memory failures are recognised whatever the fallback. */
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
    ASSERT_EQ(GPG_ERR_ENOMEM, _gcry_err_from_openssl(GPG_ERR_INTERNAL));
    ASSERT_EQ(0, ERR_peek_error()); /* The queue was drained. */

    /* Other reasons map to the fallback and are logged when verbose. */
    gcry_set_log_handler(capture_log, NULL);
    log_reset();
    _gcry_set_log_verbosity(2);
    ASSERT_EQ(2, _gcry_log_verbosity());
    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    ASSERT_EQ(GPG_ERR_INV_ARG, _gcry_err_from_openssl(GPG_ERR_INV_ARG));
    ASSERT_EQ(GCRY_LOG_DEBUG, loglevel);
    ASSERT_NOT_NULL(strstr(logbuf, "openssl:"));
    _gcry_set_log_verbosity(0);
    gcry_set_log_handler(NULL, NULL);
}

static int deinit_calls;

static void
ctx_deinit(void *payload)
{
    deinit_calls++;
    *(int *)payload = 0;
}

TEST(context_objects)
{
    gcry_ctx_t ctx = _gcry_ctx_alloc(7, sizeof(int), ctx_deinit);
    int *payload;

    ASSERT_NOT_NULL(ctx);
    payload = _gcry_ctx_find_pointer(ctx, 7);
    ASSERT_NOT_NULL(payload);
    ASSERT_EQ(0, *payload); /* Zeroed on allocation. */
    *payload = 5;
    ASSERT_TRUE(_gcry_ctx_get_pointer(ctx, 7) == payload);
    ASSERT_NULL(_gcry_ctx_find_pointer(ctx, 8));
    ASSERT_NULL(_gcry_ctx_find_pointer(NULL, 7));
    ASSERT_NULL(_gcry_ctx_get_pointer(NULL, 7));
    gcry_ctx_release(ctx);
    ASSERT_EQ(1, deinit_calls);
    gcry_ctx_release(NULL);

    ctx = _gcry_ctx_alloc(9, 32, NULL);
    ASSERT_NOT_NULL(ctx);
    gcry_ctx_release(ctx); /* No deinit callback. */
    ASSERT_EQ(1, deinit_calls);
}

static void
child_wrong_context_type(void)
{
    gcry_ctx_t ctx = _gcry_ctx_alloc(7, 8, NULL);
    void *p = _gcry_ctx_get_pointer(ctx, 8); /* Must not return. */

    test_child_exit(p ? 1 : 2);
}

TEST(wrong_context_type_is_a_bug)
{
    ASSERT_EQ(1000 + SIGABRT, run_child(child_wrong_context_type));
}

TEST(flags)
{
    unsigned int before = _gcry_get_debug_flags();

    ASSERT_OK(gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 4u));
    ASSERT_TRUE(_gcry_get_debug_flags() & 4u);
    ASSERT_OK(gcry_control(GCRYCTL_CLEAR_DEBUG_FLAGS, 4u));
    ASSERT_EQ(before, _gcry_get_debug_flags());

    ASSERT_EQ(GCRY_FIPS_FLAG_REJECT_DEFAULT, _gcry_fips_reject_flags());
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS, 0u));
    ASSERT_EQ(0, _gcry_fips_reject_flags());
    ASSERT_OK(gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS,
                           (unsigned int)GCRY_FIPS_FLAG_REJECT_DEFAULT));
    ASSERT_EQ(GCRY_FIPS_FLAG_REJECT_DEFAULT, _gcry_fips_reject_flags());

    ASSERT_OK(gcry_control(GCRYCTL_SET_VERBOSITY, 3));
    ASSERT_EQ(3, _gcry_log_verbosity());
    ASSERT_OK(gcry_control(GCRYCTL_SET_VERBOSITY, 0));
    ASSERT_EQ(0, _gcry_log_verbosity());
    /* The internal flag is what the public query reports. */
    ASSERT_EQ(gcry_fips_mode_active() ? 1 : 0, _gcry_fips_mode());
}

TEST(printhex)
{
    static const unsigned char b[2] = { 0x01, 0x02 };

    gcry_set_log_handler(capture_log, NULL);
    log_reset();
    _gcry_log_printhex("x", b, sizeof b);
    ASSERT_STR_EQ("x: 0102\n", logbuf);
    /* Without a text only the bare bytes appear, not even a newline. */
    log_reset();
    _gcry_log_printhex(NULL, b, sizeof b);
    ASSERT_STR_EQ("0102", logbuf);
    log_reset();
    _gcry_log_printhex("", b, sizeof b);
    ASSERT_STR_EQ("0102\n", logbuf);
    gcry_set_log_handler(NULL, NULL);
}

static int progress_hits;
static const char *progress_what;
static int progress_char;
static int progress_cur;
static int progress_tot;

static void
progress_cb(void *opaque, const char *what, int printchar, int current,
            int total)
{
    (void)opaque;
    progress_hits++;
    progress_what = what;
    progress_char = printchar;
    progress_cur = current;
    progress_tot = total;
}

TEST(progress)
{
    _gcry_progress("nothing", '.', 0, 0); /* No handler: ignored. */
    ASSERT_EQ(0, progress_hits);
    gcry_set_progress_handler(progress_cb, NULL);
    _gcry_progress("test", '!', 3, 7);
    ASSERT_EQ(1, progress_hits);
    ASSERT_STR_EQ("test", progress_what);
    ASSERT_EQ('!', progress_char);
    ASSERT_EQ(3, progress_cur);
    ASSERT_EQ(7, progress_tot);
    gcry_set_progress_handler(NULL, NULL);
}

static void
fatal_handler(void *opaque, int rc, const char *text)
{
    (void)opaque;

    if (rc == (int)GPG_ERR_INTERNAL && text
        && !strcmp(text, "Internal error")) {
        test_child_exit(42);
    }

    test_child_exit(43);
}

static void
child_fatal_with_handler(void)
{
    gcry_set_fatalerror_handler(fatal_handler, NULL);
    _gcry_fatal_error(GPG_ERR_INTERNAL, NULL); /* Text from the code. */
}

static void
child_fatal_without_handler(void)
{
    _gcry_fatal_error(GPG_ERR_INTERNAL, "custom text");
}

static void
child_bug(void)
{
    _gcry_bug("file.c", 42, "function");
}

static void
child_log_fatal(void)
{
    _gcry_log(GCRY_LOG_FATAL, "fatal %s\n", "message");
}

static void
child_log_unknown_level(void)
{
    _gcry_log(77, "odd level\n");
    _gcry_log(GCRY_LOG_INFO, "info\n");
    _gcry_log(GCRY_LOG_WARN, "warn\n");
    _gcry_log(GCRY_LOG_ERROR, "error\n");
    _gcry_log(GCRY_LOG_CONT, "cont\n");
    test_child_exit(7);
}

TEST(fatal_paths)
{
    /* The fatal error handler is ignored in FIPS mode, as in the
     * reference: the message goes to stderr and the process aborts. */
    ASSERT_EQ(gcry_fips_mode_active() ? 1000 + SIGABRT : 42,
              run_child(child_fatal_with_handler));
    ASSERT_EQ(1000 + SIGABRT, run_child(child_fatal_without_handler));
    ASSERT_EQ(1000 + SIGABRT, run_child(child_bug));
    ASSERT_EQ(1000 + SIGABRT, run_child(child_log_fatal));
    ASSERT_EQ(7, run_child(child_log_unknown_level));
}

static void
child_disable_secmem(void)
{
    if (_gcry_secmem_is_disabled()) {
        test_child_exit(1);
    }

    _gcry_secmem_disable();

    if (!_gcry_secmem_is_disabled()) {
        test_child_exit(2);
    }

    /* Allocations still work, they are just not secure. */
    {
        void *p = _gcry_malloc_secure(16);

        if (!p || _gcry_is_secure(p)) {
            test_child_exit(3);
        }

        _gcry_free(p);
    }
    _gcry_secmem_init(4096);
    _gcry_secmem_term();
    test_child_exit(0);
}

TEST(secmem_disable)
{
    ASSERT_EQ(0, run_child(child_disable_secmem));
}

/* ---- pk-rsa.c: PKCS#1 v1.5 decryption with implicit rejection ------- */

#define RSA_K 256 /* 2048 bit test key. */

/* The K byte ciphertext of the RSA encryption DATA under PKEY. */
static int
ciphertext_of(gcry_sexp_t data, gcry_sexp_t pkey, unsigned char ct[RSA_K])
{
    gcry_sexp_t ciph = NULL;
    gcry_sexp_t l;
    gcry_mpi_t a;
    size_t n = 0;
    int ok;

    if (gcry_pk_encrypt(&ciph, data, pkey)) {
        return 0;
    }

    l = gcry_sexp_find_token(ciph, "a", 0);
    a = l ? gcry_sexp_nth_mpi(l, 1, GCRYMPI_FMT_USG) : NULL;
    memset(ct, 0, RSA_K);
    ok = a && !gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &n, a) && n <= RSA_K
         && !gcry_mpi_print(GCRYMPI_FMT_USG, ct + (RSA_K - n), n, NULL, a);
    gcry_mpi_release(a);
    gcry_sexp_release(l);
    gcry_sexp_release(ciph);
    return ok;
}

/* The ciphertext of the K byte frame FRAME, a raw RSA encryption. */
static int
encrypt_frame(const unsigned char *frame, gcry_sexp_t pkey,
              unsigned char ct[RSA_K])
{
    gcry_mpi_t m = NULL;
    gcry_sexp_t data = NULL;
    int ok;

    ok = !gcry_mpi_scan(&m, GCRYMPI_FMT_USG, frame, RSA_K, NULL)
         && !gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", m)
         && ciphertext_of(data, pkey, ct);
    gcry_sexp_release(data);
    gcry_mpi_release(m);
    return ok;
}

/* OpenSSL's own PKCS#1 v1.5 decryption of CT through the public API; the
 * message is copied into VALUE (RSA_K bytes), its length into *VALUELEN.
 * Returns the error of gcry_pk_decrypt(). */
static gcry_error_t
openssl_decrypt(gcry_sexp_t skey, const unsigned char ct[RSA_K],
                unsigned char *value, size_t *valuelen)
{
    gcry_sexp_t enc = NULL;
    gcry_sexp_t plain = NULL;
    gcry_sexp_t l;
    const char *p;
    size_t n = 0;
    gcry_error_t err;

    err = gcry_sexp_build(&enc, NULL, "(enc-val (flags pkcs1) (rsa (a %b)))",
                          RSA_K, ct);

    if (!err) {
        err = gcry_pk_decrypt(&plain, enc, skey);
    }

    if (!err) {
        l = gcry_sexp_find_token(plain, "value", 0);
        p = l ? gcry_sexp_nth_data(l, 1, &n) : NULL;

        if (!p || n > RSA_K) {
            err = GPG_ERR_INTERNAL;
        } else {
            memcpy(value, p, n);
            *valuelen = n;
        }

        gcry_sexp_release(l);
    }

    gcry_sexp_release(plain);
    gcry_sexp_release(enc);
    return err;
}

/* The fallback on CT must agree with OpenSSL's check byte for byte, and
 * with itself: the synthetic message of a bad frame is a function of the
 * key and the ciphertext alone.  When the loaded provider does not do
 * PKCS#1 v1.5 decryption at all (a FIPS provider may not), only the
 * determinism and the length bound are checked.  EXPECT, when not NULL,
 * is the EXPECTLEN byte message a good frame must yield. */
static void
check_fallback(gcry_sexp_t skey, const unsigned char ct[RSA_K],
               const unsigned char *expect, size_t expectlen)
{
    unsigned char *v1 = NULL;
    unsigned char *v2 = NULL;
    unsigned char ref[RSA_K];
    size_t l1 = 0;
    size_t l2 = 0;
    size_t reflen = 0;
    gcry_error_t err;

    ASSERT_OK(_gcry_rsa_pkcs1_decrypt_fallback(skey, ct, RSA_K, &v1, &l1));
    ASSERT_OK(_gcry_rsa_pkcs1_decrypt_fallback(skey, ct, RSA_K, &v2, &l2));
    ASSERT_NOT_NULL(v1);
    ASSERT_TRUE(gcry_is_secure(v1));
    ASSERT_TRUE(l1 <= RSA_K - 11);
    ASSERT_EQ(l1, l2);
    ASSERT_MEM_EQ(v1, v2, l1);

    if (expect) {
        ASSERT_EQ(expectlen, l1);
        ASSERT_MEM_EQ(expect, v1, expectlen);
    }

    err = openssl_decrypt(skey, ct, ref, &reflen);

    if (!err) {
        ASSERT_EQ(reflen, l1);
        ASSERT_MEM_EQ(ref, v1, reflen);
    } else {
        ASSERT_TRUE(gcry_fips_mode_active());
    }

    gcry_free(v1);
    gcry_free(v2);
}

TEST(rsa_pkcs1_fallback)
{
    gcry_sexp_t parms = NULL;
    gcry_sexp_t keypair = NULL;
    gcry_sexp_t skey;
    gcry_sexp_t pkey;
    gcry_sexp_t data = NULL;
    unsigned char frame[RSA_K];
    unsigned char ct[RSA_K];
    unsigned char *value = NULL;
    size_t valuelen = 0;
    unsigned int i;

    ASSERT_OK(gcry_sexp_build(&parms, NULL, "(genkey (rsa (nbits 4:2048)))"));
    ASSERT_OK(gcry_pk_genkey(&keypair, parms));
    skey = gcry_sexp_find_token(keypair, "private-key", 0);
    pkey = gcry_sexp_find_token(keypair, "public-key", 0);
    ASSERT_NOT_NULL(skey);
    ASSERT_NOT_NULL(pkey);

    /* A good frame from the library's own encryption. */
    ASSERT_OK(gcry_sexp_build(&data, NULL, "(data (flags pkcs1) (value 5:hello))"));
    ASSERT_TRUE(ciphertext_of(data, pkey, ct));
    check_fallback(skey, ct, (const unsigned char *)"hello", 5);
    gcry_sexp_release(data);

    /* Hand-made frames: 00 02, padding, 00, message. */
    memset(frame, 0xA5, sizeof frame);
    frame[0] = 0;
    frame[1] = 2;
    /* The longest message, eight bytes of padding. */
    frame[10] = 0;
    memset(frame + 11, 0x42, RSA_K - 11);
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, frame + 11, RSA_K - 11);
    /* The empty message. */
    memset(frame + 2, 0xA5, RSA_K - 2);
    frame[RSA_K - 1] = 0;
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, frame + RSA_K, 0);
    /* Seven bytes of padding: too few, implicitly rejected. */
    memset(frame + 2, 0xA5, RSA_K - 2);
    frame[9] = 0;
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, NULL, 0);
    /* No separator at all. */
    memset(frame + 2, 0xA5, RSA_K - 2);
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, NULL, 0);
    /* Wrong block type. */
    frame[1] = 1;
    frame[20] = 0;
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, NULL, 0);
    /* Not a frame: small numbers, which the raw operation short-cuts for
     * 0 and 1, and the zero frame's all-zero decryption. */
    memset(frame, 0, sizeof frame);
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, NULL, 0);
    frame[RSA_K - 1] = 1;
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, NULL, 0);
    frame[RSA_K - 1] = 57;
    ASSERT_TRUE(encrypt_frame(frame, pkey, ct));
    check_fallback(skey, ct, NULL, 0);

    /* Random ciphertexts below the modulus. */
    for (i = 0; i < 8; i++) {
        gcry_randomize(ct, RSA_K, GCRY_WEAK_RANDOM);
        ct[0] = 0;
        check_fallback(skey, ct, NULL, 0);
    }

    /* Argument checks. */
    ASSERT_ERR(GPG_ERR_INV_ARG,
               _gcry_rsa_pkcs1_decrypt_fallback(skey, ct, RSA_K - 1, &value,
                                                &valuelen));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               _gcry_rsa_pkcs1_decrypt_fallback(skey, NULL, RSA_K, &value,
                                                &valuelen));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               _gcry_rsa_pkcs1_decrypt_fallback(skey, ct, RSA_K, NULL,
                                                &valuelen));
    ASSERT_ERR(GPG_ERR_INV_ARG,
               _gcry_rsa_pkcs1_decrypt_fallback(skey, ct, RSA_K, &value,
                                                NULL));
    ASSERT_NULL(value);
    /* A ciphertext not below the modulus. */
    memset(ct, 0xFF, RSA_K);
    ASSERT_ERR(GPG_ERR_INV_DATA,
               _gcry_rsa_pkcs1_decrypt_fallback(skey, ct, RSA_K, &value,
                                                &valuelen));
    ASSERT_NULL(value);
    /* No secret key, no RSA key. */
    ASSERT_TRUE(_gcry_rsa_pkcs1_decrypt_fallback(pkey, ct, RSA_K, &value,
                                                 &valuelen) != 0);
    ASSERT_NULL(value);
    ASSERT_ERR(GPG_ERR_INV_OBJ,
               _gcry_rsa_pkcs1_decrypt_fallback(parms, ct, RSA_K, &value,
                                                &valuelen));
    ASSERT_NULL(value);

    gcry_sexp_release(pkey);
    gcry_sexp_release(skey);
    gcry_sexp_release(keypair);
    gcry_sexp_release(parms);
}

int
main(void)
{
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_DISABLE_SECMEM_WARN);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    RUN_TEST(syserror);
    RUN_TEST(openssl_errors);
    RUN_TEST(context_objects);
    RUN_TEST(wrong_context_type_is_a_bug);
    RUN_TEST(flags);
    RUN_TEST(printhex);
    RUN_TEST(progress);
    RUN_TEST(fatal_paths);
    RUN_TEST(secmem_disable);
    RUN_TEST(rsa_pkcs1_fallback);
    return TEST_RESULT();
}
