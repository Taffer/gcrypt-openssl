/*
 * test_fips.c - The FIPS controls that only work before initialisation,
 * and the GCRYCTL_FIPS_REJECT_NON_FIPS flags.
 *
 * The pre-initialisation controls are exercised in forked children, each
 * starting from the untouched library state, because they are one-shot
 * per process.  The parent initialises itself only after the children
 * have run, and compares their outcome with its own mode.  Everything here
 * passes in normal mode and in FIPS mode; FIPS mode is what makes the
 * flag checks bite.
 */
#include <gcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"
#include "test_pk_rsa_vector.h"

/* FIPS mode of this process once it has initialised normally. */
static int parent_fips = -1;

/* Outcomes of the children, collected before the parent initialises. */
static int r_force;
static int r_no_fips;
static int r_force_then_no_fips;
static int r_no_fips_before_finished;

/* The FIPS mode as the three public views report it, or -1 if they
 * disagree with each other. */
static int
fips_state(void)
{
    int a = gcry_fips_mode_active();
    int b = gcry_control(GCRYCTL_FIPS_MODE_P) != 0;
    char *cfg = gcry_get_config(0, "fips-mode");
    int c = cfg && strncmp(cfg, "fips-mode:y", 11) == 0;

    gcry_free(cfg);
    return (a == b && a == c) ? a : -1;
}

static int
run_child(int (*fn)(void))
{
    pid_t pid;
    int status = 0;

    fflush(NULL); /* The child's exit() must not replay our buffers. */
    pid = fork();

    if (pid == 0) {
        test_child_exit(fn());
    }

    if (pid < 0) {
        return -1;
    }

    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }

    return WIFSIGNALED(status) ? 1000 + WTERMSIG(status) : -2;
}

/* GCRYCTL_FORCE_FIPS_MODE before initialisation: 10 + resulting mode. */
static int
child_force(void)
{
    int s;

    if (gcry_control(GCRYCTL_FORCE_FIPS_MODE)) {
        return 90;
    }

    gcry_check_version(NULL);
    s = fips_state();

    if (s < 0) {
        return 91;
    }

    /* Too late now, whatever the mode. */
    if (gcry_err_code(gcry_control(GCRYCTL_FORCE_FIPS_MODE))
        != GPG_ERR_GENERAL) {
        return 92;
    }

    return 10 + s;
}

/* GCRYCTL_NO_FIPS_MODE before initialisation: 20 + resulting mode. */
static int
child_no_fips(void)
{
    int s;

    if (gcry_control(GCRYCTL_NO_FIPS_MODE)) {
        return 90;
    }

    gcry_check_version(NULL);
    s = fips_state();
    return s < 0 ? 91 : 20 + s;
}

/* Both, in that order; the last request wins: 40 + resulting mode. */
static int
child_force_then_no_fips(void)
{
    int s;

    if (gcry_control(GCRYCTL_FORCE_FIPS_MODE)
        || gcry_control(GCRYCTL_NO_FIPS_MODE)) {
        return 90;
    }

    gcry_check_version(NULL);
    s = fips_state();
    return s < 0 ? 91 : 40 + s;
}

/* GCRYCTL_NO_FIPS_MODE after initialisation but before the application
 * declared initialisation finished switches the mode off; afterwards it
 * is refused.  Returns 30 on success. */
static int
child_no_fips_before_finished(void)
{
    gcry_check_version(NULL);

    if (gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        return 93;
    }

    if (gcry_control(GCRYCTL_NO_FIPS_MODE)) {
        return 94;
    }

    if (fips_state() != 0) {
        return 95;
    }

    gcry_control(GCRYCTL_INITIALIZATION_FINISHED);

    if (gcry_err_code(gcry_control(GCRYCTL_NO_FIPS_MODE)) != GPG_ERR_GENERAL) {
        return 96;
    }

    return 30;
}

TEST(pre_init_controls)
{
    ASSERT_TRUE(parent_fips == 0 || parent_fips == 1);

    /* Forcing FIPS mode enables it when a FIPS provider can be loaded;
     * without one the library carries on in normal mode.  It can never
     * leave the process with less than the configuration already gave. */
    ASSERT_TRUE(r_force == 11 || (r_force == 10 && !parent_fips));

    /* Declining FIPS mode only withdraws the library's own request; a
     * configuration that enables the FIPS provider still applies. */
    ASSERT_EQ(20 + parent_fips, r_no_fips);
    ASSERT_EQ(40 + parent_fips, r_force_then_no_fips);

    /* The window between initialisation and INITIALIZATION_FINISHED. */
    ASSERT_EQ(30, r_no_fips_before_finished);
}

static gcry_sexp_t
rsa_key(void)
{
    gcry_sexp_t key = NULL;

    if (gcry_sexp_build(&key, NULL,
                        "(private-key (rsa (n #" RSA_N "#) (e #010001#)"
                        " (d #" RSA_D "#) (p #" RSA_P "#) (q #" RSA_Q "#)))")) {
        return NULL;
    }

    return key;
}

static gcry_error_t
set_reject_flags(unsigned int flags)
{
    return gcry_control(GCRYCTL_FIPS_REJECT_NON_FIPS, flags);
}

TEST(reject_pk_md)
{
    gcry_sexp_t key = rsa_key();
    gcry_sexp_t data = NULL;
    gcry_sexp_t sig = NULL;

    ASSERT_NOT_NULL(key);
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pkcs1-raw) (value 5:hello))"));

    /* A PKCS#1 signature over a raw value involves no digest at all.  The
     * default flag set lets it through even in FIPS mode. */
    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT));
    ASSERT_OK(gcry_pk_sign(&sig, data, key));
    ASSERT_OK(gcry_pk_verify(sig, data, key));
    gcry_sexp_release(sig);
    sig = NULL;

    /* GCRY_FIPS_FLAG_REJECT_PK_MD refuses it in FIPS mode. */
    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT
                               | GCRY_FIPS_FLAG_REJECT_PK_MD));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_DIGEST_ALGO, gcry_pk_sign(&sig, data, key));
    gcry_sexp_release(sig);

    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT));
    gcry_sexp_release(data);
    gcry_sexp_release(key);
}

TEST(reject_pk_flags)
{
    gcry_sexp_t key = rsa_key();
    gcry_sexp_t data = NULL;
    gcry_sexp_t short_salt = NULL;
    gcry_sexp_t sig = NULL;
    unsigned char digest[32];
    size_t i;

    for (i = 0; i < sizeof digest; i++) {
        digest[i] = (unsigned char)i;
    }

    ASSERT_NOT_NULL(key);
    /* A salt longer than the SHA-256 output: legal PSS, but outside the
     * FIPS 186-5 limit of hLen. */
    ASSERT_OK(gcry_sexp_build(&data, NULL,
                              "(data (flags pss) (salt-length 2:64)"
                              " (hash sha256 %b))", 32, digest));
    ASSERT_OK(gcry_sexp_build(&short_salt, NULL,
                              "(data (flags pss) (salt-length 2:32)"
                              " (hash sha256 %b))", 32, digest));

    /* Without GCRY_FIPS_FLAG_REJECT_PK_FLAGS the long salt is accepted. */
    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT));
    ASSERT_OK(gcry_pk_sign(&sig, data, key));
    ASSERT_OK(gcry_pk_verify(sig, data, key));

    /* With it, FIPS mode refuses both signing and verifying. */
    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT
                               | GCRY_FIPS_FLAG_REJECT_PK_FLAGS));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_ARG, gcry_pk_verify(sig, data, key));
    gcry_sexp_release(sig);
    sig = NULL;
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_INV_ARG, gcry_pk_sign(&sig, data, key));
    gcry_sexp_release(sig);
    sig = NULL;

    /* A salt of hLen bytes stays fine under the flag. */
    ASSERT_OK(gcry_pk_sign(&sig, short_salt, key));
    ASSERT_OK(gcry_pk_verify(sig, short_salt, key));
    gcry_sexp_release(sig);

    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT));
    gcry_sexp_release(short_salt);
    gcry_sexp_release(data);
    gcry_sexp_release(key);
}

TEST(reject_cipher_and_mac)
{
    gcry_cipher_hd_t hd = NULL;
    unsigned char key[32];

    memset(key, 0x42, sizeof key); /* Both XTS halves identical. */

    /* With every rejection switched off, FIPS mode still only offers what
     * the provider has: Triple-DES is there, CAST5 and MD5 are not. */
    ASSERT_OK(set_reject_flags(0));
    ASSERT_OK(gcry_cipher_test_algo(GCRY_CIPHER_3DES));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_CIPHER_ALGO,
                          gcry_cipher_test_algo(GCRY_CIPHER_CAST5));
    ASSERT_OK(gcry_mac_test_algo(GCRY_MAC_CMAC_3DES));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_MAC_ALGO,
                          gcry_mac_test_algo(GCRY_MAC_HMAC_MD5));

    /* The XTS rule that the two key halves differ is not negotiable in
     * FIPS mode, flags or not. */
    ASSERT_OK(gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_XTS, 0));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_WEAK_KEY,
                          gcry_cipher_setkey(hd, key, sizeof key));
    gcry_cipher_close(hd);

    /* Back to the default set, the non-approved algorithms are refused. */
    ASSERT_OK(set_reject_flags(GCRY_FIPS_FLAG_REJECT_DEFAULT));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_CIPHER_ALGO,
                          gcry_cipher_test_algo(GCRY_CIPHER_3DES));
    ASSERT_OK_OR_FIPS_ERR(GPG_ERR_MAC_ALGO,
                          gcry_mac_test_algo(GCRY_MAC_CMAC_3DES));
    ASSERT_OK(gcry_cipher_test_algo(GCRY_CIPHER_AES));
    ASSERT_OK(gcry_mac_test_algo(GCRY_MAC_CMAC_AES));
}

int
main(void)
{
    /* Children first: they need the library untouched. */
    r_force = run_child(child_force);
    r_no_fips = run_child(child_no_fips);
    r_force_then_no_fips = run_child(child_force_then_no_fips);
    r_no_fips_before_finished = run_child(child_no_fips_before_finished);

    gcry_check_version(NULL);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
    parent_fips = fips_state();

    RUN_TEST(pre_init_controls);
    RUN_TEST(reject_pk_md);
    RUN_TEST(reject_pk_flags);
    RUN_TEST(reject_cipher_and_mac);
    return TEST_RESULT();
}
