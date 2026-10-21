#include <gcrypt.h>

#include <errno.h>

#include "test_common.h"

TEST(code_and_source)
{
    gcry_error_t err = gcry_err_make(GPG_ERR_SOURCE_GCRYPT, GPG_ERR_INV_ARG);

    ASSERT_EQ(GPG_ERR_INV_ARG, gcry_err_code(err));
    ASSERT_EQ(GPG_ERR_SOURCE_GCRYPT, gcry_err_source(err));
    ASSERT_EQ(0, gcry_err_make(GPG_ERR_SOURCE_GCRYPT, GPG_ERR_NO_ERROR));
    ASSERT_EQ(GPG_ERR_SOURCE_USER_1, gcry_err_source(gcry_error(GPG_ERR_BUG)));
}

TEST(strings)
{
    ASSERT_STR_EQ("Success", gcry_strerror(0));
    ASSERT_STR_EQ("Invalid argument", gcry_strerror(gcry_error(GPG_ERR_INV_ARG)));
    ASSERT_STR_EQ("General error", gcry_strerror(gcry_error(GPG_ERR_GENERAL)));
    ASSERT_STR_EQ("Invalid S-expression",
                  gcry_strerror(gcry_error(GPG_ERR_INV_SEXP)));
    ASSERT_STR_EQ("End of file", gcry_strerror(gcry_error(GPG_ERR_EOF)));
    ASSERT_STR_EQ("Unknown error code", gcry_strerror(gcry_error(1234)));
    ASSERT_STR_EQ("gcrypt",
                  gcry_strsource(gcry_err_make(GPG_ERR_SOURCE_GCRYPT, 1)));
    ASSERT_STR_EQ("User defined source 1", gcry_strsource(gcry_error(1)));
    ASSERT_STR_EQ("Unspecified source", gcry_strsource(0));
    ASSERT_STR_EQ("GnuPG", gcry_strsource(gcry_err_make(GPG_ERR_SOURCE_GPG, 1)));
}

TEST(errno_mapping)
{
    ASSERT_EQ(GPG_ERR_ENOMEM, gcry_err_code_from_errno(ENOMEM));
    ASSERT_EQ(GPG_ERR_EINVAL, gcry_err_code_from_errno(EINVAL));
    ASSERT_EQ(GPG_ERR_ENOENT, gcry_err_code_from_errno(ENOENT));
    ASSERT_EQ(0, gcry_err_code_from_errno(0));
    ASSERT_EQ(ENOMEM, gcry_err_code_to_errno(GPG_ERR_ENOMEM));
    ASSERT_EQ(ERANGE, gcry_err_code_to_errno(GPG_ERR_ERANGE));
    ASSERT_EQ(0, gcry_err_code_to_errno(GPG_ERR_INV_ARG));
    ASSERT_EQ(GPG_ERR_UNKNOWN_ERRNO, gcry_err_code_from_errno(99999));
    ASSERT_STR_EQ(strerror(ENOMEM), gcry_strerror(gcry_error_from_errno(ENOMEM)));
    ASSERT_EQ(GPG_ERR_SOURCE_GCRYPT, gcry_err_source(gcry_error_from_errno(EIO)));
    ASSERT_EQ(GPG_ERR_SOURCE_GPG,
              gcry_err_source(gcry_err_make_from_errno(GPG_ERR_SOURCE_GPG, EIO)));
    ASSERT_EQ(GPG_ERR_SYSTEM_ERROR | 86, GPG_ERR_ENOMEM);
}

TEST(unknown_codes_and_sources)
{
    /* Every source libgpg-error 1.33 knows; TKD arrived in 1.47.  Sources
     * above the known ones are reported as unknown, so the probe for one
     * stays well clear of where new ones get added. */
    static const char *const sources[] = {
        "Unspecified source", "gcrypt", "GnuPG", "GpgSM", "GPG Agent",
        "Pinentry", "SCD", "GPGME", "Keybox", "KSBA", "Dirmngr", "GSTI",
        "GPA", "Kleopatra", "G13", "Assuan", "TPM2d", "TLS",
#if GPG_ERROR_VERSION_NUMBER >= 0x012f00
        "TKD",
#endif
    };
    unsigned int i;

    /* A system error bit with an errno index nothing maps to. */
    ASSERT_STR_EQ("Unknown system error",
                  gcry_strerror(gcry_error(GPG_ERR_SYSTEM_ERROR | 16383)));
    ASSERT_EQ(0, gcry_err_code_to_errno(GPG_ERR_SYSTEM_ERROR | 16383));
    ASSERT_EQ(GPG_ERR_UNKNOWN_ERRNO,
              gcry_err_code(gcry_err_make_from_errno(GPG_ERR_SOURCE_GPG, 99999)));

    for (i = 0; i < sizeof sources / sizeof sources[0]; i++) {
        ASSERT_STR_EQ(sources[i],
                      gcry_strsource(gcry_err_make((gcry_err_source_t)i, 1)));
    }

    ASSERT_STR_EQ("Unknown source",
                  gcry_strsource(gcry_err_make((gcry_err_source_t)30, 1)));
    ASSERT_STR_EQ("Unknown source",
                  gcry_strsource(gcry_err_make((gcry_err_source_t)100, 1)));
    ASSERT_STR_EQ("Any source",
                  gcry_strsource(gcry_err_make(GPG_ERR_SOURCE_ANY, 1)));
    ASSERT_STR_EQ("User defined source 4",
                  gcry_strsource(gcry_err_make(GPG_ERR_SOURCE_USER_4, 1)));
}

/* The gcry_* helpers are thin wrappers over libgpg-error, so the two must
 * agree on every value, and the types must be libgpg-error's own. */
TEST(agrees_with_libgpg_error)
{
    static const gcry_err_code_t codes[] = {
        GPG_ERR_NO_ERROR, GPG_ERR_GENERAL, GPG_ERR_INV_ARG, GPG_ERR_INV_SEXP,
        GPG_ERR_WEAK_KEY, GPG_ERR_NO_KEY, GPG_ERR_ENOMEM, GPG_ERR_EOF,
        GPG_ERR_UNKNOWN_ERRNO, (gcry_err_code_t)1234
    };
    unsigned int i;

    for (i = 0; i < sizeof codes / sizeof codes[0]; i++) {
        gcry_error_t err = gcry_err_make(GPG_ERR_SOURCE_GCRYPT, codes[i]);

        ASSERT_EQ(gpg_err_make(GPG_ERR_SOURCE_GCRYPT, codes[i]), err);
        ASSERT_EQ(gpg_err_code(err), gcry_err_code(err));
        ASSERT_EQ(gpg_err_source(err), gcry_err_source(err));
        ASSERT_STR_EQ(gpg_strerror(err), gcry_strerror(err));
        ASSERT_STR_EQ(gpg_strsource(err), gcry_strsource(err));
    }

    ASSERT_EQ(gpg_err_code_from_errno(EINVAL), gcry_err_code_from_errno(EINVAL));
    ASSERT_EQ(gpg_err_code_to_errno(GPG_ERR_ENOMEM),
              gcry_err_code_to_errno(GPG_ERR_ENOMEM));
    ASSERT_EQ(gpg_err_make_from_errno(GPG_ERR_SOURCE_GPG, EIO),
              gcry_err_make_from_errno(GPG_ERR_SOURCE_GPG, EIO));
    ASSERT_EQ(sizeof(gpg_error_t), sizeof(gcry_error_t));
    ASSERT_EQ(GPG_ERR_SOURCE_USER_1, GCRY_ERR_SOURCE_DEFAULT);
}

int
main(void)
{
    RUN_TEST(code_and_source);
    RUN_TEST(strings);
    RUN_TEST(errno_mapping);
    RUN_TEST(unknown_codes_and_sources);
    RUN_TEST(agrees_with_libgpg_error);
    return TEST_RESULT();
}
