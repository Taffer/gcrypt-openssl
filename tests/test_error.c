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

TEST(gpg_error_compat_wrappers)
{
    ASSERT_STR_EQ("Invalid argument", gpg_strerror(gpg_error(GPG_ERR_INV_ARG)));
    ASSERT_EQ(GPG_ERR_EINVAL, gpg_err_code_from_errno(EINVAL));
    errno = ENOENT;
    ASSERT_EQ(GPG_ERR_ENOENT, gpg_err_code_from_syserror());
}

int
main(void)
{
    RUN_TEST(code_and_source);
    RUN_TEST(strings);
    RUN_TEST(errno_mapping);
    RUN_TEST(gpg_error_compat_wrappers);
    return TEST_RESULT();
}
