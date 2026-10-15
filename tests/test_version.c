#include <gcrypt-openssl/gcrypt_openssl.h>

#include "test_common.h"

TEST(version_is_reported)
{
    const char *version = gcrypt_openssl_version();

    ASSERT_NOT_NULL(version);
    ASSERT_TRUE(strlen(version) > 0);
    ASSERT_STR_EQ("0.1.0", version);
}

TEST(backend_version_is_reported)
{
    const char *backend = gcrypt_openssl_backend_version();

    ASSERT_NOT_NULL(backend);
    ASSERT_TRUE(strncmp(backend, "OpenSSL", 7) == 0);
}

int
main(void)
{
    RUN_TEST(version_is_reported);
    RUN_TEST(backend_version_is_reported);
    return TEST_RESULT();
}
