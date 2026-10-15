#include <gcrypt.h>

#include <stdlib.h>

#include "test_common.h"

TEST(version_string)
{
    const char *v = gcry_check_version(NULL);

    ASSERT_NOT_NULL(v);
    ASSERT_STR_EQ(GCRYPT_VERSION, v);
}

TEST(version_requirements)
{
    ASSERT_NOT_NULL(gcry_check_version("1.8.0"));
    ASSERT_NOT_NULL(gcry_check_version(GCRYPT_VERSION));
    ASSERT_NULL(gcry_check_version("1.99.0"));
    ASSERT_NULL(gcry_check_version("2.0.0"));
    ASSERT_NULL(gcry_check_version("garbage"));
    ASSERT_NULL(gcry_check_version("01.2.3"));
}

TEST(initialization_flags)
{
    ASSERT_TRUE(gcry_control(GCRYCTL_ANY_INITIALIZATION_P));
    ASSERT_OK(gcry_control(GCRYCTL_DISABLE_SECMEM_WARN));
    ASSERT_OK(gcry_control(GCRYCTL_INIT_SECMEM, 16384u, 0));
    ASSERT_OK(gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0));
    ASSERT_TRUE(gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P));
    ASSERT_TRUE(gcry_control(GCRYCTL_OPERATIONAL_P));
    ASSERT_ERR(GPG_ERR_INV_OP, gcry_control((enum gcry_ctl_cmds)9999));
    ASSERT_ERR(GPG_ERR_NOT_SUPPORTED, gcry_control(GCRYCTL_ENABLE_M_GUARD));
}

TEST(config_report)
{
    char *all = gcry_get_config(0, NULL);
    char *ver = gcry_get_config(0, "version");
    char *backend = gcry_get_config(0, "backend");

    ASSERT_NOT_NULL(all);
    ASSERT_NOT_NULL(ver);
    ASSERT_NOT_NULL(backend);
    ASSERT_TRUE(strstr(all, "version:" GCRYPT_VERSION ":10c04:") == all);
    ASSERT_TRUE(strncmp(ver, "version:", 8) == 0);
    ASSERT_NULL(strchr(ver, '\n'));
    ASSERT_TRUE(strstr(backend, "backend:gcrypt-openssl:") == backend);
    ASSERT_TRUE(strstr(all, "fips-mode:") != NULL);
    ASSERT_NULL(gcry_get_config(1, NULL));
    ASSERT_NULL(gcry_get_config(0, "no-such-item"));
    gcry_free(all);
    gcry_free(ver);
    gcry_free(backend);
}

TEST(identification)
{
    const char *id = gcry_check_version("\x01\x01");

    ASSERT_NOT_NULL(id);
    ASSERT_TRUE(strstr(id, "gcrypt-openssl") != NULL);
}

int
main(void)
{
    RUN_TEST(version_string);
    RUN_TEST(version_requirements);
    RUN_TEST(initialization_flags);
    RUN_TEST(config_report);
    RUN_TEST(identification);
    return TEST_RESULT();
}
