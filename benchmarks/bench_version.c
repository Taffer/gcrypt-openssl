#include <gcrypt-openssl/gcrypt_openssl.h>

#include "bench_common.h"

static void
bench_version(void)
{
    BENCH_KEEP(gcrypt_openssl_version());
}

static void
bench_backend_version(void)
{
    BENCH_KEEP(gcrypt_openssl_backend_version());
}

int
main(void)
{
    bench_run("gcrypt_openssl_version", 10000000UL, bench_version);
    bench_run("gcrypt_openssl_backend_version", 10000000UL,
              bench_backend_version);
    return 0;
}
