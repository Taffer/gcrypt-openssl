#include <gcrypt-openssl/gcrypt_openssl.h>

#include "bench_common.h"

int
main(void)
{
    BENCH_BEGIN("gcrypt_openssl_version", 10000000UL);
        BENCH_KEEP(gcrypt_openssl_version());
    BENCH_END();

    BENCH_BEGIN("gcrypt_openssl_backend_version", 10000000UL);
        BENCH_KEEP(gcrypt_openssl_backend_version());
    BENCH_END();

    return 0;
}
