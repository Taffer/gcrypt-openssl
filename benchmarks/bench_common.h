/*
 * Minimal benchmark helpers using only C99 facilities (clock()).
 *
 * Usage:
 *
 *     BENCH_BEGIN(name, iterations);
 *         ... one iteration of the thing being measured ...
 *     BENCH_END();
 */
#ifndef GCRYPT_OPENSSL_BENCH_COMMON_H
#define GCRYPT_OPENSSL_BENCH_COMMON_H

#include <stdio.h>
#include <time.h>

/*
 * Prevent the compiler from optimising away a result that is never read.
 * Writing through a volatile pointer forces the store to happen.
 */
static volatile const void *bench_sink_;
#define BENCH_KEEP(value) (bench_sink_ = (const void *)(value))

#define BENCH_BEGIN(name, iterations)                                     \
    do {                                                                  \
        const char *bench_name_ = (name);                                 \
        const unsigned long bench_iters_ = (iterations);                  \
        unsigned long bench_i_;                                           \
        clock_t bench_start_ = clock();                                   \
        for (bench_i_ = 0; bench_i_ < bench_iters_; bench_i_++) {

#define BENCH_END()                                                       \
        }                                                                 \
        {                                                                 \
            clock_t bench_stop_ = clock();                                \
            double bench_secs_ = (double)(bench_stop_ - bench_start_)     \
                               / (double)CLOCKS_PER_SEC;                  \
            double bench_ns_per_ = bench_secs_ * 1e9                      \
                                 / (double)bench_iters_;                  \
            printf("%-40s %12lu iters %10.3f s %12.1f ns/iter\n",         \
                   bench_name_, bench_iters_, bench_secs_, bench_ns_per_);\
        }                                                                 \
    } while (0)

#endif /* GCRYPT_OPENSSL_BENCH_COMMON_H */
