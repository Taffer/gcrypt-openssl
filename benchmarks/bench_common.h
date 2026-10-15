/*
 * Minimal benchmark helpers using only C99 facilities (clock()).
 *
 * Usage:
 *
 *     static void bench_thing(void)
 *     {
 *         BENCH_KEEP(thing_under_test());
 *     }
 *
 *     int main(void)
 *     {
 *         bench_run("thing", 1000000UL, bench_thing);
 *         return 0;
 *     }
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

typedef void (*bench_fn)(void);

/*
 * Call fn() iterations times and print the elapsed CPU time and the
 * average cost per call in nanoseconds.
 */
static void
bench_run(const char *name, unsigned long iterations, bench_fn fn)
{
    unsigned long i;
    clock_t start;
    clock_t stop;
    double secs;
    double ns_per;

    start = clock();
    for (i = 0; i < iterations; i++) {
        fn();
    }
    stop = clock();

    secs = (double)(stop - start) / (double)CLOCKS_PER_SEC;
    ns_per = secs * 1e9 / (double)iterations;

    printf("%-40s %12lu iters %10.3f s %12.1f ns/iter\n", name, iterations,
           secs, ns_per);
}

#endif /* GCRYPT_OPENSSL_BENCH_COMMON_H */
