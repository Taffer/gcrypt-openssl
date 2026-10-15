#include <gcrypt.h>

#include "bench_common.h"

static gcry_mpi_t bench_mpi;

static void
bench_check_version(void)
{
    BENCH_KEEP(gcry_check_version(NULL));
}

static void
bench_sexp_build(void)
{
    gcry_sexp_t s = NULL;

    gcry_sexp_build(&s, NULL, "(public-key (rsa (n %m) (e %m)))", bench_mpi,
                    bench_mpi);
    BENCH_KEEP(s);
    gcry_sexp_release(s);
}

int
main(void)
{
    gcry_check_version(NULL);
    bench_mpi = gcry_mpi_new(0);
    gcry_mpi_randomize(bench_mpi, 2048, GCRY_WEAK_RANDOM);

    bench_run("gcry_check_version", 10000000UL, bench_check_version);
    bench_run("gcry_sexp_build (rsa 2048)", 200000UL, bench_sexp_build);

    gcry_mpi_release(bench_mpi);
    return 0;
}
