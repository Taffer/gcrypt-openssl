/*
 * Benchmark driver: option parsing, the timing loop and output.
 *
 * Output formats:
 *
 *   human (default)
 *     group   name                               ops/s     MiB/s     us/op
 *
 *   --csv
 *     group,name,bytes,iterations,seconds,ops_per_sec,mib_per_sec,status
 *
 * Both begin with "# library: <version>" so compare.sh can label columns,
 * followed by "# fips-mode: y|n".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bench.h"

#define BENCH_INPUT_MAX (1u << 24)

static unsigned char *bench_input_buf;
static size_t bench_input_len;

const unsigned char *
bench_input(void)
{
    return bench_input_buf;
}

static double
now_seconds(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int
case_selected(const struct bench_opts *opts, const struct bench_case *c)
{
    char full[BENCH_NAME_MAX + 32];
    int i;

    if (!opts->nfilters) {
        return 1;
    }

    snprintf(full, sizeof full, "%s/%s", c->group, c->name);

    for (i = 0; i < opts->nfilters; i++) {
        if (strstr(full, opts->filters[i])) {
            return 1;
        }
    }

    return 0;
}

static void
print_row(const struct bench_opts *opts, const struct bench_case *c,
          unsigned long iters, double secs, const char *status)
{
    double ops = secs > 0 ? (double)iters / secs : 0;
    double mib = secs > 0 && c->bytes
                 ? (double)iters * (double)c->bytes / secs / 1048576.0
                 : 0;
    double us = iters ? secs * 1e6 / (double)iters : 0;

    if (opts->csv) {
        printf("%s,%s,%zu,%lu,%.6f,%.3f,%.3f,%s\n", c->group, c->name,
               c->bytes, iters, secs, ops, mib, status);
    } else if (status[0]) {
        printf("%-8s %-44s %s\n", c->group, c->name, status);
    } else if (c->bytes) {
        printf("%-8s %-44s %12.1f %9.2f %11.3f\n", c->group, c->name, ops,
               mib, us);
    } else {
        printf("%-8s %-44s %12.1f %9s %11.3f\n", c->group, c->name, ops, "-",
               us);
    }

    fflush(stdout);
}

void
bench_run_case(const struct bench_opts *opts, const struct bench_case *c)
{
    gcry_error_t err;
    unsigned long iters = 0;
    unsigned long batch = 1;
    double start;
    double elapsed = 0;
    char status[128];

    if (!case_selected(opts, c)) {
        return;
    }

    if (opts->list) {
        printf("%s/%s\n", c->group, c->name);
        return;
    }

    err = c->setup ? c->setup(c->state) : 0;

    if (err) {
        snprintf(status, sizeof status, "unsupported (%s)",
                 gcry_strerror(err));
        print_row(opts, c, 0, 0, status);
        return;
    }

    /* One untimed call warms caches.  A failure here means the library
     * rejected the operation itself, so it is reported as unsupported. */
    err = c->op(c->state);

    if (err) {
        snprintf(status, sizeof status, "unsupported (%s)",
                 gcry_strerror(err));
        print_row(opts, c, 0, 0, status);

        if (c->teardown) {
            c->teardown(c->state);
        }

        return;
    }

    start = now_seconds();

    do {
        unsigned long i;

        for (i = 0; i < batch && !err; i++) {
            err = c->op(c->state);
        }

        iters += batch;
        elapsed = now_seconds() - start;

        /* Grow the batch until a batch takes a noticeable fraction of the
         * budget, so the clock is read rarely for fast operations. */
        if (elapsed < opts->seconds / 20.0) {
            batch *= 2;
        }
    } while (!err && elapsed < opts->seconds);

    if (err) {
        snprintf(status, sizeof status, "error (%s)", gcry_strerror(err));
        print_row(opts, c, 0, 0, status);
    } else {
        print_row(opts, c, iters, elapsed, "");
    }

    if (c->teardown) {
        c->teardown(c->state);
    }
}

static void
usage(const char *prog)
{
    printf("usage: %s [options] [filter...]\n"
           "\n"
           "Benchmark the gcrypt API of the linked library.  With filters,\n"
           "only cases whose \"group/name\" contains one of the substrings\n"
           "run.  Groups: hash mac kdf cipher pk kem misc.\n"
           "\n"
           "  -s, --seconds SEC   time budget per case (default 0.5)\n"
           "  -b, --size BYTES    buffer size for bulk operations "
           "(default 16384)\n"
           "  -c, --csv           machine-readable output\n"
           "  -f, --fips          force FIPS mode before initialisation\n"
           "  -l, --list          list case names and exit\n"
           "  -h, --help          this text\n",
           prog);
}

int
main(int argc, char **argv)
{
    struct bench_opts opts;
    const char **filters;
    int i;
    size_t n;
    unsigned int seed = 0x9e3779b9u;
    int fips = 0;

    memset(&opts, 0, sizeof opts);
    opts.seconds = 0.5;
    opts.size = 16384;

    filters = calloc((size_t)argc, sizeof * filters);

    if (!filters) {
        return 1;
    }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]);
            free(filters);
            return 0;
        } else if (!strcmp(a, "-c") || !strcmp(a, "--csv")) {
            opts.csv = 1;
        } else if (!strcmp(a, "-l") || !strcmp(a, "--list")) {
            opts.list = 1;
        } else if (!strcmp(a, "-f") || !strcmp(a, "--fips")) {
            fips = 1;
        } else if ((!strcmp(a, "-s") || !strcmp(a, "--seconds"))
                   && i + 1 < argc) {
            opts.seconds = atof(argv[++i]);
        } else if ((!strcmp(a, "-b") || !strcmp(a, "--size"))
                   && i + 1 < argc) {
            opts.size = (size_t)strtoul(argv[++i], NULL, 0);
        } else if (a[0] == '-' && a[1]) {
            fprintf(stderr, "%s: unknown option %s\n", argv[0], a);
            free(filters);
            return 2;
        } else {
            filters[opts.nfilters++] = a;
        }
    }

    opts.filters = filters;

    if (opts.seconds <= 0) {
        opts.seconds = 0.5;
    }

    if (opts.size < 64 || opts.size > BENCH_INPUT_MAX) {
        fprintf(stderr, "%s: --size must be between 64 and %u\n", argv[0],
                BENCH_INPUT_MAX);
        free(filters);
        return 2;
    }

    /* Deterministic input so both libraries see identical data. */
    bench_input_len = opts.size;
    bench_input_buf = malloc(bench_input_len + 64);

    if (!bench_input_buf) {
        free(filters);
        return 1;
    }

    for (n = 0; n < bench_input_len + 64; n++) {
        seed = seed * 1103515245u + 12345u;
        bench_input_buf[n] = (unsigned char)(seed >> 16);
    }

    /* Must precede initialisation; the library then refuses algorithms
     * that are not approved, which the cases report as unsupported. */
    if (fips) {
        gcry_control(GCRYCTL_FORCE_FIPS_MODE, 0);
    }

    if (!gcry_check_version(NULL)) {
        fprintf(stderr, "gcry_check_version failed\n");
        return 1;
    }

    if (fips && !gcry_fips_mode_active()) {
        fprintf(stderr, "%s: --fips requested but FIPS mode is not active\n",
                argv[0]);
        return 1;
    }

    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (!opts.list) {
        printf("# library: %s\n", gcry_check_version(NULL));
        printf("# fips-mode: %s\n", gcry_fips_mode_active() ? "y" : "n");
        printf("# seconds-per-case: %.3f\n", opts.seconds);
        printf("# buffer-size: %zu\n", opts.size);

        if (opts.csv) {
            printf("group,name,bytes,iterations,seconds,ops_per_sec,"
                   "mib_per_sec,status\n");
        } else {
            printf("%-8s %-44s %12s %9s %11s\n", "group", "name", "ops/s",
                   "MiB/s", "us/op");
        }
    }

    bench_hash(&opts);
    bench_mac(&opts);
    bench_kdf(&opts);
    bench_cipher(&opts);
    bench_pk(&opts);
    bench_kem(&opts);
    bench_misc(&opts);

    free(bench_input_buf);
    free(filters);
    return 0;
}
