/*
 * Shared declarations for the gcrypt benchmark suite.
 *
 * The suite is one program, bench_gcrypt, that drives the public gcrypt API
 * and reports throughput.  It is compiled twice: once against this
 * library and once against the stock libgcrypt found on the system, and
 * benchmarks/compare.sh joins the two outputs into a side-by-side table.
 *
 * Every benchmark is a "case": a setup function that allocates state and
 * returns an error when the library does not support the operation, an op
 * function that performs one unit of work, and a teardown function.  The
 * runner times the op in a time-budgeted loop and prints one row.
 */
#ifndef GCRYPT_OPENSSL_BENCH_H
#define GCRYPT_OPENSSL_BENCH_H

#include <gcrypt.h>
#include <stddef.h>

struct bench_opts {
    double seconds;          /* Time budget per case. */
    size_t size;             /* Buffer size for bulk operations. */
    int csv;                 /* Machine-readable output. */
    int list;                /* Only print the case names. */
    int nfilters;
    const char *const *filters; /* Substrings a case name must contain. */
};

/* Returns 0 on success or a gcrypt error (reported as "unsupported"). */
typedef gcry_error_t (*bench_setup_fn)(void *state);
/* Returns 0 on success; any error aborts the case. */
typedef gcry_error_t (*bench_op_fn)(void *state);
typedef void (*bench_teardown_fn)(void *state);

struct bench_case {
    const char *group;       /* "hash", "cipher", ... */
    const char *name;        /* Human-readable, unique within the group. */
    size_t bytes;            /* Bytes processed per op, 0 if meaningless. */
    bench_setup_fn setup;
    bench_op_fn op;
    bench_teardown_fn teardown;
    void *state;
};

/* Run one case (honouring filters and --list) and print its row. */
void bench_run_case(const struct bench_opts *opts, const struct bench_case *c);

/* Shared scratch input: opts->size bytes of fixed pseudo-random data. */
const unsigned char *bench_input(void);

/* Groups, one per source file. */
void bench_hash(const struct bench_opts *opts);
void bench_mac(const struct bench_opts *opts);
void bench_kdf(const struct bench_opts *opts);
void bench_cipher(const struct bench_opts *opts);
void bench_pk(const struct bench_opts *opts);
void bench_kem(const struct bench_opts *opts);
void bench_misc(const struct bench_opts *opts);

/* Build a case name into a static buffer owned by the caller. */
#define BENCH_NAME_MAX 96

#endif /* GCRYPT_OPENSSL_BENCH_H */
