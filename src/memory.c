/*
 * memory.c - Memory allocation with optional "secure" (wiped, locked)
 * storage, plus the user-installable allocation handlers.
 *
 * Secure memory is a set of pools of the library's own, like the
 * reference implementation's: anonymous mappings that are locked into RAM
 * and kept out of core dumps where the system allows it, each carved up
 * by a small first-fit allocator.  That gives the two properties Libgcrypt
 * promises, wiping on free and a gcry_is_secure() that can answer for any
 * pointer at all (it is a range check), without touching OpenSSL's secure
 * heap.  The secure heap is process-wide and has no fallback once it
 * exists, so sizing it for the application's GCRYCTL_INIT_SECMEM request
 * starved OpenSSL's own callers of it, most visibly the FIPS module, whose
 * self-tests allocate their DRBG state and post-quantum keys from it.
 *
 * When the pools are full another one is mapped (the reference does the
 * same once GCRYCTL_AUTO_EXPAND_SECMEM was used); secure memory never
 * silently degrades to the ordinary heap.  Only when the system refuses
 * the mapping does a secure allocation fail.
 */
#define _DEFAULT_SOURCE 1 /* MAP_ANONYMOUS and madvise() on glibc. */

#include "gcrypt-int.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
    #define MAP_ANONYMOUS MAP_ANON
#endif

/* Same default pool size as the reference implementation; also the
 * default size of the pools added when the existing ones are full. */
#define DEFAULT_POOL_SIZE 32768

/* Payload alignment: two size_t words, the alignment of the widest
 * fundamental type on the platforms this runs on. */
#define SECMEM_ALIGN (2 * sizeof(size_t))

/* Every block carries one of these; the payload follows it directly.  The
 * header is two alignment units long, so the payload stays aligned. */
struct secblock {
    size_t magic;  /* SECBLOCK_MAGIC mixed with the header's address. */
    size_t size;   /* Payload size, a multiple of SECMEM_ALIGN. */
    size_t in_use;
    size_t unused;
};

#define SECBLOCK_MAGIC ((size_t)0x5ec0b10cu)

/* A pool is one mapping.  This descriptor sits at its start, the blocks
 * follow; the pools form a list, newest first. */
struct secpool {
    struct secpool *next;
    size_t size; /* Of the whole mapping, descriptor included. */
};

#define SECPOOL_HEADER \
    ((sizeof(struct secpool) + SECMEM_ALIGN - 1) & ~(SECMEM_ALIGN - 1))

static gcry_handler_alloc_t alloc_func;
static gcry_handler_alloc_t alloc_secure_func;
static gcry_handler_secure_check_t is_secure_func;
static gcry_handler_realloc_t realloc_func;
static gcry_handler_free_t free_func;

static gcry_handler_no_mem_t outofcore_handler;
static void *outofcore_handler_value;

static pthread_mutex_t secmem_lock = PTHREAD_MUTEX_INITIALIZER;
static struct secpool *pools; /* NULL while there is no pool. */
static size_t auto_expand_size; /* 0: DEFAULT_POOL_SIZE. */
static unsigned int secmem_flags;
static int secmem_disabled;
static int mlock_failed;     /* Some pool could not be locked ... */
static int insecure_warned;  /* ... and the warning has been given. */

/* ------------------------------------------------------------------ */
/* The secure pools.  All of these expect the lock to be held.         */
/* ------------------------------------------------------------------ */

static size_t
block_magic(const struct secblock *b)
{
    return SECBLOCK_MAGIC ^ (size_t)(uintptr_t)b;
}

static void
block_init(struct secblock *b, size_t size, size_t in_use)
{
    b->magic = block_magic(b);
    b->size = size;
    b->in_use = in_use;
    b->unused = 0;
}

static struct secblock *
block_next(struct secblock *b)
{
    return (struct secblock *)((unsigned char *)(b + 1) + b->size);
}

static struct secblock *
pool_blocks(struct secpool *pool)
{
    return (struct secblock *)((unsigned char *)pool + SECPOOL_HEADER);
}

static struct secblock *
pool_end(struct secpool *pool)
{
    return (struct secblock *)((unsigned char *)pool + pool->size);
}

/* The pool whose payload area contains A, or NULL.  A range check, which
 * is all gcry_is_secure() needs. */
static struct secpool *
pool_find(const void *a)
{
    const unsigned char *p = a;
    struct secpool *pool;

    for (pool = pools; pool; pool = pool->next) {
        if (p >= (const unsigned char *)(pool_blocks(pool) + 1)
            && p < (const unsigned char *)pool_end(pool)) {
            return pool;
        }
    }

    return NULL;
}

/* The live block whose payload starts at P, which pool_find() placed in
 * POOL, or NULL if P is not that: an interior pointer, a block already
 * freed, or something else that was never handed out. */
static struct secblock *
pool_check_block(struct secpool *pool, void *p)
{
    struct secblock *b = (struct secblock *)p - 1;

    if (((uintptr_t)p & (SECMEM_ALIGN - 1))
        || (unsigned char *)b < (unsigned char *)pool_blocks(pool)
        || b->magic != block_magic(b) || !b->in_use
        || b->size > (size_t)((unsigned char *)pool_end(pool)
                              - (unsigned char *)(b + 1))) {
        return NULL;
    }

    return b;
}

static size_t
round_up_align(size_t n)
{
    if (n > (size_t) - 1 - SECMEM_ALIGN) {
        return 0; /* Cannot be satisfied anyway. */
    }

    n = (n + SECMEM_ALIGN - 1) & ~(size_t)(SECMEM_ALIGN - 1);
    return n ? n : SECMEM_ALIGN;
}

/* Map a new pool with room for a block of N payload bytes (N already
 * aligned) and at least MIN bytes in all, and put it first in the list.
 * NULL only if the system refuses the mapping. */
static struct secpool *
pool_map(size_t n, size_t min)
{
    size_t need;
    long pagesize;
    void *p;
    struct secpool *pool;

    if (n > (size_t) - 1 - SECPOOL_HEADER - sizeof(struct secblock)) {
        return NULL;
    }

    need = SECPOOL_HEADER + sizeof(struct secblock) + n;

    if (need < min) {
        need = min;
    }

    pagesize = sysconf(_SC_PAGESIZE);

    if (pagesize > 0 && need <= (size_t) - 1 - (size_t)pagesize) {
        need = (need + (size_t)pagesize - 1) & ~((size_t)pagesize - 1);
    }

    p = mmap(NULL, need, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);

    if (p == MAP_FAILED) {
        return NULL;
    }

    /* Locking the pages is best effort: an unprivileged process may be
     * over its RLIMIT_MEMLOCK.  The reference carries on as well, with a
     * warning, which the caller gives once it has dropped the lock. */
    if (mlock(p, need)) {
        mlock_failed = 1;
    }

#ifdef MADV_DONTDUMP
    (void)madvise(p, need, MADV_DONTDUMP);
#endif

    pool = p;
    pool->next = pools;
    pool->size = need;
    block_init(pool_blocks(pool),
               need - SECPOOL_HEADER - sizeof(struct secblock), 0);
    pools = pool;
    return pool;
}

/* First fit within one pool, merging runs of free blocks on the way. */
static void *
pool_alloc_in(struct secpool *pool, size_t n)
{
    struct secblock *b;

    for (b = pool_blocks(pool); b < pool_end(pool); b = block_next(b)) {
        struct secblock *next;

        if (b->in_use) {
            continue;
        }

        for (next = block_next(b); next < pool_end(pool) && !next->in_use;
             next = block_next(next)) {
            b->size += sizeof(struct secblock) + next->size;
        }

        if (b->size < n) {
            continue;
        }

        if (b->size - n >= sizeof(struct secblock) + SECMEM_ALIGN) {
            struct secblock *rest;

            rest = (struct secblock *)((unsigned char *)(b + 1) + n);
            block_init(rest, b->size - n - sizeof(struct secblock), 0);
            b->size = n;
        }

        b->in_use = 1;
        return b + 1;
    }

    return NULL;
}

/* A block of N bytes from any pool, mapping another pool if they are all
 * full (or there is none yet). */
static void *
pool_alloc(size_t n)
{
    struct secpool *pool;
    void *p;

    n = round_up_align(n);

    if (!n) {
        return NULL;
    }

    for (pool = pools; pool; pool = pool->next) {
        p = pool_alloc_in(pool, n);

        if (p) {
            return p;
        }
    }

    pool = pool_map(n, auto_expand_size ? auto_expand_size
                    : DEFAULT_POOL_SIZE);

    if (!pool) {
        return NULL;
    }

    return pool_alloc_in(pool, n);
}

/* Create the first pool with at least N bytes.  Must be called with the
 * lock held or before any thread is running. */
static void
pool_init(size_t n)
{
    if (pools || secmem_disabled) {
        return;
    }

    (void)pool_map(0, n < DEFAULT_POOL_SIZE ? DEFAULT_POOL_SIZE : n);
}

static int
pool_in_use(struct secpool *pool)
{
    struct secblock *b;

    for (b = pool_blocks(pool); b < pool_end(pool); b = block_next(b)) {
        if (b->in_use) {
            return 1;
        }
    }

    return 0;
}

/* Release every pool from which nothing is allocated any more; the
 * others stay, with their blocks intact. */
static void
pool_term(void)
{
    struct secpool **pp = &pools;

    while (*pp) {
        struct secpool *pool = *pp;
        size_t size = pool->size;

        if (pool_in_use(pool)) {
            pp = &pool->next;
            continue;
        }

        *pp = pool->next;
        OPENSSL_cleanse(pool, size);
        (void)munlock(pool, size);
        (void)munmap(pool, size);
    }
}

static void
pool_free(struct secblock *b)
{
    OPENSSL_cleanse(b + 1, b->size);
    b->in_use = 0;
}

/* Called without the lock: a misused pointer is a caller bug, fatal like
 * glibc's "free(): invalid pointer". */
static void
secmem_misuse(const char *what)
{
    _gcry_fatal_error(GPG_ERR_INV_ARG, what);
}

/* Called without the lock, after an allocation: the reference's warning
 * when the secure memory could not be locked into RAM. */
static void
warn_insecure(void)
{
    if (!mlock_failed || insecure_warned
        || (secmem_flags & (GCRY_SECMEM_FLAG_NO_WARNING
                            | GCRY_SECMEM_FLAG_SUSPEND_WARNING))) {
        return;
    }

    insecure_warned = 1;
    log_info("Warning: using insecure memory!\n");
}

/* ------------------------------------------------------------------ */
/* Secure memory control                                               */
/* ------------------------------------------------------------------ */

void
_gcry_secmem_init(size_t n)
{
    pthread_mutex_lock(&secmem_lock);

    if (n == 0) {
        /* Zero means "I will not use secure memory", but allocations are
         * still allowed to create a pool when they come. */
        pthread_mutex_unlock(&secmem_lock);
        return;
    }

    pool_init(n);
    pthread_mutex_unlock(&secmem_lock);
    warn_insecure();
}

void
_gcry_secmem_term(void)
{
    pthread_mutex_lock(&secmem_lock);
    pool_term();
    pthread_mutex_unlock(&secmem_lock);
}

void
_gcry_secmem_disable(void)
{
    pthread_mutex_lock(&secmem_lock);
    secmem_disabled = 1;
    pthread_mutex_unlock(&secmem_lock);
}

int
_gcry_secmem_is_disabled(void)
{
    return secmem_disabled;
}

void
_gcry_secmem_set_auto_expand(size_t chunksize)
{
    pthread_mutex_lock(&secmem_lock);

    if (chunksize && chunksize < DEFAULT_POOL_SIZE) {
        chunksize = DEFAULT_POOL_SIZE;
    }

    auto_expand_size = chunksize;
    pthread_mutex_unlock(&secmem_lock);
}

void
_gcry_secmem_set_flags(unsigned int flags)
{
    pthread_mutex_lock(&secmem_lock);
    secmem_flags = flags;
    pthread_mutex_unlock(&secmem_lock);
}

unsigned int
_gcry_secmem_get_flags(void)
{
    unsigned int flags;

    pthread_mutex_lock(&secmem_lock);
    flags = secmem_flags;
    pthread_mutex_unlock(&secmem_lock);
    return flags;
}

void
_gcry_wipememory(void *ptr, size_t len)
{
    if (ptr && len) {
        OPENSSL_cleanse(ptr, len);
    }
}

/* ------------------------------------------------------------------ */
/* Allocation                                                          */
/* ------------------------------------------------------------------ */

void *
_gcry_malloc(size_t n)
{
    if (alloc_func) {
        return alloc_func(n);
    }

    return malloc(n ? n : 1);
}

void *
_gcry_malloc_secure(size_t n)
{
    void *p;

    if (alloc_secure_func) {
        return alloc_secure_func(n);
    }

    if (secmem_disabled) {
        return malloc(n ? n : 1);
    }

    pthread_mutex_lock(&secmem_lock);
    p = pool_alloc(n);
    pthread_mutex_unlock(&secmem_lock);
    warn_insecure();

    if (!p) {
        errno = ENOMEM;
    }

    return p;
}

static void *
calloc_core(size_t n, size_t m, int secure)
{
    size_t bytes = n * m;
    void *p;

    if (m && bytes / m != n) {
        errno = ENOMEM;
        return NULL;
    }

    p = secure ? _gcry_malloc_secure(bytes) : _gcry_malloc(bytes);

    if (p) {
        memset(p, 0, bytes);
    }

    return p;
}

void *
_gcry_calloc(size_t n, size_t m)
{
    return calloc_core(n, m, 0);
}

void *
_gcry_calloc_secure(size_t n, size_t m)
{
    return calloc_core(n, m, 1);
}

int
_gcry_is_secure(const void *a)
{
    int yes;

    if (secmem_disabled || !a) {
        return 0;
    }

    if (is_secure_func) {
        return is_secure_func(a);
    }

    pthread_mutex_lock(&secmem_lock);
    yes = pool_find(a) != NULL;
    pthread_mutex_unlock(&secmem_lock);
    return yes;
}

void *
_gcry_realloc(void *a, size_t n)
{
    struct secpool *pool;
    size_t oldsize = 0;
    int valid = 1;
    void *p;

    if (realloc_func) {
        return realloc_func(a, n);
    }

    if (!a) {
        return _gcry_malloc(n);
    }

    if (!is_secure_func) {
        pthread_mutex_lock(&secmem_lock);
        pool = pool_find(a);

        if (pool) {
            struct secblock *b = pool_check_block(pool, a);

            if (b) {
                oldsize = b->size;
            } else {
                valid = 0;
            }
        }

        pthread_mutex_unlock(&secmem_lock);

        if (!valid) {
            secmem_misuse("gcry_realloc: not a live secure memory block");
        }

        if (pool) {
            p = _gcry_malloc_secure(n);

            if (p) {
                memcpy(p, a, oldsize < n ? oldsize : n);
                _gcry_free(a);
            }

            return p;
        }
    }

    return realloc(a, n ? n : 1);
}

void
_gcry_free(void *p)
{
    int save_errno;

    if (!p) {
        return;
    }

    save_errno = errno;

    if (free_func) {
        free_func(p);
    } else {
        struct secpool *pool;
        int valid = 1;

        pthread_mutex_lock(&secmem_lock);
        pool = pool_find(p);

        if (pool) {
            struct secblock *b = pool_check_block(pool, p);

            if (b) {
                pool_free(b);
            } else {
                valid = 0;
            }
        }

        pthread_mutex_unlock(&secmem_lock);

        if (!valid) {
            secmem_misuse("gcry_free: not a live secure memory block "
                          "(double free or interior pointer)");
        }

        if (!pool) {
            free(p);
        }
    }

    if (save_errno && save_errno != errno) {
        errno = save_errno;
    }
}

static char *
strdup_core(const char *string, int xhint)
{
    size_t n = strlen(string) + 1;
    char *p;

    (void)xhint;
    p = _gcry_is_secure(string) ? _gcry_malloc_secure(n) : _gcry_malloc(n);

    if (p) {
        memcpy(p, string, n);
    }

    return p;
}

char *
_gcry_strdup(const char *string)
{
    return strdup_core(string, 0);
}

static void
out_of_core(size_t n, unsigned int flags)
{
    int err = errno ? errno : ENOMEM;

    if (!_gcry_fips_mode() && outofcore_handler
        && outofcore_handler(outofcore_handler_value, n, flags)) {
        return; /* The handler asked us to retry. */
    }

    _gcry_fatal_error((int)gcry_err_code_from_errno(err), NULL);
}

void *
_gcry_xmalloc(size_t n)
{
    void *p;

    while (!(p = _gcry_malloc(n))) {
        out_of_core(n, 0);
    }

    return p;
}

void *
_gcry_xmalloc_secure(size_t n)
{
    void *p;

    while (!(p = _gcry_malloc_secure(n))) {
        out_of_core(n, 1);
    }

    return p;
}

void *
_gcry_xcalloc(size_t n, size_t m)
{
    void *p;

    while (!(p = _gcry_calloc(n, m))) {
        out_of_core(n * m, 0);
    }

    return p;
}

void *
_gcry_xcalloc_secure(size_t n, size_t m)
{
    void *p;

    while (!(p = _gcry_calloc_secure(n, m))) {
        out_of_core(n * m, 1);
    }

    return p;
}

void *
_gcry_xrealloc(void *a, size_t n)
{
    void *p;

    while (!(p = _gcry_realloc(a, n))) {
        out_of_core(n, _gcry_is_secure(a) ? 3u : 2u);
    }

    return p;
}

char *
_gcry_xstrdup(const char *string)
{
    char *p;

    while (!(p = strdup_core(string, 1))) {
        /* The reference reports the string length, not the allocation. */
        out_of_core(strlen(string), _gcry_is_secure(string) ? 1u : 0u);
    }

    return p;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void
gcry_set_allocation_handler(gcry_handler_alloc_t func_alloc,
                            gcry_handler_alloc_t func_alloc_secure,
                            gcry_handler_secure_check_t func_secure_check,
                            gcry_handler_realloc_t func_realloc,
                            gcry_handler_free_t func_free)
{
    _gcry_global_init();

    if (_gcry_fips_mode()) {
        /* Custom allocators cannot guarantee zeroisation; refused in
         * FIPS mode just like the reference implementation. */
        return;
    }

    alloc_func = func_alloc;
    alloc_secure_func = func_alloc_secure;
    is_secure_func = func_secure_check;
    realloc_func = func_realloc;
    free_func = func_free;
}

void
gcry_set_outofcore_handler(gcry_handler_no_mem_t h, void *opaque)
{
    _gcry_global_init();

    if (_gcry_fips_mode()) {
        return;
    }

    outofcore_handler = h;
    outofcore_handler_value = opaque;
}

void *
gcry_malloc(size_t n)
{
    return _gcry_malloc(n);
}

void *
gcry_calloc(size_t n, size_t m)
{
    return _gcry_calloc(n, m);
}

void *
gcry_malloc_secure(size_t n)
{
    return _gcry_malloc_secure(n);
}

void *
gcry_calloc_secure(size_t n, size_t m)
{
    return _gcry_calloc_secure(n, m);
}

void *
gcry_realloc(void *a, size_t n)
{
    return _gcry_realloc(a, n);
}

char *
gcry_strdup(const char *string)
{
    if (!string) {
        errno = EINVAL;
        return NULL;
    }

    return _gcry_strdup(string);
}

void *
gcry_xmalloc(size_t n)
{
    return _gcry_xmalloc(n);
}

void *
gcry_xcalloc(size_t n, size_t m)
{
    return _gcry_xcalloc(n, m);
}

void *
gcry_xmalloc_secure(size_t n)
{
    return _gcry_xmalloc_secure(n);
}

void *
gcry_xcalloc_secure(size_t n, size_t m)
{
    return _gcry_xcalloc_secure(n, m);
}

void *
gcry_xrealloc(void *a, size_t n)
{
    return _gcry_xrealloc(a, n);
}

char *
gcry_xstrdup(const char *a)
{
    /* The x-functions never return NULL, so a NULL input is fatal, like
     * running out of memory. */
    if (!a) {
        _gcry_fatal_error(GPG_ERR_INV_ARG, "gcry_xstrdup: NULL argument");
    }

    return _gcry_xstrdup(a);
}

void
gcry_free(void *a)
{
    _gcry_free(a);
}

int
gcry_is_secure(const void *a)
{
    return _gcry_is_secure(a);
}
