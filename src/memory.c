/*
 * memory.c - Memory allocation with optional "secure" (wiped, locked)
 * storage, plus the user-installable allocation handlers.
 *
 * Secure memory is a pool of the library's own, like the reference
 * implementation's: an anonymous mapping that is locked into RAM and kept
 * out of core dumps where the system allows it, carved up by a small
 * first-fit allocator.  That gives the two properties Libgcrypt promises,
 * wiping on free and a gcry_is_secure() that can answer for any pointer at
 * all (it is a range check), without touching OpenSSL's secure heap.  The
 * secure heap is process-wide and has no fallback once it exists, so
 * sizing it for the application's GCRYCTL_INIT_SECMEM request starved
 * OpenSSL's own callers of it, most visibly the FIPS module, whose
 * self-tests allocate their DRBG state and post-quantum keys from it.
 */
#define _DEFAULT_SOURCE 1 /* MAP_ANONYMOUS and madvise() on glibc. */

#include "gcrypt-int.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
    #define MAP_ANONYMOUS MAP_ANON
#endif

/* Same default pool size as the reference implementation. */
#define DEFAULT_POOL_SIZE 32768

/* Every block carries one of these; the payload follows it directly. */
struct secblock {
    size_t size; /* Payload size, a multiple of SECMEM_ALIGN. */
    size_t in_use; /* A size_t only to keep the header aligned. */
};

/* Payload alignment, which is also the header size: two pointer-sized
 * words, the alignment of the widest fundamental type on the platforms
 * this runs on. */
#define SECMEM_ALIGN sizeof(struct secblock)

static gcry_handler_alloc_t alloc_func;
static gcry_handler_alloc_t alloc_secure_func;
static gcry_handler_secure_check_t is_secure_func;
static gcry_handler_realloc_t realloc_func;
static gcry_handler_free_t free_func;

static gcry_handler_no_mem_t outofcore_handler;
static void *outofcore_handler_value;

static pthread_mutex_t secmem_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned char *pool; /* NULL while there is no pool. */
static size_t pool_size;
static int secmem_disabled;

/* ------------------------------------------------------------------ */
/* The secure pool.  All of these expect the lock to be held.          */
/* ------------------------------------------------------------------ */

static struct secblock *
block_next(struct secblock *b)
{
    return (struct secblock *)((unsigned char *)(b + 1) + b->size);
}

static struct secblock *
pool_end(void)
{
    return (struct secblock *)(pool + pool_size);
}

static int
pool_contains(const void *p)
{
    const unsigned char *a = p;

    return pool && a >= pool + sizeof(struct secblock) && a < pool + pool_size;
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

/* Create the pool with at least N bytes.  Must be called with the lock
 * held or before any thread is running. */
static void
pool_init(size_t n)
{
    long pagesize;
    void *p;

    if (pool || secmem_disabled) {
        return;
    }

    if (n < DEFAULT_POOL_SIZE) {
        n = DEFAULT_POOL_SIZE;
    }

    pagesize = sysconf(_SC_PAGESIZE);

    if (pagesize > 0) {
        n = (n + (size_t)pagesize - 1) & ~((size_t)pagesize - 1);
    }

    p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);

    if (p == MAP_FAILED) {
        return; /* Allocations fall back to the ordinary heap. */
    }

    /* Locking the pages is best effort: an unprivileged process may be
     * over its RLIMIT_MEMLOCK, and the reference carries on as well. */
    (void)mlock(p, n);
#ifdef MADV_DONTDUMP
    (void)madvise(p, n, MADV_DONTDUMP);
#endif

    pool = p;
    pool_size = n;
    ((struct secblock *)pool)->size = n - sizeof(struct secblock);
    ((struct secblock *)pool)->in_use = 0;
}

/* Release the pool unless something is still allocated from it. */
static int
pool_term(void)
{
    struct secblock *b;

    if (!pool) {
        return 1;
    }

    for (b = (struct secblock *)pool; b < pool_end(); b = block_next(b)) {
        if (b->in_use) {
            return 0;
        }
    }

    OPENSSL_cleanse(pool, pool_size);
    (void)munlock(pool, pool_size);
    (void)munmap(pool, pool_size);
    pool = NULL;
    pool_size = 0;
    return 1;
}

/* First fit, merging runs of free blocks on the way. */
static void *
pool_alloc(size_t n)
{
    struct secblock *b;

    n = round_up_align(n);

    if (!pool || !n) {
        return NULL;
    }

    for (b = (struct secblock *)pool; b < pool_end(); b = block_next(b)) {
        struct secblock *next;

        if (b->in_use) {
            continue;
        }

        for (next = block_next(b); next < pool_end() && !next->in_use;
             next = block_next(next)) {
            b->size += sizeof(struct secblock) + next->size;
        }

        if (b->size < n) {
            continue;
        }

        if (b->size - n >= sizeof(struct secblock) + SECMEM_ALIGN) {
            struct secblock *rest;

            rest = (struct secblock *)((unsigned char *)(b + 1) + n);
            rest->size = b->size - n - sizeof(struct secblock);
            rest->in_use = 0;
            b->size = n;
        }

        b->in_use = 1;
        return b + 1;
    }

    return NULL;
}

static size_t
pool_block_size(const void *p)
{
    const struct secblock *b = (const struct secblock *)p - 1;

    return b->size;
}

static void
pool_free(void *p)
{
    struct secblock *b = (struct secblock *)p - 1;

    OPENSSL_cleanse(p, b->size);
    b->in_use = 0;
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
         * still allowed to fall back to the normal heap. */
        pthread_mutex_unlock(&secmem_lock);
        return;
    }

    pool_init(n);
    pthread_mutex_unlock(&secmem_lock);
}

void
_gcry_secmem_term(void)
{
    pthread_mutex_lock(&secmem_lock);
    (void)pool_term();
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
    pool_init(DEFAULT_POOL_SIZE);
    p = pool_alloc(n);
    pthread_mutex_unlock(&secmem_lock);

    if (!p) {
        /* Pool exhausted or unavailable: degrade gracefully. */
        p = malloc(n ? n : 1);
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

/* Is A in the pool?  Takes the lock; SIZE, when given, receives the block
 * size if it is. */
static int
secure_block(const void *a, size_t *size)
{
    int yes;

    pthread_mutex_lock(&secmem_lock);
    yes = pool_contains(a);

    if (yes && size) {
        *size = pool_block_size(a);
    }

    pthread_mutex_unlock(&secmem_lock);
    return yes;
}

int
_gcry_is_secure(const void *a)
{
    if (secmem_disabled || !a) {
        return 0;
    }

    if (is_secure_func) {
        return is_secure_func(a);
    }

    return secure_block(a, NULL);
}

void *
_gcry_realloc(void *a, size_t n)
{
    size_t oldsize;
    void *p;

    if (realloc_func) {
        return realloc_func(a, n);
    }

    if (!a) {
        return _gcry_malloc(n);
    }

    if (!is_secure_func && secure_block(a, &oldsize)) {
        p = _gcry_malloc_secure(n);

        if (p) {
            memcpy(p, a, oldsize < n ? oldsize : n);
            _gcry_free(a);
        }

        return p;
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
        int secure;

        pthread_mutex_lock(&secmem_lock);
        secure = pool_contains(p);

        if (secure) {
            pool_free(p);
        }

        pthread_mutex_unlock(&secmem_lock);

        if (!secure) {
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
