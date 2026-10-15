/*
 * memory.c - Memory allocation with optional "secure" (wiped, locked)
 * storage, plus the user-installable allocation handlers.
 *
 * Secure memory is provided by OpenSSL's secure heap.  It gives us the two
 * properties Libgcrypt promises: the memory is wiped when freed and
 * gcry_is_secure() can answer the question for any pointer at all, because
 * it is a simple range check.
 */
#include "gcrypt-int.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Same default pool size as the reference implementation. */
#define DEFAULT_POOL_SIZE 32768
#define MIN_SECURE_BLOCK 32

static gcry_handler_alloc_t alloc_func;
static gcry_handler_alloc_t alloc_secure_func;
static gcry_handler_secure_check_t is_secure_func;
static gcry_handler_realloc_t realloc_func;
static gcry_handler_free_t free_func;

static gcry_handler_no_mem_t outofcore_handler;
static void *outofcore_handler_value;

static pthread_mutex_t secmem_lock = PTHREAD_MUTEX_INITIALIZER;
static int secmem_initialized;
static int secmem_disabled;

static size_t
round_up_pow2(size_t n)
{
    size_t p = 1;

    while (p < n && p) {
        p <<= 1;
    }

    return p ? p : n;
}

/* Initialise the secure pool with at least N bytes.  Must be called with
 * the lock held or before any thread is running. */
static void
secmem_init_locked(size_t n)
{
    if (secmem_initialized || secmem_disabled) {
        return;
    }

    if (n < DEFAULT_POOL_SIZE) {
        n = DEFAULT_POOL_SIZE;
    }

    n = round_up_pow2(n);

    if (CRYPTO_secure_malloc_init(n, MIN_SECURE_BLOCK) != 0) {
        secmem_initialized = 1;
    }
}

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

    secmem_init_locked(n);
    pthread_mutex_unlock(&secmem_lock);
}

void
_gcry_secmem_term(void)
{
    pthread_mutex_lock(&secmem_lock);

    if (secmem_initialized && CRYPTO_secure_malloc_done()) {
        secmem_initialized = 0;
    }

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
    secmem_init_locked(DEFAULT_POOL_SIZE);
    pthread_mutex_unlock(&secmem_lock);

    p = CRYPTO_secure_malloc(n ? n : 1, OPENSSL_FILE, OPENSSL_LINE);

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

int
_gcry_is_secure(const void *a)
{
    if (secmem_disabled || !a) {
        return 0;
    }

    if (is_secure_func) {
        return is_secure_func(a);
    }

    return CRYPTO_secure_allocated(a);
}

void *
_gcry_realloc(void *a, size_t n)
{
    void *p;

    if (realloc_func) {
        return realloc_func(a, n);
    }

    if (!a) {
        return _gcry_malloc(n);
    }

    if (!is_secure_func && CRYPTO_secure_allocated(a)) {
        size_t oldsize = CRYPTO_secure_actual_size(a);

        p = _gcry_malloc_secure(n);

        if (p) {
            memcpy(p, a, oldsize < n ? oldsize : n);
            CRYPTO_secure_free(a, OPENSSL_FILE, OPENSSL_LINE);
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
    } else if (CRYPTO_secure_allocated(p)) {
        CRYPTO_secure_free(p, OPENSSL_FILE, OPENSSL_LINE);
    } else {
        free(p);
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
