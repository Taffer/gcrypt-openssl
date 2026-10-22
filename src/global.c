/*
 * global.c - Library initialisation, version check, gcry_control() and the
 * OpenSSL library context that every other module fetches from.
 */
#include "gcrypt-int.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static int any_init_done;
static int init_finished;
static int force_fips_mode = -1; /* -1 undecided, 0 off, 1 on. */
static int fips_mode;
static int fips_error_state; /* FIPS mode required but not established. */
static int no_fips_mode_required;
static unsigned int debug_flags;
static int preferred_rng_type;
static int quick_random; /* GCRYCTL_ENABLE_QUICK_RANDOM was used. */
static unsigned int fips_reject_flags = GCRY_FIPS_FLAG_REJECT_DEFAULT;
static OSSL_LIB_CTX *libctx;

/* The cc and cpu-arch lines of gcry_get_config().  Chosen with macros at
 * file scope: a preprocessor chain inside an expression defeats some
 * source analysers' C parsers and costs the whole file their coverage. */
#ifdef __GNUC__
    #define CC_VERSION _GCRY_GCC_VERSION
#else
    #define CC_VERSION 0
#endif
#if defined(__clang__)
    #define CC_NAME "clang:" __VERSION__
#elif defined(__GNUC__)
    #define CC_NAME "gcc:" __VERSION__
#else
    #define CC_NAME ":"
#endif
#if defined(__x86_64__) || defined(_M_X64)
    #define CPU_ARCH "x86:amd64"
#elif defined(__i386__) || defined(_M_IX86)
    #define CPU_ARCH "x86:i386"
#elif defined(__aarch64__) || defined(__arm__)
    #define CPU_ARCH "arm"
#elif defined(__powerpc__)
    #define CPU_ARCH "ppc"
#elif defined(__s390x__)
    #define CPU_ARCH "s390x"
#elif defined(__riscv)
    #define CPU_ARCH "riscv"
#else
    #define CPU_ARCH ""
#endif

/* va_arg() takes a type where C otherwise expects an expression, which
 * the same parsers reject; gcry_control() fetches its arguments through
 * these so the statements stay analysable. */
#define ARG_INT(ap) va_arg(ap, int)
#define ARG_UINT(ap) va_arg(ap, unsigned int)
#define ARG_STR(ap) va_arg(ap, const char *)
#define ARG_INT_PTR(ap) va_arg(ap, int *)
#define ARG_FILE_PTR(ap) va_arg(ap, FILE *)
#define ARG_BUFFER_PTR(ap) va_arg(ap, gcry_buffer_t *)

/* Does the operating system ask for FIPS mode?  Mirrors the reference
 * implementation's checks of /proc/sys/crypto/fips_enabled and the
 * /etc/gcrypt/fips_enabled marker file.  A build with GCRYPT_OPENSSL_FIPS
 * answers yes unconditionally, as if the marker file were present. */
static int
system_wants_fips(void)
{
#ifdef GCRYPT_OPENSSL_FIPS
    return 1;
#else
    FILE *fp;
    int c;

    fp = fopen("/etc/gcrypt/fips_enabled", "r");

    if (fp) {
        fclose(fp);
        return 1;
    }

    fp = fopen("/proc/sys/crypto/fips_enabled", "r");

    if (!fp) {
        return 0;
    }

    c = fgetc(fp);
    fclose(fp);
    return c == '1';
#endif
}

/* OpenSSL's reason for the most recent failure, for the error-state log.
 * Empty when the error queue has nothing to say. */
static char fips_failure_reason[256];

static void
remember_openssl_error(void)
{
    unsigned long err = ERR_peek_last_error();

    if (err) {
        ERR_error_string_n(err, fips_failure_reason,
                           sizeof fips_failure_reason);
    }

    ERR_clear_error();
}

static int
try_enable_fips(void)
{
    if (!OSSL_PROVIDER_available(libctx, "fips")) {
        OSSL_PROVIDER *fips = OSSL_PROVIDER_load(libctx, "fips");

        if (!fips) {
            remember_openssl_error();
            return 0;
        }
    }

    if (!EVP_default_properties_enable_fips(libctx, 1)) {
        remember_openssl_error();
        return 0;
    }

    return 1;
}

/* A configuration may activate the FIPS provider without making fips=yes
 * the default property (Chainguard's images do that, for instance).  Only
 * approved algorithms are then meant to be available, which is FIPS mode
 * in every way that matters here, so treat it as such.  Once a
 * configuration activated a provider, OpenSSL no longer loads the default
 * provider as a fallback, which is why its absence is meaningful. */
static int
fips_provider_only(void)
{
    return OSSL_PROVIDER_available(libctx, "fips")
           && !OSSL_PROVIDER_available(libctx, "default");
}

/* FIPS mode was required (by the system, the build, the application or
 * a FIPS-only provider set) but the FIPS provider cannot be activated.
 * The reference library then enters an error state in which it is not
 * operational: the self test reports a failure and every cryptographic
 * operation is refused.  The library stays in FIPS mode, so the policy
 * checks of the algorithm modules remain in force, and the fips=yes
 * property query is kept as the default: no algorithm of the providers
 * that are present satisfies it, so every fetch fails and nothing runs on
 * a non-validated implementation.  _gcry_fips_error_state() lets the
 * modules report GPG_ERR_NOT_OPERATIONAL explicitly. */
static void
enter_fips_error_state(void)
{
    fips_error_state = 1;
    fips_mode = 1;

    if (!EVP_default_properties_enable_fips(libctx, 1)) {
        ERR_clear_error();
    }

    if (fips_failure_reason[0]) {
        log_error("FIPS mode is required but no FIPS provider could be "
                  "activated (%s): the library is not operational\n",
                  fips_failure_reason);
    } else {
        log_error("FIPS mode is required but no FIPS provider could be "
                  "activated: the library is not operational\n");
    }
}

static void
do_global_init(void)
{
    int want_fips;

    libctx = OSSL_LIB_CTX_new();

    if (!libctx) {
        _gcry_fatal_error(GPG_ERR_ENOMEM, "cannot create OpenSSL context");
    }

    /* Honour the system OpenSSL configuration (which may activate the FIPS
     * provider), but never fail because of it. */
    if (!OSSL_LIB_CTX_load_config(libctx, NULL)) {
        ERR_clear_error();
    }

    /* Old and weak algorithms that Libgcrypt offers live in the legacy
     * provider.  Keep the fallback behaviour so that the default provider
     * is still activated implicitly on first use. */
    if (!OSSL_PROVIDER_try_load(libctx, "legacy", 1)) {
        ERR_clear_error();
    }

    want_fips = force_fips_mode;

    if (want_fips < 0) {
        want_fips = system_wants_fips();
    }

    if (want_fips && !no_fips_mode_required) {
        fips_mode = try_enable_fips();

        if (!fips_mode) {
            enter_fips_error_state();
        }
    } else if (EVP_default_properties_is_fips_enabled(libctx) > 0) {
        fips_mode = 1;
    } else if (fips_provider_only()) {
        /* Make the property explicit so that the legacy provider loaded
         * above cannot supply non-approved algorithms either. */
        fips_mode = try_enable_fips();

        if (!fips_mode) {
            enter_fips_error_state();
        }
    }

    any_init_done = 1;
}

void
_gcry_global_init(void)
{
    pthread_once(&init_once, do_global_init);
}

OSSL_LIB_CTX *
_gcry_libctx(void)
{
    _gcry_global_init();
    return libctx;
}

const char *
_gcry_propq(void)
{
    return NULL;
}

int
_gcry_fips_mode(void)
{
    if (!any_init_done) {
        return 0;
    }

    return fips_mode;
}

int
_gcry_fips_error_state(void)
{
    if (!any_init_done) {
        return 0;
    }

    return fips_error_state;
}

unsigned int
_gcry_get_debug_flags(void)
{
    return debug_flags;
}

int
_gcry_get_rng_type(void)
{
    if (preferred_rng_type) {
        return preferred_rng_type;
    }

    return _gcry_fips_mode() ? GCRY_RNG_TYPE_FIPS : GCRY_RNG_TYPE_STANDARD;
}

/* ------------------------------------------------------------------ */
/* Generic context objects                                             */
/* ------------------------------------------------------------------ */

struct gcry_context {
    int type;
    void (*deinit)(void *);
    union {
        long l;
        void *p;
        double d;
    } align;
    /* Payload follows. */
};

#define CTX_PAYLOAD(ctx) ((void *)((unsigned char *)(ctx) \
                                   + sizeof(struct gcry_context)))

gcry_ctx_t
_gcry_ctx_alloc(int type, size_t length, void (*deinit)(void *))
{
    gcry_ctx_t ctx = _gcry_calloc(1, sizeof * ctx + length);

    if (!ctx) {
        return NULL;
    }

    ctx->type = type;
    ctx->deinit = deinit;
    return ctx;
}

void *
_gcry_ctx_get_pointer(gcry_ctx_t ctx, int type)
{
    if (!ctx) {
        return NULL;
    }

    if (ctx->type != type) {
        log_error("context type mismatch: expected %d, got %d\n", type,
                  ctx->type);
        BUG();
    }

    return CTX_PAYLOAD(ctx);
}

void *
_gcry_ctx_find_pointer(gcry_ctx_t ctx, int type)
{
    if (!ctx || ctx->type != type) {
        return NULL;
    }

    return CTX_PAYLOAD(ctx);
}

void
gcry_ctx_release(gcry_ctx_t ctx)
{
    if (!ctx) {
        return;
    }

    if (ctx->deinit) {
        ctx->deinit(CTX_PAYLOAD(ctx));
    }

    _gcry_free(ctx);
}

/* ------------------------------------------------------------------ */
/* Version                                                             */
/* ------------------------------------------------------------------ */

static const char *
parse_version_number(const char *s, int *number)
{
    int val = 0;

    if (*s == '0' && isdigit((unsigned char)s[1])) {
        return NULL; /* No leading zeros. */
    }

    for (; isdigit((unsigned char) * s); s++) {
        val *= 10;
        val += *s - '0';
    }

    *number = val;
    return val < 0 ? NULL : s;
}

static const char *
parse_version_string(const char *s, int *major, int *minor, int *micro)
{
    s = parse_version_number(s, major);

    if (!s || *s != '.') {
        return NULL;
    }

    s++;
    s = parse_version_number(s, minor);

    if (!s || *s != '.') {
        return NULL;
    }

    s++;
    s = parse_version_number(s, micro);
    return s;
}

const char *
gcry_check_version(const char *req_version)
{
    const char *ver = GCRYPT_VERSION;
    int my_major;
    int my_minor;
    int my_micro;
    int rq_major;
    int rq_minor;
    int rq_micro;

    if (req_version && req_version[0] == 1 && req_version[1] == 1) {
        return "\n\n"
               "This is gcrypt-openssl " GCRYPT_OPENSSL_VERSION_STRING
               " - the Libgcrypt API implemented on OpenSSL\n"
               "Public domain.\n\n"
               "(" OPENSSL_VERSION_TEXT ")\n";
    }

    _gcry_global_init();

    if (!req_version) {
        return ver;
    }

    if (!parse_version_string(ver, &my_major, &my_minor, &my_micro)) {
        return NULL;
    }

    if (!parse_version_string(req_version, &rq_major, &rq_minor,
                              &rq_micro)) {
        return NULL;
    }

    if (my_major > rq_major
        || (my_major == rq_major && my_minor > rq_minor)
        || (my_major == rq_major && my_minor == rq_minor
            && my_micro >= rq_micro)) {
        return ver;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/* Configuration report                                                */
/* ------------------------------------------------------------------ */

struct strbuf {
    char *data;
    size_t len;
    size_t cap;
    int oom;
};

static void strbuf_addf(struct strbuf *sb, const char *fmt, ...)
_GCRY_GCC_ATTR_PRINTF(2, 3);

static void
strbuf_addf(struct strbuf *sb, const char *fmt, ...)
{
    va_list ap;
    int n;

    for (;;) {
        size_t avail = sb->cap - sb->len;

        va_start(ap, fmt);
        n = vsnprintf(sb->data ? sb->data + sb->len : NULL, avail, fmt, ap);
        va_end(ap);

        if (n < 0) {
            sb->oom = 1;
            return;
        }

        if ((size_t)n < avail) {
            sb->len += (size_t)n;
            return;
        }

        {
            size_t newcap = sb->cap ? sb->cap * 2 : 256;
            char *p;

            while (newcap < sb->len + (size_t)n + 1) {
                newcap *= 2;
            }

            p = _gcry_realloc(sb->data, newcap);

            if (!p) {
                sb->oom = 1;
                return;
            }

            sb->data = p;
            sb->cap = newcap;
        }
    }
}

static pthread_once_t fips_version_once = PTHREAD_ONCE_INIT;
static char fips_version[64]; /* Empty until known. */

static void
fips_version_init(void)
{
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(libctx, "fips");
    OSSL_PARAM params[2];
    char *ptr = NULL;

    if (!prov) {
        ERR_clear_error();
        return;
    }

    /* The provider answers with a pointer to its own static string; copy
     * it so that the result does not depend on the provider's lifetime. */
    params[0] = OSSL_PARAM_construct_utf8_ptr("version", &ptr, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (OSSL_PROVIDER_get_params(prov, params) && ptr) {
        snprintf(fips_version, sizeof fips_version, "%s", ptr);
    } else {
        ERR_clear_error();
    }

    /* Drop the reference taken above; whoever activated the provider in
     * the first place keeps it loaded. */
    OSSL_PROVIDER_unload(prov);
}

/* The FIPS provider's version in FIPS mode, "" otherwise.  Computed once:
 * the string is static and the provider's reference count must not grow
 * with every configuration report. */
static const char *
fips_provider_version(void)
{
    if (!_gcry_fips_mode()) {
        return "";
    }

    pthread_once(&fips_version_once, fips_version_init);
    return fips_version;
}

static void
print_config(const char *what, struct strbuf *sb)
{
    if (!what || !strcmp(what, "version")) {
        strbuf_addf(sb, "version:%s:%x:%s:%lx:\n", GCRYPT_VERSION,
                    GCRYPT_VERSION_NUMBER, OPENSSL_VERSION_STR,
                    (unsigned long)OPENSSL_VERSION_NUMBER);
    }

    if (!what || !strcmp(what, "cc")) {
        strbuf_addf(sb, "cc:%d:%s:\n", CC_VERSION, CC_NAME);
    }

    if (!what || !strcmp(what, "ciphers")) {
        strbuf_addf(sb, "ciphers:%s:\n",
                    "idea:3des:cast5:blowfish:aes:rfc2268:seed:camellia:"
                    "chacha20:sm4:aria:arcfour:des");
    }

    if (!what || !strcmp(what, "pubkeys")) {
        strbuf_addf(sb, "pubkeys:%s:\n", "dsa:elgamal:rsa:ecc");
    }

    if (!what || !strcmp(what, "digests")) {
        strbuf_addf(sb, "digests:%s:\n",
                    "crc:md4:md5:rmd160:sha1:sha256:sha512:sha3:whirlpool:"
                    "blake2:sm3");
    }

    if (!what || !strcmp(what, "rnd-mod")) {
        strbuf_addf(sb, "rnd-mod:openssl:\n");
    }

    if (!what || !strcmp(what, "cpu-arch")) {
        strbuf_addf(sb, "cpu-arch:%s:\n", CPU_ARCH);
    }

    if (!what || !strcmp(what, "mpi-asm")) {
        strbuf_addf(sb, "mpi-asm:openssl-bn:\n");
    }

    if (!what || !strcmp(what, "mpi-pow")) {
        strbuf_addf(sb, "mpi-powm:openssl-bn\n");
    }

    if (!what || !strcmp(what, "hwflist")) {
        strbuf_addf(sb, "hwflist:\n");
    }

    if (!what || !strcmp(what, "fips-mode")) {
        strbuf_addf(sb, "fips-mode:%c::%s:\n", _gcry_fips_mode() ? 'y' : 'n',
                    fips_provider_version());
    }

    /* Not a reference item: whether FIPS mode was required but could not
     * be established, in which case the library is not operational. */
    if (!what || !strcmp(what, "fips-error")) {
        strbuf_addf(sb, "fips-error:%c:\n", fips_error_state ? 'y' : 'n');
    }

    if (!what || !strcmp(what, "rng-type")) {
        int t = _gcry_get_rng_type();
        const char *s = t == GCRY_RNG_TYPE_FIPS ? "fips"
                        : t == GCRY_RNG_TYPE_SYSTEM ? "system" : "standard";

        strbuf_addf(sb, "rng-type:%s:%d:%u:%d:\n", s, t, 0u, 0);
    }

    if (!what || !strcmp(what, "compliance")) {
        strbuf_addf(sb, "compliance:%s::\n", "");
    }

    if (!what || !strcmp(what, "backend")) {
        strbuf_addf(sb, "backend:gcrypt-openssl:%s:%s:\n",
                    GCRYPT_OPENSSL_VERSION_STRING,
                    OpenSSL_version(OPENSSL_VERSION));
    }
}

char *
gcry_get_config(int mode, const char *what)
{
    struct strbuf sb = { NULL, 0, 0, 0 };

    if (mode) {
        errno = EINVAL;
        return NULL;
    }

    _gcry_global_init();
    print_config(what, &sb);

    if (sb.oom) {
        _gcry_free(sb.data);
        errno = ENOMEM;
        return NULL;
    }

    if (!sb.data) {
        errno = 0; /* Unknown WHAT: nothing printed. */
        return NULL;
    }

    if (what) {
        char *p = strchr(sb.data, '\n');

        if (p) {
            *p = 0;
        }
    }

    return sb.data;
}

/* ------------------------------------------------------------------ */
/* FIPS service indicators                                             */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
fips_indicator_cipher(int algo, int mode)
{
    switch (algo) {
    case GCRY_CIPHER_AES:
    case GCRY_CIPHER_AES192:
    case GCRY_CIPHER_AES256:
        break;

    default:
        return GPG_ERR_NOT_SUPPORTED;
    }

    switch (mode) {
    case GCRY_CIPHER_MODE_ECB:
    case GCRY_CIPHER_MODE_CBC:
    case GCRY_CIPHER_MODE_CFB:
    case GCRY_CIPHER_MODE_CFB8:
    case GCRY_CIPHER_MODE_OFB:
    case GCRY_CIPHER_MODE_CTR:
    case GCRY_CIPHER_MODE_CCM:
    case GCRY_CIPHER_MODE_GCM:
    case GCRY_CIPHER_MODE_XTS:
    case GCRY_CIPHER_MODE_AESWRAP:
        return 0;

    default:
        return GPG_ERR_NOT_SUPPORTED;
    }
}

static gcry_err_code_t
fips_indicator_md(int algo)
{
    switch (algo) {
    case GCRY_MD_SHA1:
    case GCRY_MD_SHA224:
    case GCRY_MD_SHA256:
    case GCRY_MD_SHA384:
    case GCRY_MD_SHA512:
    case GCRY_MD_SHA512_224:
    case GCRY_MD_SHA512_256:
    case GCRY_MD_SHA3_224:
    case GCRY_MD_SHA3_256:
    case GCRY_MD_SHA3_384:
    case GCRY_MD_SHA3_512:
    case GCRY_MD_SHAKE128:
    case GCRY_MD_SHAKE256:
    case GCRY_MD_CSHAKE128:
    case GCRY_MD_CSHAKE256:
        return 0;

    default:
        return GPG_ERR_NOT_SUPPORTED;
    }
}

static gcry_err_code_t
fips_indicator_mac(int algo)
{
    switch (algo) {
    case GCRY_MAC_HMAC_SHA1:
    case GCRY_MAC_HMAC_SHA224:
    case GCRY_MAC_HMAC_SHA256:
    case GCRY_MAC_HMAC_SHA384:
    case GCRY_MAC_HMAC_SHA512:
    case GCRY_MAC_HMAC_SHA512_224:
    case GCRY_MAC_HMAC_SHA512_256:
    case GCRY_MAC_HMAC_SHA3_224:
    case GCRY_MAC_HMAC_SHA3_256:
    case GCRY_MAC_HMAC_SHA3_384:
    case GCRY_MAC_HMAC_SHA3_512:
    case GCRY_MAC_CMAC_AES:
        return 0;

    default:
        return GPG_ERR_NOT_SUPPORTED;
    }
}

static gcry_err_code_t
fips_indicator_kdf(int algo)
{
    /* The reference approves PBKDF2 alone. */
    return algo == GCRY_KDF_PBKDF2 ? 0 : GPG_ERR_NOT_SUPPORTED;
}

static gcry_err_code_t
fips_indicator_function(const char *name)
{
    /* Only the functions that have an approved alternative are flagged,
     * exactly the set the reference library names. */
    static const char *const forbidden[] = {
        "gcry_pk_encrypt", "gcry_pk_decrypt", "gcry_pk_sign",
        "gcry_pk_verify", "gcry_pk_random_override_new"
    };
    size_t i;

    if (!name) {
        return GPG_ERR_INV_ARG;
    }

    for (i = 0; i < DIM(forbidden); i++) {
        if (!strcmp(forbidden[i], name)) {
            return GPG_ERR_NOT_SUPPORTED;
        }
    }

    return 0;
}

static gcry_err_code_t
fips_indicator_pk_flags(const char *flags)
{
    if (!flags) {
        return GPG_ERR_INV_ARG;
    }

    if (!strcmp(flags, "raw") || !strcmp(flags, "pkcs1")
        || !strcmp(flags, "pss") || !strcmp(flags, "eddsa")) {
        return 0;
    }

    return GPG_ERR_NOT_SUPPORTED;
}

/* ------------------------------------------------------------------ */
/* Self test                                                           */
/* ------------------------------------------------------------------ */

static int
selftest_provider_cb(OSSL_PROVIDER *prov, void *cbdata)
{
    int *failed = cbdata;

    if (!OSSL_PROVIDER_self_test(prov)) {
        ERR_clear_error();
        *failed = 1;
    }

    return 1;
}

static gcry_err_code_t
run_selftests(void)
{
    int failed = 0;

    _gcry_global_init();

    if (!OSSL_PROVIDER_do_all(libctx, selftest_provider_cb, &failed)) {
        ERR_clear_error();
        return GPG_ERR_SELFTEST_FAILED;
    }

    return failed ? GPG_ERR_SELFTEST_FAILED : 0;
}

/* ------------------------------------------------------------------ */
/* gcry_control                                                        */
/* ------------------------------------------------------------------ */

static gcry_err_code_t
vcontrol(enum gcry_ctl_cmds cmd, va_list arg_ptr)
{
    gcry_err_code_t rc = 0;

    switch (cmd) {
    case GCRYCTL_ENABLE_M_GUARD:
        rc = GPG_ERR_NOT_SUPPORTED;
        break;

    case GCRYCTL_ENABLE_QUICK_RANDOM:
        /* OpenSSL's DRBG is always fast, but remember the request so
         * that GCRYCTL_FAKED_RANDOM_P answers like the reference. */
        quick_random = 1;
        break;

    case GCRYCTL_FAKED_RANDOM_P:
        /* "True" (an error code) once quick random was enabled. */
        rc = quick_random ? GPG_ERR_GENERAL : 0;
        break;

    case GCRYCTL_DUMP_RANDOM_STATS:
    case GCRYCTL_DUMP_MEMORY_STATS:
    case GCRYCTL_DUMP_SECMEM_STATS:
        break;

    case GCRYCTL_DROP_PRIVS:
        _gcry_global_init();
        break;

    case GCRYCTL_DISABLE_SECMEM:
        _gcry_global_init();

        if (!_gcry_fips_mode()) {
            _gcry_secmem_disable();
        }

        break;

    case GCRYCTL_INIT_SECMEM:
        _gcry_global_init();
        _gcry_secmem_init(ARG_UINT(arg_ptr));
        break;

    case GCRYCTL_TERM_SECMEM:
        _gcry_global_init();
        _gcry_secmem_term();
        break;

    case GCRYCTL_DISABLE_SECMEM_WARN:
        _gcry_secmem_set_flags(_gcry_secmem_get_flags()
                               | GCRY_SECMEM_FLAG_NO_WARNING);
        break;

    case GCRYCTL_SUSPEND_SECMEM_WARN:
        _gcry_secmem_set_flags(_gcry_secmem_get_flags()
                               | GCRY_SECMEM_FLAG_SUSPEND_WARNING);
        break;

    case GCRYCTL_RESUME_SECMEM_WARN:
        _gcry_secmem_set_flags(_gcry_secmem_get_flags()
                               & ~GCRY_SECMEM_FLAG_SUSPEND_WARNING);
        break;

    case GCRYCTL_DISABLE_LOCKED_SECMEM:
    case GCRYCTL_DISABLE_PRIV_DROP:
        break;

    case GCRYCTL_AUTO_EXPAND_SECMEM:
        _gcry_secmem_set_auto_expand(ARG_UINT(arg_ptr));
        break;

    case GCRYCTL_USE_SECURE_RNDPOOL:
        _gcry_global_init();
        break;

    case GCRYCTL_SET_RANDOM_SEED_FILE:
        if (!ARG_STR(arg_ptr)) {
            rc = GPG_ERR_INV_ARG;
        }

        break;

    case GCRYCTL_UPDATE_RANDOM_SEED_FILE:
        break;

    case GCRYCTL_SET_VERBOSITY:
        _gcry_set_log_verbosity(ARG_INT(arg_ptr));
        break;

    case GCRYCTL_SET_DEBUG_FLAGS:
        debug_flags |= ARG_UINT(arg_ptr);
        break;

    case GCRYCTL_CLEAR_DEBUG_FLAGS:
        debug_flags &= ~ARG_UINT(arg_ptr);
        break;

    case GCRYCTL_DISABLE_INTERNAL_LOCKING:
        _gcry_global_init();
        break;

    case GCRYCTL_ANY_INITIALIZATION_P:
        if (any_init_done) {
            rc = GPG_ERR_GENERAL; /* Used as TRUE. */
        }

        break;

    case GCRYCTL_INITIALIZATION_FINISHED_P:
        if (init_finished) {
            rc = GPG_ERR_GENERAL;
        }

        break;

    case GCRYCTL_INITIALIZATION_FINISHED:
        if (!init_finished) {
            _gcry_global_init();
            init_finished = 1;
        }

        break;

    case GCRYCTL_SET_THREAD_CBS:
        _gcry_global_init();
        break;

    case GCRYCTL_FAST_POLL:
        _gcry_global_init();
        break;

    case GCRYCTL_SET_RNDEGD_SOCKET:
    case GCRYCTL_SET_RANDOM_DAEMON_SOCKET:
        (void)ARG_STR(arg_ptr);
        rc = GPG_ERR_NOT_SUPPORTED;
        break;

    case GCRYCTL_USE_RANDOM_DAEMON:
        rc = GPG_ERR_NOT_SUPPORTED;
        break;

    case GCRYCTL_CLOSE_RANDOM_DEVICE:
        break;

    case GCRYCTL_PRINT_CONFIG: {
        FILE *fp = ARG_FILE_PTR(arg_ptr);
        char *tmpstr = gcry_get_config(0, NULL);

        if (tmpstr) {
            if (fp) {
                fputs(tmpstr, fp);
            } else {
                log_info("%s", tmpstr);
            }

            _gcry_free(tmpstr);
        }

        break;
    }

    case GCRYCTL_OPERATIONAL_P:
        /* "True" (an error code) unless FIPS mode was required and could
         * not be established. */
        _gcry_global_init();
        rc = fips_error_state ? 0 : GPG_ERR_GENERAL;
        break;

    case GCRYCTL_FIPS_MODE_P:
        if (_gcry_fips_mode()) {
            rc = GPG_ERR_GENERAL;
        }

        break;

    case GCRYCTL_FORCE_FIPS_MODE:
        if (!any_init_done) {
            force_fips_mode = 1;
        } else {
            /* Too late to switch; the reference answers the same way
             * whether or not FIPS mode is active. */
            rc = GPG_ERR_GENERAL;
        }

        break;

    case GCRYCTL_NO_FIPS_MODE:
        if (!any_init_done) {
            force_fips_mode = 0;
        } else if (!init_finished && !fips_mode) {
            /* Before INITIALIZATION_FINISHED the request may still be
             * withdrawn, but only while nothing has established FIPS
             * mode: the OpenSSL context cannot leave it once the fips=yes
             * property is in force or only the FIPS provider is there,
             * and the policy checks must not come apart from it. */
            no_fips_mode_required = 1;
        } else {
            rc = GPG_ERR_GENERAL;
        }

        break;

    case GCRYCTL_SELFTEST:
        _gcry_global_init();
        rc = fips_error_state ? GPG_ERR_SELFTEST_FAILED : run_selftests();
        break;

    case GCRYCTL_FIPS_SERVICE_INDICATOR:
        /* The reference tracks the last operation per thread; nothing
         * here is ever marked non-approved, so the answer is "approved". */
        break;

    case GCRYCTL_FIPS_REJECT_NON_FIPS:
        fips_reject_flags = ARG_UINT(arg_ptr);
        break;

    case GCRYCTL_FIPS_SERVICE_INDICATOR_CIPHER: {
        int algo = ARG_INT(arg_ptr);
        int mode = ARG_INT(arg_ptr);

        rc = fips_indicator_cipher(algo, mode);
        break;
    }

    case GCRYCTL_FIPS_SERVICE_INDICATOR_MAC:
        rc = fips_indicator_mac(ARG_INT(arg_ptr));
        break;

    case GCRYCTL_FIPS_SERVICE_INDICATOR_MD:
        rc = fips_indicator_md(ARG_INT(arg_ptr));
        break;

    case GCRYCTL_FIPS_SERVICE_INDICATOR_KDF:
        rc = fips_indicator_kdf(ARG_INT(arg_ptr));
        break;

    case GCRYCTL_FIPS_SERVICE_INDICATOR_FUNCTION:
        rc = fips_indicator_function(ARG_STR(arg_ptr));
        break;

    case GCRYCTL_FIPS_SERVICE_INDICATOR_PK_FLAGS:
        rc = fips_indicator_pk_flags(ARG_STR(arg_ptr));
        break;

    case GCRYCTL_DISABLE_HWF:
        (void)ARG_STR(arg_ptr);
        break;

    case GCRYCTL_SET_ENFORCED_FIPS_FLAG:
        break;

    case GCRYCTL_SET_PREFERRED_RNG_TYPE: {
        int i = ARG_INT(arg_ptr);

        /* Only honoured before the library is initialised; afterwards
         * the reference silently keeps the type in use. */
        if (i > 0 && !any_init_done) {
            preferred_rng_type = i;
        }

        break;
    }

    case GCRYCTL_GET_CURRENT_RNG_TYPE: {
        int *ip = ARG_INT_PTR(arg_ptr);

        if (!ip) {
            rc = GPG_ERR_INV_ARG;
        } else {
            *ip = _gcry_get_rng_type();
        }

        break;
    }

    case GCRYCTL_INACTIVATE_FIPS_FLAG:
    case GCRYCTL_REACTIVATE_FIPS_FLAG:
        rc = GPG_ERR_NOT_IMPLEMENTED;
        break;

    case GCRYCTL_DRBG_REINIT:
        (void)ARG_STR(arg_ptr);
        (void)ARG_BUFFER_PTR(arg_ptr);
        (void)ARG_INT(arg_ptr);
        /* The generator is OpenSSL's; the reference answers the same
         * when its own DRBG is not the active generator. */
        rc = GPG_ERR_NOT_SUPPORTED;
        break;

    case GCRYCTL_REINIT_SYSCALL_CLAMP:
        break;

    default:
        rc = GPG_ERR_INV_OP;
        break;
    }

    return rc;
}

gcry_error_t
gcry_control(enum gcry_ctl_cmds cmd, ...)
{
    gcry_err_code_t rc;
    va_list arg_ptr;

    va_start(arg_ptr, cmd);
    rc = vcontrol(cmd, arg_ptr);
    va_end(arg_ptr);
    return GCRY_ERR(rc);
}

/* Exposed for the FIPS rejection logic of the algorithm modules. */
unsigned int _gcry_fips_reject_flags(void);

unsigned int
_gcry_fips_reject_flags(void)
{
    return fips_reject_flags;
}

/* Whether digest ALGO may be used in FIPS mode; the same set the
 * GCRYCTL_FIPS_SERVICE_INDICATOR_MD query approves. */
int
_gcry_fips_md_approved(int algo)
{
    return fips_indicator_md(algo) == 0;
}
