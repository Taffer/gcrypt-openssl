/* hmac256 - compute HMAC-SHA-256 over files, like sha1sum.
 *
 * Command-line compatible with the hmac256 program that ships with the
 * reference Libgcrypt, including --binary, --stdkey and the built-in key
 * the reference library's integrity check uses.  The reference tool
 * carries its own SHA-256; this one computes the MAC through the library,
 * so it exercises the same OpenSSL code path as gcry_mac_* and the RFC 4231
 * self-test it runs first checks that path.
 *
 * This file is in the public domain.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>

#define PGM "hmac256"

#ifndef KEY_FOR_BINARY_CHECK
    #define KEY_FOR_BINARY_CHECK "What am I, a doctor or a moonshuttle conductor?"
#endif

#define DIGEST_LEN 32

/* Compute HMAC-SHA-256 of FP's remaining content under KEY into DIGEST.
 * Returns 0 on success, -1 on a library error (errno-free, message
 * already printed), or 1 on a read error (errno set). */
static int
hmac_file(const char *key, size_t keylen, FILE *fp,
          unsigned char digest[DIGEST_LEN])
{
    gcry_mac_hd_t hd;
    gcry_error_t err;
    unsigned char buf[4096];
    size_t n, outlen = DIGEST_LEN;

    err = gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0, NULL);

    if (err) {
        fprintf(stderr, PGM ": error computing HMAC: %s\n",
                gcry_strerror(err));
        return -1;
    }
    err = gcry_mac_setkey(hd, key, keylen);

    while (!err && (n = fread(buf, 1, sizeof buf, fp)) > 0) {
        err = gcry_mac_write(hd, buf, n);
    }
    if (!err && ferror(fp)) {
        gcry_mac_close(hd);
        return 1;
    }
    if (!err) {
        err = gcry_mac_read(hd, digest, &outlen);
    }
    gcry_mac_close(hd);

    if (err) {
        fprintf(stderr, PGM ": error computing HMAC: %s\n",
                gcry_strerror(err));
        return -1;
    }
    return 0;
}

/* The RFC 4231 test cases the reference tool also checks itself with. */
static int
selftest(void)
{
    static const struct {
        const char *data;
        size_t datalen;
        const char *key;
        size_t keylen;
        const char *expect;
    } tv[] = {
        {
            "what do ya want for nothing?", 28, "Jefe", 4,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        },
        {
            "Hi There", 8,
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b", 20,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        },
        {
            "Test Using Larger Than Block-Size Key - Hash Key First", 54,
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
            "\xaa\xaa\xaa", 131,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        },
    };
    size_t i, j;

    for (i = 0; i < sizeof tv / sizeof tv[0]; i++) {
        gcry_mac_hd_t hd;
        unsigned char digest[DIGEST_LEN];
        char hex[2 * DIGEST_LEN + 1];
        size_t outlen = sizeof digest;

        if (gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, 0, NULL)) {
            return -1;
        }
        if (gcry_mac_setkey(hd, tv[i].key, tv[i].keylen)
            || gcry_mac_write(hd, tv[i].data, tv[i].datalen)
            || gcry_mac_read(hd, digest, &outlen)) {
            gcry_mac_close(hd);
            return -1;
        }
        gcry_mac_close(hd);

        for (j = 0; j < DIGEST_LEN; j++) {
            sprintf(hex + 2 * j, "%02x", digest[j]);
        }
        if (outlen != DIGEST_LEN || strcmp(hex, tv[i].expect) != 0) {
            return -1;
        }
    }
    return 0;
}

int
main(int argc, char **argv)
{
    const char *pgm = PGM;
    const char *key;
    size_t keylen;
    int last_argc = -1;
    int use_binary = 0;
    int use_stdkey = 0;
    int use_stdin;

    if (argc) {
        const char *slash = strrchr(*argv, '/');

        pgm = slash ? slash + 1 : *argv;
        argc--;
        argv++;
    }

    while (argc && last_argc != argc) {
        last_argc = argc;

        if (!strcmp(*argv, "--")) {
            argc--;
            argv++;
            break;
        } else if (!strcmp(*argv, "--version")) {
            fputs(PGM " (Libgcrypt) " GCRYPT_VERSION "\n"
                  "gcrypt-openssl implementation; this program is in the "
                  "public domain.\n"
                  "There is NO WARRANTY, to the extent permitted by law.\n",
                  stdout);
            return 0;
        } else if (!strcmp(*argv, "--binary")) {
            argc--;
            argv++;
            use_binary = 1;
        } else if (!strcmp(*argv, "--stdkey")) {
            argc--;
            argv++;
            use_stdkey = 1;
        }
    }

    if (argc < 1 && !use_stdkey) {
        fprintf(stderr, "usage: %s [--binary] [--stdkey|key] [filename]\n",
                pgm);
        return 1;
    }

    if (use_stdkey) {
        key = KEY_FOR_BINARY_CHECK;
    } else {
        key = *argv;
        argc--;
        argv++;
    }
    keylen = strlen(key);
    use_stdin = !argc;

    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "%s: libgcrypt is too old (need %s, have %s)\n", pgm,
                GCRYPT_VERSION, gcry_check_version(NULL));
        return 2;
    }
    gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (selftest()) {
        fprintf(stderr, "%s: fatal error: self-test failed\n", pgm);
        return 2;
    }

    for (; argc || use_stdin; argv++, argc--) {
        const char *fname = use_stdin ? "-" : *argv;
        FILE *fp = use_stdin ? stdin : fopen(fname, "rb");
        unsigned char digest[DIGEST_LEN];
        int rc;
        size_t i;

        if (!fp) {
            fprintf(stderr, "%s: can't open `%s': %s\n", pgm, fname,
                    strerror(errno));
            return 1;
        }
        rc = hmac_file(key, keylen, fp, digest);

        if (rc > 0) {
            fprintf(stderr, "%s: error reading `%s': %s\n", pgm, fname,
                    strerror(errno));
        }
        if (!use_stdin) {
            fclose(fp);
        }
        if (rc) {
            return 1;
        }

        if (use_binary) {
            if (fwrite(digest, sizeof digest, 1, stdout) != 1) {
                fprintf(stderr, "%s: error writing output: %s\n", pgm,
                        strerror(errno));
                return 1;
            }
        } else {
            for (i = 0; i < sizeof digest; i++) {
                printf("%02x", digest[i]);
            }
            if (use_stdin) {
                putchar('\n');
            } else {
                printf("  %s\n", fname);
            }
        }
        if (use_stdin) {
            break;
        }
    }
    return 0;
}
