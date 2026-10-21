# gcrypt-openssl

The [Libgcrypt](https://gnupg.org/software/libgcrypt/) API, implemented on
top of OpenSSL 4.

The point is to let software written against the gcrypt API use your own
tuned or FIPS-certified OpenSSL instead. The library implements the complete
public API of Libgcrypt 1.12 (every symbol of its `GCRYPT_1.6` version node,
reporting itself as version 1.12.4) and can be built under the reference
library's own name and soname (`libgcrypt.so.20`) so that existing binaries
pick it up unchanged.

This project was extruded by Claude. Use at your own risk.

## How it is built

- **No cryptographic primitives are implemented here.** Every cipher,
  digest, MAC, KDF, KEM, random number and big-number operation comes from
  OpenSSL's EVP, BIGNUM, EC and RAND APIs, fetched from a private
  `OSSL_LIB_CTX` that loads the system OpenSSL configuration (so a FIPS
  provider configured there applies) and tries the legacy provider for the
  old algorithms the gcrypt API exposes. Hand-written code is limited to
  glue: S-expressions, MPI import/export formats, the PKCS#1 v1.5, OAEP and
  PSS encodings (RSA itself runs unpadded in OpenSSL), the OpenPGP S2K
  iterated hash, the three CRCs, ElGamal's modular arithmetic, keygrips,
  the EdDSA and Montgomery point encodings, trial-division sieving for
  prime generation, and the composition of modes OpenSSL has no single
  cipher for (CBC-CTS, CBC-MAC, the CBC-MAC half of CCM, and CTR, XTS, OCB
  and key wrap for ciphers OpenSSL offers only in ECB).
- **Dependencies: the C library, POSIX threads, libgpg-error and OpenSSL
  4.** As in the reference library, `gcrypt.h` includes `<gpg-error.h>` and
  the `gcry_*` error helpers wrap libgpg-error's, so error values and their
  descriptions are the ones every other GnuPG component uses.
- **Relationship to upstream.** The public header, constants and
  S-expression formats are reproduced because they are the API. The rest of
  the front-end code is not independent either: the S-expression module,
  the MPI coders and flag handling, the digest, cipher and public-key
  dispatch layers, `gcry_control`, logging, the KDF and prime-generation
  skeletons and the curve tables follow the reference implementation's
  internal layouts, function names, order of checks and error codes,
  rewritten rather than copied. Independent designs are the OpenSSL
  bindings, all arithmetic, the secure memory pool, the cipher mode
  engine, the KEM module and the test harness. For licensing purposes
  treat the library as derived from Libgcrypt (LGPL-2.1-or-later); see
  [LICENSE](LICENSE).
- **Secure memory** is a pool of the library's own, like the reference
  implementation's: anonymous mappings of 32 KiB (more if
  `GCRYCTL_INIT_SECMEM` or `GCRYCTL_AUTO_EXPAND_SECMEM` ask for it),
  locked into RAM and excluded from core dumps where the system allows,
  carved up by a small first-fit allocator that validates every block it
  is handed back. When a pool is full another is mapped; only a failing
  `mmap` makes a secure allocation fail. Secure allocations are wiped on
  free and `gcry_is_secure()` is an exact range check. OpenSSL's own
  secure heap is deliberately left alone: it is process-wide with no
  fallback, and sizing it for the application starved OpenSSL's internal
  users of it, most visibly the FIPS module's self-tests. Consequently the
  limbs of secure MPIs are wiped on free but not locked; they do carry
  OpenSSL's constant-time flag.
- **Thread safety** follows the reference library: handles are not shared
  between threads, everything else is. Fetched OpenSSL algorithm objects
  are cached for the life of the process behind mutexes, and each thread
  owns its `BN_CTX`.

## Support

| Area | Supported | Not available |
|------|-----------|---------------|
| Ciphers | AES, Camellia, ARIA, SM4, 3DES, DES, CAST5, Blowfish, IDEA, RC2, SEED, RC4, ChaCha20; ECB, CBC (+CTS, +MAC), CFB, CFB8, OFB, CTR, GCM, CCM, OCB, XTS, SIV, GCM-SIV, AES key wrap (+padding), ChaCha20-Poly1305 | Twofish, Serpent, Salsa20, GOST 28147, SAFER; EAX mode; Camellia GCM-SIV |
| Digests | MD4, MD5, SHA-1, SHA-2 (all), SHA-3, SHAKE, cSHAKE (customisation string only), RIPEMD-160, Whirlpool, BLAKE2b/s (all sizes), SM3, CRC32/CRC24; HMAC flag | Tiger, Haval, GOST R 34.11, Stribog; MD2 (only if the legacy provider offers it, which OpenSSL 4 does not) |
| KDFs | S2K (all three), PBKDF2, scrypt, Argon2 (d/i/id), HKDF, one-step KDF (hash and HMAC), X9.63; the `gcry_kdf_open` handle API | PBKDF1 (upstream rejects it too), Balloon (no OpenSSL implementation) |
| KEMs | ML-KEM-512/768/1024, raw X25519/X448 and Weierstrass KEMs, DHKEM (RFC 9180) | sntrup761, Classic McEliece |
| Low-level EC | All `gcry_mpi_ec_*` operations on Weierstrass curves (NIST, Brainpool, secp256k1, SM2, GOST); scalar multiplication on Montgomery curves | Point addition/doubling on Edwards and Montgomery curves |
| MACs | HMAC (all available digests), CMAC (available block ciphers), GMAC-AES, Poly1305 | Poly1305-cipher variants, GMAC for non-AES ciphers, GOST IMIT |
| Public key | RSA (PKCS#1 v1.5, PSS, OAEP, raw), DSA (incl. RFC 6979), ElGamal (raw, PKCS#1, OAEP, PSS), ECDSA (incl. RFC 6979), ECDH, EdDSA (Ed25519, Ed448, prehash and context variants), X25519/X448, SM2 on its own curve; key generation, keygrips, curve queries | ECDSA on GOST curves, GOST signatures, SM2 on other curves |

Unsupported algorithms report the error codes upstream uses for an unknown
algorithm; names and sizes are still answered. The ECDSA/DSA nonce override
(`gcry_pk_random_override_new`) is accepted but ignored, because OpenSSL does
not allow injecting the nonce. RSA PKCS#1 v1.5 decryption uses OpenSSL's
implicit rejection: a ciphertext with bad padding decrypts to a random
value instead of failing with `GPG_ERR_ENCODING_PROBLEM` as upstream does.

## Layout

| Path           | Contents                                                    |
|----------------|-------------------------------------------------------------|
| `benchmarks/`  | `bench_gcrypt` sources and `compare.sh`                     |
| `cmake/`       | Package config, pkg-config and `libgcrypt-config` templates, `drop-in.cmake` |
| `scripts/`     | `build-openssl.sh`, `check-exports.sh`, `check-libgcrypt-config.sh`, `check-tools.sh`, `coverage.py` |
| `tools/`       | `dumpsexp`, `hmac256` and `mpicalc`, the command-line utilities the reference library installs; built with the drop-in |
| `src/`         | Library sources, one file per module; `libgcrypt.map` is the symbol version script |
| `src/include/` | The public header `gcrypt.h`                                |
| `tests/`       | One `test_*.c` program per module, `test_common.h` assertion helpers, `expected-exports.txt`, KEM vectors and the script that regenerates them |

## Building

Requires CMake 3.21 (3.25 to use the presets), a C99 compiler, the
libgpg-error development files (1.33 or newer: `libgpg-error-devel` on
Fedora, `libgpg-error-dev` on Debian, Ubuntu, Alpine and Wolfi,
`libgpg-error` on Homebrew), and OpenSSL 4.x development files.

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Without presets:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build
ctest --test-dir build
```

### Options

| Option                              | Default | Effect                          |
|-------------------------------------|---------|---------------------------------|
| `GCRYPT_OPENSSL_BENCH_ARGS`         | empty   | Arguments the `bench-compare` target passes to both benchmarks |
| `GCRYPT_OPENSSL_BUILD_BENCHMARKS`   | `ON`    | Build benchmarks (top-level)    |
| `GCRYPT_OPENSSL_BUILD_SHARED`       | `ON`    | Build the shared library        |
| `GCRYPT_OPENSSL_BUILD_STATIC`       | `ON`    | Build the static library        |
| `GCRYPT_OPENSSL_BUILD_TESTS`        | `ON`    | Build tests (top-level only)    |
| `GCRYPT_OPENSSL_COVERAGE`           | `OFF`   | Instrument for code coverage and add the `coverage` target |
| `GCRYPT_OPENSSL_DROP_IN`            | `OFF`   | Also build and install `libgcrypt.so.20`, `libgcrypt.pc`, `libgcrypt-config` and the three utilities into the standard directories |
| `GCRYPT_OPENSSL_FIPS`               | `OFF`   | Start the library in FIPS mode by default; see [FIPS mode](#fips-mode) |
| `GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT` | `OFF` | Adapt the tests to Chainguard's strict FIPS provider; see [FIPS mode](#fips-mode) |
| `GCRYPT_OPENSSL_STOCK_GCRYPT`       | found   | Path of the stock `libgcrypt.so.20` to benchmark against |
| `GCRYPT_OPENSSL_WARNINGS_AS_ERRORS` | `ON`    | Pass `-Werror` (or `/WX`) to every target that compiles C: libraries, drop-in, tests, benchmarks |
| `GPG_ERROR_ROOT_DIR`                | unset   | Install prefix of libgpg-error if it is not the system one (pkg-config finds the system one) |
| `OPENSSL_ROOT_DIR`                  | unset   | Where to find OpenSSL 4 if it is not the system one |

At least one of the two library options must stay on. Tests and benchmarks
default to off when the project is included from another CMake project.

### Presets

`CMakePresets.json` defines configure, build and test presets of the same
name; every one uses Ninja and writes `compile_commands.json`.

| Preset     | Build directory  | Configuration                                   |
|------------|------------------|-------------------------------------------------|
| `coverage` | `build-coverage/`| Debug, `GCRYPT_OPENSSL_COVERAGE=ON`, benchmarks off |
| `debug`    | `build-debug/`   | Debug                                           |
| `default`  | `build/`         | RelWithDebInfo                                  |
| `fips`     | `build-fips/`    | RelWithDebInfo, `GCRYPT_OPENSSL_FIPS=ON`        |
| `release`  | `build-release/` | Release (no test preset)                        |

The extra build presets `coverage-report` and `memcheck` run the
`coverage` target in the `coverage` tree and the `memcheck` target in the
`debug` tree. To point every preset at a non-system OpenSSL, add local
presets that inherit these in an untracked `CMakeUserPresets.json` (see
[OpenSSL 4](#openssl-4)).

### Targets

| Target | Alias | Output |
|--------|-------|--------|
| `bench-compare` | | Runs both benchmarks through `benchmarks/compare.sh` |
| `bench_gcrypt` | | Benchmark driver linked against this library |
| `bench_gcrypt_stock` | | The same sources linked against the stock `libgcrypt.so.20`, when one is found |
| `check_exports` | | CTest entry only (no build target): `scripts/check-exports.sh` compares the shared library's dynamic symbols with `tests/expected-exports.txt` |
| `check_libgcrypt_config` | | CTest entry only, with the drop-in: `scripts/check-libgcrypt-config.sh` checks the configured `libgcrypt-config` against the reference script's behaviour and `gcrypt.h` |
| `dumpsexp`, `hmac256`, `mpicalc` | | With the drop-in: the reference library's command-line utilities, linked against `libgcrypt.so.20` |
| `check_tools` | | CTest entry only, with the drop-in: `scripts/check-tools.sh` runs the three utilities against the reference programs' documented behaviour |
| `coverage` | | Runs the tests and writes the coverage report; only with `GCRYPT_OPENSSL_COVERAGE=ON` |
| `gcrypt-openssl::gcrypt-openssl` | (alias only) | The shared library when built, else the static one; what the tests and benchmarks link |
| `gcrypt_openssl_dropin` | `gcrypt-openssl::libgcrypt` | `libgcrypt.so.20.8.9` with soname `libgcrypt.so.20`; only with `GCRYPT_OPENSSL_DROP_IN=ON` |
| `gcrypt_openssl_shared` | `gcrypt-openssl::shared` | `libgcrypt-openssl.so.0.1.0` with soname `libgcrypt-openssl.so.0`; exports exactly the `gcry_*` symbols plus `_gcry_mpi_get_const` via `src/libgcrypt.map` |
| `gcrypt_openssl_static` | `gcrypt-openssl::static` | `libgcrypt-openssl.a`, built with PIC so it can be linked into other shared objects |
| `gcrypt_openssl_warnings` | `gcrypt-openssl::warnings` | Interface target carrying the warning flags; not installed |
| `install` | | Libraries, `gcrypt.h`, the CMake package (`gcrypt-openssl-config.cmake`, `-config-version.cmake`, `-targets.cmake`), `gcrypt-openssl.pc`, and with the drop-in `libgcrypt.so.20`, `libgcrypt.pc`, `libgcrypt-config`, `dumpsexp`, `hmac256` and `mpicalc` |
| `memcheck` | | Runs every test program under Valgrind through `ctest -T memcheck`; only when Valgrind is found |
| `test_curves`, `test_internal` | | Tests of internal helpers; link the static library, so they need `GCRYPT_OPENSSL_BUILD_STATIC` |
| `test_version` ... `test_fips` (17 programs) | | One executable and CTest entry per public module; link the shared library |
| `test_version_static` | | `test_version.c` linked against the static library, to prove both flavours link and run |

All libraries, tests and benchmarks are part of the default (`all`) target.
Benchmarks are not registered with CTest.

### Tests

Each `tests/test_*.c` is a standalone program using the assertion helpers
in `tests/test_common.h`; no framework is needed. The vectors come from the
relevant RFCs, NIST publications and upstream's own test suite (keygrips,
S2K, RSA encodings). `ctest --preset debug` runs everything, including the
export check:

```sh
ctest --preset debug                    # all 21 entries
ctest --preset debug -R 'cipher|md'     # by name
build-debug/tests/test_pk               # one program directly
```

When Valgrind is installed, the `memcheck` target runs every test program
(except the export check) under memcheck with full leak checking and
origin tracking; any error Valgrind reports, including a definite or
possible leak, fails that test. The
suppressions in `tests/valgrind.supp` apply, and CTest keeps the logs in
`Testing/Temporary/MemoryChecker.*.log` under the build directory. A
Debug tree gives the most useful reports:

```sh
cmake --build --preset memcheck      # or: ctest --preset debug -T memcheck
```

The shared library is linked with `--no-undefined`, which clashes with the
sanitizer runtimes. To run the suite under ASan/UBSan, build the static
library only:

```sh
CC=clang cmake -S . -B build-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
    -DGCRYPT_OPENSSL_BUILD_SHARED=OFF -DGCRYPT_OPENSSL_BUILD_BENCHMARKS=OFF \
    -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined'
cmake --build build-asan && ctest --test-dir build-asan
```

### Consuming the library

Consumers can `find_package(gcrypt-openssl)` after `cmake --install` and
link against `gcrypt-openssl::shared` or `gcrypt-openssl::static`, or use
the installed `gcrypt-openssl.pc`. The package config pulls in
`GpgError::GpgError` (through the `FindGpgError.cmake` module installed
beside it) and `OpenSSL::Crypto` as dependencies; the pkg-config file
requires `gpg-error`. Both `libgcrypt-openssl.so` and `libgcrypt-openssl.a`
are built by default.

### Drop-in replacement

With `-DGCRYPT_OPENSSL_DROP_IN=ON` the install also contains
`libgcrypt.so.20.8.9` (the reference library's current soname and
version), `libgcrypt.pc`, a `libgcrypt-config` script and the `dumpsexp`,
`hmac256` and `mpicalc` utilities. They go into the standard directories
of the install prefix, the same places the reference library's own
packages use: the library into `CMAKE_INSTALL_LIBDIR` (`lib64` or `lib`
as GNUInstallDirs picks for the platform), the pkg-config file into its
`pkgconfig/` subdirectory, and the script and utilities into
`CMAKE_INSTALL_BINDIR`:

```sh
cmake -S . -B build-drop-in -DGCRYPT_OPENSSL_DROP_IN=ON
cmake --build build-drop-in
sudo cmake --install build-drop-in
```

The default prefix is CMake's usual `/usr/local`, so this installs
`/usr/local/lib64/libgcrypt.so.20` (or `/usr/local/lib/...`) beside, not
over, a distribution's `/usr/lib64/libgcrypt.so.20`. Which one a program
loads then follows the dynamic loader's normal search order. To replace
the system library outright, install with `-DCMAKE_INSTALL_PREFIX=/usr`
and the distribution's `-DCMAKE_INSTALL_LIBDIR`; to try the drop-in
without installing it, point the loader at the build tree:

```sh
LD_LIBRARY_PATH=build-drop-in/src gpg --version
```

Set `-DCMAKE_INSTALL_PREFIX` and `-DCMAKE_INSTALL_LIBDIR` on the first
configure of a build tree so the pkg-config file, the config script and
the utilities' rpath carry the right paths. The drop-in requires the
shared library to be enabled.

The `libgcrypt-config` script takes the same options as the reference
library's and prints the same output in the same order, so
`AM_PATH_LIBGCRYPT` and hand-written configure checks work unchanged:
`--prefix`, `--exec-prefix`, `--version` (also `--modversion`),
`--api-version`, `--cflags`, `--libs`, `--host`, `--algorithms` and
`--variable=NAME`. `--prefix=DIR` and `--exec-prefix=DIR` are accepted and
ignored, and `--thread=MODEL` fails, as upstream. The values describe this
implementation: `--libs` is `-L<libdir> -lgcrypt` followed by the
libgpg-error flags the build found (normally `-lgpg-error`), `--cflags`
likewise ends with libgpg-error's, `--algorithms` lists only the algorithms
provided here, and
`--variable=NAME` additionally answers `includedir`, `libdir`, `version`,
`kdfs`, `implementation`, `implementation_version` and `openssl_version`.

The drop-in also builds and installs the three command-line utilities the
reference library ships, with the same options and output:

- `dumpsexp` hex-dumps an S-expression while scanning it, reporting syntax
  problems under a cursor; `--verbose` shows the parser events,
  `--assume-hex` reads a hex dump, `--decimal` prints decimal offsets.
  `--advanced`, which the reference tool accepts but ignores, parses the
  input with `gcry_sexp_sscan` and prints it in advanced format.
- `hmac256 [--binary] [--stdkey|KEY] [FILE...]` prints the HMAC-SHA-256 of
  each file (or stdin) like `sha1sum`; `--stdkey` is the key the reference
  library's integrity check uses. The MAC is computed through `gcry_mac_*`
  after an RFC 4231 self-test. In FIPS mode the provider refuses HMAC keys
  shorter than 14 bytes; `--stdkey` is long enough, a short `KEY` fails.
- `mpicalc` is the RPN calculator on `gcry_mpi_t` values: hexadecimal
  numbers (a leading digit is required, so `0ff` not `ff`), single-character
  operators, `?` for the operator table, `--print-config` for the library
  configuration. Unlike the reference tool, `--` really decrements.

The utilities link `libgcrypt.so.20` and carry an rpath to the install
library directory, so they load this library rather than a system
libgcrypt even when the prefix is not on the loader's search path.

### FIPS mode

At initialisation the library asks for FIPS mode when
`/etc/gcrypt/fips_enabled` exists, `/proc/sys/crypto/fips_enabled` reads
`1`, or the application called `GCRYCTL_FORCE_FIPS_MODE` beforehand, just
like the reference library. Asking means loading OpenSSL's `fips` provider
into the private library context and enabling the `fips=yes` default
property, so every algorithm fetch is served by the FIPS provider. If
FIPS mode was required but the provider cannot be loaded, the library
enters an error state like the reference: `GCRYCTL_FIPS_MODE_P` still
reports FIPS mode, `GCRYCTL_OPERATIONAL_P` is false, `GCRYCTL_SELFTEST`
fails, `gcry_get_config(0, "fips-error")` reports `y`, random numbers are
refused and no algorithm can be fetched, so every operation fails.
`GCRYCTL_NO_FIPS_MODE` before initialisation turns the request off; once
FIPS mode is active it is refused. Without any request, the library is
also in FIPS mode when the OpenSSL configuration made `fips=yes` the
default property, or when it activated the `fips` provider and not the
`default` one, so that only approved algorithms exist (Chainguard's FIPS
images are configured that way).

A few rules are enforced beyond what OpenSSL's provider checks: GCM
encryption needs an IV generated through `gcry_cipher_setup_geniv` and
`gcry_cipher_geniv` (a caller-supplied IV makes the handle refuse to
encrypt, as the reference does); GMAC is not approved; curves given as
explicit parameters must match an approved named curve; non-approved
digests are refused in public key operations.

`-DGCRYPT_OPENSSL_FIPS=ON` (the `fips` preset) makes the build ask for FIPS
mode unconditionally, as if the marker file were present, and defines
`GCRYPT_OPENSSL_FIPS=1` for every target in the tree: the libraries, the
drop-in, the tests, the benchmarks and a coverage build configured with
both options. With an OpenSSL that has no `fips` module (such as the one
`scripts/build-openssl.sh` produces) such a build is in the error state
described above and most of the test suite fails with "not operational",
so run the `fips` preset only against a FIPS-capable OpenSSL.

The test suite passes in genuine FIPS mode. `test_fips` covers the
controls that only work before initialisation (`GCRYCTL_FORCE_FIPS_MODE`,
`GCRYCTL_NO_FIPS_MODE`) in forked children and the
`GCRYCTL_FIPS_REJECT_NON_FIPS` flags. Every other test program branches on
`gcry_fips_mode_active()`: algorithms the FIPS provider lacks are asserted
to fail with the family's unknown-algorithm code, FIPS-only parameter
rules are asserted (HMAC keys of at least 14 bytes, PBKDF2 with a salt of
at least 16 bytes, at least 1000 iterations and at least 14 bytes of
output, RSA keys of at least 2048 bits with `e` at least 65537, XTS keys
with distinct halves), and everything approved is exercised as usual. To
run it, build OpenSSL with `enable-fips`, run `fipsinstall`, and point
`OPENSSL_CONF` at a configuration that activates the `fips` and `base`
providers with `fips=yes` as the default property; the library picks that
up through `OSSL_LIB_CTX_load_config()`.

Chainguard's strict FIPS provider omits some algorithms that FIPS
approves and OpenSSL's own provider offers, and the default provider
shipped beside it is stripped of the legacy algorithms too, so even with
the library outside FIPS mode its tables list algorithms the provider
lacks. `-DGCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT=ON` defines
`GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT` for every target and makes the
tests tolerate those omissions; the library has no flag-dependent code.
Under the flag the tests ask the family's `test_algo` function first: a
digest, cipher or MAC the provider lacks (SHA-512/224, RIPEMD-160,
Whirlpool, SM3, DES, Triple-DES, RC4, CAST5, Blowfish, IDEA, RC2, SM4,
Camellia, ARIA, SEED, ...) is expected to be reported as unknown
everywhere, with `GPG_ERR_DIGEST_ALGO`, `GPG_ERR_CIPHER_ALGO` or
`GPG_ERR_MAC_ALGO`, and the `GCRYCTL_FIPS_REJECT_NON_FIPS` flags cannot
bring it back; a mode error for such a cipher (Triple-DES in GCM, say) is
the algorithm error, as in FIPS mode. When DSA key generation fails,
tests that only need a signing key use ECDSA and the DSA-specific tests
are skipped with a message. When the provider has the SM2 curve but no
SM2 key type, the library reports `GPG_ERR_NOT_SUPPORTED` for SM2
signatures (in every build) and the test skips them. `test_curves` skips
its look-up of a foreign small curve (secp112r1) when the OpenSSL build
has dropped it. With the flag off nothing changes: the tests expect
exactly what OpenSSL's own providers offer.

Chainguard's FIPS images (the `openssl-config-fipshardened` package)
activate the Chainguard FIPS Provider for OpenSSL 3.4.0 inside an OpenSSL
4 libcrypto, together with a "legacy allowed" provider that supplies MD5,
MD4, SHA-1 and SHA-224 under the `fips=yes` property for non-security
uses. The library copes with that environment as follows, in every build:

- The RSA primitives are taken from the signature interface (a signature
  without padding is RSADP, its recovery RSAEP) because that provider
  restricts the asymmetric cipher interface to OAEP. PKCS#1 v1.5
  decryption asks the provider first and, when it refuses the padding
  mode, decrypts raw and checks the frame itself with the same implicit
  rejection OpenSSL applies (a bad frame yields the synthetic plaintext
  OpenSSL would compute).
- That provider fails to derive RFC 6979 nonces. An ECDSA signature
  requested with the `rfc6979` flag is then made with a random nonce,
  which every verifier accepts; the condition is logged once and later
  requests skip the attempt. The tests check the RFC 6979 known answers
  only when two signatures over the same data agree.
- Digests follow the reference library's FIPS policy before the provider
  is asked: in FIPS mode MD5 is offered unless
  `GCRY_FIPS_FLAG_REJECT_MD_MD5` is set, SHA-1 unless
  `GCRY_FIPS_FLAG_REJECT_MD_SHA1`, every other non-approved digest unless
  `GCRY_FIPS_FLAG_REJECT_MD_OTHERS` (which the default flags include), so
  the legacy-allowed provider's MD5 is usable and its MD4 is not. The
  FIPS provider's HMAC cannot use a digest from another provider, so
  HMAC-MD5 is reported as unknown by both the digest and the MAC family
  although MD5 hashes; `gcry_mac_test_algo` probes the HMAC set-up.
- ML-KEM and cSHAKE are absent from that provider. The KEM functions
  report `GPG_ERR_UNSUPPORTED_ALGORITHM` for ML-KEM, like the KEMs this
  library does not implement; the digest family reports cSHAKE as unknown.
  The tests skip them with a message under the strict flag.

A build with `GCRYPT_OPENSSL_FIPS=ON` needs the FIPS provider and its
configuration wherever its tests run: without them the library is in the
error state described above and the log names OpenSSL's reason (the
module could not be loaded, say). A melange recipe for such a package
must therefore list `openssl-config-fipshardened` in the build
environment, not only among the runtime dependencies.

What FIPS mode offers, as seen through OpenSSL 4.0.3's FIPS provider: AES
in every mode except SIV and GCM-SIV; SHA-1, SHA-2, SHA-3, SHAKE and
cSHAKE; HMAC over those, CMAC-AES and GMAC-AES; PBKDF2, HKDF, the
one-step KDF and X9.63; RSA, ECDSA and ECDH on the NIST curves, Ed25519
and Ed448 (not Ed25519ctx); ML-KEM and, composed from ECDH and HKDF,
DHKEM over P-256, P-384 and P-521; prime generation. Not available:
every other cipher and digest, Poly1305, scrypt, Argon2, DSA, ElGamal,
X25519 and X448 (the provider has no implementation at all), Brainpool,
secp256k1, SM2 and GOST curves, non-approved digests in public key
operations (including pre-computed RIPEMD-160 or CRC digests), and custom
allocation, out-of-core and fatal-error handlers, which the reference
library also ignores in FIPS mode.

### OpenSSL 4

Most distributions still ship OpenSSL 3. `scripts/build-openssl.sh` downloads
a pinned OpenSSL 4 release, verifies its checksum, and installs it under
`~/.local/opt/openssl-<version>` (pass a different prefix as the first
argument if you prefer):

```sh
scripts/build-openssl.sh
cmake --preset default -DOPENSSL_ROOT_DIR="$HOME/.local/opt/openssl-4.0.3"
```

To avoid repeating the option, put it in an untracked `CMakeUserPresets.json`:

```json
{
  "version": 6,
  "configurePresets": [
    {
      "name": "local",
      "inherits": "default",
      "cacheVariables": {
        "OPENSSL_ROOT_DIR": "$env{HOME}/.local/opt/openssl-4.0.3"
      }
    }
  ]
}
```

### Benchmarks

`bench_gcrypt` times every operation family through the public API: key
generation, signing and verification, public-key encryption and
decryption, KEM keypair/encap/decap, hashing, MACs, KDFs, symmetric
encryption and decryption in every mode, plus S-expression, MPI and random
number overhead. Each case runs for a time budget (default 0.5 s) and
reports operations per second and, for bulk operations, MiB/s.

Because the header is ABI-compatible, the same sources are also linked
against the stock `libgcrypt.so.20` when CMake finds one, producing
`bench_gcrypt_stock`. `compare.sh` runs both and joins the results, with a
ratio above 1.0 meaning this library is faster:

```sh
cmake --build build --target bench-compare
# or, with arguments passed to both binaries:
benchmarks/compare.sh build/benchmarks/bench_gcrypt \
    build/benchmarks/bench_gcrypt_stock --seconds 2 cipher/AES256 hash/SHA
```

Positional arguments are substrings matched against `group/name`; groups
are `hash`, `mac`, `kdf`, `cipher`, `pk`, `kem` and `misc`. `--list` shows
every case, `--size` changes the bulk buffer, `--csv` gives raw output and
`compare.sh -m` prints a Markdown table. Operations one library lacks show
as `n/a`. A full run takes ten to fifteen minutes, most of it in RSA,
DSA and ElGamal key generation. Point `GCRYPT_OPENSSL_STOCK_GCRYPT` at a
library file to compare against a specific build, and set
`GCRYPT_OPENSSL_BENCH_ARGS` to pass arguments through the `bench-compare`
target.

### Code coverage

The `coverage` preset builds a Debug tree instrumented with the compiler's
`--coverage` option and adds a `coverage` target that runs the test suite
and summarises the counters with `scripts/coverage.py`, which only needs
`gcov` (or `llvm-cov` with clang) and Python 3:

```sh
cmake --preset coverage
cmake --build --preset coverage
cmake --build --preset coverage-report
```

The report lands in `build-coverage/coverage/`: `summary.txt` and
`coverage.json` with line, function and branch coverage per file, and
`index.html` linking to annotated sources. Counters from the shared and the
static library are merged, so every test counts once. The script can also
gate a CI job: `scripts/coverage.py --build-dir build-coverage
--source-dir . --output cov --min-lines 75` exits non-zero below the
threshold.

## Contributing

Linting runs through [pre-commit](https://pre-commit.com/): the standard
whitespace, line-ending, YAML and JSON checks, astyle for C (pinned via
`astyle_py`, options in `.astylerc`), cmake-format and cmake-lint for
CMake, markdownlint for Markdown, and codespell for spelling. Install the
hooks once after cloning:

```sh
pre-commit install
pre-commit run --all-files
```

## License

See [LICENSE](LICENSE). The authors claim no copyright of their own, but a
side-by-side comparison with Libgcrypt 1.11.2 shows that most of the
non-cryptographic code reproduces upstream's internal design with new
text, so assume the terms of Libgcrypt's LGPL-2.1-or-later apply to
redistribution.
