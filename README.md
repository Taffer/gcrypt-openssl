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
- **No dependencies besides the C library, POSIX threads and OpenSSL 4.**
  `gcrypt.h` embeds the subset of libgpg-error it needs (error types, every
  `GPG_ERR_*` value, inline helpers); a real `<gpg-error.h>` included first
  takes precedence.
- **Clean room.** Upstream was read for behaviour only; the public header,
  constants and S-expression formats are reproduced because they are the
  API, the code is new. See [LICENSE](LICENSE).
- **Secure memory** is OpenSSL's secure heap, a process-wide pool of 32 KiB
  unless `GCRYCTL_INIT_SECMEM` asks for more. Secure allocations are wiped
  on free and `gcry_is_secure()` is an exact range check. When the pool is
  exhausted, allocations fall back to the ordinary heap and are reported as
  not secure.
- **Thread safety** follows the reference library: handles are not shared
  between threads, everything else is. Fetched OpenSSL algorithm objects
  are cached for the life of the process behind mutexes, and each thread
  owns its `BN_CTX`.

## Support

| Area | Supported | Not available |
|------|-----------|---------------|
| Ciphers | AES, Camellia, ARIA, SM4, 3DES, DES, CAST5, Blowfish, IDEA, RC2, SEED, RC4, ChaCha20; ECB, CBC (+CTS, +MAC), CFB, CFB8, OFB, CTR, GCM, CCM, OCB, XTS, SIV, GCM-SIV, AES key wrap (+padding), ChaCha20-Poly1305 | Twofish, Serpent, Salsa20, GOST 28147, SAFER; EAX mode; Camellia GCM-SIV |
| Digests | MD4, MD5, SHA-1, SHA-2 (all), SHA-3, SHAKE, cSHAKE (customisation string only), RIPEMD-160, Whirlpool, BLAKE2b/s (all sizes), SM3, CRC32/CRC24; HMAC flag | Tiger, Haval, GOST R 34.11, Stribog; MD2 (only if the legacy provider offers it, which OpenSSL 4 does not) |
| MACs | HMAC (all available digests), CMAC (available block ciphers), GMAC-AES, Poly1305 | Poly1305-cipher variants, GMAC for non-AES ciphers, GOST IMIT |
| KDFs | S2K (all three), PBKDF2, scrypt, Argon2 (d/i/id), HKDF, one-step KDF (hash and HMAC), X9.63; the `gcry_kdf_open` handle API | PBKDF1 (upstream rejects it too), Balloon (no OpenSSL implementation) |
| Public key | RSA (PKCS#1 v1.5, PSS, OAEP, raw), DSA (incl. RFC 6979), ElGamal (raw, PKCS#1, OAEP, PSS), ECDSA (incl. RFC 6979), ECDH, EdDSA (Ed25519, Ed448, prehash and context variants), X25519/X448, SM2 on its own curve; key generation, keygrips, curve queries | ECDSA on GOST curves, GOST signatures, SM2 on other curves |
| KEMs | ML-KEM-512/768/1024, raw X25519/X448 and Weierstrass KEMs, DHKEM (RFC 9180) | sntrup761, Classic McEliece |
| Low-level EC | All `gcry_mpi_ec_*` operations on Weierstrass curves (NIST, Brainpool, secp256k1, SM2, GOST); scalar multiplication on Montgomery curves | Point addition/doubling on Edwards and Montgomery curves |

Unsupported algorithms report the error codes upstream uses for an unknown
algorithm; names and sizes are still answered. The ECDSA/DSA nonce override
(`gcry_pk_random_override_new`) is accepted but ignored, because OpenSSL does
not allow injecting the nonce. RSA PKCS#1 v1.5 decryption uses OpenSSL's
implicit rejection: a ciphertext with bad padding decrypts to a random
value instead of failing with `GPG_ERR_ENCODING_PROBLEM` as upstream does.

## Layout

| Path           | Contents                                                    |
|----------------|-------------------------------------------------------------|
| `src/`         | Library sources, one file per module; `libgcrypt.map` is the symbol version script |
| `src/include/` | The public header `gcrypt.h`                                |
| `tests/`       | One `test_*.c` program per module, `test_common.h` assertion helpers, `expected-exports.txt`, KEM vectors and the script that regenerates them |
| `benchmarks/`  | `bench_gcrypt` sources and `compare.sh`                     |
| `cmake/`       | Package config, pkg-config and `libgcrypt-config` templates, `drop-in.cmake` |
| `scripts/`     | `build-openssl.sh`, `check-exports.sh`, `coverage.py`       |

## Building

Requires CMake 3.21 (3.25 to use the presets), a C99 compiler, and OpenSSL
4.x development files.

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
| `GCRYPT_OPENSSL_BUILD_SHARED`       | `ON`    | Build the shared library        |
| `GCRYPT_OPENSSL_BUILD_STATIC`       | `ON`    | Build the static library        |
| `GCRYPT_OPENSSL_BUILD_TESTS`        | `ON`    | Build tests (top-level only)    |
| `GCRYPT_OPENSSL_BUILD_BENCHMARKS`   | `ON`    | Build benchmarks (top-level)    |
| `GCRYPT_OPENSSL_WARNINGS_AS_ERRORS` | `OFF`   | Pass `-Werror`                  |
| `GCRYPT_OPENSSL_DROP_IN`            | `OFF`   | Also build `libgcrypt.so.20`, `libgcrypt.pc` and `libgcrypt-config` |
| `GCRYPT_OPENSSL_COVERAGE`           | `OFF`   | Instrument for code coverage and add the `coverage` target |
| `GCRYPT_OPENSSL_FIPS`               | `OFF`   | Start the library in FIPS mode by default; see [FIPS mode](#fips-mode) |
| `GCRYPT_OPENSSL_STOCK_GCRYPT`       | found   | Path of the stock `libgcrypt.so.20` to benchmark against |
| `GCRYPT_OPENSSL_BENCH_ARGS`         | empty   | Arguments the `bench-compare` target passes to both benchmarks |
| `OPENSSL_ROOT_DIR`                  | unset   | Where to find OpenSSL 4 if it is not the system one |

At least one of the two library options must stay on. Tests and benchmarks
default to off when the project is included from another CMake project.

### Presets

`CMakePresets.json` defines configure, build and test presets of the same
name; every one uses Ninja and writes `compile_commands.json`.

| Preset     | Build directory  | Configuration                                   |
|------------|------------------|-------------------------------------------------|
| `default`  | `build/`         | RelWithDebInfo                                  |
| `debug`    | `build-debug/`   | Debug, `GCRYPT_OPENSSL_WARNINGS_AS_ERRORS=ON`   |
| `release`  | `build-release/` | Release (no test preset)                        |
| `coverage` | `build-coverage/`| Debug, `GCRYPT_OPENSSL_COVERAGE=ON`, benchmarks off |
| `fips`     | `build-fips/`    | RelWithDebInfo, `GCRYPT_OPENSSL_FIPS=ON`        |

The extra build preset `coverage-report` runs the `coverage` target in the
`coverage` tree. To point every preset at a non-system OpenSSL, add local
presets that inherit these in an untracked `CMakeUserPresets.json` (see
[OpenSSL 4](#openssl-4)).

### Targets

| Target | Alias | Output |
|--------|-------|--------|
| `gcrypt_openssl_shared` | `gcrypt-openssl::shared` | `libgcrypt-openssl.so.0.1.0` with soname `libgcrypt-openssl.so.0`; exports exactly the `gcry_*` symbols plus `_gcry_mpi_get_const` via `src/libgcrypt.map` |
| `gcrypt_openssl_static` | `gcrypt-openssl::static` | `libgcrypt-openssl.a`, built with PIC so it can be linked into other shared objects |
| (alias only) | `gcrypt-openssl::gcrypt-openssl` | The shared library when built, else the static one; what the tests and benchmarks link |
| `gcrypt_openssl_dropin` | `gcrypt-openssl::libgcrypt` | `libgcrypt.so.20.8.9` with soname `libgcrypt.so.20`; only with `GCRYPT_OPENSSL_DROP_IN=ON` |
| `gcrypt_openssl_warnings` | `gcrypt-openssl::warnings` | Interface target carrying the warning flags; not installed |
| `test_version` ... `test_secmem` (16 programs) | | One executable and CTest entry per public module; link the shared library |
| `test_curves`, `test_internal` | | Tests of internal helpers; link the static library, so they need `GCRYPT_OPENSSL_BUILD_STATIC` |
| `test_version_static` | | `test_version.c` linked against the static library, to prove both flavours link and run |
| `check_exports` | | CTest entry only (no build target): `scripts/check-exports.sh` compares the shared library's dynamic symbols with `tests/expected-exports.txt` |
| `bench_gcrypt` | | Benchmark driver linked against this library |
| `bench_gcrypt_stock` | | The same sources linked against the stock `libgcrypt.so.20`, when one is found |
| `bench-compare` | | Runs both benchmarks through `benchmarks/compare.sh` |
| `coverage` | | Runs the tests and writes the coverage report; only with `GCRYPT_OPENSSL_COVERAGE=ON` |
| `install` | | Libraries, `gcrypt.h`, the CMake package (`gcrypt-openssl-config.cmake`, `-config-version.cmake`, `-targets.cmake`), `gcrypt-openssl.pc`, and with the drop-in `libgcrypt.so.20`, `libgcrypt.pc` and `libgcrypt-config` |

All libraries, tests and benchmarks are part of the default (`all`) target.
Benchmarks are not registered with CTest.

### Tests

Each `tests/test_*.c` is a standalone program using the assertion helpers
in `tests/test_common.h`; no framework is needed. The vectors come from the
relevant RFCs, NIST publications and upstream's own test suite (keygrips,
S2K, RSA encodings). `ctest --preset debug` runs everything, including the
export check:

```sh
ctest --preset debug                    # all 20 entries
ctest --preset debug -R 'cipher|md'     # by name
build-debug/tests/test_pk               # one program directly
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
`OpenSSL::Crypto` as a dependency. Both `libgcrypt-openssl.so` and
`libgcrypt-openssl.a` are built by default.

### Drop-in replacement

With `-DGCRYPT_OPENSSL_DROP_IN=ON` the install also contains
`libgcrypt.so.20.8.9` (the reference library's current soname and
version), `libgcrypt.pc` and a `libgcrypt-config` script. Programs built
against the reference library run unchanged when the install's library
directory is on their library path, for example:

```sh
LD_LIBRARY_PATH=/opt/gcrypt-openssl/lib64 gpg --version
```

Set `CMAKE_INSTALL_PREFIX` at configure time so the pkg-config file and the
config script carry the right paths. The drop-in requires the shared
library to be enabled.

### FIPS mode

At initialisation the library asks for FIPS mode when
`/etc/gcrypt/fips_enabled` exists, `/proc/sys/crypto/fips_enabled` reads
`1`, or the application called `GCRYCTL_FORCE_FIPS_MODE` beforehand, just
like the reference library. Asking means loading OpenSSL's `fips` provider
into the private library context and enabling the `fips=yes` default
property, so every algorithm fetch is served by the FIPS provider. If the
provider cannot be loaded the library carries on without FIPS mode;
`gcry_get_config(0, "fips-mode")` and `GCRYCTL_FIPS_MODE_P` report what
actually happened. `GCRYCTL_NO_FIPS_MODE` before initialisation turns the
request off.

`-DGCRYPT_OPENSSL_FIPS=ON` (the `fips` preset) makes the build ask for FIPS
mode unconditionally, as if the marker file were present, and defines
`GCRYPT_OPENSSL_FIPS=1` for every target in the tree: the libraries, the
drop-in, the tests, the benchmarks and a coverage build configured with
both options. The tests do not yet adapt to FIPS mode, and the setting has
not been validated against a FIPS provider: with an OpenSSL that has no
`fips` module (such as the one `scripts/build-openssl.sh` produces) the
library silently runs in non-FIPS mode and the suite passes as usual.

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

See [LICENSE](LICENSE), but this is entirely Public Domain because it wasn't
written by a human.
