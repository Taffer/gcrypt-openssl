# gcrypt-openssl

The [Libgcrypt](https://gnupg.org/software/libgcrypt/) API, implemented on
top of OpenSSL 4.

The point is to let software written against the gcrypt API use your own
tuned or FIPS-certified OpenSSL instead. The library implements the complete
public API of Libgcrypt 1.12 (every symbol of its `GCRYPT_1.6` version node)
and can be built under the reference library's own name and soname
(`libgcrypt.so.20`) so that existing binaries pick it up unchanged.

This project was extruded by Claude. Use at your own risk.

## How it is built

- **No cryptography is implemented here.** Every primitive comes from
  OpenSSL's EVP, BIGNUM, EC and RAND APIs, fetched from a private
  `OSSL_LIB_CTX` that loads the system OpenSSL configuration (so a FIPS
  provider configured there applies) and tries the legacy provider for the
  old algorithms the gcrypt API exposes. Hand-written code is limited to
  glue: S-expressions, MPI import/export formats, the OpenPGP S2K and
  PBKDF1 iterated hashes, the three CRCs, ElGamal's modular arithmetic, and
  the composition of modes OpenSSL has no single cipher for.
- **No dependencies besides the C library, POSIX threads and OpenSSL 4.**
  `gcrypt.h` embeds the subset of libgpg-error it needs (error types, every
  `GPG_ERR_*` value, inline helpers); a real `<gpg-error.h>` included first
  takes precedence.
- **Clean room.** Upstream was read for behaviour only; the public header,
  constants and S-expression formats are reproduced because they are the
  API, the code is new. See [LICENSE](LICENSE).
- "Secure memory" is OpenSSL's secure heap, so secure allocations are wiped
  on free and `gcry_is_secure()` is an exact range check.

## Support

| Area | Supported | Not available |
|------|-----------|---------------|
| Ciphers | AES, Camellia, ARIA, SM4, 3DES, DES, CAST5, Blowfish, IDEA, RC2, SEED, RC4, ChaCha20; ECB, CBC (+CTS, +MAC), CFB, CFB8, OFB, CTR, GCM, CCM, OCB, XTS, SIV, GCM-SIV, AES key wrap (+padding), ChaCha20-Poly1305 | Twofish, Serpent, Salsa20, GOST 28147, SAFER; EAX mode |
| Digests | MD4, MD5, SHA-1, SHA-2 (all), SHA-3, SHAKE, cSHAKE, RIPEMD-160, Whirlpool, BLAKE2b/s (all sizes), SM3, CRC32/CRC24; HMAC flag | Tiger, Haval, GOST R 34.11, Stribog, MD2 |
| MACs | HMAC (all available digests), CMAC (available block ciphers), GMAC-AES, Poly1305 | Poly1305-cipher variants, GMAC for non-AES, GOST IMIT |
| KDFs | S2K (all three), PBKDF2, scrypt, Argon2 (d/i/id), HKDF, one-step KDF (hash and HMAC), X9.63 | PBKDF1 (upstream also rejects it), Balloon |
| Public key | RSA (PKCS#1 v1.5, PSS, OAEP, raw), DSA (incl. RFC 6979), ElGamal, ECDSA, ECDH, EdDSA (Ed25519, Ed448), X25519/X448; key generation, keygrips, curve queries | ECDSA on GOST curves, SM2/GOST signatures |
| KEMs | ML-KEM-512/768/1024, raw X25519/X448 and Weierstrass KEMs, DHKEM (RFC 9180) | sntrup761, Classic McEliece |
| Low-level EC | All `gcry_mpi_ec_*` operations on Weierstrass curves (NIST, Brainpool, secp256k1, SM2, GOST) | Point addition/doubling on Edwards curves |

Unsupported algorithms report the error codes upstream uses for an unknown
algorithm; names and sizes are still answered. The ECDSA/DSA nonce override
(`gcry_pk_random_override_new`) is accepted but ignored, because OpenSSL does
not allow injecting the nonce.

## Layout

| Directory     | Contents                                                   |
|---------------|------------------------------------------------------------|
| `src/`        | Library sources; public header `src/include/gcrypt.h`     |
| `tests/`      | One test program per module with published test vectors   |
| `benchmarks/` | `bench_gcrypt` suite and `compare.sh` for stock libgcrypt  |
| `cmake/`      | Package config, pkg-config and drop-in templates           |
| `scripts/`    | `build-openssl.sh`, `check-exports.sh`, `coverage.py`      |

## Building

Requires CMake 3.21+, a C99 compiler, and OpenSSL 4.x development files.

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Both `libgcrypt-openssl.so` and `libgcrypt-openssl.a` are built by default.
Useful options:

| Option                              | Default | Effect                          |
|-------------------------------------|---------|---------------------------------|
| `GCRYPT_OPENSSL_BUILD_SHARED`       | `ON`    | Build the shared library        |
| `GCRYPT_OPENSSL_BUILD_STATIC`       | `ON`    | Build the static library        |
| `GCRYPT_OPENSSL_BUILD_TESTS`        | `ON`    | Build tests (top-level only)    |
| `GCRYPT_OPENSSL_BUILD_BENCHMARKS`   | `ON`    | Build benchmarks (top-level)    |
| `GCRYPT_OPENSSL_WARNINGS_AS_ERRORS` | `OFF`   | Pass `-Werror`                  |
| `GCRYPT_OPENSSL_DROP_IN`            | `OFF`   | Also build `libgcrypt.so.20`    |
| `GCRYPT_OPENSSL_COVERAGE`           | `OFF`   | Instrument for code coverage    |

Consumers can `find_package(gcrypt-openssl)` after `cmake --install` and link
against `gcrypt-openssl::shared` or `gcrypt-openssl::static`, or use the
installed `gcrypt-openssl.pc`.

### Drop-in replacement

With `-DGCRYPT_OPENSSL_DROP_IN=ON` the install also contains
`libgcrypt.so.20.8.9` (upstream's current version), `libgcrypt.pc` and a
`libgcrypt-config` script. Programs built against the reference library run
unchanged when the install's library directory is on their library path,
for example:

```sh
LD_LIBRARY_PATH=/opt/gcrypt-openssl/lib64 gpg --version
```

Set `CMAKE_INSTALL_PREFIX` at configure time so the pkg-config file and the
config script carry the right paths.

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
library file to compare against a specific build.

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

Linting runs through [pre-commit](https://pre-commit.com/): astyle for
C, cmake-format and cmake-lint for CMake, markdownlint for Markdown, and
codespell for spelling. Install the hooks once after cloning:

```sh
pre-commit install
pre-commit run --all-files
```

## License

See [LICENSE](LICENSE), but this is entirely Public Domain because it wasn't
written by a human.
