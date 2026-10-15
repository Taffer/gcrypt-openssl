# gcrypt-openssl

The gcrypt API, implemented using OpenSSL for the cryptography.

The point is to let you use our own tuned or FIPS-certified OpenSSL with
software that uses the gcrypt API.

This project was extruded by Claude. Use at your own risk.

## Layout

| Directory     | Contents                                                   |
|---------------|------------------------------------------------------------|
| `src/`        | Library sources; public headers in `src/include/`          |
| `tests/`      | Unit tests, run via CTest                                  |
| `benchmarks/` | Benchmark executables, built but not run automatically     |
| `cmake/`      | CMake package-config template for `find_package()` support |

## Building

Requires CMake 3.21+, a C99 compiler, and OpenSSL 4.x development files.

```sh
cmake --preset default
cmake --build --preset default
ctest --preset default
./build/benchmarks/bench_version
```

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

Both `libgcrypt-openssl.so` and `libgcrypt-openssl.a` are built by default.
Useful options:

| Option                              | Default | Effect                          |
|-------------------------------------|---------|---------------------------------|
| `GCRYPT_OPENSSL_BUILD_SHARED`       | `ON`    | Build the shared library        |
| `GCRYPT_OPENSSL_BUILD_STATIC`       | `ON`    | Build the static library        |
| `GCRYPT_OPENSSL_BUILD_TESTS`        | `ON`    | Build tests (top-level only)    |
| `GCRYPT_OPENSSL_BUILD_BENCHMARKS`   | `ON`    | Build benchmarks (top-level)    |
| `GCRYPT_OPENSSL_WARNINGS_AS_ERRORS` | `OFF`   | Pass `-Werror`                  |

Consumers can `find_package(gcrypt-openssl)` after `cmake --install` and link
against `gcrypt-openssl::shared` or `gcrypt-openssl::static`.

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
