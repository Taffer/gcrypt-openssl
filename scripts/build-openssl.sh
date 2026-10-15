#!/bin/sh
# Download, verify, build and install a pinned OpenSSL 4 release.
#
# Usage: scripts/build-openssl.sh [PREFIX]
#
# PREFIX defaults to ~/.local/opt/openssl-<version>. Only the libraries,
# headers and openssl(1) binary are installed (install_sw); documentation
# and the default config directory are skipped.
set -eu

OPENSSL_VERSION="${OPENSSL_VERSION:-4.0.3}"
OPENSSL_SHA256="${OPENSSL_SHA256:-325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9}"

prefix="${1:-$HOME/.local/opt/openssl-$OPENSSL_VERSION}"
tarball="openssl-$OPENSSL_VERSION.tar.gz"
url="https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/$tarball"
jobs="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT INT TERM
cd "$workdir"

echo "Downloading $url"
curl -fsSLO "$url"

echo "Verifying checksum"
echo "$OPENSSL_SHA256  $tarball" | sha256sum -c -

echo "Building OpenSSL $OPENSSL_VERSION with $jobs jobs"
tar xzf "$tarball"
cd "openssl-$OPENSSL_VERSION"
./Configure --prefix="$prefix" --libdir=lib no-docs
make -j"$jobs"
make install_sw

echo
echo "OpenSSL $OPENSSL_VERSION installed in $prefix"
echo "Configure this project with:"
echo "  cmake --preset default -DOPENSSL_ROOT_DIR=\"$prefix\""
