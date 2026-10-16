#!/bin/sh
# Compare the dynamic symbols exported by a built shared library with the
# list of symbols the reference Libgcrypt exports (tests/expected-exports.txt,
# derived from upstream's libgcrypt.vers).
#
# Usage: scripts/check-exports.sh <path/to/libgcrypt-openssl.so> [expected-list]
#
# Exit status is 0 when every expected symbol is present and nothing
# unexpected is exported; otherwise the differences are printed.
set -eu

# The expected list is in C-locale order; sort and comm must agree on that
# whatever the caller's locale (underscores collate differently elsewhere).
export LC_ALL=C

lib="${1:?usage: $0 <shared-library> [expected-list]}"
expected="${2:-$(dirname "$0")/../tests/expected-exports.txt}"

actual="$(mktemp)"
trap 'rm -f "$actual"' EXIT INT TERM

nm -D --defined-only "$lib" | awk '$2 ~ /^[TtWwDdBb]$/ { print $3 }' \
    | sed 's/@.*//' | sort -u > "$actual"

status=0

missing="$(comm -23 "$expected" "$actual")"
if [ -n "$missing" ]; then
    echo "Missing exports ($(printf '%s\n' "$missing" | wc -l)):"
    printf '%s\n' "$missing" | sed 's/^/  /'
    status=1
fi

extra="$(comm -13 "$expected" "$actual")"
if [ -n "$extra" ]; then
    echo "Unexpected exports ($(printf '%s\n' "$extra" | wc -l)):"
    printf '%s\n' "$extra" | sed 's/^/  /'
    status=1
fi

if [ "$status" -eq 0 ]; then
    echo "All $(wc -l < "$expected") expected symbols exported, nothing extra."
fi

exit "$status"
