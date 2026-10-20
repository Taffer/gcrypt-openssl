#!/bin/sh
# Check that a configured libgcrypt-config script behaves like the one the
# reference Libgcrypt ships: same options, same output layout, same exit
# statuses, and values that agree with gcrypt.h.
#
# Usage: scripts/check-libgcrypt-config.sh <path/to/libgcrypt-config> [gcrypt.h]
#
# Exit status is 0 when every check passes; otherwise each failure is printed.
set -u

config="${1:?usage: $0 <libgcrypt-config> [gcrypt.h]}"
header="${2:-$(dirname "$0")/../src/include/gcrypt.h}"

status=0
fail() {
    echo "FAIL: $*"
    status=1
}

run() {
    out="$("$config" "$@" 2>/dev/null)"
    rc=$?
}

# No options: usage on stderr, exit 1, nothing on stdout.
out="$("$config" 2>/dev/null)"; rc=$?
[ "$rc" -eq 1 ] || fail "no options: exit $rc, expected 1"
[ -z "$out" ] || fail "no options: unexpected stdout"
err="$("$config" 2>&1 >/dev/null)"
case "$err" in
    Usage:*) ;;
    *) fail "no options: usage text missing from stderr" ;;
esac

# Unknown options and the obsolete --thread= fail as upstream.
run --bogus; [ "$rc" -eq 1 ] || fail "--bogus: exit $rc, expected 1"
run --thread=pthread; [ "$rc" -eq 1 ] || fail "--thread=: exit $rc, expected 1"

# --prefix=/x and --exec-prefix=/x are accepted and ignored (old M4 macros).
run --prefix=/nonexistent --exec-prefix=/nonexistent
[ "$rc" -eq 0 ] || fail "--prefix=: exit $rc, expected 0"
[ -z "$out" ] || fail "--prefix=: unexpected output '$out'"

# Version matches GCRYPT_VERSION in the header; --modversion is an alias.
expected_version="$(sed -n 's/^#define GCRYPT_VERSION "\(.*\)"/\1/p' "$header")"
[ -n "$expected_version" ] || fail "cannot read GCRYPT_VERSION from $header"
run --version
[ "$rc" -eq 0 ] || fail "--version: exit $rc"
[ "$out" = "$expected_version" ] || fail "--version: '$out', expected '$expected_version'"
run --modversion
[ "$out" = "$expected_version" ] || fail "--modversion: '$out', expected '$expected_version'"
run --api-version
[ "$out" = "1" ] || fail "--api-version: '$out', expected '1'"

# Prefix and exec-prefix.
run --prefix; prefix="$out"
[ -n "$prefix" ] || fail "--prefix: empty"
run --exec-prefix
[ "$out" = "$prefix" ] || fail "--exec-prefix: '$out', expected '$prefix'"

# Host triplet is non-empty and looks like cpu-vendor-os.
run --host
case "$out" in
    *-*) ;;
    *) fail "--host: '$out' is not a triplet" ;;
esac

# --cflags: -I<includedir> unless that is a default search directory.
run --variable=includedir; includedir="$out"
[ -n "$includedir" ] || fail "--variable=includedir: empty"
run --cflags
[ "$rc" -eq 0 ] || fail "--cflags: exit $rc"
if [ "$includedir" != /usr/include ] && [ "$includedir" != /include ]; then
    [ "$out" = "-I$includedir" ] || fail "--cflags: '$out', expected '-I$includedir'"
else
    [ -z "$out" ] || fail "--cflags: '$out', expected nothing"
fi

# --libs: -L<libdir> unless default, then -lgcrypt and nothing else (no
# libgpg-error in this implementation).
run --variable=libdir; libdir="$out"
[ -n "$libdir" ] || fail "--variable=libdir: empty"
run --libs
[ "$rc" -eq 0 ] || fail "--libs: exit $rc"
if [ "$libdir" != /usr/lib ] && [ "$libdir" != /lib ]; then
    [ "$out" = "-L$libdir -lgcrypt" ] || fail "--libs: '$out', expected '-L$libdir -lgcrypt'"
else
    [ "$out" = "-lgcrypt" ] || fail "--libs: '$out', expected '-lgcrypt'"
fi
case "$out" in
    *gpg-error*) fail "--libs: mentions gpg-error" ;;
esac

# Combined options print in upstream's fixed order: prefix, exec-prefix,
# cflags, libs, version, api-version, host, algorithms.
run --libs --version --cflags --prefix
expected="$(printf '%s\n' "$prefix" "$("$config" --cflags)" \
                          "$("$config" --libs)" "$expected_version")"
[ "$out" = "$expected" ] || fail "combined options: order or content differs"

# --algorithms: three labelled lines.
run --algorithms
[ "$rc" -eq 0 ] || fail "--algorithms: exit $rc"
[ "$(printf '%s\n' "$out" | wc -l)" -eq 3 ] || fail "--algorithms: expected 3 lines"
printf '%s\n' "$out" | sed -n 1p | grep -q '^Symmetric cipher algorithms: .*aes' \
    || fail "--algorithms: line 1 wrong"
printf '%s\n' "$out" | sed -n 2p | grep -q '^Public-key cipher algorithms: .*rsa' \
    || fail "--algorithms: line 2 wrong"
printf '%s\n' "$out" | sed -n 3p | grep -q '^Message digest algorithms: .*sha256' \
    || fail "--algorithms: line 3 wrong"

# --variable= answers for every documented name and exits at once.
for name in prefix exec_prefix includedir libdir host version api_version \
            symmetric_ciphers asymmetric_ciphers digests kdfs \
            implementation implementation_version openssl_version; do
    run "--variable=$name" --libs
    [ "$rc" -eq 0 ] || fail "--variable=$name: exit $rc"
    [ -n "$out" ] || fail "--variable=$name: empty"
    case "$out" in
        *-lgcrypt*) fail "--variable=$name: did not exit before --libs" ;;
    esac
done
run --variable=implementation
[ "$out" = gcrypt-openssl ] || fail "--variable=implementation: '$out'"

[ "$status" -eq 0 ] && echo "libgcrypt-config: all checks passed"
exit "$status"
