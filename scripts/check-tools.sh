#!/bin/sh
# Check that the drop-in's dumpsexp, hmac256 and mpicalc behave like the
# programs the reference Libgcrypt ships: same options, same output, same
# exit statuses.
#
# Usage: scripts/check-tools.sh <dumpsexp> <hmac256> <mpicalc>
#
# Exit status is 0 when every check passes; otherwise each failure is printed.
set -u

dumpsexp="${1:?usage: $0 <dumpsexp> <hmac256> <mpicalc>}"
hmac256="${2:?usage: $0 <dumpsexp> <hmac256> <mpicalc>}"
mpicalc="${3:?usage: $0 <dumpsexp> <hmac256> <mpicalc>}"

status=0
fail() {
    echo "FAIL: $*"
    status=1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

# ---------------------------------------------------------------- dumpsexp
out="$("$dumpsexp" --version | head -1)"
case "$out" in
    "dumpsexp (Libgcrypt) "*) ;;
    *) fail "dumpsexp --version: '$out'" ;;
esac
"$dumpsexp" --help | grep -q -- '--assume-hex' || fail "dumpsexp --help lacks options"
"$dumpsexp" --bogus >/dev/null 2>&1 && fail "dumpsexp --bogus: expected exit 1"

# The hex dump: tokens are echoed as parsed, then each 16-byte line.
expected='a00000000  28 61 29                                          |(a)|'
out="$(printf '(a)' | "$dumpsexp")"
[ "$out" = "$expected" ] || fail "dumpsexp dump: '$out'"
out="$(printf '28 61 29' | "$dumpsexp" --assume-hex --decimal)"
[ "$out" = "$expected" ] || fail "dumpsexp --assume-hex --decimal: '$out'"

# --verbose reports parser events under a cursor.
printf '(a)' | "$dumpsexp" --verbose | grep -q '^ *\^ open$' \
    || fail "dumpsexp --verbose: no 'open' event"
printf '(a)' | "$dumpsexp" --verbose | grep -q '^ *\^ close$' \
    || fail "dumpsexp --verbose: no 'close' event"

# Errors are reported inline and do not fail the run (as upstream).
out="$(printf '(a 0:x)' | "$dumpsexp")"; rc=$?
[ "$rc" -eq 0 ] || fail "dumpsexp error input: exit $rc"
printf '%s\n' "$out" | grep -q 'Error: zero prefixed length' \
    || fail "dumpsexp: zero prefixed length not reported"

# --advanced parses with the library and prints advanced format.
out="$(printf '(3:key(1:n3:abc)(1:e2:\001\002))' | "$dumpsexp" --advanced | tr -d ' \n')"
[ "$out" = '(key(nabc)(e#0102#))' ] || fail "dumpsexp --advanced: '$out'"
printf '(a' | "$dumpsexp" --advanced >/dev/null 2>&1 && fail "dumpsexp --advanced on bad input: expected exit 1"

# Files: a missing one fails, a good one is dumped.
"$dumpsexp" "$tmp/missing" >/dev/null 2>&1 && fail "dumpsexp missing file: expected exit 1"
printf '(a)' > "$tmp/a.sexp"
[ "$("$dumpsexp" "$tmp/a.sexp")" = "$expected" ] || fail "dumpsexp file argument"

# ----------------------------------------------------------------- hmac256
# FIPS mode refuses HMAC keys shorter than 14 bytes, so the RFC 4231 "Jefe"
# vector is only checked outside FIPS mode; the rest use a 20-byte key.
fips=no
"$mpicalc" --print-config | grep -q '^fips-mode:y' && fips=yes
key='Jefe-Jefe-Jefe-Jefe!'
mac=8c3cd4e29fb19f5e722fd388e994f6241ea894f32f72fe19b5d3b32f6f311e41
jefe=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
stdkey_empty=f2353f4c2eae21f5a2113d024a70e9210736cd1663b3c655a3a1e243398baaf2

out="$("$hmac256" --version | head -1)"
case "$out" in
    "hmac256 (Libgcrypt) "*) ;;
    *) fail "hmac256 --version: '$out'" ;;
esac
"$hmac256" >/dev/null 2>&1 && fail "hmac256 without key: expected exit 1"

if [ "$fips" = no ]; then
    out="$(printf 'what do ya want for nothing?' | "$hmac256" Jefe)"
    [ "$out" = "$jefe" ] || fail "hmac256 RFC 4231 Jefe: '$out'"
else
    printf 'x' | "$hmac256" Jefe >/dev/null 2>&1 \
        && fail "hmac256 short key in FIPS mode: expected failure"
fi

out="$(printf 'what do ya want for nothing?' | "$hmac256" "$key")"
[ "$out" = "$mac" ] || fail "hmac256 stdin: '$out'"

printf 'what do ya want for nothing?' > "$tmp/data"
out="$("$hmac256" "$key" "$tmp/data")"
[ "$out" = "$mac  $tmp/data" ] || fail "hmac256 file: '$out'"

out="$("$hmac256" "$key" "$tmp/data" "$tmp/data" | wc -l | tr -d ' ')"
[ "$out" = 2 ] || fail "hmac256 two files: $out lines"

out="$(printf 'what do ya want for nothing?' | "$hmac256" --binary "$key" | od -An -tx1 | tr -d ' \n')"
[ "$out" = "$mac" ] || fail "hmac256 --binary: '$out'"

# --stdkey uses the reference library's built-in integrity-check key.
out="$(printf '' | "$hmac256" --stdkey)"
[ "$out" = "$stdkey_empty" ] || fail "hmac256 --stdkey: '$out'"

"$hmac256" "$key" "$tmp/missing" >/dev/null 2>&1 && fail "hmac256 missing file: expected exit 1"

# ----------------------------------------------------------------- mpicalc
out="$("$mpicalc" --version | head -1)"
[ "$out" = "mpicalc 2.0" ] || fail "mpicalc --version: '$out'"
"$mpicalc" --print-config | grep -q '^version:1\.' || fail "mpicalc --print-config"
"$mpicalc" extra >/dev/null 2>&1 && fail "mpicalc with argument: expected exit 1"

calc() {
    printf '%s\n' "$1" | "$mpicalc" 2>/dev/null
}
check() {
    out="$(calc "$1")"
    [ "$out" = "$2" ] || fail "mpicalc '$1': '$out', expected '$2'"
}
check '0ff 1 + p' 0100           # hex in, hex out, even digit count
check '-1 2 * p' -02             # negative numbers
check '7 3 / p' 02
check '-7 2 / p' -04             # floor division
check '7 3 % p' 01
check '2 10 11 ^ p' 01           # 2^16 mod 17
check '3 7 I p' 05               # inverse mod
check '18 0c G p' 0C             # gcd(0x18, 0x0c); hex output is upper case
check '0ff b p' 08               # bit count
check '7 P p' 01                 # prime
check '8 P p' 00                 # composite
check '5 ++ p' 06
check '5 -- p' 04
check '1 < p' 02
check '4 > p' 02
check '1 2 r f' '[ 1]: 01
[ 0]: 02'
check '1 d f' '[ 1]: 01
[ 0]: 01'
check '1 2 i p' 01
check '1 c p' 'stack is empty'
check '# comment 5 p
2 p' 02
printf '?\n' | "$mpicalc" | grep -q '^P   prime check' || fail "mpicalc ? help"
out="$(printf '+\n' | "$mpicalc" 2>&1)"
[ "$out" = "stack underflow" ] || fail "mpicalc underflow: '$out'"
out="$(printf 'z\n' | "$mpicalc" 2>&1)"
[ "$out" = "invalid operator" ] || fail "mpicalc invalid operator: '$out'"

[ "$status" -eq 0 ] && echo "tools: all checks passed"
exit "$status"
