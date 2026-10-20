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
out="$(printf '28 6A 29' | "$dumpsexp" --assume-hex)"
[ "$out" = 'j00000000  28 6a 29                                          |(j)|' ] \
    || fail "dumpsexp --assume-hex upper case: '$out'"

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

# Every syntax error the scanner knows is reported under a cursor.  Each
# case feeds one construct and looks for its message.
expect_error() {
    out="$(printf '%s' "$1" | "$dumpsexp" 2>&1)"
    printf '%s\n' "$out" | grep -q "Error: $2" \
        || fail "dumpsexp '$1': missing 'Error: $2'"
}
expect_error '(a "x\q")' 'invalid escape sequence'
expect_error '(#616#)' 'odd number of hex digits'
expect_error '(#6g1#)' 'bad hex character'
expect_error '([a [b] ]c)' 'nested display hint'
expect_error '([a [b] ]c)' 'no open display hint'
expect_error '([a)' 'unmatched display hint'
expect_error '(a]' 'no open display hint'
expect_error '({)' 'rescanning is not supported'
expect_error '(&)' 'reserved punctuation detected'
expect_error '(,)' 'bad character detected'
expect_error '(1x)' 'invalid length specification'
expect_error '(99999999999999999999999:)' 'overflow in data length'
expect_error '([a (b))' 'unmatched display hint'

# Well-formed constructs pass through without an error: quoted strings with
# every escape form, hex and base64 strings, length-prefixed data, display
# hints, and a length prefix in front of a quoted string.
for good in '(a "x\n\t\101\x41\\\"" "a\
b")' '(#6162# |YWI=| 3:abc [hint]x)' '(3"abc" 2#61#)' '("\1x\xZ")'; do
    out="$(printf '%s' "$good" | "$dumpsexp" 2>&1)"
    printf '%s\n' "$out" | grep -q 'Error:' \
        && fail "dumpsexp '$good': unexpected error"
done

# --verbose names every parser event.
out="$(printf '(#61#|YQ==|3:abc"s")' | "$dumpsexp" --verbose)"
for event in open beginhex endhex beginbase64 endbase64 begindata enddata \
             beginstring endstring close; do
    printf '%s\n' "$out" | grep -q "\\^ $event\$" \
        || fail "dumpsexp --verbose: no '$event' event"
done

# A line wraps every 16 bytes; tokens are echoed before the line.
out="$(printf '(abcdefghijklmnopqrstuvwxyz)' | "$dumpsexp" --decimal)"
expected='abcdefghijklmno00000000  28 61 62 63 64 65 66 67  68 69 6a 6b 6c 6d 6e 6f  |(abcdefghijklmno|
pqrstuvwxyz00000016  70 71 72 73 74 75 76 77  78 79 7a 29              |pqrstuvwxyz)|'
[ "$out" = "$expected" ] || fail "dumpsexp two-line dump differs"

# Malformed hex input stops the dump with a message on stderr.
for bad in '2x' '2' 'zz'; do
    err="$(printf '%s' "$bad" | "$dumpsexp" --assume-hex 2>&1 >/dev/null)"
    case "$err" in
        dumpsexp:*hex*) ;;
        *) fail "dumpsexp --assume-hex '$bad': '$err'" ;;
    esac
done

# "--" ends option parsing; an unreadable input is a read error.
[ "$(printf '(a)' | "$dumpsexp" --)" = "$(printf '(a)' | "$dumpsexp")" ] \
    || fail "dumpsexp --: differs"
"$dumpsexp" "$tmp" >/dev/null 2>&1 && fail "dumpsexp on a directory: expected exit 1"
"$dumpsexp" --advanced "$tmp" >/dev/null 2>&1 && fail "dumpsexp --advanced on a directory: expected exit 1"

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

# "--" ends option parsing; a directory is a read error; --binary writes
# exactly 32 bytes.
out="$(printf 'what do ya want for nothing?' | "$hmac256" -- "$key")"
[ "$out" = "$mac" ] || fail "hmac256 -- key: '$out'"
out="$("$hmac256" "$key" "$tmp" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] || fail "hmac256 on a directory: exit $rc"
case "$out" in
    *"error reading"*) ;;
    *) fail "hmac256 on a directory: '$out'" ;;
esac
out="$("$hmac256" --binary --stdkey </dev/null | wc -c | tr -d ' ')"
[ "$out" = 32 ] || fail "hmac256 --binary --stdkey: $out bytes"
if [ -w /dev/full ]; then
    "$hmac256" --binary --stdkey </dev/null >/dev/full 2>"$tmp/err" \
        && fail "hmac256 write error: expected exit 1"
    grep -q 'error writing output' "$tmp/err" || fail "hmac256 write error message"
fi

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

check '5 3 - p' 02               # subtract
check '3 4 5 m p' 02             # 3*4 mod 5
check '-0a p' -0A                # negative hex number
check '-5 -3 - p' -02            # '-' before a digit is a sign, else subtract
[ "$(printf '1 p\n' | "$mpicalc" --)" = 01 ] || fail "mpicalc --"
out="$(printf '%s\n' '-' | "$mpicalc" 2>&1)"
[ "$out" = "stack underflow" ] || fail "mpicalc subtract underflow: '$out'"
out="$(printf '1 2 m\n' | "$mpicalc" 2>&1)"
[ "$out" = "stack underflow" ] || fail "mpicalc mulm underflow: '$out'"

# --disable-hwf consumes its argument, with or without one.
"$mpicalc" --disable-hwf bogus </dev/null >/dev/null 2>&1 \
    || fail "mpicalc --disable-hwf NAME: expected exit 0"
"$mpicalc" --disable-hwf </dev/null >/dev/null 2>&1 \
    || fail "mpicalc --disable-hwf without argument: expected exit 0"

# Non-ASCII bytes are skipped with one notice.
out="$(printf '1 \303\251 \303\251 p\n' | "$mpicalc" 2>&1)"
[ "$out" = "note: Non ASCII characters are ignored
01" ] || fail "mpicalc non-ASCII: '$out'"

# The stack holds 500 items; the 501st push and a dup beyond it overflow.
pushes="$(i=0; while [ $i -lt 500 ]; do printf '1 '; i=$((i + 1)); done)"
out="$(printf '%s 1\n' "$pushes" | "$mpicalc" 2>&1)"
[ "$out" = "stack overflow" ] || fail "mpicalc push overflow: '$out'"
out="$(printf '%s d\n' "$pushes" | "$mpicalc" 2>&1)"
[ "$out" = "stack overflow" ] || fail "mpicalc dup overflow: '$out'"

# A number longer than the input buffer is truncated with a notice.
digits="$(i=0; while [ $i -lt 4100 ]; do printf '0'; i=$((i + 1)); done)"
out="$(printf '1%s b p\n' "$digits" | "$mpicalc" 2>&1)"
[ "$out" = "input too large - truncated
3FF1" ] || fail "mpicalc truncation: '$out'"

[ "$status" -eq 0 ] && echo "tools: all checks passed"
exit "$status"
