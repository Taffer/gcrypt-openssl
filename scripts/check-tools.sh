#!/bin/sh
# Check that the drop-in's dumpsexp, hmac256, mpicalc, gpg-error and yat2m
# behave like the programs the reference Libgcrypt and libgpg-error ship:
# same options, same output, same exit statuses.  The expected texts were
# recorded from the reference programs (libgpg-error 1.58).
#
# Usage: scripts/check-tools.sh <dumpsexp> <hmac256> <mpicalc> <gpg-error> <yat2m>
#
# Exit status is 0 when every check passes; otherwise each failure is printed.
set -u

usage="usage: $0 <dumpsexp> <hmac256> <mpicalc> <gpg-error> <yat2m>"
dumpsexp="${1:?$usage}"
hmac256="${2:?$usage}"
mpicalc="${3:?$usage}"
gpgerror="${4:?$usage}"
yat2m="${5:?$usage}"

# Some checks run the tools from another directory.
absolute() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$(pwd)" "$1" ;;
    esac
}
gpgerror="$(absolute "$gpgerror")"
yat2m="$(absolute "$yat2m")"

status=0
fail() {
    echo "FAIL: $*"
    status=1
}

sp=' '  # Trailing spaces in expected output; editors strip them.
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

# --------------------------------------------------------------- gpg-error
out="$("$gpgerror" --version | head -1)"
case "$out" in
    "gpg-error (Libgcrypt) "*) ;;
    *) fail "gpg-error --version: '$out'" ;;
esac
[ "$("$gpgerror" --version | wc -l | tr -d ' ')" = 3 ] || fail "gpg-error --version: line count"
"$gpgerror" --help 2>/dev/null | grep -q '^     fconcat         Construct a file name$' \
    || fail "gpg-error --help lacks the command list"

# Error values are printed as number, source/code pair, names and texts.
check_err() {
    out="$("$gpgerror" "$1" 2>/dev/null)"
    [ "$out" = "$2" ] || fail "gpg-error $1: '$out'"
}
check_err 1 '1 = (0, 1) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_GENERAL) = (Unspecified source, General error)'
check_err 33554433 '33554433 = (2, 1) = (GPG_ERR_SOURCE_GPG, GPG_ERR_GENERAL) = (GnuPG, General error)'
check_err 0x1000001 '16777217 = (1, 1) = (GPG_ERR_SOURCE_GCRYPT, GPG_ERR_GENERAL) = (gcrypt, General error)'
check_err GPG_ERR_BAD_KEY '19 = (0, 19) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_BAD_KEY) = (Unspecified source, Bad session key)'
check_err bad_key '19 = (0, 19) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_BAD_KEY) = (Unspecified source, Bad session key)'
check_err EPERM '32875 = (0, 32875) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_EPERM) = (Unspecified source, Operation not permitted)'
check_err 'Operation not permitted' '32875 = (0, 32875) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_EPERM) = (Unspecified source, Operation not permitted)'
check_err GPG_ERR_SOURCE_GCRYPT '16777216 = (1, 0) = (GPG_ERR_SOURCE_GCRYPT, GPG_ERR_NO_ERROR) = (gcrypt, Success)'
check_err gcrypt '16777216 = (1, 0) = (GPG_ERR_SOURCE_GCRYPT, GPG_ERR_NO_ERROR) = (gcrypt, Success)'
check_err 'User defined source 2' '553648128 = (33, 0) = (GPG_ERR_SOURCE_USER_2, GPG_ERR_NO_ERROR) = (User defined source 2, Success)'
check_err 99999 '99999 = (0, 34463) = (GPG_ERR_SOURCE_UNKNOWN, -) = (Unspecified source, Unknown system error)'
check_err 4096 '4096 = (0, 4096) = (GPG_ERR_SOURCE_UNKNOWN, -) = (Unspecified source, Unknown error code)'
check_err 4294967295 '4294967295 = (127, 65535) = (-, -) = (Unknown source, Unknown system error)'
check_err '' '0 = (0, 0) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_NO_ERROR) = (Unspecified source, Success)'
check_err '1 ' '0 = (0, 0) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_NO_ERROR) = (Unspecified source, Success)'
check_err +7 '7 = (0, 7) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_BAD_SECKEY) = (Unspecified source, Bad secret key)'

# Unrecognised words are reported, the others still printed, exit 1.
out="$("$gpgerror" 1 bogus 4294967296 -1 'GPG_ERR_GENERAL ' 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] || fail "gpg-error with unknown word: exit $rc"
[ "$out" = "gpg-error: warning: could not recognize bogus
gpg-error: warning: could not recognize 4294967296
gpg-error: warning: could not recognize -1
gpg-error: warning: could not recognize GPG_ERR_GENERAL " ] \
    || fail "gpg-error unknown words: '$out'"
[ "$("$gpgerror" 1 bogus 2>/dev/null | wc -l | tr -d ' ')" = 1 ] \
    || fail "gpg-error: known value not printed next to unknown one"

# Options stop at the first error number.
[ "$("$gpgerror" 1 --desc 2>&1 >/dev/null)" = "gpg-error: warning: could not recognize --desc" ] \
    || fail "gpg-error: option after a number"

# list and defines cover every source and code, in order.
out="$("$gpgerror" list)"
[ "$(printf '%s\n' "$out" | head -1)" = '0 = (0, -) = (GPG_ERR_SOURCE_UNKNOWN, -) = (Unspecified source, -)' ] \
    || fail "gpg-error list: first line"
printf '%s\n' "$out" | grep -q '^587202560 = (35, -) = (GPG_ERR_SOURCE_USER_4, -) = (User defined source 4, -)$' \
    || fail "gpg-error list: last source"
printf '%s\n' "$out" | grep -q '^0 = (-, 0) = (-, GPG_ERR_NO_ERROR) = (-, Success)$' \
    || fail "gpg-error list: first code"
[ "$(printf '%s\n' "$out" | tail -1)" = '32908 = (-, 32908) = (-, GPG_ERR_EXFULL) = (-, Exchange full)' ] \
    || fail "gpg-error list: last line"
n="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
[ "$n" -ge 607 ] || fail "gpg-error list: only $n lines"
[ "$("$gpgerror" --list | wc -l | tr -d ' ')" = "$n" ] || fail "gpg-error --list"
printf '%s\n' "$out" | awk -F'[(,) ]+' '/\(-, /{ if ($3 < p) bad=1; p=$3 } END { exit bad }' \
    || fail "gpg-error list: codes not sorted"
out="$("$gpgerror" defines)"
[ "$(printf '%s\n' "$out" | head -1)" = '#define GPG_ERR_SOURCE_UNKNOWN    0' ] \
    || fail "gpg-error defines: first line"
printf '%s\n' "$out" | grep -q '^#define GPG_ERR_SOURCE_ANY       31$' || fail "gpg-error defines: ANY"
printf '%s\n' "$out" | grep -q '^#define GPG_ERR_NO_ERROR                     0$' || fail "gpg-error defines: NO_ERROR"
[ "$(printf '%s\n' "$out" | tail -1)" = '#define GPG_ERR_EXFULL                   32908' ] \
    || fail "gpg-error defines: last line"
[ "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" = "$n" ] || fail "gpg-error defines: line count"
"$gpgerror" list --desc | sed -n 2p | grep -q '^$' || fail "gpg-error list --desc: no blank line"

# lib-version reports the header and library versions.
out="$("$gpgerror" lib-version)"
printf '%s\n' "$out" | grep -q '^Version from header: 1\.[0-9.]* (0x01[0-9a-f]*)$' || fail "gpg-error lib-version header"
printf '%s\n' "$out" | grep -q '^Version from binary: 1\.' || fail "gpg-error lib-version binary"
printf '%s\n' "$out" | grep -q '^Copyright blurb \.\.\.: ' || fail "gpg-error lib-version blurb"

# --desc appends libgpg-error's errorref.txt entry when the file exists,
# otherwise just an empty line; unknown codes get neither.
cat > "$tmp/errorref.txt" <<'EOF_REF'
# errorref.txt - test fixture

GPG_ERR_GENERAL                 General error

    Used when nothing better fits.

GPG_ERR_UNKNOWN_PACKET          Unknown packet

    GNUPG:  - Redefined to G10ERR_UNKNOWN_PACKET in gpg.

EOF_REF
out="$(GPG_ERROR_ERRORREF="$tmp/errorref.txt" "$gpgerror" --desc 2 99999 7)"
[ "$out" = '2 = (0, 2) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_UNKNOWN_PACKET) = (Unspecified source, Unknown packet)

    GNUPG:  - Redefined to G10ERR_UNKNOWN_PACKET in gpg.

99999 = (0, 34463) = (GPG_ERR_SOURCE_UNKNOWN, -) = (Unspecified source, Unknown system error)
7 = (0, 7) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_BAD_SECKEY) = (Unspecified source, Bad secret key)' ] \
    || fail "gpg-error --desc with errorref: '$out'"
out="$(GPG_ERROR_ERRORREF="$tmp/missing" "$gpgerror" -d 1 | wc -l | tr -d ' ')"
[ "$out" = 2 ] || fail "gpg-error -d without errorref: $out lines"
out="$(GPG_ERROR_ERRORREF="$tmp/errorref.txt" "$gpgerror" -qd 1 | sed -n 3p)"
[ "$out" = '    Used when nothing better fits.' ] || fail "gpg-error -qd: '$out'"

# The file system helpers report success or the system error.
[ "$("$gpgerror" fopen "$tmp/errorref.txt")" = "success opening '$tmp/errorref.txt'" ] || fail "gpg-error fopen"
[ -z "$("$gpgerror" -q fopen "$tmp/errorref.txt")" ] || fail "gpg-error -q fopen: not silent"
out="$("$gpgerror" fopen "$tmp/missing" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] || fail "gpg-error fopen missing: exit $rc"
[ "$out" = "gpg-error: error opening '$tmp/missing': No such file or directory" ] || fail "gpg-error fopen missing: '$out'"
"$gpgerror" --openmode w fopen "$tmp/created" >/dev/null && [ -f "$tmp/created" ] || fail "gpg-error --openmode w"
[ "$("$gpgerror" chdir "$tmp")" = "success chdir '$tmp'" ] || fail "gpg-error chdir"
"$gpgerror" chdir "$tmp/missing" >/dev/null 2>&1 && fail "gpg-error chdir missing: expected exit 1"
[ "$("$gpgerror" mkdir "$tmp/newdir")" = "success mkdir '$tmp/newdir'" ] && [ -d "$tmp/newdir" ] || fail "gpg-error mkdir"
"$gpgerror" mkdir "$tmp/newdir" >/dev/null 2>&1 && fail "gpg-error mkdir existing: expected exit 1"
[ "$("$gpgerror" fconcat 0 a '' b)" = 'a//b' ] || fail "gpg-error fconcat 0"
[ "$("$gpgerror" fconcat /usr lib 'foo bar')" = 'lib/foo bar' ] || fail "gpg-error fconcat with junk flags"
[ "$("$gpgerror" fconcat 1 /abs x)" = '/abs/x' ] || fail "gpg-error fconcat 1 absolute part"
[ "$(cd "$tmp" && "$gpgerror" fconcat 1 rel x)" = "$(cd "$tmp" && pwd)/rel/x" ] || fail "gpg-error fconcat 1 relative part"
"$gpgerror" fconcat 0 >/dev/null 2>&1; [ $? -eq 2 ] || fail "gpg-error fconcat without parts: expected exit 2"

# Usage errors exit 2 and print the usage line on stderr.
for args in "" "list 1" "lib-version x" "fopen" "fopen a b" "--desc"; do
    # shellcheck disable=SC2086
    out="$("$gpgerror" $args 2>&1 >/dev/null)"; rc=$?
    [ "$rc" -eq 2 ] || fail "gpg-error $args: exit $rc"
    [ "$out" = 'Usage: gpg-error [commands] [options] error-numbers' ] || fail "gpg-error $args: '$out'"
    [ -z "$("$gpgerror" $args 2>/dev/null)" ] || fail "gpg-error $args: usage on stdout"
done
for opt in --xyz -x; do
    out="$("$gpgerror" $opt 2>&1 >/dev/null)"; rc=$?
    [ "$rc" -eq 2 ] || fail "gpg-error $opt: exit $rc"
    [ "$out" = "gpg-error: invalid option \"$opt\"
Usage: gpg-error [commands] [options] error-numbers" ] || fail "gpg-error $opt: '$out'"
done
out="$("$gpgerror" --openmode 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 2 ] && [ "$out" = 'gpg-error: missing argument for option "--openmode"
Usage: gpg-error [commands] [options] error-numbers' ] || fail "gpg-error --openmode without argument: '$out' ($rc)"

# -h is --help; its usage line goes to stderr too.  -- ends the options.
[ "$("$gpgerror" -h 2>/dev/null | grep -c '^     mkdir           Create the given directory$')" = 1 ] || fail "gpg-error -h"
[ "$("$gpgerror" -h 2>&1 >/dev/null)" = 'Usage: gpg-error [commands] [options] error-numbers' ] || fail "gpg-error -h: usage not on stderr"
[ "$("$gpgerror" -- 1)" = '1 = (0, 1) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_GENERAL) = (Unspecified source, General error)' ] \
    || fail "gpg-error -- 1"
[ -z "$("$gpgerror" --quiet chdir "$tmp")" ] || fail "gpg-error --quiet chdir: not silent"
[ -z "$("$gpgerror" -q mkdir "$tmp/quietdir")" ] && [ -d "$tmp/quietdir" ] || fail "gpg-error -q mkdir"

# An errorref entry at the very end of the file, with or without a final
# newline, and a last line that is not an entry.
printf 'GPG_ERR_GENERAL  General error\n\n    Last entry, no final newline.' > "$tmp/ref-nonl.txt"
out="$(GPG_ERROR_ERRORREF="$tmp/ref-nonl.txt" "$gpgerror" -d 1)"
[ "$out" = '1 = (0, 1) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_GENERAL) = (Unspecified source, General error)

    Last entry, no final newline.' ] || fail "gpg-error -d last entry: '$out'"
printf 'GPG_ERR_BAD_KEY  Bad\n\n    Other.\nGPG_ERR_GENERAL' > "$tmp/ref-nomatch.txt"
out="$(GPG_ERROR_ERRORREF="$tmp/ref-nomatch.txt" "$gpgerror" -d 1 | wc -l | tr -d ' ')"
[ "$out" = 2 ] || fail "gpg-error -d unmatched last line: $out lines"
out="$(GPG_ERROR_ERRORREF="$tmp/ref-nomatch.txt" "$gpgerror" -d 19)"
[ "$out" = '19 = (0, 19) = (GPG_ERR_SOURCE_UNKNOWN, GPG_ERR_BAD_KEY) = (Unspecified source, Bad session key)

    Other.' ] || fail "gpg-error -d entry before unterminated line: '$out'"

# fconcat 1 from a directory whose path is longer than the first getcwd
# buffer.
deep="$tmp"
i=0
while [ $i -lt 12 ]; do deep="$deep/a-rather-long-directory-name"; i=$((i + 1)); done
mkdir -p "$deep" || fail "cannot create deep directory"
[ "$(cd "$deep" && "$gpgerror" fconcat 1 x y)" = "$(cd "$deep" && pwd)/x/y" ] || fail "gpg-error fconcat 1 in a deep directory"

# ------------------------------------------------------------------- yat2m
out="$("$yat2m" --version | head -1)"
[ "$out" = "yat2m 1.1" ] || fail "yat2m --version: '$out'"
"$yat2m" --help | grep -q -- '--store          write output using @manpage name' || fail "yat2m --help"
"$yat2m" --bogus >/dev/null 2>&1; [ $? -eq 1 ] || fail "yat2m --bogus: expected exit 1"
"$yat2m" a b >/dev/null 2>&1; [ $? -eq 1 ] || fail "yat2m with two files: expected exit 1"
out="$("$yat2m" "$tmp/missing.texi" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] || fail "yat2m missing file: exit $rc"
[ "$out" = "yat2m: $tmp/missing.texi:0: can't open file: No such file or directory" ] || fail "yat2m missing file: '$out'"

# A manual with the constructs the GnuPG manuals use, and the roff and
# HTML the reference converter produces for it.
mkdir -p "$tmp/texi/inc"
cat > "$tmp/texi/page.texi" <<'EOF_FIXTURE'
\input texinfo
@c A small manual exercising the constructs the real ones use.
@include defs.texi
@macro manpage {a}
@end macro
@macro mansect {a}
@end macro
@macro manpause
@end macro
@macro mancont
@end macro
@macro gnupgtabopt{body}
@code{\body\}
@end macro
@macro toolname
frob
@end macro

@node Top
@top Frob

@menu
* Invoking frob::  How to run it.
@end menu

@manpage frob.1
@ifset manverb
.B frob
\- Frobnicate files
@end ifset

@mansect synopsis
@ifset manverb
.B  frob
.RB [ \-\-verbose ]
.RI [ options ]
.I file
@end ifset

@mansect description
@command{@toolname} frobnicates @var{file} -- quickly.  See @command{gpg}(1)
and @xref{Options}.  Version @value{VERSION} in @file{@value{SYSCONFDIR}/frob.conf};
use @samp{--help}, @option{-v}, @emph{care}, @code{a-b}, @dfn{term}, @kbd{RET},
@sc{small}, @url{https://example.org/}, @uref{https://example.org/doc}, @acronym{API},
@env{HOME}, @dots{}, @minus{}, @@at, @{braces@}, a back\slash and
@footnote{a note}.
Line one@*
Line two.

@ifset extra
Extra text from -D.
@end ifset
@ifclear extra
No extra text.
@end ifclear

@menu
* gone::  Not in the man page.
@end menu

@manpause
@node Invoking frob
@section Invoking frob
Not for the man page.
@mancont

@mansect options
@noindent
Options:

@table @gnupgtabopt
@item --verbose
@itemx -v
@opindex verbose
Say more about a-b --- always.

@item --output @var{file}
@opindex output
Write to @var{file}.
@table @asis
  @item @code{nested} x-y
  Nested tables keep their indentation.
@end table
@end table

@mansect examples
@example
frob --verbose "in.txt" \ out.txt
  indented @var{x}
@end example

@mansect see also
@command{gpg}(1), @command{@toolname}(5)
@include inc/note.texi

@mansect files
@table @file
@item @value{SYSCONFDIR}/frob.conf
Site configuration.
@end table
@subsection Odd heading
@c man:.B verbatim roff
@quotation
Quoted.
@end quotation
@cartouche
Boxed.
@end cartouche

@manpage frobd.8
@ifset manverb
.B frobd
\- Frob daemon
@end ifset
@mansect description
The daemon.
@mansect bugs
None.
@manpause
@bye
EOF_FIXTURE
printf '@set VERSION 1.2\n@set SYSCONFDIR /etc/frob\n' > "$tmp/texi/defs.texi"
printf 'The full documentation is in the Texinfo manual.\n' > "$tmp/texi/inc/note.texi"
sed 's/{SP}$/ /' > "$tmp/texi/expected.man" <<'EOF_MAN'
.\" Created from Texinfo source by yat2m 1.1
.TH FROB 1 2023-11-14 "frob 1.2" "Frob Tools"
.SH NAME
.B frob
\- Frobnicate files
.SH SYNOPSIS
.B  frob
.RB [ \-\-verbose ]
.RI [ options ]
.I file

.SH DESCRIPTION
\fBfrob\fP frobnicates \fIfile\fP \[en] quickly.  See \fBgpg\fP(1)
and See: [Options].  Version 1.2 in \(oq\fI/etc/frob/frob.conf\fP\(cq;
use \(oq\-\-help\(cq, \fB\-v\fP, \fIcare\fP, \fBa\-b\fP, term, \(oqRET\(cq,
\fBsmall\fP, \fBhttps://example.org/\fP, (\fBhttps://example.org/doc\fP), API,
\(oq\fIHOME\fP\(cq, ..., \-, @at, {braces}, a back\[rs]slash and
 ([a note]).
Line one
.br
Line two.

No extra text.



.SH OPTIONS

Options:

.TP
.B  \-\-verbose
.TQ
.B  \-v
Say more about a-b --- always.

.TP
.B  \-\-output \fIfile\fP
Write to \fIfile\fP.
.RS
.TP
.B  \fBnested\fP x-y
Nested tables keep their indentation.
.RE
.P

.SH EXAMPLES
.RS 2
.nf
frob \-\-verbose "in.txt" \[rs] out.txt
  indented \fIx\fP
.fi
.RE

.SH FILES
.TP
.B  /etc/frob/frob.conf
Site configuration.
.P

.SS  Odd heading
\{SP}
.B verbatim roff
.RS
\fBQuoted.
\fR
.RE
Boxed.

.SH SEE ALSO
\fBgpg\fP(1), \fBfrob\fP(5)
The full documentation is in the Texinfo manual.

.\" Created from Texinfo source by yat2m 1.1
.TH FROBD 8 2023-11-14 "frob 1.2" "Frob Tools"
.SH NAME
.B frobd
\- Frob daemon
.SH DESCRIPTION
The daemon.
.SH BUGS
None.
EOF_MAN
cat > "$tmp/texi/expected.html" <<'EOF_HTML'
<!-- Created from Texinfo source by yat2m 1.1 -->
<html>
<head>
 <title>FROB(1)</title>
<style type="text/css">
  .y2m {
    font-family: monospace;
  }
  .y2m u {
    text-decoration: underline;
  }
  .y2m-sc {
    font-variant: small-caps;
  }
  .y2m li {
    margin-top: 1em;
  }
  .y2m-item {
     display: block;
     font-weight: bold;
  }
  .y2m-args {
     font-weight: normal;
  }
</style>
</head>
<body>
<div class="y2m">
<p class="y2m y2m-top"><span class="y2m-left">FROB(1)</span> <span class="y2m-center">Frob Tools</span> <span class="y2m-right">FROB(1)</span></p>
<div class="y2m-section">
<h2 class="y2m-sh">NAME</h2>
@para{}<strong>frob</strong>
 &mdash; Frobnicate files
</div>
<div class="y2m-section">
<h2 class="y2m-sh">SYNOPSIS</h2>
@para{}<strong> frob</strong>
<span>[</span>  <strong>--verbose</strong>  <span>]</span>
<span>[</span>  <em>options</em>  <span>]</span>
<em>file</em>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">DESCRIPTION</h2>

<p><i>frob</i> frobnicates <u>file</u> &ndash; quickly.  See <i>gpg</i>(1)
and Options.  Version 1.2 in /etc/frob/frob.conf;
use --help, <samp>-v</samp>, <em>care</em>, <samp>a-b</samp>, term, RET,
<span class="y2m-sc">small</span>, <strong>https://example.org/</strong>, https://example.org/doc, API,
HOME, &hellip;, &minus;, @at, {braces}, a back&bsol;slash and
a note.
Line one
Line two.
</p>

<p>
No extra text.
</p>

<p>
</p>

<p>
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">OPTIONS</h2>

<p>
Options:
</p>

<p>
<ul>
<li><span class="y2m-item">--verbose</span>
    <span class="y2m-item">-v</span>
Say more about a-b --- always.

</li>
<li><span class="y2m-item">--output <span class="y2m-args"><u>file</u></span></span>
Write to <u>file</u>.
</li>
<ul>
<li><span class="y2m-item">@code{nested} <span class="y2m-args">x-y</span></span>
Nested tables keep their indentation.
</li>
</ul>
</ul>
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">EXAMPLES</h2>

<p>
<pre>
frob --verbose "in.txt" &bsol; out.txt
  indented <u>x</u>
</pre>
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">FILES</h2>

<p><ul>
<li><span class="y2m-item">@value{SYSCONFDIR}/frob.conf</span>
Site configuration.
</li>
</ul>
<h3> Odd heading</h3>
Quoted.
xxBoxed.
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">SEE ALSO</h2>

<p><i><a href="gpg.1.html">gpg</a>(1)</i>, <i><a href="frob.5.html">frob</a>(5)</i>
The full documentation is in the Texinfo manual.
</p>

<p>
</div>
<p class="y2m y2m-footer"><span class="y2m-left">frob 1.2</span> <span class="y2m-center">2023-11-14</span> <span class="y2m-right">FROB(1)</span></p>
</div><!-- class y2m -->
</body>
</html>
EOF_HTML

"$yat2m" --source "Frob Tools" --release "frob 1.2" --date 1700000000 -I "$tmp/texi" \
    "$tmp/texi/page.texi" > "$tmp/texi/out.man" 2> "$tmp/texi/err"; rc=$?
[ "$rc" -eq 0 ] || fail "yat2m man: exit $rc"
[ ! -s "$tmp/texi/err" ] || fail "yat2m man: unexpected messages: $(cat "$tmp/texi/err")"
cmp -s "$tmp/texi/expected.man" "$tmp/texi/out.man" \
    || fail "yat2m man output differs: $(diff "$tmp/texi/expected.man" "$tmp/texi/out.man" | head -5)"

"$yat2m" --html --source "Frob Tools" --release "frob 1.2" --date 1700000000 -I "$tmp/texi" \
    --select frob.1 "$tmp/texi/page.texi" > "$tmp/texi/out.html" 2> "$tmp/texi/err"; rc=$?
[ "$rc" -eq 0 ] || fail "yat2m html: exit $rc"
[ "$(cat "$tmp/texi/err")" = "yat2m: selected 'frob.1'
yat2m: unknown special comment \"man:\"" ] || fail "yat2m html: messages: $(cat "$tmp/texi/err")"
cmp -s "$tmp/texi/expected.html" "$tmp/texi/out.html" \
    || fail "yat2m html output differs: $(diff "$tmp/texi/expected.html" "$tmp/texi/out.html" | head -5)"

# --gnupgorg swaps the inline style sheet for the site's.
"$yat2m" --html --gnupgorg --date 0 --select frobd.8 -I "$tmp/texi" "$tmp/texi/page.texi" 2>/dev/null \
    | grep -q '<link rel="stylesheet" href="/share/site.css" type="text/css" />' \
    || fail "yat2m --gnupgorg"

# -D sets a condition; stdin and - read standard input; --select picks a
# page; --store writes files named after the pages.
out="$("$yat2m" -D extra --date 0 --select frob.1 -I "$tmp/texi" "$tmp/texi/page.texi" 2>/dev/null | grep -c 'Extra text from -D')"
[ "$out" = 1 ] || fail "yat2m -D"
out="$("$yat2m" --date 0 -I "$tmp/texi" - < "$tmp/texi/page.texi" 2>/dev/null | grep -c '^\.TH ')"
[ "$out" = 2 ] || fail "yat2m from stdin: $out pages"
out="$("$yat2m" --date 0 --select frobd.8 -I "$tmp/texi" "$tmp/texi/page.texi" 2>/dev/null)"
[ "$out" = '.\" Created from Texinfo source by yat2m 1.1
.TH FROBD 8 1970-01-01 "" "GNU"
.SH NAME
.B frobd
\- Frob daemon
.SH DESCRIPTION
The daemon.
.SH BUGS
None.' ] || fail "yat2m --select: '$out'"
mkdir -p "$tmp/store" && (cd "$tmp/store" && "$yat2m" --store --date 0 -I "$tmp/texi" "$tmp/texi/page.texi" 2>/dev/null \
    && "$yat2m" --store --html --date 0 -I "$tmp/texi" "$tmp/texi/page.texi" 2>/dev/null)
[ "$(ls "$tmp/store" | tr '\n' ' ')" = 'frob.1 frob.1.html frobd.8 frobd.8.html ' ] \
    || fail "yat2m --store files: $(ls "$tmp/store")"
grep -q '^\.TH FROBD 8 ' "$tmp/store/frobd.8" || fail "yat2m --store content"
"$yat2m" --verbose --date 0 -I "$tmp/texi" "$tmp/texi/page.texi" 2>&1 >/dev/null | grep -q "^yat2m: starting page 'frob.1'$" \
    || fail "yat2m --verbose"

# Errors in the source are reported with file and line and exit 1.
printf '@manpage x.1\n@mansect name\nx\n@mancont\n' > "$tmp/texi/e1.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e1.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] || fail "yat2m mancont: exit $rc"
[ "$out" = "$tmp/texi/e1.texi:4: continue while not pausing" ] || fail "yat2m mancont: '$out'"
printf '@manpage x.1\n@mansect name\n@end ifset\n' > "$tmp/texi/e2.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e2.texi" 2>&1 >/dev/null)"
[ "$out" = "$tmp/texi/e2.texi:3: unbalanced \"@end isset\"" ] || fail "yat2m unbalanced end: '$out'"
printf '@manpage noext\n' > "$tmp/texi/e3.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e3.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] && [ "$out" = "yat2m: no section name in man page 'noext'" ] || fail "yat2m no section: '$out' ($rc)"
printf '@include nowhere.texi\n' > "$tmp/texi/e4.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e4.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] && [ "$out" = "yat2m: can't open include file 'nowhere.texi': No such file or directory" ] \
    || fail "yat2m missing include: '$out' ($rc)"
printf '@manpage x.1\n@mansect name\nno newline' > "$tmp/texi/e5.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e5.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] && [ "$out" = "$tmp/texi/e5.texi:3: trailing linefeed missing, line too long or embedded Nul character" ] \
    || fail "yat2m missing newline: '$out' ($rc)"
printf '@manpage x.1\n@mansect name\n@sp 1 @copyright{} x @value{NOPE}\n' > "$tmp/texi/e6.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e6.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 0 ] || fail "yat2m unsupported commands: exit $rc"
[ "$out" = "yat2m: texinfo command 'sp' not supported ( 1 @copyright{} x @value{NOPE})
yat2m: texinfo command 'copyright' not supported ({} x @value{NOPE})
yat2m: texinfo variable 'NOPE' is not set" ] || fail "yat2m unsupported commands: '$out'"
[ "$("$yat2m" --date 0 "$tmp/texi/e6.texi" 2>/dev/null | tail -1)" = ' 1  x ' ] || fail "yat2m unsupported command text"

# A second manual covering the rarer constructs: entities, @itemize, @w,
# markup without braces, unknown section names, includes found in the
# current directory and in the second -I directory, nested skipped
# conditionals, and the verbatim roff requests the HTML converter knows.
mkdir -p "$tmp/texi2/dir1" "$tmp/texi2/dir2"
cat > "$tmp/texi2/more.texi" <<'EOF_FIXTURE2'
@macro manpage {a}
@end macro
@macro mansect {a}
@end macro
@macro name
widget
@end macro
@set V first
@set V second
@include local.texi
@include far.texi

@manpage widget.1
@ifset manverb
.B widget
\- Twiddle <things> & more
.br
\fBbold\fP line
plain verbatim line
.RI a  b
@end ifset

@mansect description
Compare a < b > c & d; @name{} and @name: @code x @anchor{here}@asis{gone}
@dots @minus @bullet{} list; punctuation@: @! @? @.
Trailing @w{text and} more words
@code{@w{wrapped} kept} after.
@ifset isman
Only in man pages.
@end ifset
@ifset NOPE
@ifset isman
nested skipped
@end ifset
@end ifset
Value is @value{V} from @value{LOCAL} and @value{FAR}.
@section A live section
@cindex index entry
@chapter A live chapter
@chapheading heading text
@noindent kept text

@mansect notation
Unknown sections follow the last created one.

@mansect widget protocol
Another unknown section.

@mansect options
@itemize @bullet
@item
First bullet.
@item
Second bullet.
@end itemize
@itemize @minus
@item
Minus bullet.
@end itemize
@table @code
@item <tag> & more
Item with markup characters.
@item --x
@end table

@mansect see also
@command{a<b}(1), @command{@name}(7) and @command{plain}
EOF_FIXTURE2
printf '@set LOCAL here\n' > "$tmp/texi2/local.texi"
printf '@set FAR there\n' > "$tmp/texi2/dir2/far.texi"
sed 's/{SP}$/ /' > "$tmp/texi2/expected.man" <<'EOF_MAN2'
.\" Created from Texinfo source by yat2m 1.1
.TH WIDGET 1 2023-11-14 "" "GNU"
.SH NAME
.B widget
\- Twiddle <things> & more
.br
\fBbold\fP line
plain verbatim line
.RI a  b
.SH DESCRIPTION
Compare a < b > c & d; widget and  \fB\fP x{SP}
... \- *  list; punctuation ! ? .
Trailing \fB\fP after.
Only in man pages.
Value is second from here and there.
 heading text
 kept text

.SH NOTATION
Unknown sections follow the last created one.

.SH WIDGET PROTOCOL
Another unknown section.

.SH OPTIONS
.TP
.B{SP}
First bullet.
.TP
.B{SP}
Second bullet.
.RS
.TP
.B{SP}
Minus bullet.
.RS
.TP
.B  <tag> & more
Item with markup characters.
.TP
.B  \-\-x
.RE

.SH SEE ALSO
\fBa<b\fP(1), \fBwidget\fP(7) and \fBplain\fP
EOF_MAN2
sed 's/{SP}$/ /' > "$tmp/texi2/expected.html" <<'EOF_HTML2'
<!-- Created from Texinfo source by yat2m 1.1 -->
<html>
<head>
 <title>WIDGET(1)</title>
<style type="text/css">
  .y2m {
    font-family: monospace;
  }
  .y2m u {
    text-decoration: underline;
  }
  .y2m-sc {
    font-variant: small-caps;
  }
  .y2m li {
    margin-top: 1em;
  }
  .y2m-item {
     display: block;
     font-weight: bold;
  }
  .y2m-args {
     font-weight: normal;
  }
</style>
</head>
<body>
<div class="y2m">
<p class="y2m y2m-top"><span class="y2m-left">WIDGET(1)</span> <span class="y2m-center">GNU</span> <span class="y2m-right">WIDGET(1)</span></p>
<div class="y2m-section">
<h2 class="y2m-sh">NAME</h2>
@para{}<strong>widget</strong>
 &mdash; Twiddle <things> & more
<br/>
<br/>

plain verbatim line
<span>a</span>   <em>b</em>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">DESCRIPTION</h2>

<p>Compare a &lt; b &gt; c &amp; d; widget and  <samp></samp> x{SP}
&hellip; &minus;  list; punctuation ! ? .
Trailing <samp></samp> after.
Only in man pages.
Value is second from here and there.
 heading text
 kept text
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">NOTATION</h2>

<p>Unknown sections follow the last created one.
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">WIDGET PROTOCOL</h2>

<p>Another unknown section.
</p>

<p>
</div>
<div class="y2m-section">
<h2 class="y2m-sh">OPTIONS</h2>

<p><ul>
First bullet.
Second bullet.
<ul>
Minus bullet.
<ul>
<li><span class="y2m-item">&lt;tag&gt; <span class="y2m-args">&amp; more</span></span>
Item with markup characters.
</li>
<li><span class="y2m-item">--x</span>
</li>
</ul>

</div>
<div class="y2m-section">
<h2 class="y2m-sh">SEE ALSO</h2>

<p><i><a href="a&lt;b.1.html">a&lt;b</a>(1)</i>, <i><a href="widget.7.html">widget</a>(7)</i> and <i>plain</i>
</div>
<p class="y2m y2m-footer"><span class="y2m-left"></span> <span class="y2m-center">2023-11-14</span> <span class="y2m-right">WIDGET(1)</span></p>
</div><!-- class y2m -->
</body>
</html>
EOF_HTML2
(cd "$tmp/texi2" && "$yat2m" --date 1700000000 -I dir1 -I dir2 more.texi > out.man 2> err); rc=$?
[ "$rc" -eq 0 ] || fail "yat2m second manual: exit $rc"
[ "$(cat "$tmp/texi2/err")" = "yat2m: texinfo command 'name:' not supported ( @code x @anchor{here}@asis{gone})" ] \
    || fail "yat2m second manual: messages: $(cat "$tmp/texi2/err")"
cmp -s "$tmp/texi2/expected.man" "$tmp/texi2/out.man" \
    || fail "yat2m second manual differs: $(diff "$tmp/texi2/expected.man" "$tmp/texi2/out.man" | head -5)"
(cd "$tmp/texi2" && "$yat2m" --debug --html --date 1700000000 -I dir1 -I dir2 -- more.texi > out.html 2> err); rc=$?
[ "$rc" -eq 0 ] || fail "yat2m second manual html: exit $rc"
grep -q "^yat2m: starting page 'widget.1'$" "$tmp/texi2/err" || fail "yat2m --debug: no page messages"
cmp -s "$tmp/texi2/expected.html" "$tmp/texi2/out.html" \
    || fail "yat2m second manual html differs: $(diff "$tmp/texi2/expected.html" "$tmp/texi2/out.html" | head -5)"

# More source errors: @ifclear manverb, an absolute include that is
# missing, a section before any page, @value without braces (which ends
# the section), and an output file that cannot be created.
printf '@manpage x.1\n@mansect name\n@ifclear manverb\nx\n@end ifclear\n' > "$tmp/texi/e7.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e7.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] && [ "$out" = "$tmp/texi/e7.texi:3: using \"@ifclear manverb\" is not allowed
$tmp/texi/e7.texi:5: unbalanced \"@end isclear\"" ] || fail "yat2m ifclear manverb: '$out' ($rc)"
[ "$("$yat2m" --date 0 "$tmp/texi/e7.texi" 2>/dev/null | tail -1)" = x ] || fail "yat2m ifclear manverb: text lost"
printf '@include /nonexistent/abs.texi\n' > "$tmp/texi/e8.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e8.texi" 2>&1)"; rc=$?
[ "$rc" -eq 1 ] && [ "$out" = "yat2m: can't open include file '/nonexistent/abs.texi': No such file or directory" ] \
    || fail "yat2m absolute include: '$out' ($rc)"
printf '@mansect stray\ntext\n@manpage x.1\n@mansect name\nn\n' > "$tmp/texi/e9.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e9.texi" 2>&1 >/dev/null)"; rc=$?
[ "$rc" -eq 1 ] && [ "$out" = "$tmp/texi/e9.texi:1: section outside of a man page" ] || fail "yat2m stray section: '$out' ($rc)"
[ "$("$yat2m" --date 0 "$tmp/texi/e9.texi" 2>/dev/null | tail -1)" = n ] || fail "yat2m stray section: page lost"
printf '@manpage x.1\n@mansect name\nk @value x l\nm after\n@mansect bugs\nb\n' > "$tmp/texi/e10.texi"
out="$("$yat2m" --date 0 "$tmp/texi/e10.texi" 2>"$tmp/texi/err")"; rc=$?
[ "$rc" -eq 1 ] && [ "$(cat "$tmp/texi/err")" = "yat2m: opening brace for command 'value' missing" ] \
    || fail "yat2m value without braces: $(cat "$tmp/texi/err") ($rc)"
[ "$out" = '.\" Created from Texinfo source by yat2m 1.1
.TH X 1 1970-01-01 "" "GNU"
.SH NAME
k'"$sp"'
.SH BUGS
b' ] || fail "yat2m value without braces: '$out'"
if [ "$(id -u)" -ne 0 ]; then
    mkdir -p "$tmp/ro" && chmod 500 "$tmp/ro"
    out="$(cd "$tmp/ro" && "$yat2m" --store --date 0 "$tmp/texi/e9.texi" 2>&1 >/dev/null)"; rc=$?
    chmod 700 "$tmp/ro"
    [ "$rc" -eq 1 ] || fail "yat2m --store in a read-only directory: exit $rc"
    case "$out" in
        *"yat2m: failed to create 'x.1': Permission denied"*) ;;
        *) fail "yat2m --store in a read-only directory: '$out'" ;;
    esac
fi

# Entities in item names and SEE ALSO links, the HTML em dash, and a plain
# comment inside a section.
printf '@manpage z.1\n@mansect description\nem --- dash\n@c a comment\n@table @code\n@item a&b c>d\nx\n@end table\n@mansect see also\n@command{p>q&r}(2)\n' > "$tmp/texi/e11.texi"
out="$("$yat2m" --html --date 0 "$tmp/texi/e11.texi" 2>/dev/null | sed -n '/y2m-sh">DESCRIPTION/,/y2m-footer/p' | grep -v y2m-footer)"
[ "$out" = '<h2 class="y2m-sh">DESCRIPTION</h2>

<p>em &mdash; dash
<ul>
<li><span class="y2m-item">a&amp;b <span class="y2m-args">c&gt;d</span></span>
x

</div>
<div class="y2m-section">
<h2 class="y2m-sh">SEE ALSO</h2>

<p><i><a href="p&gt;q&amp;r.2.html">p&gt;q&amp;r</a>(2)</i>
</div>' ] || fail "yat2m html entities: '$out'"
out="$("$yat2m" --date 0 "$tmp/texi/e11.texi" 2>/dev/null | sed -n 3,6p)"
[ "$out" = '.SH DESCRIPTION
em \[em] dash
.TP
.B  a&b c>d' ] || fail "yat2m man with comment: '$out'"

# Unlike the reference programs, both report a failed write.
if [ -w /dev/full ]; then
    "$yat2m" --date 0 "$tmp/texi/e11.texi" >/dev/full 2>"$tmp/err" && fail "yat2m write error: expected exit 1"
    grep -q '^yat2m: error writing output' "$tmp/err" || fail "yat2m write error message"
    "$gpgerror" 1 >/dev/full 2>"$tmp/err" && fail "gpg-error write error: expected exit 1"
    grep -q '^gpg-error: error writing output' "$tmp/err" || fail "gpg-error write error message"
fi

[ "$status" -eq 0 ] && echo "tools: all checks passed"
exit "$status"
