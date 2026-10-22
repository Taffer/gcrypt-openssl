#!/bin/sh
# Run the benchmark suite against this library and against stock libgcrypt
# and print the results side by side.
#
#   compare.sh [-m] [-o FILE] <bench_gcrypt> <bench_gcrypt_stock> [bench args]
#
#   -m       print a Markdown table instead of aligned text
#   -o FILE  also keep the two raw CSV outputs as FILE.openssl.csv and
#            FILE.stock.csv
#
# Any further arguments are passed to both benchmark binaries, e.g.
# "--seconds 2 cipher/AES" to spend two seconds per case on AES only.
#
# The ratio column is this library's rate divided by stock's: above 1.0
# means the OpenSSL-backed implementation is faster.

set -eu

markdown=0
keep=""

while [ $# -gt 0 ]; do
    case "$1" in
    -m) markdown=1; shift ;;
    -o) keep="$2"; shift 2 ;;
    -h|--help)
        sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *) break ;;
    esac
done

if [ $# -lt 2 ]; then
    echo "usage: $0 [-m] [-o FILE] <bench_gcrypt> <bench_gcrypt_stock> [args]" >&2
    exit 2
fi

ours="$1"
stock="$2"
shift 2

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

lib_of() {
    ldd "$1" 2>/dev/null | awk '/libgcrypt/ { print $3; exit }'
}

echo "# this library : $("$ours" --list >/dev/null 2>&1 && lib_of "$ours")"
echo "# stock library: $(lib_of "$stock")"
echo "# arguments    : $*"
echo

# A crash in one binary must not discard the other's results: run both
# without -e and report the exit status, keeping whatever rows were printed.
set +e
"$ours" --csv "$@" >"$tmp/ours.csv"
ours_rc=$?
"$stock" --csv "$@" >"$tmp/stock.csv"
stock_rc=$?
set -e

if [ "$ours_rc" -ne 0 ]; then
    echo "# WARNING: $ours exited with status $ours_rc; results are partial" >&2
fi

if [ "$stock_rc" -ne 0 ]; then
    echo "# WARNING: $stock exited with status $stock_rc; results are partial" >&2
fi

if [ -n "$keep" ]; then
    cp "$tmp/ours.csv" "$keep.openssl.csv"
    cp "$tmp/stock.csv" "$keep.stock.csv"
fi

awk -F, -v markdown="$markdown" '
function fmt(v, mib) {
    if (v == "" || v == "-") return "-"
    if (mib) return sprintf("%.2f", v)
    if (v >= 1000) return sprintf("%.0f", v)
    return sprintf("%.2f", v)
}
function header() {
    if (markdown) {
        print "| group | operation | this ops/s | stock ops/s | ratio | this MiB/s | stock MiB/s |"
        print "|---|---|---:|---:|---:|---:|---:|"
    } else {
        printf "%-7s %-44s %12s %12s %7s %10s %10s\n", "group", "operation",
            "this ops/s", "stock ops/s", "ratio", "this MiB/s", "stock MiB/s"
    }
}
function row(g, n, o1, s1, r, m1, m2) {
    if (markdown)
        printf "| %s | %s | %s | %s | %s | %s | %s |\n", g, n, o1, s1, r, m1, m2
    else
        printf "%-7s %-44s %12s %12s %7s %10s %10s\n", g, n, o1, s1, r, m1, m2
}
FNR == 1 { file++ }
/^#/ {
    if ($0 ~ /^# library:/) {
        sub(/^# library: */, "")
        if (file == 1) ours_ver = $0; else stock_ver = $0
    }
    if ($0 ~ /^# fips-mode:/) {
        sub(/^# fips-mode: */, "")
        if (file == 1) ours_fips = $0; else stock_fips = $0
    }
    next
}
$1 == "group" { next }
file == 1 {
    key = $1 SUBSEP $2
    order[++n] = key
    group[key] = $1; name[key] = $2
    o_ops[key] = $6; o_mib[key] = $7; o_status[key] = $8
    o_bytes[key] = $3
    next
}
{
    key = $1 SUBSEP $2
    s_ops[key] = $6; s_mib[key] = $7; s_status[key] = $8
    if (!(key in group)) { order[++n] = key; group[key] = $1; name[key] = $2 }
}
END {
    printf "# this library : libgcrypt %s (gcrypt-openssl), fips-mode:%s\n", ours_ver, ours_fips
    printf "# stock library: libgcrypt %s, fips-mode:%s\n\n", stock_ver, stock_fips
    header()
    for (i = 1; i <= n; i++) {
        key = order[i]
        o = (key in o_status && o_status[key] == "") ? o_ops[key] : ""
        s = (key in s_status && s_status[key] == "") ? s_ops[key] : ""
        om = (o != "" && o_bytes[key] > 0) ? o_mib[key] : ""
        sm = (s != "" && o_bytes[key] > 0) ? s_mib[key] : ""
        if (o == "" && (key in o_status)) o_txt = "n/a"; else o_txt = fmt(o, 0)
        if (s == "" && (key in s_status)) s_txt = "n/a"; else s_txt = fmt(s, 0)
        if (o != "" && s != "" && s > 0) r = sprintf("%.2fx", o / s); else r = "-"
        row(group[key], name[key], o_txt, s_txt, r, fmt(om, 1), fmt(sm, 1))
    }
}' "$tmp/ours.csv" "$tmp/stock.csv"
