#!/bin/sh
# Check that libgcrypt.m4 behaves like the macro the reference Libgcrypt
# ships: a configure script using AM_PATH_LIBGCRYPT finds this library
# through libgcrypt-config and through gpgrt-config, honours the minimum
# version and API arguments, --with-libgcrypt-prefix, LIBGCRYPT_CONFIG and
# SYSROOT, and reports the host as upstream does.
#
# Usage: scripts/check-libgcrypt-m4.sh <path/to/libgcrypt.m4> <build-dir>
#
# <build-dir> is a configured drop-in build tree holding libgcrypt-config
# and libgcrypt.pc.  AUTOCONF names the autoconf program (default: the one
# on PATH).  Exit status is 0 when every check passes, 77 when autoconf is
# not available (ctest counts that as skipped); otherwise each failure is
# printed.  KEEP_WORK=1 keeps the temporary directory with every configure
# log.
set -u

m4file="${1:?usage: $0 <libgcrypt.m4> <build-dir>}"
builddir="${2:?usage: $0 <libgcrypt.m4> <build-dir>}"
# Absolute paths: the script links to them from a temporary directory.
builddir="$(cd "$builddir" 2>/dev/null && pwd)" \
    || { echo "FAIL: no such directory: $2"; exit 1; }
case "$m4file" in
    /*) ;;
    *) m4file="$(pwd)/$m4file" ;;
esac
config="$builddir/libgcrypt-config"
pcfile="$builddir/libgcrypt.pc"

autoconf="${AUTOCONF:-autoconf}"
if ! "$autoconf" --version >/dev/null 2>&1; then
    echo "SKIP: autoconf not found"
    exit 77
fi
for f in "$m4file" "$config" "$pcfile"; do
    [ -r "$f" ] || { echo "FAIL: cannot read $f"; exit 1; }
done

# AC_CANONICAL_HOST needs config.guess and config.sub; autoconf ships them.
autoconf_bin="$(dirname "$(command -v "$autoconf")")"
auxdir=""
for d in "$autoconf_bin/../share/autoconf/build-aux" \
         /usr/share/autoconf/build-aux /usr/local/share/autoconf/build-aux; do
    if [ -r "$d/config.guess" ] && [ -r "$d/config.sub" ]; then
        auxdir="$d"
        break
    fi
done
if [ -z "$auxdir" ]; then
    echo "SKIP: config.guess and config.sub not found beside autoconf"
    exit 77
fi

# KEEP_WORK=1 leaves the work directory behind for inspection.
work="$(mktemp -d)" || exit 1
if [ -n "${KEEP_WORK:-}" ]; then
    echo "work directory: $work"
else
    trap 'rm -rf "$work"' EXIT INT TERM
fi

status=0
fail() {
    echo "FAIL: $*"
    status=1
}

# A fake install prefix for --with-libgcrypt-prefix and SYSROOT, and a
# pkg-config directory for gpgrt-config.
mkdir -p "$work/prefix/bin" "$work/pc" "$work/src"
ln -s "$config" "$work/prefix/bin/libgcrypt-config"
cp "$pcfile" "$work/pc/libgcrypt.pc"

cp "$m4file" "$work/src/libgcrypt.m4"
cp "$auxdir/config.guess" "$auxdir/config.sub" "$work/src/"
cat >"$work/src/configure.ac" <<'END'
AC_INIT([m4check], [1])
m4_include([libgcrypt.m4])
AM_PATH_LIBGCRYPT([$MIN], [found=yes], [found=no])
AC_SUBST([found])
AC_SUBST([gpg_config_script_warn])
AC_SUBST([use_gpgrt_config])
AC_CONFIG_FILES([result])
AC_OUTPUT
END
cat >"$work/src/result.in" <<'END'
found=@found@
cflags=@LIBGCRYPT_CFLAGS@
libs=@LIBGCRYPT_LIBS@
config=@LIBGCRYPT_CONFIG@
host=@host@
warn=@gpg_config_script_warn@
gpgrt=@use_gpgrt_config@
END

# Reads the configure.ac MIN placeholder from $MIN; autoconf is run once per
# minimum version string.
generate() {
    rm -rf "$work/conf"
    mkdir "$work/conf"
    sed "s/\$MIN/$1/" "$work/src/configure.ac" >"$work/conf/configure.ac"
    cp "$work/src/libgcrypt.m4" "$work/src/result.in" \
       "$work/src/config.guess" "$work/src/config.sub" "$work/conf/"
    (cd "$work/conf" && "$autoconf" >autoconf.log 2>&1) \
        || { cat "$work/conf/autoconf.log"; fail "autoconf failed for MIN=$1"; return 1; }
}

# run NAME [configure options]: configure in a fresh directory with the
# current environment; results land in $found, $cflags, $libs, $cfg, $host,
# $warn, $gpgrt and the log in $log.
run() {
    name="$1"; shift
    dir="$work/run-$name"
    rm -rf "$dir"
    mkdir "$dir"
    log="$dir/configure.log"
    (cd "$dir" && sh "$work/conf/configure" "$@") >"$log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] || [ ! -r "$dir/result" ]; then
        cat "$log"
        fail "$name: configure exited $rc"
        found=; cflags=; libs=; cfg=; host=; warn=; gpgrt=
        return 1
    fi
    found="$(sed -n 's/^found=//p' "$dir/result")"
    cflags="$(sed -n 's/^cflags=//p' "$dir/result")"
    libs="$(sed -n 's/^libs=//p' "$dir/result")"
    cfg="$(sed -n 's/^config=//p' "$dir/result")"
    host="$(sed -n 's/^host=//p' "$dir/result")"
    warn="$(sed -n 's/^warn=//p' "$dir/result")"
    gpgrt="$(sed -n 's/^gpgrt=//p' "$dir/result")"
    return 0
}

# The host check: a warning and gpg_config_script_warn exactly when the
# script's host differs from configure's canonical host, as upstream.
check_host() {
    name="$1"; script_host="$2"
    if [ "$script_host" != "$host" ]; then
        [ "$warn" = " libgcrypt" ] \
            || fail "$name: host $script_host != $host but warn='$warn'"
        grep -q 'may not match' "$log" || fail "$name: host warning missing"
    else
        [ -z "$warn" ] || fail "$name: hosts match but warn='$warn'"
    fi
}

expected_version="$("$config" --version)"
expected_cflags="$("$config" --cflags)"
expected_libs="$("$config" --libs)"
expected_host="$("$config" --host)"

# ---- Through libgcrypt-config (GPGRT_CONFIG=no disables gpgrt-config). ----
export GPGRT_CONFIG=no
unset LIBGCRYPT_CONFIG SYSROOT
# A copy of PATH without any libgcrypt-config, so that what the macro finds
# is decided by this script and not by what is installed: one directory of
# links to every program on PATH, minus that one name.
save_path="$PATH"
mkdir -p "$work/nobin"
for d in $(echo "$PATH" | tr ':' ' '); do
    [ -d "$d" ] || continue
    for exe in "$d"/*; do
        name="${exe##*/}"
        [ "$name" = libgcrypt-config ] && continue
        [ -e "$work/nobin/$name" ] || ln -s "$exe" "$work/nobin/$name" 2>/dev/null
    done
done

if generate "1:1.2.0"; then
    # --with-libgcrypt-prefix.
    if run prefix --with-libgcrypt-prefix="$work/prefix"; then
        [ "$found" = yes ] || fail "prefix: not found"
        [ -z "$gpgrt" ] || fail "prefix: used gpgrt-config"
        [ "$cfg" = "$work/prefix/bin/libgcrypt-config" ] || fail "prefix: config is '$cfg'"
        [ "$cflags" = "$expected_cflags" ] || fail "prefix: cflags '$cflags'"
        [ "$libs" = "$expected_libs" ] || fail "prefix: libs '$libs'"
        grep -q "checking for LIBGCRYPT - version >= 1.2.0... yes ($expected_version)" "$log" \
            || fail "prefix: version message missing"
        grep -q "checking LIBGCRYPT API version... okay" "$log" \
            || fail "prefix: API message missing"
        check_host prefix "$expected_host"
    fi

    # LIBGCRYPT_CONFIG in the environment wins over the prefix.
    if LIBGCRYPT_CONFIG="$config" run env --with-libgcrypt-prefix=/nonexistent; then
        [ "$found" = yes ] || fail "env: not found"
        [ "$cfg" = "$config" ] || fail "env: config is '$cfg'"
    fi

    # SYSROOT/bin is searched before PATH.
    if SYSROOT="$work/prefix" PATH="$work/nobin" run sysroot; then
        [ "$found" = yes ] || fail "sysroot: not found"
        [ "$cfg" = "$work/prefix/bin/libgcrypt-config" ] || fail "sysroot: config is '$cfg'"
    fi
    # A relative SYSROOT is ignored with a warning.
    if SYSROOT="relative" PATH="$work/prefix/bin:$work/nobin" run relsysroot; then
        # shellcheck disable=SC2016  # the literal text configure prints
        grep -q -F 'Ignoring $SYSROOT' "$log" || fail "relsysroot: warning missing"
        [ "$found" = yes ] || fail "relsysroot: not found via PATH"
    fi

    # Nothing to find: not found, empty flags, action-if-not-found run.
    if PATH="$work/nobin" run missing; then
        [ "$found" = no ] || fail "missing: found='$found'"
        [ -z "$cflags" ] && [ -z "$libs" ] || fail "missing: flags not empty"
        [ "$cfg" = no ] || fail "missing: config is '$cfg'"
        grep -q "checking for LIBGCRYPT - version >= 1.2.0... no" "$log" \
            || fail "missing: result message wrong"
    fi
fi

# Exactly the installed version passes; a newer minimum fails.
if generate "1:$expected_version"; then
    if LIBGCRYPT_CONFIG="$config" run exact; then
        [ "$found" = yes ] || fail "exact: not found"
    fi
fi
if generate "1.99.0"; then
    if LIBGCRYPT_CONFIG="$config" run toonew; then
        [ "$found" = no ] || fail "toonew: found='$found'"
        [ -z "$libs" ] || fail "toonew: libs not empty"
        grep -q "checking for LIBGCRYPT - version >= 1.99.0... no" "$log" \
            || fail "toonew: result message wrong"
    fi
fi
# A bare version asks for no API; a wrong API fails after the version passes.
if generate "1.2.0"; then
    if LIBGCRYPT_CONFIG="$config" run noapi; then
        [ "$found" = yes ] || fail "noapi: not found"
        grep -q "LIBGCRYPT API version" "$log" && fail "noapi: API was checked"
    fi
fi
if generate "2:1.2.0"; then
    if LIBGCRYPT_CONFIG="$config" run badapi; then
        [ "$found" = no ] || fail "badapi: found='$found'"
        grep -q "checking LIBGCRYPT API version... does not match. want=2 got=1" "$log" \
            || fail "badapi: API message wrong"
    fi
fi

# ---- Through gpgrt-config, when libgpg-error provides it. ----
PATH="$save_path"
unset GPGRT_CONFIG
if command -v gpgrt-config >/dev/null 2>&1 \
   && gpgrt-config gpg-error --exists 2>/dev/null; then
    # gpgrt-config reads PKG_CONFIG_PATH only when PKG_CONFIG_LIBDIR is set
    # but empty; that keeps a system libgcrypt.pc out of the way.
    gpg_error_pcdir="$(pkg-config --variable=pcfiledir gpg-error 2>/dev/null)"
    [ -n "$gpg_error_pcdir" ] \
        || gpg_error_pcdir="$(gpgrt-config gpg-error --variable=libdir)/pkgconfig"
    export PKG_CONFIG_LIBDIR=
    export PKG_CONFIG_PATH="$work/pc:$gpg_error_pcdir"
    expected_pc_cflags="$(gpgrt-config libgcrypt --cflags)"
    expected_pc_libs="$(gpgrt-config libgcrypt --libs)"

    # libgcrypt.pc must carry what the macro asks gpgrt-config for.
    pc_api="$(gpgrt-config libgcrypt --variable=api_version)"
    [ "$pc_api" = "$("$config" --api-version)" ] \
        || fail "libgcrypt.pc: api_version '$pc_api'"
    pc_host="$(gpgrt-config libgcrypt --variable=host)"
    [ "$pc_host" = "$expected_host" ] || fail "libgcrypt.pc: host '$pc_host'"
    pc_version="$(gpgrt-config libgcrypt --modversion)"
    [ "$pc_version" = "$expected_version" ] || fail "libgcrypt.pc: version '$pc_version'"
    for v in symmetric_ciphers asymmetric_ciphers digests; do
        got="$(gpgrt-config libgcrypt --variable=$v | tr -d '"')"
        [ "$got" = "$("$config" --variable=$v)" ] || fail "libgcrypt.pc: $v '$got'"
    done

    if generate "1:1.2.0"; then
        if run gpgrt; then
            [ "$found" = yes ] || fail "gpgrt: not found"
            [ "$gpgrt" = yes ] || fail "gpgrt: gpgrt-config not used"
            grep -q "Use gpgrt-config as libgcrypt-config" "$log" \
                || fail "gpgrt: notice missing"
            case "$cfg" in
                *gpgrt-config\ --libdir=*\ libgcrypt) ;;
                *) fail "gpgrt: config is '$cfg'" ;;
            esac
            [ "$cflags" = "$expected_pc_cflags" ] || fail "gpgrt: cflags '$cflags'"
            [ "$libs" = "$expected_pc_libs" ] || fail "gpgrt: libs '$libs'"
            case "$libs" in
                *-lgcrypt*) ;;
                *) fail "gpgrt: libs lack -lgcrypt" ;;
            esac
            grep -q "checking LIBGCRYPT API version... okay" "$log" \
                || fail "gpgrt: API message missing"
            check_host gpgrt "$pc_host"
        fi
    fi
    if generate "2:1.2.0"; then
        if run gpgrtbadapi; then
            [ "$found" = no ] || fail "gpgrtbadapi: found='$found'"
            grep -q "does not match. want=2 got=1" "$log" \
                || fail "gpgrtbadapi: API message wrong"
        fi
    fi
    unset PKG_CONFIG_LIBDIR PKG_CONFIG_PATH
else
    echo "note: gpgrt-config not available, gpgrt-config path not checked"
fi

[ "$status" -eq 0 ] && echo "libgcrypt.m4: all checks passed"
exit "$status"
