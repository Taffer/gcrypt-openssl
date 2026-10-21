# libgcrypt.m4 - Autoconf macros to detect Libgcrypt.
#
# Compatible with the libgcrypt.m4 that ships with the reference Libgcrypt
# (src/libgcrypt.m4): the same macro names, arguments, configure options,
# environment variables, messages and results, so that a configure.ac
# written against the reference macro works unchanged whether it finds the
# reference library or the gcrypt-openssl drop-in.
#
# AM_PATH_LIBGCRYPT([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
#
#   Looks for Libgcrypt and defines LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS.
#   MINIMUM-VERSION is "major.minor.micro", optionally preceded by the API
#   version and a colon ("1:1.2.5" demands at least 1.2.5 and API 1);
#   the default is 1:1.2.0.
#
#   The library is located through gpgrt-config (libgpg-error's pkg-config
#   substitute, reading libgcrypt.pc) when that works, else through the
#   libgcrypt-config script named by the LIBGCRYPT_CONFIG environment
#   variable, by --with-libgcrypt-prefix=PFX (PFX/bin/libgcrypt-config),
#   by $SYSROOT/bin, or found along $PATH, in that order.  When the found
#   library was built for a host other than the one configure is targeting
#   a warning is printed and "libgcrypt" is appended to the shell variable
#   gpg_config_script_warn, as the reference macro does.
#
# This file is in the public domain.  Last changed: 2026-10-21.


dnl _AM_PATH_GPGRT_CONFIG
dnl
dnl Find gpgrt-config and the library directory whose pkgconfig/ it should
dnl read.  On success GPGRT_CONFIG holds "<path> --libdir=<dir>", verified
dnl to answer for gpg-error; otherwise GPGRT_CONFIG is unset.
dnl
dnl The same macro is defined, identically in effect, by the reference
dnl gpg-error.m4, libgcrypt.m4, libassuan.m4 and ksba.m4, so that any one
dnl of them is enough on its own.
dnl
AC_DEFUN([_AM_PATH_GPGRT_CONFIG],[dnl
  AC_PATH_PROG(GPGRT_CONFIG, gpgrt-config, no, [$prefix/bin:$PATH])
  if test "$GPGRT_CONFIG" != "no"; then
    # gpgrt-config is assumed to live in <PREFIX>/bin.  The candidate
    # library directories, from least to most preferred:
    #   possible_libdir0  a directory the compiler searches that has a
    #                     pkgconfig/ subdirectory (/usr/<triplet>/lib,
    #                     /usr/lib/<multiarch> or /usr/lib64, say)
    #   possible_libdir1  <PREFIX>/lib
    #   possible_libdir2  <PREFIX> with possible_libdir0's layout applied
    #                     (<PREFIX>/<triplet>/lib, <PREFIX>/lib/<multiarch>
    #                     or <PREFIX>/lib64)
    # CC is taken to be the host compiler when cross-building.
    gpgrt_prefix=${GPGRT_CONFIG%/*/*}
    possible_libdir1=${gpgrt_prefix}/lib
    if libdir_candidates=$(${CC:-cc} -print-search-dirs | \
          sed -n -e "/^libraries/{s/libraries: =//;s/:/\\
/g;p;}"); then
      libdir_candidates=$(for dir in $libdir_candidates; do
        if p=$(cd $dir 2>/dev/null && pwd); then
          test -d "$p/pkgconfig" && echo $p;
        fi
      done)

      for possible_libdir0 in $libdir_candidates; do
        if test "${possible_libdir0##*/}" = "lib"; then
          possible_prefix0=${possible_libdir0%/lib}
          possible_prefix0_triplet=${possible_prefix0##*/}
          if test -z "$possible_prefix0_triplet"; then
            continue
          fi
          possible_libdir2=${gpgrt_prefix}/$possible_prefix0_triplet/lib
        else
          possible_prefix0=${possible_libdir0%%/lib*}
          possible_libdir2=${gpgrt_prefix}${possible_libdir0#$possible_prefix0}
        fi
        if test -f ${possible_libdir2}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir2}
        elif test -f ${possible_libdir1}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir1}
        elif test -f ${possible_libdir0}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir0}
        fi
        if test -n "$gpgrt_libdir"; then break; fi
      done
    fi
    if test -z "$gpgrt_libdir"; then
      # No gpg-error.pc anywhere the compiler looks; take <PREFIX>/lib.
      gpgrt_libdir=${possible_libdir1}
    fi
  else
    unset GPGRT_CONFIG
  fi

  if test -n "$gpgrt_libdir"; then
    GPGRT_CONFIG="$GPGRT_CONFIG --libdir=$gpgrt_libdir"
    # Keep it only if it really answers for gpg-error.
    if ! $GPGRT_CONFIG gpg-error --exists; then
      unset GPGRT_CONFIG
    fi
  else
    unset GPGRT_CONFIG
  fi
])

dnl AM_PATH_LIBGCRYPT([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for Libgcrypt and define LIBGCRYPT_CFLAGS and LIBGCRYPT_LIBS.
dnl See the top of this file for the arguments.
dnl
AC_DEFUN([AM_PATH_LIBGCRYPT],
[ AC_REQUIRE([AC_CANONICAL_HOST])dnl
  AC_REQUIRE([_AM_PATH_GPGRT_CONFIG])dnl
  AC_ARG_WITH(libgcrypt-prefix,
            AS_HELP_STRING([--with-libgcrypt-prefix=PFX],
                           [prefix where LIBGCRYPT is installed (optional)]),
     libgcrypt_config_prefix="$withval", libgcrypt_config_prefix="")
  if test x"${LIBGCRYPT_CONFIG}" = x ; then
     if test x"${libgcrypt_config_prefix}" != x ; then
        LIBGCRYPT_CONFIG="${libgcrypt_config_prefix}/bin/libgcrypt-config"
     fi
  fi

  # gpgrt-config reading libgcrypt.pc is preferred over the script.
  use_gpgrt_config=""
  if test x"$GPGRT_CONFIG" != x && test "$GPGRT_CONFIG" != "no"; then
    if $GPGRT_CONFIG libgcrypt --exists; then
      LIBGCRYPT_CONFIG="$GPGRT_CONFIG libgcrypt"
      AC_MSG_NOTICE([Use gpgrt-config as libgcrypt-config])
      use_gpgrt_config=yes
    fi
  fi
  if test -z "$use_gpgrt_config"; then
    if test x"${LIBGCRYPT_CONFIG}" = x ; then
      case "${SYSROOT}" in
         /*)
           if test -x "${SYSROOT}/bin/libgcrypt-config" ; then
             LIBGCRYPT_CONFIG="${SYSROOT}/bin/libgcrypt-config"
           fi
           ;;
         '')
           ;;
          *)
           AC_MSG_WARN([Ignoring \$SYSROOT as it is not an absolute path.])
           ;;
      esac
    fi
    AC_PATH_PROG(LIBGCRYPT_CONFIG, libgcrypt-config, no)
  fi

  # Split "API:VERSION"; a bare VERSION asks for no particular API.
  tmp=m4_default([$1], [1:1.2.0])
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
     req_libgcrypt_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
     min_libgcrypt_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
     req_libgcrypt_api=0
     min_libgcrypt_version="$tmp"
  fi

  AC_MSG_CHECKING(for LIBGCRYPT - version >= $min_libgcrypt_version)
  ok=no
  if test "$LIBGCRYPT_CONFIG" != "no" ; then
    req_major=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libgcrypt_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    if test -z "$use_gpgrt_config"; then
      libgcrypt_config_version=`$LIBGCRYPT_CONFIG --version`
    else
      libgcrypt_config_version=`$LIBGCRYPT_CONFIG --modversion`
    fi
    # Anything after the third component (a -beta suffix, say) is ignored.
    major=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    minor=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    micro=`echo $libgcrypt_config_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "$major" -gt "$req_major"; then
        ok=yes
    else
        if test "$major" -eq "$req_major"; then
            if test "$minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$minor" -eq "$req_minor"; then
                   if test "$micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
  fi
  if test $ok = yes; then
    AC_MSG_RESULT([yes ($libgcrypt_config_version)])
  else
    AC_MSG_RESULT(no)
  fi
  if test $ok = yes; then
     # A recent enough library must also offer the requested API.
     if test "$req_libgcrypt_api" -gt 0 ; then
        if test -z "$use_gpgrt_config"; then
           tmp=`$LIBGCRYPT_CONFIG --api-version 2>/dev/null || echo 0`
        else
           tmp=`$LIBGCRYPT_CONFIG --variable=api_version 2>/dev/null || echo 0`
        fi
        if test "$tmp" -gt 0 ; then
           AC_MSG_CHECKING([LIBGCRYPT API version])
           if test "$req_libgcrypt_api" -eq "$tmp" ; then
             AC_MSG_RESULT([okay])
           else
             ok=no
             AC_MSG_RESULT([does not match. want=$req_libgcrypt_api got=$tmp])
           fi
        fi
     fi
  fi
  if test $ok = yes; then
    LIBGCRYPT_CFLAGS=`$LIBGCRYPT_CONFIG --cflags`
    LIBGCRYPT_LIBS=`$LIBGCRYPT_CONFIG --libs`
    m4_default([$2], [:])
    if test -z "$use_gpgrt_config"; then
      libgcrypt_config_host=`$LIBGCRYPT_CONFIG --host 2>/dev/null || echo none`
    else
      libgcrypt_config_host=`$LIBGCRYPT_CONFIG --variable=host 2>/dev/null || echo none`
    fi
    if test x"$libgcrypt_config_host" != xnone ; then
      if test x"$libgcrypt_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The config script "$LIBGCRYPT_CONFIG" was
*** built for $libgcrypt_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-libgcrypt-prefix
*** to specify a matching config script or use \$SYSROOT.
***]])
        gpg_config_script_warn="$gpg_config_script_warn libgcrypt"
      fi
    fi
  else
    LIBGCRYPT_CFLAGS=""
    LIBGCRYPT_LIBS=""
    m4_default([$3], [:])
  fi
  AC_SUBST(LIBGCRYPT_CFLAGS)
  AC_SUBST(LIBGCRYPT_LIBS)
])
