# ---------------------------------------------------------------------------
# FindGpgError
# ------------
#
# Finds libgpg-error, the GnuPG error-code library that <gcrypt.h> includes
# as <gpg-error.h>.
#
# Imported target:
#
#   GpgError::GpgError      The library and its include directory.
#
# Result variables:
#
#   GpgError_FOUND
#   GPG_ERROR_VERSION       x.y as reported by pkg-config or gpg-error.h
#   GPG_ERROR_INCLUDE_DIR   Directory holding gpg-error.h
#   GPG_ERROR_LIBRARY       Path of the library
#   GPG_ERROR_CFLAGS        Preprocessor flags a consumer needs, as a string
#                           ("" when the header is in a default directory)
#   GPG_ERROR_LIBS          Linker flags a consumer needs, as a string
#                           (what gpgrt-config --libs would print)
#
# Hints:
#
#   GPG_ERROR_ROOT_DIR      Install prefix of a libgpg-error that is not the
#                           system one (variable or environment variable).
#
# pkg-config is consulted first when it is available (libgpg-error installs
# gpg-error.pc); the plain path searches cover the rest.
#
# This file is in the public domain.
# ---------------------------------------------------------------------------

set(gpg_error_hints "")
if(GPG_ERROR_ROOT_DIR)
    list(APPEND gpg_error_hints "${GPG_ERROR_ROOT_DIR}")
endif()
if(DEFINED ENV{GPG_ERROR_ROOT_DIR})
    list(APPEND gpg_error_hints "$ENV{GPG_ERROR_ROOT_DIR}")
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    if(gpg_error_hints)
        # Let a hinted prefix win over the system pkg-config search path.
        set(gpg_error_pc_path_save "$ENV{PKG_CONFIG_PATH}")
        set(gpg_error_pc_path "")
        foreach(hint IN LISTS gpg_error_hints)
            foreach(lib lib lib64)
                list(APPEND gpg_error_pc_path "${hint}/${lib}/pkgconfig")
            endforeach()
        endforeach()
        if(CMAKE_HOST_WIN32)
            list(JOIN gpg_error_pc_path ";" gpg_error_pc_path)
        else()
            list(JOIN gpg_error_pc_path ":" gpg_error_pc_path)
        endif()
        if(gpg_error_pc_path_save)
            set(ENV{PKG_CONFIG_PATH}
                "${gpg_error_pc_path}:${gpg_error_pc_path_save}"
            )
        else()
            set(ENV{PKG_CONFIG_PATH} "${gpg_error_pc_path}")
        endif()
    endif()
    pkg_check_modules(gpg_error_pc QUIET gpg-error)
    if(gpg_error_hints)
        set(ENV{PKG_CONFIG_PATH} "${gpg_error_pc_path_save}")
    endif()
endif()

find_path(
    GPG_ERROR_INCLUDE_DIR
    NAMES gpg-error.h
    HINTS ${gpg_error_pc_INCLUDE_DIRS} ${gpg_error_pc_INCLUDEDIR}
          ${gpg_error_hints}
    PATH_SUFFIXES include
)
mark_as_advanced(GPG_ERROR_INCLUDE_DIR)

find_library(
    GPG_ERROR_LIBRARY
    NAMES gpg-error libgpg-error
    HINTS ${gpg_error_pc_LIBRARY_DIRS} ${gpg_error_pc_LIBDIR} ${gpg_error_hints}
    PATH_SUFFIXES lib lib64
)
mark_as_advanced(GPG_ERROR_LIBRARY)

# Version: pkg-config's answer, else the header's GPG_ERROR_VERSION string.
# Some distributions append a suffix ("1.58-unknown"); keep the numbers.
set(GPG_ERROR_VERSION "")
if(gpg_error_pc_VERSION)
    set(gpg_error_raw_version "${gpg_error_pc_VERSION}")
elseif(GPG_ERROR_INCLUDE_DIR AND EXISTS "${GPG_ERROR_INCLUDE_DIR}/gpg-error.h")
    file(STRINGS "${GPG_ERROR_INCLUDE_DIR}/gpg-error.h" gpg_error_raw_version
         REGEX "^#define[ \t]+GPG_ERROR_VERSION[ \t]+\""
    )
else()
    set(gpg_error_raw_version "")
endif()
if(gpg_error_raw_version MATCHES "([0-9]+\\.[0-9]+(\\.[0-9]+)?)")
    set(GPG_ERROR_VERSION "${CMAKE_MATCH_1}")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    GpgError
    REQUIRED_VARS GPG_ERROR_LIBRARY GPG_ERROR_INCLUDE_DIR
    VERSION_VAR GPG_ERROR_VERSION
)

if(GpgError_FOUND)
    # Flags for tools that print them (libgcrypt-config), in the form
    # gpgrt-config uses: nothing for the compiler's default directories.
    set(GPG_ERROR_CFLAGS "")
    if(NOT GPG_ERROR_INCLUDE_DIR MATCHES "^/usr/include$|^/include$")
        set(GPG_ERROR_CFLAGS "-I${GPG_ERROR_INCLUDE_DIR}")
    endif()

    get_filename_component(gpg_error_libdir "${GPG_ERROR_LIBRARY}" DIRECTORY)
    set(GPG_ERROR_LIBS "-lgpg-error")
    if(NOT gpg_error_libdir MATCHES
       "^/usr/lib$|^/usr/lib64$|^/lib$|^/lib64$|^/usr/lib/[^/]+-linux-gnu[^/]*$"
    )
        set(GPG_ERROR_LIBS "-L${gpg_error_libdir} -lgpg-error")
    endif()

    if(NOT TARGET GpgError::GpgError)
        add_library(GpgError::GpgError UNKNOWN IMPORTED)
        set_target_properties(
            GpgError::GpgError
            PROPERTIES IMPORTED_LOCATION "${GPG_ERROR_LIBRARY}"
                       INTERFACE_INCLUDE_DIRECTORIES "${GPG_ERROR_INCLUDE_DIR}"
        )
    endif()
endif()

unset(gpg_error_hints)
unset(gpg_error_pc_path)
unset(gpg_error_pc_path_save)
unset(gpg_error_raw_version)
unset(gpg_error_libdir)
