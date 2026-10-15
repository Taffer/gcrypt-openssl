cmake_minimum_required(VERSION 3.21)

project(gcrypt-openssl
    VERSION 0.1.0
    DESCRIPTION "The gcrypt API, implemented using OpenSSL for the cryptography"
    LANGUAGES C
)

# ---------------------------------------------------------------------------
# Language standard: strict C99, no compiler extensions.
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Hide everything from shared libraries unless explicitly exported.
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# Build PIC objects everywhere so the static library can be linked into
# other shared objects.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}" GCRYPT_OPENSSL_IS_TOP_LEVEL)

option(GCRYPT_OPENSSL_BUILD_SHARED     "Build the shared library"       ON)
option(GCRYPT_OPENSSL_BUILD_STATIC     "Build the static library"       ON)
option(GCRYPT_OPENSSL_BUILD_TESTS      "Build the unit tests"           ${GCRYPT_OPENSSL_IS_TOP_LEVEL})
option(GCRYPT_OPENSSL_BUILD_BENCHMARKS "Build the benchmarks"           ${GCRYPT_OPENSSL_IS_TOP_LEVEL})
option(GCRYPT_OPENSSL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

if(NOT GCRYPT_OPENSSL_BUILD_SHARED AND NOT GCRYPT_OPENSSL_BUILD_STATIC)
    message(FATAL_ERROR "At least one of GCRYPT_OPENSSL_BUILD_SHARED or GCRYPT_OPENSSL_BUILD_STATIC must be ON")
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

# Needed before add_subdirectory(src) so CMAKE_INSTALL_INCLUDEDIR is defined
# when the library's INSTALL_INTERFACE include path is set.
include(GNUInstallDirs)

# ---------------------------------------------------------------------------
# Common compiler warnings, applied to every target via an INTERFACE library.
# ---------------------------------------------------------------------------
add_library(gcrypt_openssl_warnings INTERFACE)
add_library(gcrypt-openssl::warnings ALIAS gcrypt_openssl_warnings)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(gcrypt_openssl_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wcast-qual
        -Wpointer-arith
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wmissing-declarations
        -Wundef
        -Wwrite-strings
        -Wvla
        $<$<BOOL:${GCRYPT_OPENSSL_WARNINGS_AS_ERRORS}>:-Werror>
    )
elseif(MSVC)
    target_compile_options(gcrypt_openssl_warnings INTERFACE
        /W4
        $<$<BOOL:${GCRYPT_OPENSSL_WARNINGS_AS_ERRORS}>:/WX>
    )
endif()

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
add_subdirectory(src)

if(GCRYPT_OPENSSL_BUILD_TESTS)
    include(CTest)
    add_subdirectory(tests)
endif()

if(GCRYPT_OPENSSL_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
# Install: CMake package config so consumers can find_package(gcrypt-openssl)
# ---------------------------------------------------------------------------
include(CMakePackageConfigHelpers)

set(GCRYPT_OPENSSL_CMAKE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/gcrypt-openssl")

install(EXPORT gcrypt-openssl-targets
    FILE        gcrypt-openssl-targets.cmake
    NAMESPACE   gcrypt-openssl::
    DESTINATION "${GCRYPT_OPENSSL_CMAKE_INSTALL_DIR}"
)

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/gcrypt-openssl-config.cmake.in"
    "${PROJECT_BINARY_DIR}/gcrypt-openssl-config.cmake"
    INSTALL_DESTINATION "${GCRYPT_OPENSSL_CMAKE_INSTALL_DIR}"
)

write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/gcrypt-openssl-config-version.cmake"
    VERSION       ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${PROJECT_BINARY_DIR}/gcrypt-openssl-config.cmake"
    "${PROJECT_BINARY_DIR}/gcrypt-openssl-config-version.cmake"
    DESTINATION "${GCRYPT_OPENSSL_CMAKE_INSTALL_DIR}"
)
