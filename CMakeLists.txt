cmake_minimum_required(VERSION 3.21)

project(
    gcrypt-openssl
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
    set(CMAKE_BUILD_TYPE
        "RelWithDebInfo"
        CACHE STRING "Build type" FORCE
    )
    set_property(
        CACHE CMAKE_BUILD_TYPE
        PROPERTY STRINGS
                 Debug
                 Release
                 RelWithDebInfo
                 MinSizeRel
    )
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}"
               GCRYPT_OPENSSL_IS_TOP_LEVEL
)

option(GCRYPT_OPENSSL_BUILD_SHARED "Build the shared library" ON)
option(GCRYPT_OPENSSL_BUILD_STATIC "Build the static library" ON)
option(GCRYPT_OPENSSL_BUILD_TESTS "Build the unit tests"
       ${GCRYPT_OPENSSL_IS_TOP_LEVEL}
)
option(GCRYPT_OPENSSL_BUILD_BENCHMARKS "Build the benchmarks"
       ${GCRYPT_OPENSSL_IS_TOP_LEVEL}
)
option(GCRYPT_OPENSSL_WARNINGS_AS_ERRORS
       "Treat compiler warnings as errors in every target that compiles C" ON
)
option(GCRYPT_OPENSSL_DROP_IN
       "Also build libgcrypt.so.20 plus libgcrypt.pc and libgcrypt-config" OFF
)
option(GCRYPT_OPENSSL_COVERAGE
       "Instrument for code coverage (gcc/clang --coverage) and add the
       coverage target" OFF
)
option(GCRYPT_OPENSSL_FIPS
       "Start the library in FIPS mode by default (as if the system asked
       for it) and define GCRYPT_OPENSSL_FIPS for every target" OFF
)
option(GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT
       "Adapt the tests to Chainguard's strict FIPS provider, which omits
       some approved algorithms (currently: SHA-512/224)" OFF
)

if(NOT GCRYPT_OPENSSL_BUILD_SHARED AND NOT GCRYPT_OPENSSL_BUILD_STATIC)
    message(FATAL_ERROR "At least one of GCRYPT_OPENSSL_BUILD_SHARED or "
                        "GCRYPT_OPENSSL_BUILD_STATIC must be ON"
    )
endif()

# ---------------------------------------------------------------------------
# FIPS mode. The definition reaches every target configured below (the
# libraries, the drop-in, the tests, the benchmarks and the coverage build)
# so that the library enables FIPS mode at initialisation and the tests can
# adapt their expectations. Whether FIPS mode actually works depends on the
# OpenSSL installation providing a FIPS provider.
# ---------------------------------------------------------------------------
if(GCRYPT_OPENSSL_FIPS)
    add_compile_definitions(GCRYPT_OPENSSL_FIPS=1)
    message(STATUS "FIPS mode enabled by default (GCRYPT_OPENSSL_FIPS)")
endif()

# Chainguard's strict FIPS provider leaves out some algorithms that FIPS
# approves and OpenSSL's own provider offers. The definition only changes
# what the tests expect; the library needs no adjustment.
if(GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT)
    add_compile_definitions(GCRYPT_OPENSSL_FIPS_CHAINGUARD_STRICT=1)
    message(STATUS "Tests adapted to the Chainguard strict FIPS provider")
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
# OpenSSL 4.x is required. If your distribution only ships OpenSSL 3, build
# it with scripts/build-openssl.sh and point CMake at the result with
# -DOPENSSL_ROOT_DIR=<prefix> (or set it in CMakeUserPresets.json).
find_package(OpenSSL 4.0 REQUIRED COMPONENTS Crypto)
message(
    STATUS "Using OpenSSL ${OPENSSL_VERSION} from ${OPENSSL_CRYPTO_LIBRARY}"
)

# The drop-in replacement must not shadow the system libgcrypt, so by
# default it installs under /opt/gcrypt-openssl with the libraries in lib64
# (the layout the README documents) instead of the usual prefix and the
# platform's library directory.  Both remain overridable with
# -DCMAKE_INSTALL_PREFIX and -DCMAKE_INSTALL_LIBDIR.  The prefix default is
# only applied on the first configure of a build tree, like CMake's own.
if(GCRYPT_OPENSSL_DROP_IN)
    if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
        set(CMAKE_INSTALL_PREFIX
            "/opt/gcrypt-openssl"
            CACHE PATH
                  "Install path prefix, prepended onto install directories"
                  FORCE
        )
    endif()
    if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
        set(CMAKE_INSTALL_LIBDIR
            "lib64"
            CACHE PATH "Object code libraries (lib64)"
        )
    endif()
endif()

# Needed before add_subdirectory(src) so CMAKE_INSTALL_INCLUDEDIR is defined
# when the library's INSTALL_INTERFACE include path is set.
include(GNUInstallDirs)

# ---------------------------------------------------------------------------
# Common compiler warnings, applied to every target via an INTERFACE library.
# ---------------------------------------------------------------------------
add_library(gcrypt_openssl_warnings INTERFACE)
add_library(gcrypt-openssl::warnings ALIAS gcrypt_openssl_warnings)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(
        gcrypt_openssl_warnings
        INTERFACE -Wall
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
    target_compile_options(
        gcrypt_openssl_warnings
        INTERFACE /W4 $<$<BOOL:${GCRYPT_OPENSSL_WARNINGS_AS_ERRORS}>:/WX>
    )
endif()

# ---------------------------------------------------------------------------
# Code coverage: instrument everything in this tree with gcc/clang's
# --coverage and provide a `coverage` target that runs the tests and
# produces a report with scripts/coverage.py (needs gcov or llvm-cov).
# ---------------------------------------------------------------------------
if(GCRYPT_OPENSSL_COVERAGE)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "GCRYPT_OPENSSL_COVERAGE needs gcc or clang")
    endif()

    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(WARNING "Coverage builds should use CMAKE_BUILD_TYPE=Debug; "
                        "optimisation makes line counts misleading"
        )
    endif()

    add_compile_options(--coverage)
    add_link_options(--coverage)

    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        find_program(GCRYPT_OPENSSL_GCOV NAMES llvm-cov)
        set(gcov_arg "--gcov=${GCRYPT_OPENSSL_GCOV} gcov")
    else()
        find_program(GCRYPT_OPENSSL_GCOV NAMES gcov)
        set(gcov_arg "--gcov=${GCRYPT_OPENSSL_GCOV}")
    endif()

    find_package(
        Python3
        COMPONENTS Interpreter
        REQUIRED
    )
    add_custom_target(
        coverage
        COMMAND
            ${Python3_EXECUTABLE} "${PROJECT_SOURCE_DIR}/scripts/coverage.py"
            --build-dir "${PROJECT_BINARY_DIR}" --source-dir
            "${PROJECT_SOURCE_DIR}" --output "${PROJECT_BINARY_DIR}/coverage"
            --run-tests ${gcov_arg}
        WORKING_DIRECTORY "${PROJECT_BINARY_DIR}"
        USES_TERMINAL
        COMMENT "Running the tests and collecting coverage"
        VERBATIM
    )
    unset(gcov_arg)
endif()

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
add_subdirectory(src)

if(GCRYPT_OPENSSL_BUILD_TESTS)
    # Valgrind integration for `ctest -T memcheck` and the memcheck target
    # defined in tests/. These must be set before CTest is included so that
    # they land in DartConfiguration.tcl.
    find_program(
        GCRYPT_OPENSSL_VALGRIND
        NAMES valgrind
        DOC "Valgrind"
    )
    if(GCRYPT_OPENSSL_VALGRIND)
        set(MEMORYCHECK_COMMAND "${GCRYPT_OPENSSL_VALGRIND}")
        set(MEMORYCHECK_COMMAND_OPTIONS
            "--tool=memcheck --error-exitcode=1 --leak-check=full \
--errors-for-leak-kinds=definite,possible --track-origins=yes \
--num-callers=30 \
--read-var-info=yes"
        )
        set(MEMORYCHECK_SUPPRESSIONS_FILE
            "${PROJECT_SOURCE_DIR}/tests/valgrind.supp"
        )
    endif()

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

set(GCRYPT_OPENSSL_CMAKE_INSTALL_DIR
    "${CMAKE_INSTALL_LIBDIR}/cmake/gcrypt-openssl"
)

install(
    EXPORT gcrypt-openssl-targets
    FILE gcrypt-openssl-targets.cmake
    NAMESPACE gcrypt-openssl::
    DESTINATION "${GCRYPT_OPENSSL_CMAKE_INSTALL_DIR}"
)

configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/gcrypt-openssl-config.cmake.in"
    "${PROJECT_BINARY_DIR}/gcrypt-openssl-config.cmake"
    INSTALL_DESTINATION "${GCRYPT_OPENSSL_CMAKE_INSTALL_DIR}"
)

write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/gcrypt-openssl-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES "${PROJECT_BINARY_DIR}/gcrypt-openssl-config.cmake"
              "${PROJECT_BINARY_DIR}/gcrypt-openssl-config-version.cmake"
        DESTINATION "${GCRYPT_OPENSSL_CMAKE_INSTALL_DIR}"
)
