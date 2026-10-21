# ---------------------------------------------------------------------------
# Unit tests. Each test_*.c file becomes one executable and one CTest entry.
# Tests use the tiny assertion helpers in test_common.h; no external
# framework is required.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_TESTS
    test_version
    test_error
    test_memory
    test_sexp
    test_mpi
    test_kem
    test_md
    test_mac
    test_kdf
    test_random
    test_prime
    test_cipher
    test_pk
    test_ec
    test_global
    test_secmem
    test_fips
)

# Tests of internal helpers link the static library so that symbols hidden
# from the shared library's export list are reachable.
set(GCRYPT_OPENSSL_INTERNAL_TESTS test_curves test_internal)

foreach(test IN LISTS GCRYPT_OPENSSL_TESTS)
    add_executable(${test} ${test}.c)
    target_include_directories(${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(
        ${test} PRIVATE gcrypt-openssl::gcrypt-openssl gcrypt-openssl::warnings
    )
    add_test(NAME ${test} COMMAND ${test})
endforeach()

if(GCRYPT_OPENSSL_BUILD_STATIC)
    foreach(test IN LISTS GCRYPT_OPENSSL_INTERNAL_TESTS)
        add_executable(${test} ${test}.c)
        target_include_directories(${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_definitions(${test} PRIVATE _POSIX_C_SOURCE=200809L)
        target_link_libraries(
            ${test} PRIVATE gcrypt-openssl::static gcrypt-openssl::warnings
        )
        add_test(NAME ${test} COMMAND ${test})
    endforeach()
endif()

# Also exercise the static library if it was built, so both flavours are
# known to link and run.
if(GCRYPT_OPENSSL_BUILD_SHARED AND GCRYPT_OPENSSL_BUILD_STATIC)
    add_executable(test_version_static test_version.c)
    target_include_directories(
        test_version_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(
        test_version_static PRIVATE gcrypt-openssl::static
                                    gcrypt-openssl::warnings
    )
    add_test(NAME test_version_static COMMAND test_version_static)
endif()

# `cmake --build <dir> --target memcheck` runs every test program under
# Valgrind's memcheck through CTest (`ctest -T memcheck`), with the options
# and suppressions configured at the top level. check_exports runs a shell
# script and is skipped. A defect reported by Valgrind fails the test.
if(GCRYPT_OPENSSL_VALGRIND)
    add_custom_target(
        memcheck
        COMMAND
            ${CMAKE_CTEST_COMMAND} -T memcheck --output-on-failure
            --exclude-regex check_exports --parallel 4 --test-dir
            "${PROJECT_BINARY_DIR}"
        WORKING_DIRECTORY "${PROJECT_BINARY_DIR}"
        USES_TERMINAL
        COMMENT "Running the tests under Valgrind"
        VERBATIM
    )
else()
    message(STATUS "Valgrind not found; memcheck target not available")
endif()

# The shared library must export exactly the reference library's symbols.
if(GCRYPT_OPENSSL_BUILD_SHARED
   AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
   AND NOT APPLE
)
    add_test(
        NAME check_exports
        COMMAND
            sh "${PROJECT_SOURCE_DIR}/scripts/check-exports.sh"
            $<TARGET_FILE:gcrypt_openssl_shared>
            "${CMAKE_CURRENT_SOURCE_DIR}/expected-exports.txt"
    )
endif()

# The drop-in's libgcrypt-config must answer like the reference script.
if(GCRYPT_OPENSSL_DROP_IN)
    add_test(
        NAME check_libgcrypt_config
        COMMAND
            sh "${PROJECT_SOURCE_DIR}/scripts/check-libgcrypt-config.sh"
            "${PROJECT_BINARY_DIR}/libgcrypt-config"
            "${PROJECT_SOURCE_DIR}/src/include/gcrypt.h"
    )
    set(check_libgcrypt_config_env "GPG_ERROR_LIBS=${GPG_ERROR_LIBS}"
                                   "GPG_ERROR_CFLAGS=${GPG_ERROR_CFLAGS}"
    )
    set_tests_properties(
        check_libgcrypt_config PROPERTIES ENVIRONMENT
                                          "${check_libgcrypt_config_env}"
    )

    # AM_PATH_LIBGCRYPT must find the drop-in through libgcrypt-config and
    # through gpgrt-config.  The script skips (exit 77) without autoconf.
    add_test(
        NAME check_libgcrypt_m4
        COMMAND sh "${PROJECT_SOURCE_DIR}/scripts/check-libgcrypt-m4.sh"
                "${PROJECT_SOURCE_DIR}/m4/libgcrypt.m4" "${PROJECT_BINARY_DIR}"
    )
    set_tests_properties(check_libgcrypt_m4 PROPERTIES SKIP_RETURN_CODE 77)
endif()
