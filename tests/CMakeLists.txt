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
)

# Tests of internal helpers link the static library so that symbols hidden
# from the shared library's export list are reachable.
set(GCRYPT_OPENSSL_INTERNAL_TESTS test_curves test_internal)

# Sanitizer settings for ASan/LSan builds; harmless otherwise. The leak
# checker needs the slow unwinder to see through libcrypto (built without
# frame pointers) so that the suppressions in lsan.supp can match.
set(GCRYPT_OPENSSL_LSAN_ENV
    "LSAN_OPTIONS=suppressions=${CMAKE_CURRENT_SOURCE_DIR}/lsan.supp"
    "ASAN_OPTIONS=fast_unwind_on_malloc=0"
)

foreach(test IN LISTS GCRYPT_OPENSSL_TESTS)
    add_executable(${test} ${test}.c)
    target_include_directories(${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(
        ${test} PRIVATE gcrypt-openssl::gcrypt-openssl gcrypt-openssl::warnings
    )
    add_test(NAME ${test} COMMAND ${test})
    set_tests_properties(
        ${test} PROPERTIES ENVIRONMENT "${GCRYPT_OPENSSL_LSAN_ENV}"
    )
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
        set_tests_properties(
            ${test} PROPERTIES ENVIRONMENT "${GCRYPT_OPENSSL_LSAN_ENV}"
        )
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
    set_tests_properties(
        test_version_static PROPERTIES ENVIRONMENT "${GCRYPT_OPENSSL_LSAN_ENV}"
    )
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
