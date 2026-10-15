# ---------------------------------------------------------------------------
# Unit tests. Each test_*.c file becomes one executable and one CTest entry.
# Tests use the tiny assertion helpers in test_common.h; no external
# framework is required.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_TESTS
    test_version
)

foreach(test IN LISTS GCRYPT_OPENSSL_TESTS)
    add_executable(${test} ${test}.c)
    target_include_directories(${test} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${test}
        PRIVATE
            gcrypt-openssl::gcrypt-openssl
            gcrypt-openssl::warnings
    )
    add_test(NAME ${test} COMMAND ${test})
endforeach()

# Also exercise the static library if it was built, so both flavours are
# known to link and run.
if(GCRYPT_OPENSSL_BUILD_SHARED AND GCRYPT_OPENSSL_BUILD_STATIC)
    add_executable(test_version_static test_version.c)
    target_include_directories(test_version_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_version_static
        PRIVATE
            gcrypt-openssl::static
            gcrypt-openssl::warnings
    )
    add_test(NAME test_version_static COMMAND test_version_static)
endif()
