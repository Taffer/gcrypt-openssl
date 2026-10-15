# ---------------------------------------------------------------------------
# Benchmarks. Each bench_*.c file becomes one executable. They are built as
# part of the default target but are not registered with CTest; run them by
# hand from the build directory.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_BENCHMARKS
    bench_version
)

foreach(bench IN LISTS GCRYPT_OPENSSL_BENCHMARKS)
    add_executable(${bench} ${bench}.c)
    target_include_directories(${bench} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${bench}
        PRIVATE
            gcrypt-openssl::gcrypt-openssl
            gcrypt-openssl::warnings
    )
endforeach()
