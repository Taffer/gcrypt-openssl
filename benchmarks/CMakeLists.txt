# ---------------------------------------------------------------------------
# Benchmarks. bench_gcrypt drives the public gcrypt API and prints
# throughput for every operation. It is linked against this library and,
# when a stock libgcrypt is found on the system, a second copy is linked
# against that so compare.sh can print both side by side. The benchmarks
# are built as part of the default target but are not registered with
# CTest.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_BENCH_SOURCES
    bench_main.c
    bench_hash.c
    bench_mac.c
    bench_kdf.c
    bench_cipher.c
    bench_pk.c
    bench_kem.c
    bench_misc.c
)

# Create a benchmark executable from the shared sources.
function(gcrypt_openssl_add_benchmark target)
    add_executable(${target} ${GCRYPT_OPENSSL_BENCH_SOURCES})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_definitions(${target} PRIVATE _POSIX_C_SOURCE=200809L)
    target_link_libraries(${target} PRIVATE gcrypt-openssl::warnings)
endfunction()

gcrypt_openssl_add_benchmark(bench_gcrypt)
target_link_libraries(bench_gcrypt PRIVATE gcrypt-openssl::gcrypt-openssl)

# The stock library: only the runtime object is needed, since the benchmark
# is compiled against this project's ABI-compatible header. Point
# GCRYPT_OPENSSL_STOCK_GCRYPT at a specific file to override the search.
find_library(
    GCRYPT_OPENSSL_STOCK_GCRYPT
    NAMES libgcrypt.so.20 gcrypt
    DOC "Stock libgcrypt to benchmark against"
)

if(GCRYPT_OPENSSL_STOCK_GCRYPT)
    message(STATUS "Benchmarking against stock ${GCRYPT_OPENSSL_STOCK_GCRYPT}")
    gcrypt_openssl_add_benchmark(bench_gcrypt_stock)
    target_include_directories(
        bench_gcrypt_stock PRIVATE "${PROJECT_SOURCE_DIR}/src/include"
    )
    target_link_libraries(
        bench_gcrypt_stock PRIVATE "${GCRYPT_OPENSSL_STOCK_GCRYPT}"
    )

    # `cmake --build <dir> --target bench-compare` runs both and prints the
    # comparison. Extra arguments go through GCRYPT_OPENSSL_BENCH_ARGS.
    set(GCRYPT_OPENSSL_BENCH_ARGS
        ""
        CACHE STRING "Arguments passed to bench_gcrypt by bench-compare"
    )
    separate_arguments(bench_args NATIVE_COMMAND "${GCRYPT_OPENSSL_BENCH_ARGS}")
    add_custom_target(
        bench-compare
        COMMAND
            sh "${CMAKE_CURRENT_SOURCE_DIR}/compare.sh"
            $<TARGET_FILE:bench_gcrypt> $<TARGET_FILE:bench_gcrypt_stock>
            ${bench_args}
        DEPENDS bench_gcrypt bench_gcrypt_stock
        USES_TERMINAL
        COMMENT "Comparing bench_gcrypt against the stock libgcrypt"
        VERBATIM
    )
else()
    message(STATUS "No stock libgcrypt found; bench_gcrypt_stock not built")
endif()
