# ---------------------------------------------------------------------------
# Library sources. Everything that goes into libgcrypt-openssl lives here.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_SOURCES
    ecc-curves.c
    error.c
    global.c
    kem.c
    memory.c
    misc.c
    mpi.c
    mpi-ec.c
    sexp.c
)

set(GCRYPT_OPENSSL_PUBLIC_HEADERS include/gcrypt.h)

find_package(Threads REQUIRED)

# The same sources are compiled twice (once per library flavour).
function(gcrypt_openssl_configure_library target export_name)
    target_sources(${target} PRIVATE ${GCRYPT_OPENSSL_SOURCES})

    target_include_directories(
        ${target}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
               $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_compile_definitions(
        ${target}
        PRIVATE _POSIX_C_SOURCE=200809L
                GCRYPT_OPENSSL_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
                GCRYPT_OPENSSL_VERSION_MINOR=${PROJECT_VERSION_MINOR}
                GCRYPT_OPENSSL_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    )

    target_link_libraries(
        ${target}
        PUBLIC OpenSSL::Crypto Threads::Threads
        PRIVATE $<BUILD_INTERFACE:gcrypt_openssl_warnings>
    )

    # Exports are controlled by the version script instead of visibility
    # attributes, so the public header stays identical to upstream's.
    set_target_properties(
        ${target}
        PROPERTIES OUTPUT_NAME gcrypt-openssl
                   VERSION ${PROJECT_VERSION}
                   SOVERSION ${PROJECT_VERSION_MAJOR}
                   PUBLIC_HEADER "${GCRYPT_OPENSSL_PUBLIC_HEADERS}"
                   EXPORT_NAME ${export_name}
                   C_VISIBILITY_PRESET default
    )
endfunction()

set(GCRYPT_OPENSSL_INSTALL_TARGETS "")

if(GCRYPT_OPENSSL_BUILD_SHARED)
    add_library(gcrypt_openssl_shared SHARED)
    add_library(gcrypt-openssl::shared ALIAS gcrypt_openssl_shared)
    gcrypt_openssl_configure_library(gcrypt_openssl_shared shared)

    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT APPLE)
        target_link_options(
            gcrypt_openssl_shared PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libgcrypt.map"
            "-Wl,--no-undefined"
        )
        set_property(
            TARGET gcrypt_openssl_shared
            APPEND
            PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libgcrypt.map"
        )
    endif()

    list(APPEND GCRYPT_OPENSSL_INSTALL_TARGETS gcrypt_openssl_shared)
endif()

if(GCRYPT_OPENSSL_BUILD_STATIC)
    add_library(gcrypt_openssl_static STATIC)
    add_library(gcrypt-openssl::static ALIAS gcrypt_openssl_static)
    gcrypt_openssl_configure_library(gcrypt_openssl_static static)
    list(APPEND GCRYPT_OPENSSL_INSTALL_TARGETS gcrypt_openssl_static)
endif()

# A convenience alias for in-tree consumers (tests, benchmarks): prefer the
# shared library, fall back to static.
if(GCRYPT_OPENSSL_BUILD_SHARED)
    add_library(gcrypt-openssl::gcrypt-openssl ALIAS gcrypt_openssl_shared)
else()
    add_library(gcrypt-openssl::gcrypt-openssl ALIAS gcrypt_openssl_static)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
install(
    TARGETS ${GCRYPT_OPENSSL_INSTALL_TARGETS}
    EXPORT gcrypt-openssl-targets
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# pkg-config files and the optional libgcrypt.so.20 drop-in target.
include("${PROJECT_SOURCE_DIR}/cmake/drop-in.cmake")
