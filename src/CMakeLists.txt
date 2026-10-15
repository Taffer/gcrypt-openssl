# ---------------------------------------------------------------------------
# Library sources. Everything that goes into libgcrypt-openssl lives here.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_SOURCES gcrypt_openssl.c)

set(GCRYPT_OPENSSL_PUBLIC_HEADERS include/gcrypt-openssl/gcrypt_openssl.h)

include(GenerateExportHeader)

# The same sources are compiled twice (once per library flavour) so each
# build gets the right export/import annotations in the export header.
function(gcrypt_openssl_configure_library target export_name)
    target_sources(${target} PRIVATE ${GCRYPT_OPENSSL_SOURCES})

    target_include_directories(
        ${target}
        PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
               $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
               $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    )

    target_compile_definitions(
        ${target}
        PRIVATE GCRYPT_OPENSSL_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
                GCRYPT_OPENSSL_VERSION_MINOR=${PROJECT_VERSION_MINOR}
                GCRYPT_OPENSSL_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    )

    target_link_libraries(
        ${target}
        PUBLIC OpenSSL::Crypto
        PRIVATE $<BUILD_INTERFACE:gcrypt_openssl_warnings>
    )

    set_target_properties(
        ${target}
        PROPERTIES OUTPUT_NAME gcrypt-openssl
                   VERSION ${PROJECT_VERSION}
                   SOVERSION ${PROJECT_VERSION_MAJOR}
                   PUBLIC_HEADER "${GCRYPT_OPENSSL_PUBLIC_HEADERS}"
                   EXPORT_NAME ${export_name}
    )
endfunction()

set(GCRYPT_OPENSSL_INSTALL_TARGETS "")

if(GCRYPT_OPENSSL_BUILD_SHARED)
    add_library(gcrypt_openssl_shared SHARED)
    add_library(gcrypt-openssl::shared ALIAS gcrypt_openssl_shared)
    gcrypt_openssl_configure_library(gcrypt_openssl_shared shared)

    generate_export_header(
        gcrypt_openssl_shared
        BASE_NAME
        GCRYPT_OPENSSL
        EXPORT_FILE_NAME
        "${CMAKE_CURRENT_BINARY_DIR}/include/gcrypt-openssl/export.h"
    )

    list(APPEND GCRYPT_OPENSSL_INSTALL_TARGETS gcrypt_openssl_shared)
endif()

if(GCRYPT_OPENSSL_BUILD_STATIC)
    add_library(gcrypt_openssl_static STATIC)
    add_library(gcrypt-openssl::static ALIAS gcrypt_openssl_static)
    gcrypt_openssl_configure_library(gcrypt_openssl_static static)

    # Tell the export header to emit no visibility attributes.
    target_compile_definitions(
        gcrypt_openssl_static PUBLIC GCRYPT_OPENSSL_STATIC_DEFINE
    )

    if(NOT GCRYPT_OPENSSL_BUILD_SHARED)
        # Only the static build exists, so it owns the export header.
        generate_export_header(
            gcrypt_openssl_static
            BASE_NAME
            GCRYPT_OPENSSL
            EXPORT_FILE_NAME
            "${CMAKE_CURRENT_BINARY_DIR}/include/gcrypt-openssl/export.h"
        )
    endif()

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
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/gcrypt-openssl"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/gcrypt-openssl/export.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/gcrypt-openssl"
)
