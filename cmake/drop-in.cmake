# ---------------------------------------------------------------------------
# Drop-in replacement for the reference Libgcrypt.
#
# Included from src/CMakeLists.txt after the regular targets exist.  Always
# installs a pkg-config file for libgcrypt-openssl.  With
# GCRYPT_OPENSSL_DROP_IN enabled it additionally builds the same code as
# libgcrypt.so.20 (the reference library's soname and version), and installs
# libgcrypt.pc plus a libgcrypt-config script, so that existing programs and
# build systems pick this library up unchanged.
# ---------------------------------------------------------------------------

# Version string reported by gcry_check_version(); keep in sync with the
# GCRYPT_VERSION macro in include/gcrypt.h.
set(GCRYPT_API_VERSION "1.12.4")

# Reference library: LT_CURRENT=28, LT_AGE=8, LT_REVISION=9.
set(GCRYPT_DROP_IN_SOVERSION 20)
set(GCRYPT_DROP_IN_VERSION 20.8.9)

string(CONCAT GCRYPT_CONFIG_CIPHERS
              "idea:3des:cast5:blowfish:aes:rfc2268:seed:"
              "camellia:chacha20:sm4:aria:arcfour:des"
)
set(GCRYPT_CONFIG_PUBKEYS "dsa:elgamal:rsa:ecc")
set(GCRYPT_CONFIG_DIGESTS
    "crc:md4:md5:rmd160:sha1:sha256:sha512:sha3:whirlpool:blake2:sm3"
)

if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(PC_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
else()
    set(PC_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
endif()

if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
    set(PC_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
else()
    set(PC_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
endif()

configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/gcrypt-openssl.pc.in"
    "${PROJECT_BINARY_DIR}/gcrypt-openssl.pc" @ONLY
)
install(FILES "${PROJECT_BINARY_DIR}/gcrypt-openssl.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

if(NOT GCRYPT_OPENSSL_DROP_IN)
    return()
endif()

if(NOT GCRYPT_OPENSSL_BUILD_SHARED)
    message(
        FATAL_ERROR
            "GCRYPT_OPENSSL_DROP_IN requires GCRYPT_OPENSSL_BUILD_SHARED"
    )
endif()

add_library(gcrypt_openssl_dropin SHARED)
add_library(gcrypt-openssl::libgcrypt ALIAS gcrypt_openssl_dropin)
gcrypt_openssl_configure_library(gcrypt_openssl_dropin libgcrypt)
set_target_properties(
    gcrypt_openssl_dropin
    PROPERTIES OUTPUT_NAME gcrypt
               VERSION ${GCRYPT_DROP_IN_VERSION}
               SOVERSION ${GCRYPT_DROP_IN_SOVERSION}
               PUBLIC_HEADER ""
)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND NOT APPLE)
    target_link_options(
        gcrypt_openssl_dropin PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libgcrypt.map"
        "-Wl,--no-undefined"
    )
    set_property(
        TARGET gcrypt_openssl_dropin
        APPEND
        PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/libgcrypt.map"
    )
endif()

install(
    TARGETS gcrypt_openssl_dropin
    EXPORT gcrypt-openssl-targets
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

# The install-time absolute libdir/includedir for the config script, which
# unlike pkg-config cannot expand ${prefix}.
set(PC_LIBDIR_SAVE "${PC_LIBDIR}")
set(PC_INCLUDEDIR_SAVE "${PC_INCLUDEDIR}")
set(PC_LIBDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
set(PC_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}")
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(PC_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
    set(PC_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
endif()
set(LIBGCRYPT_CONFIG_HOST "${CMAKE_C_COMPILER_TARGET}")
if(NOT LIBGCRYPT_CONFIG_HOST)
    set(LIBGCRYPT_CONFIG_HOST "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}")
endif()

configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/libgcrypt-config.in"
    "${PROJECT_BINARY_DIR}/libgcrypt-config"
    @ONLY
    FILE_PERMISSIONS
    OWNER_READ
    OWNER_WRITE
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)
set(PC_LIBDIR "${PC_LIBDIR_SAVE}")
set(PC_INCLUDEDIR "${PC_INCLUDEDIR_SAVE}")

configure_file(
    "${PROJECT_SOURCE_DIR}/cmake/libgcrypt.pc.in"
    "${PROJECT_BINARY_DIR}/libgcrypt.pc" @ONLY
)

install(FILES "${PROJECT_BINARY_DIR}/libgcrypt.pc"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
install(PROGRAMS "${PROJECT_BINARY_DIR}/libgcrypt-config"
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
