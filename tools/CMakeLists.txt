# ---------------------------------------------------------------------------
# Command-line utilities that the reference Libgcrypt and libgpg-error
# install alongside their libraries: dumpsexp, hmac256, mpicalc, gpg-error
# and yat2m.  Only built with the drop-in.  Those that use the library are
# linked against libgcrypt.so.20 so they run against the same library a
# packaged program would; yat2m is a plain text converter and needs none.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_TOOLS
    dumpsexp
    hmac256
    mpicalc
    gpg-error
    yat2m
)
set(GCRYPT_OPENSSL_LIBRARY_TOOLS dumpsexp hmac256 mpicalc gpg-error)

foreach(tool IN LISTS GCRYPT_OPENSSL_TOOLS)
    add_executable(${tool} ${tool}.c)
    target_link_libraries(${tool} PRIVATE gcrypt-openssl::warnings)
    if(tool IN_LIST GCRYPT_OPENSSL_LIBRARY_TOOLS)
        target_link_libraries(${tool} PRIVATE gcrypt-openssl::libgcrypt)
        # Find the drop-in library from the install prefix without
        # LD_LIBRARY_PATH.
        set_target_properties(
            ${tool}
            PROPERTIES INSTALL_RPATH
                       "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
        )
    endif()
endforeach()

# gpg-error needs the symbolic names of every error source and code, which
# gcrypt.h defines as enumerators.  A CMake script turns them into a table
# whenever the header changes.
set(GPG_ERROR_NAMES_HEADER "${CMAKE_CURRENT_BINARY_DIR}/gpg-error-names.h")
add_custom_command(
    OUTPUT "${GPG_ERROR_NAMES_HEADER}"
    COMMAND
        "${CMAKE_COMMAND}" -DINPUT=${PROJECT_SOURCE_DIR}/src/include/gcrypt.h
        -DOUTPUT=${GPG_ERROR_NAMES_HEADER} -P
        "${PROJECT_SOURCE_DIR}/cmake/gen-gpg-error-names.cmake"
    DEPENDS "${PROJECT_SOURCE_DIR}/src/include/gcrypt.h"
            "${PROJECT_SOURCE_DIR}/cmake/gen-gpg-error-names.cmake"
    COMMENT "Generating gpg-error-names.h from gcrypt.h"
    VERBATIM
)
target_sources(gpg-error PRIVATE "${GPG_ERROR_NAMES_HEADER}")
target_include_directories(gpg-error PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")

# --desc shows libgpg-error's errorref.txt when it is installed.  Look in
# this installation's data directory first, then in /usr/share.
target_compile_definitions(
    gpg-error
    PRIVATE
        "GPG_ERROR_ERRORREF_DIR=\"${CMAKE_INSTALL_FULL_DATADIR}/libgpg-error\""
)

install(TARGETS ${GCRYPT_OPENSSL_TOOLS}
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

# Each tool must behave like the reference program it replaces.
if(GCRYPT_OPENSSL_BUILD_TESTS)
    add_test(
        NAME check_tools
        COMMAND
            sh "${PROJECT_SOURCE_DIR}/scripts/check-tools.sh"
            $<TARGET_FILE:dumpsexp> $<TARGET_FILE:hmac256>
            $<TARGET_FILE:mpicalc> $<TARGET_FILE:gpg-error>
            $<TARGET_FILE:yat2m>
    )
endif()
