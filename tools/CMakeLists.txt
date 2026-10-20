# ---------------------------------------------------------------------------
# Command-line utilities that the reference Libgcrypt installs alongside
# the library: dumpsexp, hmac256 and mpicalc.  Only built with the drop-in,
# and linked against libgcrypt.so.20 so they run against the same library
# a packaged program would.
# ---------------------------------------------------------------------------
set(GCRYPT_OPENSSL_TOOLS dumpsexp hmac256 mpicalc)

foreach(tool IN LISTS GCRYPT_OPENSSL_TOOLS)
    add_executable(${tool} ${tool}.c)
    target_link_libraries(
        ${tool} PRIVATE gcrypt-openssl::libgcrypt gcrypt-openssl::warnings
    )
    # Find the drop-in library from the install prefix without LD_LIBRARY_PATH.
    set_target_properties(
        ${tool} PROPERTIES INSTALL_RPATH
                           "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}"
    )
endforeach()

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
            $<TARGET_FILE:mpicalc>
    )
endif()
