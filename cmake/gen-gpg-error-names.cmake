# Generate gpg-error-names.h for the gpg-error utility from gcrypt.h.
#
# Usage: cmake -DINPUT=<gcrypt.h> -DOUTPUT=<header> -P gen-gpg-error-names.cmake
#
# Every enumerator of gpg_err_source_t and gpg_err_code_t becomes a
# (value, name) pair, except the GPG_ERR_SOURCE_DIM, GPG_ERR_CODE_DIM and
# GPG_ERR_SYSTEM_ERROR markers, which are not error values.  The tables
# are sorted by value.

if(NOT INPUT OR NOT OUTPUT)
    message(FATAL_ERROR "INPUT and OUTPUT must be set")
endif()

file(STRINGS "${INPUT}" lines REGEX "^    GPG_ERR_[A-Z0-9_]+ = ")

set(sources "")
set(codes "")

foreach(line IN LISTS lines)
    if(line MATCHES "^    GPG_ERR_SOURCE_([A-Z0-9_]+) = ([0-9]+)")
        if(NOT CMAKE_MATCH_1 STREQUAL "DIM")
            # Zero-pad the value so that a plain sort orders numerically.
            string(LENGTH "${CMAKE_MATCH_2}" len)
            math(EXPR pad "5 - ${len}")
            string(REPEAT "0" ${pad} zeros)
            list(APPEND sources
                 "${zeros}${CMAKE_MATCH_2} GPG_ERR_SOURCE_${CMAKE_MATCH_1}"
            )
        endif()
    elseif(line MATCHES
           "^    GPG_ERR_([A-Z0-9_]+) = GPG_ERR_SYSTEM_ERROR \\| ([0-9]+)"
    )
        math(EXPR value "32768 + ${CMAKE_MATCH_2}")
        list(APPEND codes "${value} GPG_ERR_${CMAKE_MATCH_1}")
    elseif(line MATCHES "^    GPG_ERR_([A-Z0-9_]+) = ([0-9]+)")
        if(NOT CMAKE_MATCH_1 STREQUAL "CODE_DIM")
            string(LENGTH "${CMAKE_MATCH_2}" len)
            math(EXPR pad "5 - ${len}")
            string(REPEAT "0" ${pad} zeros)
            list(APPEND codes
                 "${zeros}${CMAKE_MATCH_2} GPG_ERR_${CMAKE_MATCH_1}"
            )
        endif()
    endif()
endforeach()

list(SORT sources)
list(SORT codes)

set(text "/* Generated from gcrypt.h by gen-gpg-error-names.cmake. */\n")
string(APPEND text "/* Do not edit. */\n")
string(APPEND text "struct gpg_error_name {\n")
string(APPEND text "    unsigned int value;\n")
string(APPEND text "    const char *name;\n")
string(APPEND text "};\n\n")

string(APPEND text "static const struct gpg_error_name source_names[] = {\n")
foreach(entry IN LISTS sources)
    string(REGEX MATCH "^0*([0-9]+) (.*)$" _ "${entry}")
    string(APPEND text "    { ${CMAKE_MATCH_1}, \"${CMAKE_MATCH_2}\" },\n")
endforeach()
string(APPEND text "};\n\n")

string(APPEND text "static const struct gpg_error_name code_names[] = {\n")
foreach(entry IN LISTS codes)
    string(REGEX MATCH "^0*([0-9]+) (.*)$" _ "${entry}")
    string(APPEND text "    { ${CMAKE_MATCH_1}, \"${CMAKE_MATCH_2}\" },\n")
endforeach()
string(APPEND text "};\n")

# Only touch the output when it changes, to spare rebuilds.
set(old "")
if(EXISTS "${OUTPUT}")
    file(READ "${OUTPUT}" old)
endif()
if(NOT old STREQUAL text)
    file(WRITE "${OUTPUT}" "${text}")
endif()
