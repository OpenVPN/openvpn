set(_GENERATE_HTML_DOC YES)
set(_GENERATE_MAN_DOC  YES)
set(_MAYBE_PYTHON "")
find_program(RST2HTML NAMES rst2html rst2html.py)
find_program(RST2MAN  NAMES rst2man  rst2man.py)

if (RST2HTML STREQUAL "RST2HTML-NOTFOUND")
    message(STATUS "rst2html not found, not generating HTML documentation")
    set(_GENERATE_HTML_DOC NO)
else ()
    # We only run this for RST2HTML and assume the result would be the same
    # for RST2MAN
    if (DEFINED CACHE{DOCUTILS_NEED_PYTHON})
        if ($CACHE{DOCUTILS_NEED_PYTHON})
            set(_MAYBE_PYTHON ${PYTHON})
        endif ()
    else ()
        execute_process(
            COMMAND ${RST2HTML} --version
            OUTPUT_VARIABLE RST2HTML_VERSION_EXE
            )
        execute_process(
            COMMAND ${PYTHON} ${RST2HTML} --version
            OUTPUT_VARIABLE RST2HTML_VERSION_PY
            )
        set(_DOCUTILS_NEED_PYTHON OFF)
        if(RST2HTML_VERSION_EXE STREQUAL "")
            if(RST2HTML_VERSION_PY STREQUAL "")
                message(STATUS "${RST2HTML} found but not working, not generating documentation")
                set(_GENERATE_HTML_DOC NO)
                set(_GENERATE_MAN_DOC NO)
            else ()
                message(STATUS "${RST2HTML} needs to be executed by ${PYTHON} to work")
                set(_MAYBE_PYTHON ${PYTHON})
                set(_DOCUTILS_NEED_PYTHON ON)
            endif ()
        endif ()
        set(DOCUTILS_NEED_PYTHON ${_DOCUTILS_NEED_PYTHON} CACHE BOOL
            "Whether we need to call python instead of rst2*.py directly")
    endif (DEFINED CACHE{DOCUTILS_NEED_PYTHON})
endif ()
if (RST2MAN STREQUAL "RST2MAN-NOTFOUND")
    message(STATUS "rst2man not found, not generating man pages")
    set(_GENERATE_MAN_DOC NO)
endif ()

set(OPENVPN_SECTIONS
    man-sections/advanced-options.rst
    man-sections/cipher-negotiation.rst
    man-sections/client-options.rst
    man-sections/connection-profiles.rst
    man-sections/encryption-options.rst
    man-sections/generic-options.rst
    man-sections/inline-files.rst
    man-sections/link-options.rst
    man-sections/log-options.rst
    man-sections/management-options.rst
    man-sections/network-config.rst
    man-sections/pkcs11-options.rst
    man-sections/plugin-options.rst
    man-sections/protocol-options.rst
    man-sections/proxy-options.rst
    man-sections/renegotiation.rst
    man-sections/signals.rst
    man-sections/script-options.rst
    man-sections/server-options.rst
    man-sections/tls-options.rst
    man-sections/unsupported-options.rst
    man-sections/virtual-routing-and-forwarding.rst
    man-sections/vpn-network-options.rst
    man-sections/windows-options.rst
    )

set(OPENVPN_EXAMPLES_SECTIONS
    man-sections/example-fingerprint.rst
    man-sections/examples.rst
    )

set(RST_FLAGS --strict)

if (_GENERATE_HTML_DOC)
    list(APPEND ALL_DOCS openvpn.8.html openvpn-examples.5.html)
    add_custom_command(
        OUTPUT openvpn.8.html
        COMMAND ${_MAYBE_PYTHON} ${RST2HTML} ${RST_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/openvpn.8.rst ${CMAKE_CURRENT_BINARY_DIR}/openvpn.8.html
        MAIN_DEPENDENCY openvpn.8.rst
        DEPENDS ${OPENVPN_SECTIONS}
        )
    add_custom_command(
        OUTPUT openvpn-examples.5.html
        COMMAND ${_MAYBE_PYTHON} ${RST2HTML} ${RST_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/openvpn-examples.5.rst ${CMAKE_CURRENT_BINARY_DIR}/openvpn-examples.5.html
        MAIN_DEPENDENCY openvpn-examples.5.rst
        DEPENDS ${OPENVPN_EXAMPLES_SECTIONS}
        )
endif ()
if (_GENERATE_MAN_DOC)
    list(APPEND ALL_DOCS openvpn.8 openvpn-examples.5)
    add_custom_command(
        OUTPUT openvpn.8
        COMMAND ${_MAYBE_PYTHON} ${RST2MAN} ${RST_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/openvpn.8.rst ${CMAKE_CURRENT_BINARY_DIR}/openvpn.8
        MAIN_DEPENDENCY openvpn.8.rst
        DEPENDS ${OPENVPN_SECTIONS}
        )
    add_custom_command(
        OUTPUT openvpn-examples.5
        COMMAND ${_MAYBE_PYTHON} ${RST2MAN} ${RST_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/openvpn-examples.5.rst ${CMAKE_CURRENT_BINARY_DIR}/openvpn-examples.5
        MAIN_DEPENDENCY openvpn-examples.5.rst
        DEPENDS ${OPENVPN_EXAMPLES_SECTIONS}
        )
endif ()

add_custom_target(documentation ALL DEPENDS ${ALL_DOCS})

