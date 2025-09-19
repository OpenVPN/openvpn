if (NOT WIN32)
    return ()
endif ()

project(openvpnserv)

add_executable(openvpnserv)

set(MC_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/mc)

target_include_directories(openvpnserv PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../
    ../../include/
    ../openvpn/
    ../compat/
    ${MC_GEN_DIR}
    )
target_sources(openvpnserv PRIVATE
    common.c
    interactive.c
    service.c service.h
    validate.c validate.h
    ../openvpn/block_dns.c ../openvpn/block_dns.h
    openvpnserv_resources.rc
    ../openvpn/ring_buffer.h
    )
target_compile_options(openvpnserv PRIVATE
    -D_UNICODE
    -UNTDDI_VERSION
    -D_WIN32_WINNT=_WIN32_WINNT_VISTA
    )
target_link_libraries(openvpnserv
    advapi32.lib userenv.lib iphlpapi.lib fwpuclnt.lib rpcrt4.lib shlwapi.lib netapi32.lib ws2_32.lib ntdll.lib)
if (MINGW)
    target_compile_options(openvpnserv PRIVATE -municode)
    target_link_options(openvpnserv PRIVATE -municode)
endif ()

# below we generate a DLL which contains an event source for event log messages from eventmsg.mc template
file(MAKE_DIRECTORY ${MC_GEN_DIR})
set(MC_FILE ${CMAKE_CURRENT_SOURCE_DIR}/eventmsg.mc)

find_program(MC_COMPILER NAMES mc.exe x86_64-w64-mingw32-windmc i686-w64-mingw32-windmc windmc)

if (NOT MC_COMPILER)
    message(FATAL_ERROR "No message compiler found.")
endif()

add_custom_command(
    OUTPUT ${MC_GEN_DIR}/eventmsg.rc ${MC_GEN_DIR}/eventmsg.h
    COMMAND ${MC_COMPILER} -U -h ${MC_GEN_DIR} -r ${MC_GEN_DIR} ${MC_FILE}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/eventmsg.mc
    VERBATIM
    )

# generate rc file for DLL and header for the service binary
add_custom_target(msg_mc_gen ALL DEPENDS ${MC_GEN_DIR}/eventmsg.rc ${MC_GEN_DIR}/eventmsg.h)

add_library(openvpnservmsg SHARED ${MC_GEN_DIR}/eventmsg.rc)
add_dependencies(openvpnservmsg msg_mc_gen)

if (MSVC)
    set_target_properties(openvpnservmsg PROPERTIES LINK_FLAGS "/NOENTRY")
else()
    set_target_properties(openvpnservmsg PROPERTIES LINKER_LANGUAGE C OUTPUT_NAME "openvpnservmsg")
    target_link_options(openvpnservmsg PRIVATE
        -Wl,--entry=0
        -nostdlib
        -nostartfiles
    )
endif()

add_dependencies(openvpnserv msg_mc_gen)
