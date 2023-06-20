if (NOT WIN32)
    return ()
endif ()

project(openvpnserv)

add_executable(openvpnserv)

target_include_directories(openvpnserv PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../
    ../../include/
    ../openvpn/
    ../compat/
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
