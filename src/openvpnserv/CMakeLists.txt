if (NOT WIN32)
    return ()
endif ()

project(openvpnserv)

add_executable(openvpnserv)

include(CheckSymbolExists)

set(MC_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/mc)

function(add_common_options target)
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}/../../
        ../../include/
        ../openvpn/
        ../compat/
        ${MC_GEN_DIR}
    )
    target_compile_options(${target} PRIVATE
        -D_UNICODE
        -UNTDDI_VERSION
        -D_WIN32_WINNT=_WIN32_WINNT_VISTA
    )
    target_link_libraries(${target} PRIVATE
        advapi32.lib userenv.lib iphlpapi.lib fwpuclnt.lib rpcrt4.lib
        shlwapi.lib netapi32.lib ws2_32.lib ntdll.lib ole32.lib pathcch.lib)
    if (MINGW)
        target_compile_options(${target} PRIVATE -municode)
        target_link_options(${target} PRIVATE -municode)
    endif ()
endfunction()

add_common_options(openvpnserv)
target_sources(openvpnserv PRIVATE
    common.c
    interactive.c
    service.c service.h
    validate.c validate.h
    ../tapctl/basic.h
    ../openvpn/wfp_block.c ../openvpn/wfp_block.h
    openvpnserv_resources.rc
    )

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

if (BUILD_TESTING)
    set(unit_tests
        "test_openvpnserv"
    )

    foreach (test_name ${unit_tests})
        add_test(${test_name} ${test_name})
        add_executable(${test_name}
            ../../tests/unit_tests/openvpnserv/${test_name}.c
            ${MC_GEN_DIR}/eventmsg.h
        )

        add_common_options(${test_name})
        target_link_libraries(${test_name} PUBLIC ${CMOCKA_LIBRARIES})
        target_include_directories(${test_name} PRIVATE
            .
            ../../tests/unit_tests/openvpn
        )
    endforeach()

    target_sources(test_openvpnserv PRIVATE
        common.c
        validate.c
        ../openvpn/wfp_block.c ../openvpn/wfp_block.h
    )
endif ()
