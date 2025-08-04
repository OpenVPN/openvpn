if (NOT WIN32)
    return ()
endif ()

project(openvpnmsica)

add_library(openvpnmsica SHARED)

target_include_directories(openvpnmsica PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../
    ../../include/
    ../compat/
    )
target_sources(openvpnmsica PRIVATE
    dllmain.c
    msiex.c msiex.h
    msica_arg.c msica_arg.h
    openvpnmsica.c openvpnmsica.h
    ../tapctl/basic.h
    ../tapctl/error.c ../tapctl/error.h
    ../tapctl/tap.c ../tapctl/tap.h
    openvpnmsica_resources.rc
    )
target_compile_options(openvpnmsica PRIVATE
    -D_UNICODE
    -UNTDDI_VERSION
    -D_WIN32_WINNT=_WIN32_WINNT_VISTA
    )

if (MSVC)
    target_compile_options(openvpnmsica PRIVATE
        "$<$<CONFIG:Release>:/MT>"
        "$<$<CONFIG:Debug>:/MTd>"
        )
endif ()

target_link_libraries(openvpnmsica
    advapi32.lib ole32.lib msi.lib setupapi.lib iphlpapi.lib shell32.lib shlwapi.lib version.lib newdev.lib)
if (MINGW)
    target_compile_options(openvpnmsica PRIVATE -municode)
    target_link_options(openvpnmsica PRIVATE -municode)
    target_link_options(openvpnmsica PRIVATE
        -Wl,--kill-at)
endif ()
