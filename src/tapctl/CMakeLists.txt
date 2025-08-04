if (NOT WIN32)
    return ()
endif ()

project(tapctl)

add_executable(tapctl)

target_include_directories(tapctl PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/../../
    ../../include/
    ../compat/
    )
target_sources(tapctl PRIVATE
    basic.h
    error.c error.h
    main.c
    tap.c tap.h
    tapctl_resources.rc
    )
target_compile_options(tapctl PRIVATE
    -D_UNICODE
    -UNTDDI_VERSION
    -D_WIN32_WINNT=_WIN32_WINNT_VISTA
    )
target_link_libraries(tapctl
    advapi32.lib ole32.lib setupapi.lib)
if (MINGW)
    target_compile_options(tapctl PRIVATE -municode)
    target_link_options(tapctl PRIVATE -municode)
endif ()
