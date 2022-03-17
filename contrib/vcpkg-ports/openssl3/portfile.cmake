# based on openssl port from vcpkg official repo

if(EXISTS ${CURRENT_INSTALLED_DIR}/include/openssl/ssl.h)
    message(FATAL_ERROR "Can't build '${PORT}' if another SSL library is installed. Please remove existing one and try install '${PORT}' again if you need it.")
endif()

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO openssl/openssl
    REF openssl-3.0.2
    SHA512 d69c87b8250da813f282ead0bd005ebde663e77595ee8d99560d25f345570da2fa552b57c372956d461e3b631a19d6d60bebafe6ff89aeebbb5d34ad516b62ac
)

vcpkg_find_acquire_program(PERL)
get_filename_component(PERL_EXE_PATH ${PERL} DIRECTORY)
vcpkg_add_to_path("${PERL_EXE_PATH}")

vcpkg_find_acquire_program(NASM)
get_filename_component(NASM_EXE_PATH "${NASM}" DIRECTORY)
vcpkg_add_to_path(PREPEND "${NASM_EXE_PATH}")

vcpkg_find_acquire_program(JOM)

set(OPENSSL_SHARED no-shared)
if(VCPKG_LIBRARY_LINKAGE STREQUAL dynamic)
    set(OPENSSL_SHARED shared)
endif()

# see ${SOURCE_PATH}/INSTALL.md
list(APPEND CONFIGURE_OPTIONS
    no-zlib
    no-ui-console   # Don't build with the User Interface (UI) console method
    no-makedepend   # Don't generate dependencies
    no-module       # Don't build any dynamically loadable engines
    no-tests        # Don't build test programs or run any tests
    enable-legacy   # link statically legacy provider instead of generating legacy.dll
    -utf-8
    -FS
    ${OPENSSL_SHARED}
)

set(CONFIGURE_COMMAND "${PERL}" Configure ${CONFIGURE_OPTIONS})

if(VCPKG_TARGET_ARCHITECTURE STREQUAL "x86")
    set(OPENSSL_ARCH VC-WIN32)
elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "x64")
    set(OPENSSL_ARCH VC-WIN64A)
elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm")
    set(OPENSSL_ARCH VC-WIN32-ARM)
elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm64")
    set(OPENSSL_ARCH VC-WIN64-ARM)
else()
    message(FATAL_ERROR "Unsupported target architecture: ${VCPKG_TARGET_ARCHITECTURE}")
endif()

set(OPENSSL_MAKEFILE "makefile")

file(REMOVE_RECURSE "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel"
                    "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg")

if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "release")

    # Copy openssl sources.
    message(STATUS "Copying openssl release source files...")
    file(GLOB OPENSSL_SOURCE_FILES ${SOURCE_PATH}/*)
    foreach(SOURCE_FILE ${OPENSSL_SOURCE_FILES})
        file(COPY ${SOURCE_FILE} DESTINATION "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel")
    endforeach()
    message(STATUS "Copying openssl release source files... done")
    set(SOURCE_PATH_RELEASE "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-rel")

    set(OPENSSLDIR_RELEASE ${CURRENT_PACKAGES_DIR})

    message(STATUS "Configure ${TARGET_TRIPLET}-rel")
    vcpkg_execute_required_process(
        COMMAND ${CONFIGURE_COMMAND} ${OPENSSL_ARCH} "--prefix=${OPENSSLDIR_RELEASE}" "--openssldir=${OPENSSLDIR_RELEASE}"
        WORKING_DIRECTORY ${SOURCE_PATH_RELEASE}
        LOGNAME configure-perl-${TARGET_TRIPLET}-rel
    )
    message(STATUS "Configure ${TARGET_TRIPLET}-rel done")

    message(STATUS "Build ${TARGET_TRIPLET}-rel")
    # Openssl's buildsystem has a race condition which will cause JOM to fail at some point.
    # This is ok; we just do as much work as we can in parallel first, then follow up with a single-threaded build.
    execute_process(
        COMMAND ${JOM} -k -j ${VCPKG_CONCURRENCY} -f ${OPENSSL_MAKEFILE}
        WORKING_DIRECTORY ${SOURCE_PATH_RELEASE}
        OUTPUT_FILE ${CURRENT_BUILDTREES_DIR}/build-${TARGET_TRIPLET}-rel-0-out.log
        ERROR_FILE ${CURRENT_BUILDTREES_DIR}/build-${TARGET_TRIPLET}-rel-0-err.log
    )
    vcpkg_execute_required_process(
        COMMAND nmake -f ${OPENSSL_MAKEFILE} install_dev install_runtime install_ssldirs
        WORKING_DIRECTORY ${SOURCE_PATH_RELEASE}
        LOGNAME build-${TARGET_TRIPLET}-rel-1)

    message(STATUS "Build ${TARGET_TRIPLET}-rel done")
endif()

if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "debug")
    # Copy openssl sources.
    message(STATUS "Copying openssl debug source files...")
    file(GLOB OPENSSL_SOURCE_FILES ${SOURCE_PATH}/*)
    foreach(SOURCE_FILE ${OPENSSL_SOURCE_FILES})
        file(COPY ${SOURCE_FILE} DESTINATION "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg")
    endforeach()
    message(STATUS "Copying openssl debug source files... done")
    set(SOURCE_PATH_DEBUG "${CURRENT_BUILDTREES_DIR}/${TARGET_TRIPLET}-dbg")

    set(OPENSSLDIR_DEBUG ${CURRENT_PACKAGES_DIR}/debug)

    message(STATUS "Configure ${TARGET_TRIPLET}-dbg")
    vcpkg_execute_required_process(
        COMMAND ${CONFIGURE_COMMAND} debug-${OPENSSL_ARCH} "--prefix=${OPENSSLDIR_DEBUG}" "--openssldir=${OPENSSLDIR_DEBUG}"
        WORKING_DIRECTORY ${SOURCE_PATH_DEBUG}
        LOGNAME configure-perl-${TARGET_TRIPLET}-dbg
    )
    message(STATUS "Configure ${TARGET_TRIPLET}-dbg done")

    message(STATUS "Build ${TARGET_TRIPLET}-dbg")
    execute_process(
        COMMAND "${JOM}" -k -j ${VCPKG_CONCURRENCY} -f "${OPENSSL_MAKEFILE}"
        WORKING_DIRECTORY ${SOURCE_PATH_DEBUG}
        OUTPUT_FILE ${CURRENT_BUILDTREES_DIR}/build-${TARGET_TRIPLET}-dbg-0-out.log
        ERROR_FILE ${CURRENT_BUILDTREES_DIR}/build-${TARGET_TRIPLET}-dbg-0-err.log
    )
    vcpkg_execute_required_process(
        COMMAND nmake -f "${OPENSSL_MAKEFILE}" install_dev install_runtime install_ssldirs
        WORKING_DIRECTORY ${SOURCE_PATH_DEBUG}
        LOGNAME build-${TARGET_TRIPLET}-dbg-1)

    message(STATUS "Build ${TARGET_TRIPLET}-dbg done")
endif()

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/certs")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/private")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/certs")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/private")
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

file(REMOVE
    "${CURRENT_PACKAGES_DIR}/ct_log_list.cnf"
    "${CURRENT_PACKAGES_DIR}/ct_log_list.cnf.dist"
    "${CURRENT_PACKAGES_DIR}/openssl.cnf.dist"
    "${CURRENT_PACKAGES_DIR}/debug/bin/openssl.exe"
    "${CURRENT_PACKAGES_DIR}/debug/ct_log_list.cnf"
    "${CURRENT_PACKAGES_DIR}/debug/ct_log_list.cnf.dist"
    "${CURRENT_PACKAGES_DIR}/debug/openssl.cnf"
    "${CURRENT_PACKAGES_DIR}/debug/openssl.cnf.dist"
)

file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/tools/openssl/")
file(RENAME "${CURRENT_PACKAGES_DIR}/bin/openssl.exe" "${CURRENT_PACKAGES_DIR}/tools/openssl/openssl.exe")
file(RENAME "${CURRENT_PACKAGES_DIR}/openssl.cnf" "${CURRENT_PACKAGES_DIR}/tools/openssl/openssl.cnf")

vcpkg_copy_tool_dependencies("${CURRENT_PACKAGES_DIR}/tools/openssl")

if(VCPKG_LIBRARY_LINKAGE STREQUAL static)
    # They should be empty, only the exes deleted above were in these directories
    file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/bin/")
    file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/bin/")
endif()

vcpkg_copy_pdbs()

file(INSTALL "${SOURCE_PATH}/LICENSE.txt" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
