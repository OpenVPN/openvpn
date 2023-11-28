cmake_minimum_required(VERSION 3.12)
set(CMAKE_CONFIGURATION_TYPES "Release;Debug;ASAN")
project(openvpn)

# This CMake file implements building OpenVPN with CMAKE
#
# Note that this is *NOT* the official way to build openvpn on anything
# other than Windows/mingw despite working on other platforms too. You will need
# to add -DUNSUPPORTED_BUILDS=true to build on non Windows platforms.
#
# This cmake also makes a few assertions like lzo, lz4 being used
# and OpenSSL having version 1.1.1+ and generally does not offer the same
# configurability like autoconf

find_package(PkgConfig REQUIRED)
include(CheckSymbolExists)
include(CheckIncludeFiles)
include(CheckCCompilerFlag)
include(CheckLinkerFlag OPTIONAL)
include(CheckTypeSize)
include(CheckStructHasMember)
include(CTest)

option(UNSUPPORTED_BUILDS "Allow unsupported builds" OFF)

if (NOT WIN32 AND NOT ${UNSUPPORTED_BUILDS})
    message(FATAL_ERROR "Note: on Unix platform the official and supported build method is using autoconfig. CMake based build should be only used for Windows and internal testing/development.")
endif()

if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config.h")
    message(FATAL_ERROR "The top level source directory has a config.h file. Note that you can't mix in-tree autoconfig builds with out-of-tree cmake builds.")
endif ()

option(MBED "BUILD with mbed" OFF)
option(WOLFSSL "BUILD with wolfSSL" OFF)
option(ENABLE_LZ4 "BUILD with lz4" ON)
option(ENABLE_LZO "BUILD with lzo" ON)
option(ENABLE_PKCS11 "BUILD with pkcs11-helper" ON)
option(USE_WERROR "Treat compiler warnings as errors (-Werror)" ON)

set(PLUGIN_DIR /usr/local/lib/openvpn/plugins CACHE FILEPATH "Location of the plugin directory")

# AddressSanitize - use CXX=clang++ CC=clang cmake -DCMAKE_BUILD_TYPE=asan to build with ASAN
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_ASAN
    "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
    FORCE)

if (MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D_WINSOCK_DEPRECATED_NO_WARNINGS)
    if (USE_WERROR)
        add_compile_options(/WX)
    endif ()
    add_compile_options(
        /MP
        /W2
        /sdl
        /Qspectre
        /guard:cf
        /FC
        /ZH:SHA_256
        "$<$<CONFIG:Release>:/GL>"
        "$<$<CONFIG:Release>:/Oi>"
        "$<$<CONFIG:Release>:/Gy>"
        "$<$<CONFIG:Release>:/Zi>"
        )
    add_link_options(
        /Brepro
        "$<$<CONFIG:Release>:/LTCG:incremental>"
        "$<$<CONFIG:Release>:/DEBUG:FULL>"
        "$<$<CONFIG:Release>:/OPT:REF>"
        "$<$<CONFIG:Release>:/OPT:ICF>"
        )
    if (${CMAKE_GENERATOR_PLATFORM} STREQUAL "x64" OR ${CMAKE_GENERATOR_PLATFORM} STREQUAL "x86")
        add_link_options("$<$<CONFIG:Release>:/CETCOMPAT>")
    endif()
else ()
    set(CMAKE_C_FLAGS_RELEASE "-O2")
    set(CMAKE_CXX_FLAGS_RELEASE "-O2")
    set(CMAKE_C_FLAGS_DEBUG "-g -O1")
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O1")
    add_compile_options(-Wall -Wuninitialized)
    check_c_compiler_flag(-Wno-stringop-truncation NoStringOpTruncation)

    if (${NoStringOpTruncation})
        add_compile_options(-Wno-stringop-truncation)
    endif()
    # We are not ready for this
    #add_compile_options(-Wconversion -Wno-sign-conversion -Wsign-compare)
    if (USE_WERROR)
        add_compile_options(-Werror)
    endif ()
endif ()

find_program(PYTHON NAMES python3 python)
execute_process(
    COMMAND ${PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/contrib/cmake/parse-version.m4.py ${CMAKE_CURRENT_SOURCE_DIR}/version.m4
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
include(${CMAKE_CURRENT_BINARY_DIR}/version.cmake)

set(OPENVPN_VERSION_MAJOR ${PRODUCT_VERSION_MAJOR})
set(OPENVPN_VERSION_MINOR ${PRODUCT_VERSION_MINOR})
set(OPENVPN_VERSION_PATCH ${PRODUCT_VERSION_PATCH})
set(OPENVPN_VERSION_RESOURCE ${PRODUCT_VERSION_RESOURCE})

set(CMAKE_C_STANDARD 99)

# Set the various defines for config.h.cmake.in
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set(TARGET_LINUX YES)
    set(ENABLE_ASYNC_PUSH YES)
    set(ENABLE_LINUXDCO YES)
    set(ENABLE_SITNL YES)
    set(HAVE_DECL_SO_MARK YES)
    set(ENABLE_FEATURE_TUN_PERSIST 1)
    set(HAVE_LINUX_TYPES_H 1)
    set(ENABLE_DCO YES)
    set(HAVE_CMSGHDR YES)
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    set(TARGET_FREEBSD YES)
    set(ENABLE_DCO YES)
    link_libraries(-lnv)
elseif (WIN32)
    set(ENABLE_DCO YES)
elseif (APPLE)
    set(TARGET_DARWIN YES)
    set(HAVE_NET_IF_UTUN_H YES)
endif ()

if (UNIX)
    set(PATH_SEPARATOR /)
    set(ENABLE_PORT_SHARE YES)
    set(HAVE_SA_FAMILY_T YES)
elseif (WIN32)
    set(PATH_SEPARATOR \\\\)
    set(TARGET_WIN32 YES)
endif ()

check_symbol_exists(chroot unistd.h HAVE_CHROOT)
check_symbol_exists(chdir unistd.h HAVE_CHDIR)
check_symbol_exists(dup unistd.h HAVE_DUP)
check_symbol_exists(dup2 unistd.h HAVE_DUP2)
check_symbol_exists(fork unistd.h HAVE_FORK)
check_symbol_exists(execve unistd.h HAVE_EXECVE)
check_symbol_exists(ftruncate unistd.h HAVE_FTRUNCATE)
check_symbol_exists(nice unistd.h HAVE_NICE)
check_symbol_exists(setgid unistd.h HAVE_SETGID)
check_symbol_exists(setuid unistd.h HAVE_SETUID)
check_symbol_exists(setsid unistd.h HAVE_SETSID)
check_symbol_exists(getpeereid unistd.h HAVE_GETPEEREID)

check_symbol_exists(epoll_create sys/epoll.h HAVE_EPOLL_CREATE)

check_symbol_exists(gettimeofday sys/time.h HAVE_GETTIMEOFDAY)
check_symbol_exists(basename libgen.h HAVE_BASENAME)
check_symbol_exists(chsize io.h HAVE_CHSIZE)
check_symbol_exists(daemon "unistd.h;stdlib.h" HAVE_DAEMON)
check_symbol_exists(dirname libgen.h HAVE_DIRNAME)
check_symbol_exists(getrlimit sys/resource.h HAVE_GETRLIMIT)
check_symbol_exists(mlockall sys/mman.h HAVE_MLOCKALL)

check_symbol_exists(sendmsg sys/socket.h HAVE_SENDMSG)
check_symbol_exists(recvmsg sys/socket.h HAVE_RECVMSG)
check_symbol_exists(cmsghdr sys/socket.h HAVE_CMSGHDR)
check_symbol_exists(openlog syslog.h HAVE_OPENLOG)
check_symbol_exists(syslog syslog.h HAVE_SYSLOG)
check_symbol_exists(getgrnam grp.h HAVE_GETGRNAM)
check_symbol_exists(getpwnam pwd.h HAVE_GETPWNAM)
check_symbol_exists(getsockname sys/socket.h HAVE_GETSOCKNAME)

# Some OS (e.g. FreeBSD) need some basic headers to allow
# including network headers
set(NETEXTRA sys/types.h)
check_include_files("${NETEXTRA};netinet/in.h" HAVE_NETINET_IN_H)

if (HAVE_NETINET_IN_H)
    list(APPEND NETEXTRA netinet/in.h)
endif ()

check_include_files("${NETEXTRA};netinet/in6.h" HAVE_NETINET_IN_H)
check_include_files(linux/if_tun.h HAVE_LINUX_IF_TUN_H)
check_include_files(linux/sockios.h HAVE_LINUX_SOCKIOS_H)
check_include_files(dlfcn.h HAVE_DLFCN_H)
check_include_files(fcntl.h HAVE_FCNTL_H)
check_include_files(dmalloc.h HAVE_DMALLOC_H)
check_include_files(err.h HAVE_ERR_H)
check_include_files(sys/epoll.h HAVE_SYS_EPOLL_H)
check_include_files(poll.h HAVE_POLL_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(netdb.h HAVE_NETDB_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(sys/un.h HAVE_SYS_UN_H)
check_include_files(libgen.h HAVE_LIBGEN_H)
check_include_files(net/if.h HAVE_NET_IF_H)
check_include_files("${NETEXTRA};netinet/ip.h" HAVE_NETINET_IP_H)
check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(net/if_utun.h HAVE_NET_UTUN_H)
check_include_files(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files(sys/inotify.h HAVE_SYS_INOTIFY_H)
check_include_files("${NETEXTRA};sys/uio.h" HAVE_SYS_UIO_H)
check_include_files(syslog.h HAVE_SYSLOG_H)
check_include_files(sys/wait.h HAVE_SYS_WAIT_H)
check_include_files(grp.h HAVE_GRP_H)
check_include_files(pwd.h HAVE_PWD_H)
check_include_files(sys/mman.h HAVE_SYS_MMAN_H)


check_include_files("${NETEXTRA};resolv.h" HAVE_RESOLV_H)
check_include_files("${NETEXTRA};net/if_tun.h" HAVE_NET_IF_TUN_H)

set(CMAKE_EXTRA_INCLUDE_FILES netinet/ip.h)
check_type_size("struct in_pktinfo" IN_PKTINFO)
check_struct_has_member("struct in_pktinfo" ipi_spec_dst netinet/ip.h HAVE_IPI_SPEC_DST)
check_type_size("struct msghdr" MSGHDR)
set(CMAKE_EXTRA_INCLUDE_FILES)

find_program(IFCONFIG_PATH ifconfig)
find_program(IPROUTE_PATH ip)
find_program(ROUTE_PATH route)

if (${ENABLE_LZ4})
    pkg_search_module(liblz4 liblz4 REQUIRED IMPORTED_TARGET)
endif ()

if (${ENABLE_LZO})
    pkg_search_module(lzo2 lzo2 REQUIRED IMPORTED_TARGET)
endif ()

if (${ENABLE_PKCS11})
    pkg_search_module(pkcs11-helper libpkcs11-helper-1 REQUIRED IMPORTED_TARGET)
endif ()

function(add_library_deps target)
    if (${MBED})
        target_link_libraries(${target} -lmbedtls -lmbedx509 -lmbedcrypto)
    elseif (${WOLFSSL})
        pkg_search_module(wolfssl wolfssl REQUIRED)
        target_link_libraries(${target} PUBLIC ${wolfssl_LINK_LIBRARIES})
        target_include_directories(${target} PRIVATE ${wolfssl_INCLUDE_DIRS}/wolfssl)
    else ()
        set(ENABLE_X509ALTUSERNAME YES)

        find_package(OpenSSL REQUIRED)
        target_link_libraries(${target} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        if (WIN32)
            target_link_libraries(${target} PUBLIC
                ws2_32.lib crypt32.lib fwpuclnt.lib iphlpapi.lib
                wininet.lib setupapi.lib rpcrt4.lib wtsapi32.lib ncrypt.lib bcrypt.lib)
        endif ()

    endif ()

    # optional dependencies
    target_link_libraries(${target} PUBLIC
        $<TARGET_NAME_IF_EXISTS:PkgConfig::liblz4>
        $<TARGET_NAME_IF_EXISTS:PkgConfig::lzo2>
        $<TARGET_NAME_IF_EXISTS:PkgConfig::pkcs11-helper>
        )

    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        pkg_search_module(libcapng REQUIRED libcap-ng IMPORTED_TARGET)
        pkg_search_module(libnl REQUIRED libnl-genl-3.0 IMPORTED_TARGET)

        target_link_libraries(${target} PUBLIC PkgConfig::libcapng PkgConfig::libnl)
    endif ()

endfunction()

if (${MBED})
    set(ENABLE_CRYPTO_MBEDTLS YES)
elseif (${WOLFSSL})
    set(ENABLE_CRYPTO_OPENSSL YES)
    set(ENABLE_CRYPTO_WOLFSSL YES)
    set(ENABLE_X509ALTUSERNAME YES)
else ()
    set(ENABLE_CRYPTO_OPENSSL YES)
    set(ENABLE_X509ALTUSERNAME YES)
endif ()

include_directories(${CMAKE_CURRENT_SOURCE_DIR} src/compat include)

add_custom_command(
    OUTPUT always_rebuild config-version.h
    COMMAND ${PYTHON} ${CMAKE_CURRENT_SOURCE_DIR}/contrib/cmake/git-version.py
    )
set(HAVE_CONFIG_VERSION_H YES)

configure_file(config.h.cmake.in config.h)
configure_file(include/openvpn-plugin.h.in openvpn-plugin.h)
# TODO we should remove the need for this, and always include config.h
add_definitions(-DHAVE_CONFIG_H)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(doc)
add_subdirectory(src/openvpnmsica)
add_subdirectory(src/openvpnserv)
add_subdirectory(src/tapctl)

set(SOURCE_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
    ${CMAKE_CURRENT_BINARY_DIR}/config-version.h
    ${CMAKE_CURRENT_BINARY_DIR}/openvpn-plugin.h

    src/compat/compat-basename.c
    src/compat/compat-daemon.c
    src/compat/compat-dirname.c
    src/compat/compat-gettimeofday.c
    src/compat/compat-strsep.c
    src/openvpn/argv.c
    src/openvpn/argv.h
    src/openvpn/base64.c
    src/openvpn/base64.h
    src/openvpn/basic.h
    src/openvpn/block_dns.h
    src/openvpn/block_dns.c
    src/openvpn/buffer.c
    src/openvpn/buffer.h
    src/openvpn/circ_list.h
    src/openvpn/clinat.c
    src/openvpn/clinat.h
    src/openvpn/common.h
    src/openvpn/comp-lz4.c
    src/openvpn/comp-lz4.h
    src/openvpn/comp.c
    src/openvpn/comp.h
    src/openvpn/compstub.c
    src/openvpn/console.c
    src/openvpn/console_builtin.c
    src/openvpn/console.h
    src/openvpn/crypto.c
    src/openvpn/crypto.h
    src/openvpn/crypto_backend.h
    src/openvpn/crypto_openssl.c
    src/openvpn/crypto_openssl.h
    src/openvpn/crypto_mbedtls.c
    src/openvpn/crypto_mbedtls.h
    src/openvpn/cryptoapi.c
    src/openvpn/cryptoapi.h
    src/openvpn/dco.c
    src/openvpn/dco.h
    src/openvpn/dco_win.c
    src/openvpn/dco_win.h
    src/openvpn/dco_linux.c
    src/openvpn/dco_linux.h
    src/openvpn/dco_freebsd.c
    src/openvpn/dco_freebsd.h
    src/openvpn/dhcp.c
    src/openvpn/dhcp.h
    src/openvpn/dns.c
    src/openvpn/dns.h
    src/openvpn/errlevel.h
    src/openvpn/env_set.c
    src/openvpn/env_set.h
    src/openvpn/error.c
    src/openvpn/error.h
    src/openvpn/event.c
    src/openvpn/event.h
    src/openvpn/fdmisc.c
    src/openvpn/fdmisc.h
    src/openvpn/forward.c
    src/openvpn/forward.h
    src/openvpn/fragment.c
    src/openvpn/fragment.h
    src/openvpn/gremlin.c
    src/openvpn/gremlin.h
    src/openvpn/helper.c
    src/openvpn/helper.h
    src/openvpn/httpdigest.c
    src/openvpn/httpdigest.h
    src/openvpn/init.c
    src/openvpn/init.h
    src/openvpn/integer.h
    src/openvpn/interval.c
    src/openvpn/interval.h
    src/openvpn/list.c
    src/openvpn/list.h
    src/openvpn/lladdr.c
    src/openvpn/lladdr.h
    src/openvpn/lzo.c
    src/openvpn/lzo.h
    src/openvpn/manage.c
    src/openvpn/manage.h
    src/openvpn/mbuf.c
    src/openvpn/mbuf.h
    src/openvpn/memdbg.h
    src/openvpn/misc.c
    src/openvpn/misc.h
    src/openvpn/mroute.c
    src/openvpn/mroute.h
    src/openvpn/mss.c
    src/openvpn/mss.h
    src/openvpn/mstats.c
    src/openvpn/mstats.h
    src/openvpn/mtcp.c
    src/openvpn/mtcp.h
    src/openvpn/mtu.c
    src/openvpn/mtu.h
    src/openvpn/mudp.c
    src/openvpn/mudp.h
    src/openvpn/multi.c
    src/openvpn/multi.h
    src/openvpn/ntlm.c
    src/openvpn/ntlm.h
    src/openvpn/occ.c
    src/openvpn/occ.h
    src/openvpn/openvpn.c
    src/openvpn/openvpn.h
    src/openvpn/openvpn_win32_resources.rc
    src/openvpn/options.c
    src/openvpn/options.h
    src/openvpn/options_util.c
    src/openvpn/options_util.h
    src/openvpn/otime.c
    src/openvpn/otime.h
    src/openvpn/ovpn_dco_win.h
    src/openvpn/packet_id.c
    src/openvpn/packet_id.h
    src/openvpn/perf.c
    src/openvpn/perf.h
    src/openvpn/ping.c
    src/openvpn/ping.h
    src/openvpn/pkcs11.c
    src/openvpn/pkcs11.h
    src/openvpn/pkcs11_backend.h
    src/openvpn/pkcs11_openssl.c
    src/openvpn/pkcs11_mbedtls.c
    src/openvpn/platform.c
    src/openvpn/platform.h
    src/openvpn/plugin.c
    src/openvpn/plugin.h
    src/openvpn/pool.c
    src/openvpn/pool.h
    src/openvpn/proto.c
    src/openvpn/proto.h
    src/openvpn/proxy.c
    src/openvpn/proxy.h
    src/openvpn/ps.c
    src/openvpn/ps.h
    src/openvpn/push.c
    src/openvpn/push.h
    src/openvpn/pushlist.h
    src/openvpn/reflect_filter.c
    src/openvpn/reflect_filter.h
    src/openvpn/reliable.c
    src/openvpn/reliable.h
    src/openvpn/route.c
    src/openvpn/route.h
    src/openvpn/run_command.c
    src/openvpn/run_command.h
    src/openvpn/schedule.c
    src/openvpn/schedule.h
    src/openvpn/session_id.c
    src/openvpn/session_id.h
    src/openvpn/shaper.c
    src/openvpn/shaper.h
    src/openvpn/sig.c
    src/openvpn/sig.h
    src/openvpn/socket.c
    src/openvpn/socket.h
    src/openvpn/socks.c
    src/openvpn/socks.h
    src/openvpn/ssl.c
    src/openvpn/ssl.h
    src/openvpn/ssl_backend.h
    src/openvpn/ssl_common.h
    src/openvpn/ssl_openssl.c
    src/openvpn/ssl_openssl.h
    src/openvpn/ssl_mbedtls.c
    src/openvpn/ssl_mbedtls.h
    src/openvpn/ssl_verify.c
    src/openvpn/ssl_verify.h
    src/openvpn/ssl_verify_backend.h
    src/openvpn/ssl_verify_openssl.c
    src/openvpn/ssl_verify_openssl.h
    src/openvpn/ssl_verify_mbedtls.c
    src/openvpn/ssl_verify_mbedtls.h
    src/openvpn/status.c
    src/openvpn/status.h
    src/openvpn/syshead.h
    src/openvpn/tls_crypt.c
    src/openvpn/tun.c
    src/openvpn/tun.h
    src/openvpn/networking_sitnl.c
    src/openvpn/networking_freebsd.c
    src/openvpn/auth_token.c
    src/openvpn/auth_token.h
    src/openvpn/ssl_ncp.c
    src/openvpn/ssl_ncp.h
    src/openvpn/ssl_pkt.c
    src/openvpn/ssl_pkt.h
    src/openvpn/ssl_util.c
    src/openvpn/ssl_util.h
    src/openvpn/vlan.c
    src/openvpn/vlan.h
    src/openvpn/win32.c
    src/openvpn/win32-util.c
    src/openvpn/win32.h
    src/openvpn/win32-util.h
    src/openvpn/xkey_helper.c
    src/openvpn/xkey_provider.c
    )

add_executable(openvpn ${SOURCE_FILES})

add_library_deps(openvpn)

if (MINGW)
    target_compile_options(openvpn PRIVATE
        -DWIN32_LEAN_AND_MEAN
        -DNTDDI_VERSION=NTDDI_VISTA -D_WIN32_WINNT=_WIN32_WINNT_VISTA
        )
    target_compile_options(openvpn PRIVATE -municode -UUNICODE)
    target_link_options(openvpn PRIVATE -municode)
endif()

if (MSVC)
    # we have our own manifest
    target_link_options(openvpn PRIVATE /MANIFEST:NO)
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    target_link_libraries(openvpn PUBLIC -ldl)
endif ()

if (NOT WIN32)
    target_compile_options(openvpn PRIVATE -DPLUGIN_LIBDIR=\"${PLUGIN_DIR}\")

    find_library(resolv resolv)
    # some platform like BSDs already include resolver functionality in the libc and not have an extra resolv library
    if (${resolv} OR APPLE)
        target_link_libraries(openvpn PUBLIC -lresolv)
    endif ()
endif ()


if (BUILD_TESTING)
    find_package(cmocka CONFIG)
    if (TARGET cmocka::cmocka)
        set(CMOCKA_LIBRARIES cmocka::cmocka)
    else ()
        pkg_search_module(cmocka cmocka REQUIRED IMPORTED_TARGET)
        set(CMOCKA_LIBRARIES PkgConfig::cmocka)
    endif ()

    set(unit_tests
        "test_auth_token"
        "test_buffer"
        "test_crypto"
        "test_misc"
        "test_ncp"
        "test_packet_id"
        "test_pkt"
        "test_provider"
        )

    if (WIN32)
        list(APPEND unit_tests
            "test_cryptoapi"
            )
    endif ()

    # MSVC and Apple's LLVM ld do not support --wrap
    # This test requires cmake >= 3.18, so check if check_linker_flag is
    # available
    if (COMMAND check_linker_flag)
        check_linker_flag(C -Wl,--wrap=parse_line LD_SUPPORTS_WRAP)
    endif()

    if (${LD_SUPPORTS_WRAP})
        list(APPEND unit_tests
            "test_argv"
            "test_tls_crypt"
            )
    endif ()

    # These tests work on only on Linux since they depend on special Linux features
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        list(APPEND unit_tests
            "test_networking"
            )
    endif ()

    foreach (test_name ${unit_tests})
        # test_networking needs special environment
        if (NOT ${test_name} STREQUAL "test_networking")
            add_test(${test_name} ${test_name})
        endif ()
        add_executable(${test_name}
            tests/unit_tests/openvpn/${test_name}.c
            tests/unit_tests/openvpn/mock_msg.c
            tests/unit_tests/openvpn/mock_msg.h
            src/openvpn/platform.c
            src/openvpn/win32-util.c
            src/compat/compat-gettimeofday.c
            )

        add_library_deps(${test_name})
        target_link_libraries(${test_name} PUBLIC ${CMOCKA_LIBRARIES})

        target_include_directories(${test_name} PRIVATE src/openvpn)

        if (NOT ${test_name} STREQUAL "test_buffer")
            target_sources(${test_name} PRIVATE
                src/openvpn/buffer.c
                )
        endif ()

    endforeach()

    target_sources(test_auth_token PRIVATE
        src/openvpn/base64.c
        src/openvpn/crypto_mbedtls.c
        src/openvpn/crypto_openssl.c
        src/openvpn/crypto.c
        src/openvpn/otime.c
        src/openvpn/packet_id.c
        )

    target_sources(test_buffer PRIVATE
        tests/unit_tests/openvpn/mock_get_random.c
        )

    target_sources(test_crypto PRIVATE
        src/openvpn/crypto_mbedtls.c
        src/openvpn/crypto_openssl.c
        src/openvpn/crypto.c
        src/openvpn/otime.c
        src/openvpn/packet_id.c
        src/openvpn/mtu.c
        src/openvpn/mss.c
        )

    target_sources(test_misc PRIVATE
        tests/unit_tests/openvpn/mock_get_random.c
        src/openvpn/options_util.c
        src/openvpn/ssl_util.c
        )

    target_sources(test_ncp PRIVATE
        src/openvpn/crypto_mbedtls.c
        src/openvpn/crypto_openssl.c
        src/openvpn/crypto.c
        src/openvpn/otime.c
        src/openvpn/packet_id.c
        src/openvpn/ssl_util.c
        src/compat/compat-strsep.c
        )

    target_sources(test_packet_id PRIVATE
        tests/unit_tests/openvpn/mock_get_random.c
        src/openvpn/otime.c
        src/openvpn/packet_id.c
        src/openvpn/reliable.c
        src/openvpn/session_id.c
        )

    target_sources(test_pkt PRIVATE
        tests/unit_tests/openvpn/mock_win32_execve.c
        src/openvpn/argv.c
        src/openvpn/base64.c
        src/openvpn/crypto_mbedtls.c
        src/openvpn/crypto_openssl.c
        src/openvpn/crypto.c
        src/openvpn/env_set.c
        src/openvpn/otime.c
        src/openvpn/packet_id.c
        src/openvpn/reliable.c
        src/openvpn/run_command.c
        src/openvpn/session_id.c
        src/openvpn/ssl_pkt.c
        src/openvpn/tls_crypt.c
        )

    target_sources(test_provider PRIVATE
        tests/unit_tests/openvpn/mock_get_random.c
        src/openvpn/xkey_provider.c
        src/openvpn/xkey_helper.c
        src/openvpn/base64.c
        )

    if (TARGET test_argv)
        target_link_options(test_argv PRIVATE -Wl,--wrap=parse_line)
        target_sources(test_argv PRIVATE
            tests/unit_tests/openvpn/mock_get_random.c
            src/openvpn/argv.c
            )
    endif ()

    if (TARGET test_cryptoapi)
        target_sources(test_cryptoapi PRIVATE
            tests/unit_tests/openvpn/mock_get_random.c
            tests/unit_tests/openvpn/cert_data.h
            src/openvpn/xkey_provider.c
            src/openvpn/xkey_helper.c
            src/openvpn/base64.c
            )
    endif ()

    if (TARGET test_networking)
        target_link_options(test_networking PRIVATE -Wl,--wrap=parse_line)
        target_compile_options(test_networking PRIVATE -UNDEBUG)
        target_sources(test_networking PRIVATE
            src/openvpn/networking_sitnl.c
            src/openvpn/crypto_mbedtls.c
            src/openvpn/crypto_openssl.c
            src/openvpn/crypto.c
            src/openvpn/otime.c
            src/openvpn/packet_id.c
            )
    endif ()

    if (TARGET test_tls_crypt)
        target_link_options(test_tls_crypt PRIVATE -Wl,--wrap=parse_line)
        target_link_options(test_tls_crypt PRIVATE
            -Wl,--wrap=buffer_read_from_file
            -Wl,--wrap=buffer_write_file
            -Wl,--wrap=rand_bytes)
        target_sources(test_tls_crypt PRIVATE
            tests/unit_tests/openvpn/mock_win32_execve.c
            src/openvpn/argv.c
            src/openvpn/base64.c
            src/openvpn/crypto_mbedtls.c
            src/openvpn/crypto_openssl.c
            src/openvpn/crypto.c
            src/openvpn/env_set.c
            src/openvpn/otime.c
            src/openvpn/packet_id.c
            src/openvpn/run_command.c
            )
    endif ()

endif (BUILD_TESTING)
