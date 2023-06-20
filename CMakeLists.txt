  cmake_minimum_required(VERSION 3.3)
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

# -DCMAKE_TOOLCHAIN_FILE=C:/Users/User/source/repos/vcpkg/scripts/buildsystems/vcpkg.cmake
#-DVCPKG_OVERLAY_PORTS=C:/Users/User/source/repos/openvpn/contrib/vcpkg-ports
#-GNinja

option(UNSUPPORTED_BUILDS "Allow unsupported builds" OFF)

if (NOT WIN32 AND NOT ${UNSUPPORTED_BUILDS})
    message(FATAL_ERROR "Note: on Unix platform the official and supported build method is using autoconfig. CMake based build should be only used for Windows and internal testing/development.")
endif()

option(MBED "BUILD with mbed" OFF)
option(WOLFSSL "BUILD with wolfSSL" OFF)
if (MSVC)
    option(USE_WERROR "Treat compiler warnings as errors (-Werror)" OFF)
else ()
    option(USE_WERROR "Treat compiler warnings as errors (-Werror)" ON)
endif ()
option(PLUGIN_DIR "Location of the plugin directory" /usr/local/lib/openvpn/plugins)

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
    target_compile_options(${target} PRIVATE /W3)
else ()
    add_compile_options(-Wall -Wuninitialized)
    # We are not ready for this
    #add_compile_options(-Wsign-compare)
endif ()

find_package(PkgConfig)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckIncludeFiles)
INCLUDE(CheckTypeSize)
INCLUDE(CheckStructHasMember)

set(OPENVPN_VERSION_MAJOR 2)
set(OPENVPN_VERSION_MINOR 6)
set(OPENVPN_VERSION_PATCH _git)

if (NOT WIN32)
    add_definitions(-DPLUGIN_LIBDIR=\"${PLUGIN_DIR}\")
endif ()

# TODO remove later when msvc-config.h is removed and we can always include config.h
add_definitions(-DHAVE_CONFIG_H)


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

CHECK_SYMBOL_EXISTS(chroot unistd.h HAVE_CHROOT)
CHECK_SYMBOL_EXISTS(chdir unistd.h HAVE_CHDIR)
CHECK_SYMBOL_EXISTS(dup unistd.h HAVE_DUP)
CHECK_SYMBOL_EXISTS(dup2 unistd.h HAVE_DUP2)
CHECK_SYMBOL_EXISTS(fork unistd.h HAVE_FORK)
CHECK_SYMBOL_EXISTS(execve unistd.h HAVE_EXECVE)
CHECK_SYMBOL_EXISTS(ftruncate unistd.h HAVE_FTRUNCATE)
CHECK_SYMBOL_EXISTS(setgid unistd.h HAVE_SETGID)
CHECK_SYMBOL_EXISTS(setuid unistd.h HAVE_SETUID)
CHECK_SYMBOL_EXISTS(getpeereid unistd.h HAVE_GETPEEREID)

CHECK_SYMBOL_EXISTS(epoll_create sys/epoll.h HAVE_EPOLL_CREATE)

CHECK_SYMBOL_EXISTS(gettimeofday sys/time.h HAVE_GETTIMEOFDAY)
CHECK_SYMBOL_EXISTS(basename libgen.h HAVE_BASENAME)
CHECK_SYMBOL_EXISTS(chsize io.h HAVE_CHSIZE)
CHECK_SYMBOL_EXISTS(daemon stdlib.h HAVE_DAEMON)
CHECK_SYMBOL_EXISTS(dirname libgen.h HAVE_DIRNAME)
CHECK_SYMBOL_EXISTS(getrlimit sys/resource.h HAVE_GETRLIMIT)
CHECK_SYMBOL_EXISTS(mlockall sys/mman.h HAVE_MLOCKALL)

CHECK_SYMBOL_EXISTS(sendmsg sys/socket.h HAVE_SENDMSG)
CHECK_SYMBOL_EXISTS(recvmsg sys/socket.h HAVE_RECVMSG)
CHECK_SYMBOL_EXISTS(cmsghdr sys/socket.h HAVE_CMSGHDR)
CHECK_SYMBOL_EXISTS(openlog syslog.h HAVE_OPENLOG)
CHECK_SYMBOL_EXISTS(syslog syslog.h HAVE_SYSLOG)
CHECK_SYMBOL_EXISTS(getgrnam grp.h HAVE_GETGRNAM)
CHECK_SYMBOL_EXISTS(getpwnam pwd.h HAVE_GETPWNAM)
CHECK_SYMBOL_EXISTS(getsockname sys/socket.h HAVE_GETSOCKNAME)

# Some OS (e.g. FreeBSD) need some basic headers to allow
# including network headers
SET(NETEXTRA sys/types.h)
CHECK_INCLUDE_FILES("${NETEXTRA};netinet/in.h" HAVE_NETINET_IN_H)

if (HAVE_NETINET_IN_H)
    LIST(APPEND NETEXTRA netinet/in.h)
endif ()

CHECK_INCLUDE_FILES("${NETEXTRA};netinet/in6.h" HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(linux/if_tun.h HAVE_LINUX_IF_TUN_H)
CHECK_INCLUDE_FILES(linux/sockios.h HAVE_LINUX_SOCKIOS_H)
CHECK_INCLUDE_FILES(dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILES(fcntl.h HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(dmalloc.h HAVE_DMALLOC_H)
CHECK_INCLUDE_FILES(err.h HAVE_ERR_H)
CHECK_INCLUDE_FILES(sys/epoll.h HAVE_SYS_EPOLL_H)
CHECK_INCLUDE_FILES(poll.h HAVE_POLL_H)
CHECK_INCLUDE_FILES(sys/socket.h HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES(sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(netdb.h HAVE_NETDB_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(sys/un.h HAVE_SYS_UN_H)
CHECK_INCLUDE_FILES(libgen.h HAVE_LIBGEN_H)
CHECK_INCLUDE_FILES(net/if.h HAVE_NET_IF_H)
CHECK_INCLUDE_FILES("${NETEXTRA};netinet/ip.h" HAVE_NETINET_IP_H)
CHECK_INCLUDE_FILES(arpa/inet.h HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(net/if_utun.h HAVE_NET_UTUN_H)
CHECK_INCLUDE_FILES(sys/ioctl.h HAVE_SYS_IOCTL_H)
CHECK_INCLUDE_FILES(sys/inotify.h HAVE_SYS_INOTIFY_H)
CHECK_INCLUDE_FILES("${NETEXTRA};sys/uio.h" HAVE_SYS_UIO_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(sys/wait.h HAVE_SYS_WAIT_H)
CHECK_INCLUDE_FILES(grp.h HAVE_GRP_H)
CHECK_INCLUDE_FILES(pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES(sys/mman.h HAVE_SYS_MMAN_H)


CHECK_INCLUDE_FILES("${NETEXTRA};resolv.h" HAVE_RESOLV_H)
CHECK_INCLUDE_FILES("${NETEXTRA};net/if_tun.h" HAVE_NET_IF_TUN_H)

# Is this obscure header needed anywhere?!
CHECK_INCLUDE_FILES(netinet/in_systm.h HAVE_NETINET_IN_SYSTM_H)


SET(CMAKE_EXTRA_INCLUDE_FILES netinet/ip.h)
CHECK_TYPE_SIZE("struct in_pktinfo" IN_PKTINFO)
CHECK_STRUCT_HAS_MEMBER("struct in_pktinfo" ipi_spec_dst netinet/ip.h HAVE_IPI_SPEC_DST)
CHECK_TYPE_SIZE("struct msghdr" MSGHDR)
SET(CMAKE_EXTRA_INCLUDE_FILES)

find_program(IFCONFIG_PATH ifconfig)
find_program(IPROUTE_PATH ip)
find_program(ROUTE_PATH route)


if (NOT WIN32)
    set(ENABLE_LZ4 YES)
    set(ENABLE_LZO YES)
endif ()

function(add_library_deps target)
    if (${MBED})
        target_include_directories(${target} PRIVATE $ENV{HOME}/oss/mbedtls2/include)
        message("Building ${target} for mbed TLS")
        target_link_libraries(${target} PUBLIC -L$ENV{HOME}/oss/mbedtls2/library -L/usr/local/opt/lzo/lib -lmbedtls -lmbedx509 -lmbedcrypto)
    elseif (${WOLFSSL})
        pkg_search_module(wolfssl wolfssl REQUIRED)
        target_link_libraries(${target} PUBLIC ${wolfssl_LINK_LIBRARIES})
        target_include_directories(${target} PRIVATE ${wolfssl_INCLUDE_DIRS}/wolfssl)
        message("Building ${target} for WolfSSL: ${wolfssl_LINK_LIBRARIES} ${wolfssl_INCLUDE_DIRS}/wolfsll")
    else ()
        set(ENABLE_X509ALTUSERNAME YES)

        find_package(OpenSSL REQUIRED)
        target_link_libraries(${target} PUBLIC OpenSSL::SSL)

        message("Building ${target} for default OpenSSL")
    endif ()


    if (${ENABLE_LZ4})
        pkg_search_module(liblz4 liblz4 REQUIRED IMPORTED_TARGET)
        target_link_libraries(${target} PUBLIC PkgConfig::liblz4)
    endif ()

    if (${ENABLE_LZO})
        pkg_search_module(lzo2 lzo2 REQUIRED IMPORTED_TARGET)
        target_link_libraries(${target} PUBLIC PkgConfig::lzo2)
    endif ()

    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        target_include_directories(${target} PUBLIC ${LIBNL_INCLUDE_DIRS})
        target_link_libraries(${target} PUBLIC ${LIBNL_LIBRARIES})
    endif ()

    if (USE_WERROR)
        if (MSVC)
            target_compile_options(${target} PRIVATE /WX)
        else ()
            target_compile_options(${target} PRIVATE -Werror)
        endif ()
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

if (WIN32)
    find_package(OpenSSL REQUIRED)

    link_libraries(OpenSSL::SSL OpenSSL::Crypto ws2_32.lib Crypt32.lib fwpuclnt.lib iphlpapi.lib
            wininet.lib setupapi.lib rpcrt4.lib wtsapi32.lib Ncrypt.lib)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D _WINSOCK_DEPRECATED_NO_WARNINGS -D_CONSOLE)
endif ()

configure_file(config.h.cmake.in config.h)
configure_file(include/openvpn-plugin.h.in openvpn-plugin.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SOURCE_FILES
        ${CMAKE_CURRENT_BINARY_DIR}/config.h
        ${CMAKE_CURRENT_BINARY_DIR}/openvpn-plugin.h

        src/compat/compat-basename.c
        src/compat/compat-daemon.c
        src/compat/compat-dirname.c
        src/compat/compat-gettimeofday.c
        src/compat/compat-strsep.c
        src/compat/compat-versionhelpers.h
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

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    target_link_libraries(openvpn PUBLIC -ldl)

    find_package(PkgConfig)
    pkg_search_module(LIBNL REQUIRED libnl-genl-3.0)

    target_link_libraries(openvpn PUBLIC ${LIBNL_LIBRARIES})
    target_include_directories(openvpn PRIVATE ${LIBNL_INCLUDE_DIRS})
endif ()


if (MINGW)
    target_link_options(openvpn PRIVATE -municode)
endif ()

if (NOT WIN32)
    find_library(resolv resolv)
    # some platform like BSDs already include resolver functionality in the libc and not have an extra resolv library
    if (${resolv} OR APPLE)
        target_link_libraries(openvpn PUBLIC -lresolv)
    endif ()
endif ()


pkg_search_module(cmocka cmocka REQUIRED IMPORTED_TARGET)
enable_testing()

SET(unit_tests "test_packet_id" "test_crypto" "test_ncp" "test_auth_token" "test_misc" "test_buffer" "test_provider" "test_pkt")

# These tests work on only on Linux since they depend on special linker features
if (WIN32)
    LIST(APPEND unit_tests "test_cryptoapi")
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    LIST(APPEND unit_tests "test_networking" "test_tls_crypt" "test_argv")
endif ()


FOREACH (test_name ${unit_tests})
    add_executable(${test_name}
            tests/unit_tests/openvpn/${test_name}.c
            tests/unit_tests/openvpn/mock_msg.c
            src/openvpn/platform.c
            src/openvpn/crypto_mbedtls.c
            src/openvpn/crypto_openssl.c
            src/openvpn/crypto.c
            src/openvpn/otime.c
            src/openvpn/packet_id.c
            src/openvpn/base64.c
            src/openvpn/win32-util.c
            src/openvpn/mtu.c
            src/openvpn/networking_sitnl.c
            src/compat/compat-strsep.c
            src/compat/compat-gettimeofday.c
            src/openvpn/ssl_util.c
            src/openvpn/reliable.c
            src/openvpn/session_id.c
            src/openvpn/mss.c
            src/openvpn/xkey_provider.c
            )

    add_library_deps(${test_name})
    target_link_libraries(${test_name} PUBLIC PkgConfig::cmocka)

    target_include_directories(${test_name} PRIVATE src/openvpn)

    if (NOT ${test_name} STREQUAL "test_buffer")
        target_sources(${test_name} PRIVATE
                src/openvpn/buffer.c
                )
    endif ()
    add_test(NAME ${test_name} COMMAND ${test_name})
ENDFOREACH ()

target_sources(test_pkt PRIVATE
        src/openvpn/argv.c
        src/openvpn/env_set.c
        src/openvpn/reliable.c
        src/openvpn/run_command.c
        src/openvpn/session_id.c
        src/openvpn/ssl_pkt.c
        src/openvpn/tls_crypt.c
        )

if (TARGET test_cryptoapi)
    target_sources(test_cryptoapi PRIVATE
            src/openvpn/xkey_helper.c
            src/openvpn/xkey_provider.c
            )
endif ()

target_sources(test_provider PRIVATE
        src/openvpn/xkey_provider.c
        src/openvpn/xkey_helper.c
        )

target_sources(test_misc PRIVATE
        src/openvpn/options_util.c
        )

IF (TARGET test_tls_crypt)
    target_sources(test_tls_crypt PRIVATE
            src/openvpn/argv.c
            src/openvpn/env_set.c
            src/openvpn/run_command.c)
endif ()

if (TARGET test_argv)
    target_sources(test_argv PRIVATE
            src/openvpn/argv.c
            src/openvpn/env_set.c
            src/openvpn/run_command.c)
endif ()


FOREACH (test_name "networking" "tls_crypt" "argv")
    if (TARGET test_${test_name})
        target_link_options(test_${test_name} PRIVATE -Wl,--wrap=parse_line)
    endif ()
ENDFOREACH ()

if (TARGET test_tls_crypt)
    target_link_options("test_tls_crypt" PRIVATE
            -Wl,--wrap=buffer_read_from_file
            -Wl,--wrap=buffer_write_file
            -Wl,--wrap=rand_bytes)
ENDIF ()