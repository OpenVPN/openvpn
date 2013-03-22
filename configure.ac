dnl  OpenVPN -- An application to securely tunnel IP networks
dnl             over a single UDP port, with support for SSL/TLS-based
dnl             session authentication and key exchange,
dnl             packet encryption, packet authentication, and
dnl             packet compression.
dnl
dnl  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
dnl  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
dnl
dnl  This program is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 2 of the License, or
dnl  (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program (see the file COPYING included with this
dnl  distribution); if not, write to the Free Software Foundation, Inc.,
dnl  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

m4_include(version.m4)
AC_INIT([PRODUCT_NAME], [PRODUCT_VERSION], [PRODUCT_BUGREPORT], [PRODUCT_TARNAME])
m4_include(compat.m4)
AC_DEFINE([OPENVPN_VERSION_RESOURCE], [PRODUCT_VERSION_RESOURCE], [Version in windows resource format])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([src/openvpn/syshead.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE(
	[lzo],
	[AS_HELP_STRING([--disable-lzo], [disable LZO compression support @<:@default=yes@:>@])],
	,
	[enable_lzo="yes"]
)

AC_ARG_ENABLE(
	[lzo-stub],
	[AS_HELP_STRING([--enable-lzo-stub], [don't compile LZO compression support but still allow limited interoperability with LZO-enabled peers @<:@default=no@:>@])],
	,
	[enable_lzo_stub="no"]
)

AC_ARG_ENABLE(
	[crypto],
	[AS_HELP_STRING([--disable-crypto], [disable crypto support @<:@default=yes@:>@])],
	,
	[enable_crypto="yes"]
)

AC_ARG_ENABLE(
	[ssl],
	[AS_HELP_STRING([--disable-ssl], [disable SSL support for TLS-based key exchange @<:@default=yes@:>@])],
	,
	[enable_ssl="yes"]
)

AC_ARG_ENABLE(
	[x509-alt-username],
	[AS_HELP_STRING([--enable-x509-alt-username], [enable the --x509-username-field feature @<:@default=no@:>@])],
	,
	[enable_x509_alt_username="no"]
)

AC_ARG_ENABLE(
	[multi],
	[AS_HELP_STRING([--disable-multi], [disable client/server support (--mode server + client mode) @<:@default=yes@:>@])],
	,
	[enable_multi="yes"]
)

AC_ARG_ENABLE(
	[server],
	[AS_HELP_STRING([--disable-server], [disable server support only (but retain client support) @<:@default=yes@:>@])],
	,
	[enable_server="yes"]
)

AC_ARG_ENABLE(
	[plugins],
	[AS_HELP_STRING([--disable-plugins], [disable plug-in support @<:@default=yes@:>@])],
	,
	[enable_plugins="yes"]
)

AC_ARG_ENABLE(
	[eurephia],
	[AS_HELP_STRING([--disable-eurephia], [disable support for the eurephia plug-in @<:@default=yes@:>@])],
	,
	[enable_eurephia="yes"]
)

AC_ARG_ENABLE(
	[management],
	[AS_HELP_STRING([--disable-management], [disable management server support @<:@default=yes@:>@])],
	,
	[enable_management="yes"]
)

AC_ARG_ENABLE(
	[pkcs11],
	[AS_HELP_STRING([--enable-pkcs11], [enable pkcs11 support @<:@default=no@:>@])],
	,
	[enable_pkcs11="no"]
)

AC_ARG_ENABLE(
	[socks],
	[AS_HELP_STRING([--disable-socks], [disable Socks support @<:@default=yes@:>@])],
	,
	[enable_socks="yes"]
)

AC_ARG_ENABLE(
	[http-proxy],
	[AS_HELP_STRING([--disable-http-proxy], [disable HTTP proxy support @<:@default=yes@:>@])],
	,
	[enable_http_proxy="yes"]
)

AC_ARG_ENABLE(
	[fragment],
	[AS_HELP_STRING([--disable-fragment], [disable internal fragmentation support (--fragment) @<:@default=yes@:>@])],
	,
	[enable_fragment="yes"]
)

AC_ARG_ENABLE(
	[multihome],
	[AS_HELP_STRING([--disable-multihome], [disable multi-homed UDP server support (--multihome) @<:@default=yes@:>@])],
	,
	[enable_multihome="yes"]
)

AC_ARG_ENABLE(
	[port-share],
	[AS_HELP_STRING([--disable-port-share], [disable TCP server port-share support (--port-share) @<:@default=yes@:>@])],
	,
	[enable_port_share="yes"]
)

AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--disable-debug], [disable debugging support (disable gremlin and verb 7+ messages) @<:@default=yes@:>@])],
	,
	[enable_debug="yes"]
)

AC_ARG_ENABLE(
	[small],
	[AS_HELP_STRING([--enable-small], [enable smaller executable size (disable OCC, usage message, and verb 4 parm list) @<:@default=yes@:>@])],
	,
	[enable_small="no"]
)

AC_ARG_ENABLE(
	[password-save],
	[AS_HELP_STRING([--enable-password-save], [allow --askpass and --auth-user-pass passwords to be read from a file @<:@default=yes@:>@])],
	,
	[enable_password_save="no"]
)

AC_ARG_ENABLE(
	[iproute2],
	[AS_HELP_STRING([--enable-iproute2], [enable support for iproute2 @<:@default=no@:>@])],
	,
	[enable_iproute2="no"]
)

AC_ARG_ENABLE(
	[def-auth],
	[AS_HELP_STRING([--disable-def-auth], [disable deferred authentication @<:@default=yes@:>@])],
	,
	[enable_def_auth="yes"]
)

AC_ARG_ENABLE(
	[pf],
	[AS_HELP_STRING([--disable-pf], [disable internal packet filter @<:@default=yes@:>@])],
	,
	[enable_pf="yes"]
)

AC_ARG_ENABLE(
	[plugin-auth-pam],
	[AS_HELP_STRING([--disable-plugin-auth-pam], [disable auth-pam plugin @<:@default=platform specific@:>@])],
	,
	[
		case "$host" in
			*-*-openbsd*) enable_plugin_auth_pam="no";;
			*-mingw*) enable_plugin_auth_pam="no";;
			*) enable_plugin_auth_pam="yes";;
		esac
	]
)

AC_ARG_ENABLE(
	[plugin-down-root],
	[AS_HELP_STRING([--disable-plugin-down-root], [disable down-root plugin @<:@default=platform specific@:>@])],
	,
	[
		case "$host" in
			*-mingw*) enable_plugin_down_root="no";;
			*) enable_plugin_down_root="yes";;
		esac
	]
)

AC_ARG_ENABLE(
	[pam-dlopen],
	[AS_HELP_STRING([--enable-pam-dlopen], [dlopen libpam @<:@default=no@:>@])],
	,
	[enable_pam_dlopen="no"]
)

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict], [enable strict compiler warnings (debugging option) @<:@default=no@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic], [enable pedantic compiler warnings, will not generate a working executable (debugging option) @<:@default=no@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[strict-options],
	[AS_HELP_STRING([--enable-strict-options], [enable strict options check between peers (debugging option) @<:@default=no@:>@])],
	,
	[enable_strict_options="no"]
)

AC_ARG_ENABLE(
	[selinux],
	[AS_HELP_STRING([--enable-selinux], [enable SELinux support @<:@default=no@:>@])],
	,
	[enable_selinux="no"]
)

AC_ARG_ENABLE(
	[systemd],
	[AS_HELP_STRING([--enable-systemd], [enable systemd suppport @<:@default=no@:>@])],
	,
	[enable_systemd="no"]
)

AC_ARG_WITH(
	[special-build],
	[AS_HELP_STRING([--with-special-build=STRING], [specify special build string])],
	[test -n "${withval}" && AC_DEFINE_UNQUOTED([CONFIGURE_SPECIAL_BUILD], ["${withval}"], [special build string])]
)

AC_ARG_WITH(
	[mem-check],
	[AS_HELP_STRING([--with-mem-check=TYPE], [build with debug memory checking, TYPE=no|dmalloc|valgrind|ssl @<:@default=no@:>@])],
	[
		case "${withval}" in
			dmalloc|valgrind|ssl|no) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --mem-check]) ;;
		esac
	],
	[with_mem_check="no"]
)

AC_ARG_WITH(
	[crypto-library],
	[AS_HELP_STRING([--with-crypto-library=library], [build with the given crypto library, TYPE=openssl|polarssl @<:@default=openssl@:>@])],
	[
		case "${withval}" in 
			openssl|polarssl) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --with-crypto-library]) ;;
		esac
	],
	[with_crypto_library="openssl"]
)

AC_ARG_WITH(
	[plugindir],
	[AS_HELP_STRING([--with-plugindir], [plugin directory @<:@default=LIBDIR/openvpn@:>@])],
	,
	[with_plugindir="\$(libdir)/openvpn/plugins"]
)


AC_DEFINE_UNQUOTED([TARGET_ALIAS], ["${host}"], [A string representing our host])
case "$host" in
	*-*-linux*)
		AC_DEFINE([TARGET_LINUX], [1], [Are we running on Linux?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["L"], [Target prefix])
		;;
	*-*-solaris*)
		AC_DEFINE([TARGET_SOLARIS], [1], [Are we running on Solaris?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["S"], [Target prefix])
		;;
	*-*-openbsd*)
		AC_DEFINE([TARGET_OPENBSD], [1], [Are we running on OpenBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["O"], [Target prefix])
		;;
	*-*-freebsd*)
		AC_DEFINE([TARGET_FREEBSD], [1], [Are we running on FreeBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["F"], [Target prefix])
		;;
	*-*-netbsd*)
		AC_DEFINE([TARGET_NETBSD], [1], [Are we running NetBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["N"], [Target prefix])
		;;
	*-*-darwin*)
		AC_DEFINE([TARGET_DARWIN], [1], [Are we running on Mac OS X?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["M"], [Target prefix])
		have_tap_header="yes"
		dnl some Mac OS X tendering (we use vararg macros...)
		CPPFLAGS="$CPPFLAGS -no-cpp-precomp"
		;;
	*-mingw*)
		AC_DEFINE([TARGET_WIN32], [1], [Are we running WIN32?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["W"], [Target prefix])
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		CPPFLAGS="${CPPFLAGS} -DNTDDI_VERSION=NTDDI_WINXP -D_WIN32_WINNT=_WIN32_WINNT_WINXP"
		WIN32=yes
		;;
	*-*-dragonfly*)
		AC_DEFINE([TARGET_DRAGONFLY], [1], [Are we running on DragonFlyBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["D"], [Target prefix])
		;;
	*)
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["X"], [Target prefix])
		have_tap_header="yes"
		;;
esac

PKG_PROG_PKG_CONFIG
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_MAKE_SET

AC_ARG_VAR([IFCONFIG], [full path to ipconfig utility])
AC_ARG_VAR([ROUTE], [full path to route utility])
AC_ARG_VAR([IPROUTE], [full path to ip utility])
AC_ARG_VAR([NETSTAT], [path to netstat utility]) # tests
AC_ARG_VAR([MAN2HTML], [path to man2html utility])
AC_ARG_VAR([GIT], [path to git utility])
AC_PATH_PROGS([IFCONFIG], [ifconfig],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([ROUTE], [route],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([IPROUTE], [ip],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_CHECK_PROGS([NETSTAT], [netstat], [netstat], [$PATH:/usr/local/sbin:/usr/sbin:/sbin:/etc]) # tests
AC_CHECK_PROGS([MAN2HTML], [man2html])
AC_CHECK_PROGS([GIT], [git]) # optional
AC_DEFINE_UNQUOTED([IFCONFIG_PATH], ["$IFCONFIG"], [Path to ifconfig tool])
AC_DEFINE_UNQUOTED([IPROUTE_PATH], ["$IPROUTE"], [Path to iproute tool])
AC_DEFINE_UNQUOTED([ROUTE_PATH], ["$ROUTE"], [Path to route tool])

#
# Libtool
#
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIGNAL
AX_CPP_VARARG_MACRO_ISO
AX_CPP_VARARG_MACRO_GCC
AX_TYPE_SOCKLEN_T
AX_EMPTY_ARRAY
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_HEADERS([ \
	stdio.h stdarg.h stdbool.h limits.h \
	time.h errno.h fcntl.h io.h direct.h \
	ctype.h sys/types.h sys/socket.h \
	signal.h unistd.h dlfcn.h \
	netinet/in.h netinet/in_systm.h \
	netinet/tcp.h arpa/inet.h netdb.h \
	windows.h winsock2.h ws2tcpip.h \
])
AC_CHECK_HEADERS([ \
	sys/time.h sys/ioctl.h sys/stat.h \
	sys/mman.h sys/file.h sys/wait.h \
	unistd.h signal.h libgen.h stropts.h \
	syslog.h pwd.h grp.h \
	sys/sockio.h sys/uio.h linux/sockios.h \
	linux/types.h sys/poll.h sys/epoll.h err.h \
])

SOCKET_INCLUDES="
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif
"

AC_CHECK_HEADERS(
	[net/if.h netinet/ip.h netinet/if_ether.h resolv.h sys/un.h],
	,
	,
	[[${SOCKET_INCLUDES}]]
)

AC_CHECK_TYPES(
	[in_addr_t],
	,
	[AC_DEFINE([in_addr_t], [uint32_t], [Workaround missing in_addr_t])],
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct iphdr],
	[AC_DEFINE([HAVE_IPHDR], [1], [struct iphdr needed for IPv6 support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct sock_extended_err],
	[AC_DEFINE([HAVE_SOCK_EXTENDED_ERR], [1], [struct sock_extended_err needed for extended socket error support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct msghdr],
	[AC_DEFINE([HAVE_MSGHDR], [1], [struct msghdr needed for extended socket error support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct cmsghdr],
	[AC_DEFINE([HAVE_CMSGHDR], [1], [struct cmsghdr needed for extended socket error support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct in_pktinfo],
	[AC_DEFINE([HAVE_IN_PKTINFO], [1], [struct in_pktinfo needed for IP_PKTINFO support])],
	,
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct sockaddr_in6],
	,
	[AC_MSG_ERROR([struct sockaddr_in6 not found, needed for ipv6 transport support.])],
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_DECLS(
	[SO_MARK],
	,
	,
	[[${SOCKET_INCLUDES}]]
)

dnl We emulate signals in Windows
AC_CHECK_DECLS(
	[SIGHUP],
	,
	[AC_DEFINE([SIGHUP], [1], [SIGHUP replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGINT],
	,
	[AC_DEFINE([SIGINT], [2], [SIGINT replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGUSR1],
	,
	[AC_DEFINE([SIGUSR1], [10], [SIGUSR1 replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGUSR2],
	,
	[AC_DEFINE([SIGUSR2], [12], [SIGUSR2 replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)
AC_CHECK_DECLS(
	[SIGTERM],
	,
	[AC_DEFINE([SIGTERM], [15], [SIGTERM replacement])],
	[[
		#ifdef HAVE_SIGNAL_H
		#include <signal.h>
		#endif
	]]
)

AC_FUNC_FORK

AC_CHECK_FUNCS([ \
	daemon chroot getpwnam setuid nice system getpid dup dup2 \
	getpass strerror syslog openlog mlockall getgrnam setgid \
	setgroups stat flock readv writev time gettimeofday \
	ctime memset vsnprintf strdup \
	setsid chdir putenv getpeername unlink \
	chsize ftruncate execve getpeereid umask basename dirname access \
	epoll_create \
])

AC_CHECK_LIB(
	[dl],
	[dlopen],
	[DL_LIBS="-ldl"]
)
AC_SUBST([DL_LIBS])

AC_CHECK_LIB(
	[nsl],
	[inet_ntoa],
	[SOCKETS_LIBS="${SOCKETS_LIBS} -lnsl"]
)
AC_CHECK_LIB(
	[socket],
	[socket],
	[SOCKETS_LIBS="${SOCKETS_LIBS} -lsocket"]
)
AC_CHECK_LIB(
	[resolv],
	[gethostbyname],
	[SOCKETS_LIBS="${SOCKETS_LIBS} -lresolv"]
)
AC_SUBST([SOCKETS_LIBS])

old_LIBS="${LIBS}"
LIBS="${LIBS} ${SOCKETS_LIBS}"
AC_CHECK_FUNCS([sendmsg recvmsg inet_ntop inet_pton])
AC_CHECK_FUNCS(
	[res_init],
	,
	,
	[[#include <resolv.h>]]
)
# Windows use stdcall for winsock so we cannot auto detect these
m4_define(
	[SOCKET_FUNCS],
[socket recv recvfrom send sendto listen dnl
accept connect bind select gethostbyname inet_ntoa]dnl
)
m4_define(
	[SOCKET_OPT_FUNCS],
	[setsockopt getsockopt getsockname poll]dnl
)
if test "${WIN32}" = "yes"; then
	m4_foreach(
		[F],
		m4_split(SOCKET_FUNCS SOCKET_OPT_FUNCS),
			m4_define([UF], [[m4_join([_], [HAVE], m4_toupper(F))]])
			AC_DEFINE([UF], [1], [Win32 builtin])
	)
else
	AC_CHECK_FUNCS(
		SOCKET_FUNCS,
		,
		[AC_MSG_ERROR([Required library function not found])]
	)
	AC_CHECK_FUNCS(SOCKET_OPT_FUNCS)
fi
LIBS="${old_LIBS}"

AC_ARG_VAR([TAP_CFLAGS], [C compiler flags for tap])
old_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${TAP_CFLAGS}"
AC_CHECK_HEADERS(
	[ \
		net/if_tun.h net/tun/if_tun.h \
		linux/if_tun.h \
		tap-windows.h \
	],
	[have_tap_header="yes"]
)
AC_CHECK_DECLS(
	[TUNSETPERSIST],
	[AC_DEFINE([ENABLE_FEATURE_TUN_PERSIST], [1], [We have persist tun capability])],
	,
	[[
		#ifdef HAVE_LINUX_IF_TUN_H
		#include <linux/if_tun.h>
		#endif
	]]
)
CFLAGS="${old_CFLAGS}"
test "${have_tap_header}" = "yes" || AC_MSG_ERROR([no tap header could be found])

AC_CHECK_LIB(
	[selinux],
	[setcon],
	[SELINUX_LIBS="-lselinux"]
)
AC_SUBST([SELINUX_LIBS])

AC_ARG_VAR([LIBPAM_CFLAGS], [C compiler flags for libpam])
AC_ARG_VAR([LIBPAM_LIBS], [linker flags for libpam])
if test -z "${LIBPAM_LIBS}"; then
	AC_CHECK_LIB(
		[pam],
		[pam_start],
		[LIBPAM_LIBS="-lpam"]
	)
fi

case "${with_mem_check}" in
	valgrind)
		AC_CHECK_HEADER(
			[valgrind/memcheck.h],
			[
				CFLAGS="${CFLAGS} -g -fno-inline"
				AC_DEFINE(
					[USE_VALGRIND],
					[1],
					[Use valgrind memory debugging library]
				)
			],
			[AC_MSG_ERROR([valgrind headers not found.])]
		)
		;;
	dmalloc)
		AC_CHECK_HEADER(
			[dmalloc.h],
			[AC_CHECK_LIB(
				[dmalloc],
				[malloc],
				[
					LIBS="${LIBS} -ldmalloc"
					AC_DEFINE(
						[DMALLOC],
						[1],
						[Use dmalloc memory debugging library]
					)
				],
				[AC_MSG_ERROR([dmalloc library not found.])]
			)],
			[AC_MSG_ERROR([dmalloc headers not found.])]
		)
		;;
	ssl)
		AC_CHECK_LIB(
			[ssl],
			[CRYPTO_mem_ctrl],
			[
				AC_DEFINE(
					[CRYPTO_MDEBUG],
					[1],
					[Use memory debugging function in OpenSSL]
				)
				AC_MSG_NOTICE([NOTE: OpenSSL library must be compiled with CRYPTO_MDEBUG])
			],
			[AC_MSG_ERROR([Memory Debugging function in OpenSSL library not found.])]
		)
		;;
esac

PKG_CHECK_MODULES(
	[PKCS11_HELPER],
	[libpkcs11-helper-1 >= 1.02],
	[have_pkcs11_helper="yes"],
	[]
)

PKG_CHECK_MODULES(
	[OPENSSL_CRYPTO],
	[libcrypto >= 0.9.6],
	[have_openssl_crypto="yes"],
	[AC_CHECK_LIB(
		[crypto],
		[RSA_new],
		[
			have_openssl_crypto="yes"
			OPENSSL_CRYPTO_LIBS="-lcrypto"
		]
	)]
)

PKG_CHECK_MODULES(
	[OPENSSL_SSL],
	[libssl >= 0.9.6],
	[have_openssl_ssl="yes"],
	[AC_CHECK_LIB(
		[ssl],
		[SSL_CTX_new],
		[
			have_openssl_ssl="yes"
			OPENSSL_SSL_LIBS="-lssl"
		]
	)]
)

if test "${have_openssl_crypto}" = "yes"; then
	saved_CFLAGS="${CFLAGS}"
	saved_LIBS="${LIBS}"
	CFLAGS="${CFLAGS} ${OPENSSL_CRYPTO_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_CRYPTO_LIBS}"
	AC_CHECK_FUNCS([EVP_CIPHER_CTX_set_key_length])
	have_openssl_engine="yes"
	AC_CHECK_FUNCS(
		[ \
			ENGINE_load_builtin_engines \
			ENGINE_register_all_complete \
			ENGINE_cleanup \
		],
		,
		[have_openssl_engine="no"; break]
	)

	CFLAGS="${saved_CFLAGS}"
	LIBS="${saved_LIBS}"
fi

AC_ARG_VAR([POLARSSL_CFLAGS], [C compiler flags for polarssl])
AC_ARG_VAR([POLARSSL_LIBS], [linker flags for polarssl])
have_polarssl_ssl="yes"
have_polarssl_crypto="yes"
if test -z "${POLARSSL_LIBS}"; then
	AC_CHECK_LIB(
		[polarssl],
		[ssl_init],
		[POLARSSL_LIBS="-lpolarssl"],
		[
			have_polarssl_ssl="no"
			AC_CHECK_LIB(
				[polarssl],
				[aes_crypt_cbc],
				,
				[have_polarssl_crypto="no"],
				[${PKCS11_HELPER_LIBS}]
			)
		],
		[${PKCS11_HELPER_LIBS}]
	)
fi

if test "${with_crypto_library}" = "polarssl" ; then
	AC_MSG_CHECKING([polarssl version])
	old_CFLAGS="${CFLAGS}"
	CFLAGS="${POLARSSL_CFLAGS} ${CFLAGS}"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
			[[
#include <polarssl/version.h>
			]],
			[[
#if POLARSSL_VERSION_NUMBER < 0x01020500
#error invalid version
#endif
			]]
		)],
		[AC_MSG_RESULT([ok])],
		[AC_MSG_ERROR([PolarSSL 1.2.5 or newer required])]
	)

	polarssl_with_pkcs11="no"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
			[[
#include <polarssl/config.h>
			]],
			[[
#ifndef POLARSSL_PKCS11_C
#error pkcs11 wrapper missing
#endif
			]]
		)],
		polarssl_with_pkcs11="yes")
	CFLAGS="${old_CFLAGS}"

	AC_MSG_CHECKING([polarssl pkcs11 support])
	if test "${enable_pkcs11}" = "yes"; then
		if test "${polarssl_with_pkcs11}" = "yes"; then
			AC_MSG_RESULT([ok])
		else
			AC_MSG_ERROR([polarssl has no pkcs11 wrapper compiled in])
		fi
	else
		if test "${polarssl_with_pkcs11}" != "yes"; then
			AC_MSG_RESULT([ok])
		else
			AC_MSG_ERROR([PolarSSL compiled with PKCS11, while OpenVPN is not])
		fi
	fi

fi

AC_ARG_VAR([LZO_CFLAGS], [C compiler flags for lzo])
AC_ARG_VAR([LZO_LIBS], [linker flags for lzo])
have_lzo="yes"
if test -z "${LZO_LIBS}"; then
	AC_CHECK_LIB(
		[lzo2],
		[lzo1x_1_15_compress],
		[LZO_LIBS="-llzo2"],
		[AC_CHECK_LIB(
			[lzo],
			[lzo1x_1_15_compress],
			[LZO_LIBS="-llzo"],
			[have_lzo="no"]
		)]
	)
fi
if test "${have_lzo}" = "yes"; then
	saved_CFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} ${LZO_CFLAGS}"
	AC_CHECK_HEADERS(
		[lzo/lzoutil.h],
		,
		[AC_CHECK_HEADERS(
			[lzoutil.h],
			,
			[AC_MSG_ERROR([lzoutil.h is missing])]
		)]
	)
	AC_CHECK_HEADERS(
		[lzo/lzo1x.h],
		,
		[AC_CHECK_HEADERS(
			[lzo1x.h],
			,
			[AC_MSG_ERROR([lzo1x.h is missing])]
		)]
	)
	CFLAGS="${saved_CFLAGS}"
fi

AC_MSG_CHECKING([git checkout])
GIT_CHECKOUT="no"
if test -n "${GIT}" -a -d "${srcdir}/.git"; then
	AC_DEFINE([HAVE_CONFIG_VERSION_H], [1], [extra version available in config-version.h])
	GIT_CHECKOUT="yes"
fi
AC_MSG_RESULT([${GIT_CHECKOUT}])

if test -n "${SP_PLATFORM_WINDOWS}"; then
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR], ['\\\\'], [Path separator]) #"
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR_STR], ["\\\\"], [Path separator]) #"
else
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR], ['/'], [Path separator])
	AC_DEFINE_UNQUOTED([PATH_SEPARATOR_STR], ["/"], [Path separator])
fi

dnl enable --x509-username-field feature if requested
if test "${enable_x509_alt_username}" = "yes"; then
	if test "${with_crypto_library}" = "polarssl" ; then
		AC_MSG_ERROR([PolarSSL does not support the --x509-username-field feature])
	fi

	AC_DEFINE([ENABLE_X509ALTUSERNAME], [1], [Enable --x509-username-field feature])
fi

test "${ac_cv_header_sys_uio_h}" = "yes" && AC_DEFINE([HAVE_IOVEC], [1], [struct iovec needed for IPv6 support])
test "${enable_multi}" = "yes" && AC_DEFINE([ENABLE_CLIENT_SERVER], [1], [Enable client/server capability])
test "${enable_server}" = "no" && AC_DEFINE([ENABLE_CLIENT_ONLY], [1], [Enable client capability only])
test "${enable_management}" = "yes" && AC_DEFINE([ENABLE_MANAGEMENT], [1], [Enable management server capability])
test "${enable_socks}" = "yes" && AC_DEFINE([ENABLE_SOCKS], [1], [Enable Socks proxy support])
test "${enable_http_proxy}" = "yes" && AC_DEFINE([ENABLE_HTTP_PROXY], [1], [Enable HTTP proxy support])
test "${enable_multihome}" = "yes" && AC_DEFINE([ENABLE_MULTIHOME], [1], [Enable multi-homed UDP server capability])
test "${enable_debug}" = "yes" && AC_DEFINE([ENABLE_DEBUG], [1], [Enable debugging support])
test "${enable_small}" = "yes" && AC_DEFINE([ENABLE_SMALL], [1], [Enable smaller executable size])
test "${enable_fragment}" = "yes" && AC_DEFINE([ENABLE_FRAGMENT], [1], [Enable internal fragmentation support])
test "${enable_port_share}" = "yes" && AC_DEFINE([ENABLE_PORT_SHARE], [1], [Enable TCP Server port sharing])
test "${enable_def_auth}" = "yes" && AC_DEFINE([ENABLE_DEF_AUTH], [1], [Enable deferred authentication])
test "${enable_pf}" = "yes" && AC_DEFINE([ENABLE_PF], [1], [Enable internal packet filter])
test "${enable_strict_options}" = "yes" && AC_DEFINE([ENABLE_STRICT_OPTIONS_CHECK], [1], [Enable strict options check between peers])
test "${enable_password_save}" = "yes" && AC_DEFINE([ENABLE_PASSWORD_SAVE], [1], [Allow --askpass and --auth-user-pass passwords to be read from a file])
test "${enable_systemd}" = "yes" && AC_DEFINE([ENABLE_SYSTEMD], [1], [Enable systemd support])

case "${with_crypto_library}" in
	openssl)
		have_crypto_crypto="${have_openssl_crypto}"
		have_crypto_ssl="${have_openssl_ssl}"
		CRYPTO_CRYPTO_CFLAGS="${OPENSSL_CRYPTO_CFLAGS}"
		CRYPTO_CRYPTO_LIBS="${OPENSSL_CRYPTO_LIBS}"
		CRYPTO_SSL_CFLAGS="${OPENSSL_SSL_CFLAGS}"
		CRYPTO_SSL_LIBS="${OPENSSL_SSL_LIBS}"
		AC_DEFINE([ENABLE_CRYPTO_OPENSSL], [1], [Use OpenSSL library])
		test "${have_openssl_engine}" = "yes" && AC_DEFINE([HAVE_OPENSSL_ENGINE], [1], [Use crypto library])
		;;
	polarssl)
		have_crypto_crypto="${have_polarssl_crypto}"
		have_crypto_ssl="${have_polarssl_ssl}"
		CRYPTO_CRYPTO_CFLAGS="${POLARSSL_CFLAGS}"
		CRYPTO_CRYPTO_LIBS="${POLARSSL_LIBS}"
		AC_DEFINE([ENABLE_CRYPTO_POLARSSL], [1], [Use PolarSSL library])
		;;
esac

if test "${enable_ssl}" = "yes"; then
	test "${enable_crypto}" != "yes" && AC_MSG_ERROR([crypto must be enabled for ssl])
	test "${have_crypto_ssl}" != "yes" && AC_MSG_ERROR([${with_ssl_library} ssl is required but missing])
	OPTIONAL_CRYPTO_CFLAGS="${OPTIONAL_CRYPTO_CFLAGS} ${CRYPTO_SSL_CFLAGS}"
	OPTIONAL_CRYPTO_LIBS="${OPTIONAL_CRYPTO_LIBS} ${CRYPTO_SSL_LIBS}"
	AC_DEFINE([ENABLE_SSL], [1], [Enable ssl library])
fi

if test "${enable_crypto}" = "yes"; then
	test "${have_crypto_crypto}" != "yes" && AC_MSG_ERROR([${with_crypto_library} crypto is required but missing])
	OPTIONAL_CRYPTO_CFLAGS="${OPTIONAL_CRYPTO_CFLAGS} ${CRYPTO_CRYPTO_CFLAGS}"
	OPTIONAL_CRYPTO_LIBS="${OPTIONAL_CRYPTO_LIBS} ${CRYPTO_CRYPTO_LIBS}"
	AC_DEFINE([ENABLE_CRYPTO], [1], [Enable crypto library])
fi

if test "${enable_plugins}" = "yes"; then
	OPTIONAL_DL_LIBS="${DL_LIBS}"
	AC_DEFINE([ENABLE_PLUGIN], [1], [Enable systemd support])
	test "${enable_eurephia}" = "yes" && AC_DEFINE([ENABLE_EUREPHIA], [1], [Enable support for the eurephia plug-in])
else
	enable_plugin_auth_pam="no"
	enable_plugin_down_root="no"
fi

if test "${enable_iproute2}" = "yes"; then
	test -z "${IPROUTE}" && AC_MSG_ERROR([ip utility is required but missing])
	AC_DEFINE([ENABLE_IPROUTE], [1], [enable iproute2 support])
else
	if test "${WIN32}" != "yes"; then
		test -z "${ROUTE}" && AC_MSG_ERROR([route utility is required but missing])
		test -z "${IFCONFIG}" && AC_MSG_ERROR([ifconfig utility is required but missing])
	fi
fi

if test "${enable_selinux}" = "yes"; then
	test -z "${SELINUX_LIBS}" && AC_MSG_ERROR([libselinux required but missing])
	OPTIONAL_SELINUX_LIBS="${SELINUX_LIBS}"
	AC_DEFINE([ENABLE_SELINUX], [1], [SELinux support])
fi

if test "${enable_lzo}" = "yes"; then
	test "${have_lzo}" != "yes" && AC_MSG_ERROR([lzo enabled but missing])
	OPTIONAL_LZO_CFLAGS="${LZO_CFLAGS}"
	OPTIONAL_LZO_LIBS="${LZO_LIBS}"
	AC_DEFINE([ENABLE_LZO], [1], [Enable LZO compression library])
fi
if test "${enable_lzo_stub}" = "yes"; then
	test "${enable_lzo}" = "yes" && AC_MSG_ERROR([Cannot have both lzo stub and lzo enabled])
	AC_DEFINE([ENABLE_LZO_STUB], [1], [Enable LZO stub capability])
	AC_DEFINE([ENABLE_LZO], [1], [Enable LZO compression library])
fi

if test "${enable_pkcs11}" = "yes"; then
	test "${have_pkcs11_helper}" != "yes" && AC_MSG_ERROR([PKCS11 enabled but libpkcs11-helper is missing])
	test "${enable_ssl}" != "yes" && AC_MSG_ERROR([PKCS11 can be enabled only if SSL is enabled])
	OPTIONAL_PKCS11_HELPER_CFLAGS="${PKCS11_HELPER_CFLAGS}"
	OPTIONAL_PKCS11_HELPER_LIBS="${PKCS11_HELPER_LIBS}"
	AC_DEFINE([ENABLE_PKCS11], [1], [Enable PKCS11])
fi

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -pedantic"
	test "${WIN32}" != "yes" && CFLAGS="${CFLAGS} -ansi"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wno-unused-parameter -Wno-unused-function"
fi

if test "${WIN32}" = "yes"; then
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

if test "${enable_plugin_auth_pam}" = "yes"; then
	PLUGIN_AUTH_PAM_CFLAGS="${LIBPAM_CFLAGS}"
	if test "${enable_pam_dlopen}" = "yes"; then
		AC_DEFINE([USE_PAM_DLOPEN], [1], [dlopen libpam])
		PLUGIN_AUTH_PAM_LIBS="${DL_LIBS}"
	else
		test -z "${LIBPAM_LIBS}" && AC_MSG_ERROR([libpam required but missing])
		PLUGIN_AUTH_PAM_LIBS="${LIBPAM_LIBS}"
	fi
fi

CONFIGURE_DEFINES="`set | grep '^enable_.*=' ; set | grep '^with_.*='`"
AC_DEFINE_UNQUOTED([CONFIGURE_DEFINES], ["`echo ${CONFIGURE_DEFINES}`"], [Configuration settings])

TAP_WIN_COMPONENT_ID="PRODUCT_TAP_WIN_COMPONENT_ID"
TAP_WIN_MIN_MAJOR="PRODUCT_TAP_WIN_MIN_MAJOR"
TAP_WIN_MIN_MINOR="PRODUCT_TAP_WIN_MIN_MINOR"
AC_DEFINE_UNQUOTED([TAP_WIN_COMPONENT_ID], ["${TAP_WIN_COMPONENT_ID}"], [The tap-windows id])
AC_DEFINE_UNQUOTED([TAP_WIN_MIN_MAJOR], [${TAP_WIN_MIN_MAJOR}], [The tap-windows version number is required for OpenVPN])
AC_DEFINE_UNQUOTED([TAP_WIN_MIN_MINOR], [${TAP_WIN_MIN_MINOR}], [The tap-windows version number is required for OpenVPN])
AC_SUBST([TAP_WIN_COMPONENT_ID])
AC_SUBST([TAP_WIN_MIN_MAJOR])
AC_SUBST([TAP_WIN_MIN_MINOR])

AC_SUBST([OPTIONAL_DL_LIBS])
AC_SUBST([OPTIONAL_SELINUX_LIBS])
AC_SUBST([OPTIONAL_CRYPTO_CFLAGS])
AC_SUBST([OPTIONAL_CRYPTO_LIBS])
AC_SUBST([OPTIONAL_LZO_CFLAGS])
AC_SUBST([OPTIONAL_LZO_LIBS])
AC_SUBST([OPTIONAL_PKCS11_HELPER_CFLAGS])
AC_SUBST([OPTIONAL_PKCS11_HELPER_LIBS])

AC_SUBST([PLUGIN_AUTH_PAM_CFLAGS])
AC_SUBST([PLUGIN_AUTH_PAM_LIBS])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([GIT_CHECKOUT], [test "${GIT_CHECKOUT}" = "yes"])
AM_CONDITIONAL([ENABLE_PLUGIN_AUTH_PAM], [test "${enable_plugin_auth_pam}" = "yes"])
AM_CONDITIONAL([ENABLE_PLUGIN_DOWN_ROOT], [test "${enable_plugin_down_root}" = "yes"])

plugindir="${with_plugindir}"
sampledir="\$(docdir)/sample"
AC_SUBST([plugindir])
AC_SUBST([sampledir])

AC_CONFIG_FILES([
	version.sh
	Makefile
	build/Makefile
	build/msvc/Makefile
	build/msvc/msvc-generate/Makefile
	distro/Makefile
	distro/rpm/Makefile
	distro/rpm/openvpn.spec
	include/Makefile
	src/Makefile
	src/compat/Makefile
	src/openvpn/Makefile
	src/openvpnserv/Makefile
	src/plugins/Makefile
	src/plugins/auth-pam/Makefile
	src/plugins/down-root/Makefile
	tests/Makefile
	sample/Makefile
	doc/Makefile
])
AC_CONFIG_FILES([tests/t_client.sh], [chmod +x tests/t_client.sh])
AC_OUTPUT
