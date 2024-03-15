dnl  OpenVPN -- An application to securely tunnel IP networks
dnl             over a single UDP port, with support for SSL/TLS-based
dnl             session authentication and key exchange,
dnl             packet encryption, packet authentication, and
dnl             packet compression.
dnl
dnl  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
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
dnl  You should have received a copy of the GNU General Public License along
dnl  with this program; if not, write to the Free Software Foundation, Inc.,
dnl  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

m4_include(version.m4)
AC_INIT([PRODUCT_NAME], [PRODUCT_VERSION], [PRODUCT_BUGREPORT], [PRODUCT_TARNAME])
m4_include(compat.m4)
AC_DEFINE([OPENVPN_VERSION_RESOURCE], [PRODUCT_VERSION_RESOURCE], [Version in windows resource format])
AC_SUBST([OPENVPN_VERSION_MAJOR], [PRODUCT_VERSION_MAJOR], [OpenVPN major version])
AC_SUBST([OPENVPN_VERSION_MINOR], [PRODUCT_VERSION_MINOR], [OpenVPN minor version])
AC_SUBST([OPENVPN_VERSION_PATCH], [PRODUCT_VERSION_PATCH], [OpenVPN patch level - may be a string or integer])
AC_DEFINE([OPENVPN_VERSION_MAJOR], [PRODUCT_VERSION_MAJOR], [OpenVPN major version - integer])
AC_DEFINE([OPENVPN_VERSION_MINOR], [PRODUCT_VERSION_MINOR], [OpenVPN minor version - integer])
AC_DEFINE([OPENVPN_VERSION_PATCH], ["PRODUCT_VERSION_PATCH"], [OpenVPN patch level - may be a string or integer])

AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h include/openvpn-plugin.h])
AC_CONFIG_SRCDIR([src/openvpn/syshead.h])
AC_CONFIG_MACRO_DIR([m4])

dnl Initialize automake.  automake < 1.12 didn't have serial-tests and
dnl gives an error if it sees this, but for automake >= 1.13
dnl serial-tests is required so we have to include it.  Solution is to
dnl test for the version of automake (by running an external command)
dnl and provide it if necessary.  Note we have to do this entirely using
dnl m4 macros since automake queries this macro by running
dnl 'autoconf --trace ...'.
m4_define([serial_tests], [
    m4_esyscmd([automake --version |
                head -1 |
                awk '{split ($NF,a,"."); if (a[1] == 1 && a[2] >= 12) { print "serial-tests" }}'
    ])
])

dnl Automake 1.14+ warns if sources are in sub-directories but subdir-objects
dnl options is not enabled. However, automake before 1.15a has a bug that causes
dnl variable expansion to fail in foo_SOURCES when this option is used.
dnl As most of our build systems are now likely to use automake 1.16+ add a
dnl work around to conditionally add subdir-objects option.
m4_define([subdir_objects], [
    m4_esyscmd([automake --version |
                head -1 |
                awk '{split ($NF,a,"."); if (a[1] == 1 && a[2] >= 16) { print "subdir-objects" }}'
    ])
])

# This foreign option prevents autoreconf from overriding our COPYING and
# INSTALL targets:
AM_INIT_AUTOMAKE(foreign serial_tests subdir_objects 1.9) dnl NB: Do not [quote] this parameter.
AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS

AC_ARG_ENABLE(
	[lzo],
	[AS_HELP_STRING([--disable-lzo], [disable LZO compression support @<:@default=yes@:>@])],
	,
	[enable_lzo="yes"]
)

AC_ARG_ENABLE(
	[lz4],
	[AS_HELP_STRING([--disable-lz4], [disable LZ4 compression support @<:@default=yes@:>@])],
	[enable_lz4="$enableval"],
	[enable_lz4="yes"]
)

AC_ARG_ENABLE(
	[comp-stub],
	[AS_HELP_STRING([--enable-comp-stub], [disable compression support but still allow limited interoperability with compression-enabled peers @<:@default=no@:>@])],
	[enable_comp_stub="$enableval"],
	[enable_comp_stub="no"]
)

AC_ARG_ENABLE(
	[ofb-cfb],
	[AS_HELP_STRING([--disable-ofb-cfb], [disable support for OFB and CFB cipher modes @<:@default=yes@:>@])],
	,
	[enable_crypto_ofb_cfb="yes"]
)

AC_ARG_ENABLE(
	[x509-alt-username],
	[AS_HELP_STRING([--enable-x509-alt-username], [enable the --x509-username-field feature @<:@default=no@:>@])],
	,
	[enable_x509_alt_username="no"]
)

AC_ARG_ENABLE(
	[plugins],
	[AS_HELP_STRING([--disable-plugins], [disable plug-in support @<:@default=yes@:>@])],
	,
	[enable_plugins="yes"]
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
	[fragment],
	[AS_HELP_STRING([--disable-fragment], [disable internal fragmentation support (--fragment) @<:@default=yes@:>@])],
	,
	[enable_fragment="yes"]
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
	[AS_HELP_STRING([--enable-small], [enable smaller executable size (disable OCC, usage message, and verb 4 parm list) @<:@default=no@:>@])],
	,
	[enable_small="no"]
)

AC_ARG_ENABLE(
	[dco],
	[AS_HELP_STRING([--disable-dco], [disable data channel offload support using the ovpn-dco kernel module @<:@default=yes@:>@ on Linux/FreeBSD, can't disable on Windows])],
	,
	[
		case "$host" in
			*-*-linux*)
				enable_dco="auto"
			;;
			*-*-freebsd*)
				enable_dco="auto"
			;;
			*)
				# note that this does not disable it for Windows
				enable_dco="no"
			;;
		esac
	]
)

AC_ARG_ENABLE(
	[iproute2],
	[AS_HELP_STRING([--enable-iproute2], [enable support for iproute2 (disables DCO) @<:@default=no@:>@])],
	,
	[enable_iproute2="no"]
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
	[werror],
	[AS_HELP_STRING([--enable-werror], [promote compiler warnings to errors, will cause builds to fail if the compiler issues warnings (debugging option) @<:@default=no@:>@])],
	,
	[enable_werror="no"]
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
	[AS_HELP_STRING([--enable-systemd], [enable systemd support @<:@default=no@:>@])],
	,
	[enable_systemd="no"]
)

AC_ARG_ENABLE(
	[async-push],
	[AS_HELP_STRING([--enable-async-push], [enable async-push support for plugins providing deferred authentication @<:@default=no@:>@])],
	,
	[enable_async_push="no"]
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
	[AS_HELP_STRING([--with-crypto-library=library], [build with the given crypto library, TYPE=openssl|mbedtls|wolfssl @<:@default=openssl@:>@])],
	[
		case "${withval}" in
			openssl|mbedtls|wolfssl) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --with-crypto-library]) ;;
		esac
	],
	[with_crypto_library="openssl"]
)

AC_ARG_ENABLE(
	[wolfssl-options-h],
	[AS_HELP_STRING([--disable-wolfssl-options-h], [Disable including options.h in wolfSSL @<:@default=yes@:>@])],
	,
	[enable_wolfssl_options_h="yes"]
)

AC_ARG_WITH(
	[openssl-engine],
	[AS_HELP_STRING([--with-openssl-engine], [enable engine support with OpenSSL. Default enabled for OpenSSL < 3.0, auto,yes,no @<:@default=auto@:>@])],
	[
		case "${withval}" in
			auto|yes|no) ;;
			*) AC_MSG_ERROR([bad value ${withval} for --with-engine]) ;;
		esac
	],
	[with_openssl_engine="auto"]
)

AC_ARG_VAR([PLUGINDIR], [Path of plug-in directory @<:@default=LIBDIR/openvpn/plugins@:>@])
if test -n "${PLUGINDIR}"; then
	plugindir="${PLUGINDIR}"
else
	plugindir="\${libdir}/openvpn/plugins"
fi

AC_DEFINE_UNQUOTED([TARGET_ALIAS], ["${host}"], [A string representing our host])
AM_CONDITIONAL([TARGET_LINUX], [false])
case "$host" in
	*-*-linux*)
		AC_DEFINE([TARGET_LINUX], [1], [Are we running on Linux?])
		AM_CONDITIONAL([TARGET_LINUX], [true])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["L"], [Target prefix])
		have_sitnl="yes"
		pkg_config_required="yes"
		;;
	*-*-solaris*)
		AC_DEFINE([TARGET_SOLARIS], [1], [Are we running on Solaris?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["S"], [Target prefix])
		CPPFLAGS="$CPPFLAGS -D_XPG4_2"
		test -x /bin/bash && SHELL="/bin/bash"
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
		ac_cv_type_struct_in_pktinfo=no
		;;
	*-mingw*)
		AC_DEFINE([TARGET_WIN32], [1], [Are we running WIN32?])
		AC_DEFINE([ENABLE_DCO], [1], [DCO is always enabled on Windows])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["W"], [Target prefix])
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		CPPFLAGS="${CPPFLAGS} -DNTDDI_VERSION=NTDDI_VISTA -D_WIN32_WINNT=_WIN32_WINNT_VISTA"
		WIN32=yes
		;;
	*-*-dragonfly*)
		AC_DEFINE([TARGET_DRAGONFLY], [1], [Are we running on DragonFlyBSD?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["D"], [Target prefix])
		;;
	*-aix*)
		AC_DEFINE([TARGET_AIX], [1], [Are we running AIX?])
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["A"], [Target prefix])
		ROUTE="/usr/sbin/route"
		have_tap_header="yes"
		ac_cv_header_net_if_h="no"	# exists, but breaks things
		;;
	*)
		AC_DEFINE_UNQUOTED([TARGET_PREFIX], ["X"], [Target prefix])
		have_tap_header="yes"
		;;
esac

AM_CONDITIONAL([CROSS_COMPILING], test "${cross_compiling}" = "yes")

PKG_PROG_PKG_CONFIG
# Add variable to print if pkg-config is found or not. Users often miss that
if test "${PKG_CONFIG}" = ""; then
	if test "${pkg_config_required}" = "yes"; then
		AC_MSG_ERROR([pkg-config is required])
	fi
	pkg_config_found="(not found)"
else
	pkg_config_found="(${PKG_CONFIG})"
fi

AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED
AC_PROG_MAKE_SET

AC_ARG_VAR([IFCONFIG], [full path to ipconfig utility])
AC_ARG_VAR([ROUTE], [full path to route utility])
AC_ARG_VAR([IPROUTE], [full path to ip utility])
AC_ARG_VAR([NETSTAT], [path to netstat utility]) # tests
AC_ARG_VAR([GIT], [path to git utility])
AC_ARG_VAR([SYSTEMD_ASK_PASSWORD], [path to systemd-ask-password utility])
AC_ARG_VAR([SYSTEMD_UNIT_DIR], [Path of systemd unit directory @<:@default=LIBDIR/systemd/system@:>@])
AC_ARG_VAR([TMPFILES_DIR], [Path of tmpfiles directory @<:@default=LIBDIR/tmpfiles.d@:>@])
AC_PATH_PROGS([IFCONFIG], [ifconfig],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([ROUTE], [route],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([IPROUTE], [ip],, [$PATH:/usr/local/sbin:/usr/sbin:/sbin])
AC_PATH_PROGS([SYSTEMD_ASK_PASSWORD], [systemd-ask-password],, [$PATH:/usr/local/bin:/usr/bin:/bin])
AC_CHECK_PROGS([NETSTAT], [netstat], [netstat], [$PATH:/usr/local/sbin:/usr/sbin:/sbin:/etc]) # tests
AC_CHECK_PROGS([GIT], [git]) # optional
AC_DEFINE_UNQUOTED([IFCONFIG_PATH], ["$IFCONFIG"], [Path to ifconfig tool])
AC_DEFINE_UNQUOTED([IPROUTE_PATH], ["$IPROUTE"], [Path to iproute tool])
AC_DEFINE_UNQUOTED([ROUTE_PATH], ["$ROUTE"], [Path to route tool])
AC_DEFINE_UNQUOTED([SYSTEMD_ASK_PASSWORD_PATH], ["$SYSTEMD_ASK_PASSWORD"], [Path to systemd-ask-password tool])

#
#  man page generation - based on python-docutils
#
AC_ARG_VAR([RST2MAN], [path to rst2man utility])
AC_ARG_VAR([RST2HTML], [path to rst2html utility])
AC_CHECK_PROGS([RST2MAN], [rst2man rst2man.py])
AC_CHECK_PROGS([RST2HTML], [rst2html rst2html.py])
AM_CONDITIONAL([HAVE_PYDOCUTILS], [test "${RST2MAN}" -a "${RST2HTML}"])

# Set -std=c99 unless user already specified a -std=
case "${CFLAGS}" in
  *-std=*) ;;
  *)       CFLAGS="${CFLAGS} -std=c99" ;;
esac

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
AX_TYPE_SOCKLEN_T
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([unsigned long])
AC_CHECK_HEADERS([ \
	fcntl.h io.h \
	sys/types.h sys/socket.h \
	unistd.h dlfcn.h \
	netinet/in.h netinet/in_systm.h \
	netinet/tcp.h arpa/inet.h netdb.h \
])
AC_CHECK_HEADERS([ \
	sys/time.h sys/ioctl.h sys/stat.h \
	sys/mman.h sys/file.h sys/wait.h \
	unistd.h libgen.h stropts.h \
	syslog.h pwd.h grp.h termios.h \
	sys/sockio.h sys/uio.h linux/sockios.h \
	linux/types.h linux/errqueue.h poll.h sys/epoll.h err.h \
])

SOCKET_INCLUDES="
#include <stdlib.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif
#ifdef _WIN32
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
	[net/if.h netinet/ip.h resolv.h sys/un.h net/if_utun.h sys/kern_control.h],
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
AC_CHECK_TYPES(
	[in_port_t],
	,
	[AC_DEFINE([in_port_t], [uint16_t], [Workaround missing in_port_t])],
	[[${SOCKET_INCLUDES}]]
)
AC_CHECK_TYPE(
	[struct iphdr],
	[AC_DEFINE([HAVE_IPHDR], [1], [struct iphdr needed for IPv6 support])],
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
        [sa_family_t],
        [AC_DEFINE([HAVE_SA_FAMILY_T], [1], [sa_family_t, needed to hold AF_* info])],
        ,
        [[${SOCKET_INCLUDES}]]
)
AC_CHECK_MEMBER(
	[struct in_pktinfo.ipi_spec_dst],
	[AC_DEFINE([HAVE_IPI_SPEC_DST], [1], [struct in_pktinfo.ipi_spec_dst needed for IP_PKTINFO support])],
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
AC_MSG_CHECKING([anonymous union support])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[
			struct mystruct {
			  union {
			    int m1;
			    char m2;
			  };
			};
		]],
		[[
			struct mystruct s;
			s.m1 = 1; s.m2 = 2;
		]]
	)],
	[
		AC_MSG_RESULT([yes])
		AC_DEFINE([HAVE_ANONYMOUS_UNION_SUPPORT], [], [Compiler supports anonymous unions])
	],
	[AC_MSG_RESULT([no])]
)

saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,--wrap=exit"
AC_MSG_CHECKING([linker supports --wrap])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
		[[
			void exit(int);
			void __real_exit(int);
			void __wrap_exit(int i) {
				__real_exit(i);
			}
		]],
		[[
			exit(0);
		]]
	)],
	[
		AC_MSG_RESULT([yes])
		have_ld_wrap_support=yes
	],
	[AC_MSG_RESULT([no])],
)
LDFLAGS="$saved_LDFLAGS"

dnl We emulate signals in Windows
AC_CHECK_DECLS(
	[SIGHUP],
	,
	[AC_DEFINE([SIGHUP], [1], [SIGHUP replacement])],
	[[
		#include <signal.h>
	]]
)
AC_CHECK_DECLS(
	[SIGINT],
	,
	[AC_DEFINE([SIGINT], [2], [SIGINT replacement])],
	[[
		#include <signal.h>
	]]
)
AC_CHECK_DECLS(
	[SIGUSR1],
	,
	[AC_DEFINE([SIGUSR1], [10], [SIGUSR1 replacement])],
	[[
		#include <signal.h>
	]]
)
AC_CHECK_DECLS(
	[SIGUSR2],
	,
	[AC_DEFINE([SIGUSR2], [12], [SIGUSR2 replacement])],
	[[
		#include <signal.h>
	]]
)
AC_CHECK_DECLS(
	[SIGTERM],
	,
	[AC_DEFINE([SIGTERM], [15], [SIGTERM replacement])],
	[[
		#include <signal.h>
	]]
)

AC_FUNC_FORK

AC_CHECK_FUNCS([ \
	daemon chroot getpwnam setuid nice system dup dup2 \
	syslog openlog mlockall getrlimit getgrnam setgid \
	setgroups flock readv writev time gettimeofday \
	setsid chdir \
	chsize ftruncate execve getpeereid basename dirname access \
	epoll_create strsep \
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
AC_CHECK_FUNCS([sendmsg recvmsg])

LIBS="${old_LIBS}"

# we assume res_init() always exist, but need to find out *where*...
AC_SEARCH_LIBS(__res_init, resolv bind, ,
    AC_SEARCH_LIBS(res_9_init, resolv bind, ,
	AC_SEARCH_LIBS(res_init, resolv bind, , )))

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
		AC_CHECK_HEADERS(
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
		AC_CHECK_HEADERS(
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
	[libpkcs11-helper-1 >= 1.11],
	[have_pkcs11_helper="yes"],
	[]
)


if test "$enable_dco" != "no"; then
	enable_dco_arg="$enable_dco"
	if test "${enable_iproute2}" = "yes"; then
		AC_MSG_WARN([DCO cannot be enabled when using iproute2])
		enable_dco="no"
	fi
	case "$host" in
		*-*-linux*)
			if test "$enable_dco" = "no"; then
				if test "$enable_dco_arg" = "auto"; then
					AC_MSG_WARN([DCO support disabled])
				else
					AC_MSG_ERROR([DCO support can't be enabled])
				fi
			else
				dnl
				dnl Include generic netlink library used to talk to ovpn-dco
				dnl
				PKG_CHECK_MODULES([LIBNL_GENL],
					  [libnl-genl-3.0 >= 3.4.0],
					  [have_libnl="yes"],
					  [
					   AC_MSG_ERROR([libnl-genl-3.0 package not found or too old. Is the development package and pkg-config ${pkg_config_found} installed? Must be version 3.4.0 or newer for DCO])
					  ]
				)
				CFLAGS="${CFLAGS} ${LIBNL_GENL_CFLAGS}"
				LIBS="${LIBS} ${LIBNL_GENL_LIBS}"

				AC_DEFINE(ENABLE_DCO, 1, [Enable shared data channel offload])
				AC_MSG_NOTICE([Enabled ovpn-dco support for Linux])
			fi
			;;
		*-*-freebsd*)
			AC_CHECK_HEADERS([net/if_ovpn.h],
				[
				 LIBS="${LIBS} -lnv"
				 AC_DEFINE(ENABLE_DCO, 1, [Enable data channel offload for FreeBSD])
				 AC_MSG_NOTICE([Enabled ovpn-dco support for FreeBSD])
				],
				[
				 enable_dco="no"
				 AC_MSG_WARN([DCO header not found.])
				]
			)
			if test "$enable_dco" = "no"; then
				if test "$enable_dco_arg" = "auto"; then
					AC_MSG_WARN([DCO support disabled])
				else
					AC_MSG_ERROR([DCO support can't be enabled])
				fi
			fi
			;;
		*-mingw*)
			AC_MSG_NOTICE([NOTE: --enable-dco ignored on Windows because it's always enabled])
			;;
		*)
			AC_MSG_NOTICE([Ignoring --enable-dco on non supported platform])
			;;
	esac
fi

dnl
dnl Depend on libcap-ng on Linux
dnl
case "$host" in
	*-*-linux*)
		# We require pkg-config
		PKG_CHECK_MODULES([LIBCAPNG],
				  [libcap-ng],
				  [],
				  [AC_MSG_ERROR([libcap-ng package not found. Is the development package and pkg-config ${pkg_config_found} installed?])]
		)
		AC_CHECK_HEADER([sys/prctl.h],,[AC_MSG_ERROR([sys/prctl.h not found!])])

		CFLAGS="${CFLAGS} ${LIBCAPNG_CFLAGS}"
		LIBS="${LIBS} ${LIBCAPNG_LIBS}"
		AC_DEFINE(HAVE_LIBCAPNG, 1, [Enable libcap-ng support])
	;;
esac


if test "${with_crypto_library}" = "openssl"; then
	AC_ARG_VAR([OPENSSL_CFLAGS], [C compiler flags for OpenSSL])
	AC_ARG_VAR([OPENSSL_LIBS], [linker flags for OpenSSL])

	if test -z "${OPENSSL_CFLAGS}" -a -z "${OPENSSL_LIBS}"; then
		# if the user did not explicitly specify flags, try to autodetect
		PKG_CHECK_MODULES(
			[OPENSSL],
			[openssl >= 1.0.2],
			[have_openssl="yes"],
			[AC_MSG_WARN([OpenSSL not found by pkg-config ${pkg_config_found}])] # If this fails, we will do another test next
		)
		OPENSSL_LIBS=${OPENSSL_LIBS:--lssl -lcrypto}
	fi

	saved_CFLAGS="${CFLAGS}"
	saved_LIBS="${LIBS}"
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"

	# If pkgconfig check failed or OPENSSL_CFLAGS/OPENSSL_LIBS env vars
	# are used, check the version directly in the OpenSSL include file
	if test "${have_openssl}" != "yes"; then
		AC_MSG_CHECKING([additionally if OpenSSL is available and version >= 1.0.2])
		AC_COMPILE_IFELSE(
			[AC_LANG_PROGRAM(
				[[
#include <openssl/opensslv.h>
				]],
				[[
/*	     Version encoding: MNNFFPPS - see opensslv.h for details */
#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error OpenSSL too old
#endif
				]]
			)],
			[AC_MSG_RESULT([ok])],
			[AC_MSG_ERROR([OpenSSL version too old])]
		)
	fi

	AC_CHECK_FUNCS([SSL_CTX_new],
				   ,
				   [AC_MSG_ERROR([openssl check failed])]
	)

	if test "${with_openssl_engine}" = "auto"; then
	    AC_COMPILE_IFELSE(
				    [AC_LANG_PROGRAM(
					    [[
	    #include <openssl/opensslv.h>
	    #include <openssl/opensslconf.h>
					    ]],
					    [[
	    /*	     Version encoding: MNNFFPPS - see opensslv.h for details */
	    #if OPENSSL_VERSION_NUMBER >= 0x30000000L
	    #error Engine support disabled by default in OpenSSL 3.0+
	    #endif

	    /*	     BoringSSL and LibreSSL >= 3.8.1 removed engine support */
	    #ifdef OPENSSL_NO_ENGINE
	    #error Engine support disabled in openssl/opensslconf.h
	    #endif
					    ]]
				    )],
				    [have_openssl_engine="yes"],
				    [have_openssl_engine="no"]
	    )
	    if test "${have_openssl_engine}" = "yes"; then
		AC_CHECK_FUNCS(
		    [ \
			ENGINE_load_builtin_engines \
			ENGINE_register_all_complete \
		    ],
		    ,
		    [have_openssl_engine="no"; break]
		)
	    fi
	else
	    have_openssl_engine="${with_openssl_engine}"
	    if test "${have_openssl_engine}" = "yes"; then
		AC_CHECK_FUNCS(
		    [ \
			ENGINE_load_builtin_engines \
			ENGINE_register_all_complete \
		    ],
		    ,
		    [AC_MSG_ERROR([OpenSSL engine support not found])]
		)
	    fi
	fi
	if test "${have_openssl_engine}" = "yes"; then
		AC_DEFINE([HAVE_OPENSSL_ENGINE], [1], [OpenSSL engine support available])
	fi

	AC_CHECK_FUNC(
		[EVP_aes_256_gcm],
		,
		[AC_MSG_ERROR([OpenSSL check for AES-256-GCM support failed])]
	)

	# All supported OpenSSL version (>= 1.0.2)
	# have this feature
	have_export_keying_material="yes"

	CFLAGS="${saved_CFLAGS}"
	LIBS="${saved_LIBS}"

	AC_DEFINE([ENABLE_CRYPTO_OPENSSL], [1], [Use OpenSSL library])
	CRYPTO_CFLAGS="${OPENSSL_CFLAGS}"
	CRYPTO_LIBS="${OPENSSL_LIBS}"
elif test "${with_crypto_library}" = "mbedtls"; then
	AC_ARG_VAR([MBEDTLS_CFLAGS], [C compiler flags for mbedtls])
	AC_ARG_VAR([MBEDTLS_LIBS], [linker flags for mbedtls])

	saved_CFLAGS="${CFLAGS}"
	saved_LIBS="${LIBS}"

	if test -z "${MBEDTLS_CFLAGS}" -a -z "${MBEDTLS_LIBS}"; then
		# if the user did not explicitly specify flags, try to autodetect
		LIBS="${LIBS} -lmbedtls -lmbedx509 -lmbedcrypto"
		AC_CHECK_LIB(
			[mbedtls],
			[mbedtls_ssl_init],
			[MBEDTLS_LIBS="-lmbedtls -lmbedx509 -lmbedcrypto"],
			[AC_MSG_ERROR([Could not find mbed TLS.])],
			[${PKCS11_HELPER_LIBS}]
		)
	fi

	CFLAGS="${MBEDTLS_CFLAGS} ${PKCS11_HELPER_CFLAGS} ${CFLAGS}"
	LIBS="${MBEDTLS_LIBS} ${PKCS11_HELPER_LIBS} ${LIBS}"

	AC_MSG_CHECKING([mbedtls version])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
			[[
#include <mbedtls/version.h>
			]],
			[[
#if MBEDTLS_VERSION_NUMBER < 0x02000000 || (MBEDTLS_VERSION_NUMBER >= 0x03000000 && MBEDTLS_VERSION_NUMBER < 0x03020100)
#error invalid version
#endif
			]]
		)],
		[AC_MSG_RESULT([ok])],
		[AC_MSG_ERROR([mbed TLS version >= 2.0.0 or >= 3.2.1 required])]
	)

	AC_CHECK_HEADER(
		psa/crypto.h,
		[AC_DEFINE([HAVE_MBEDTLS_PSA_CRYPTO_H], [1], [yes])],
		[AC_DEFINE([HAVE_MBEDTLS_PSA_CRYPTO_H], [0], [no])]
	)

	AC_CHECK_FUNCS(
		[ \
			mbedtls_cipher_write_tag \
			mbedtls_cipher_check_tag \
		],
		,
		[AC_MSG_ERROR([mbed TLS check for AEAD support failed])]
	)

	AC_CHECK_FUNC(
		[mbedtls_ssl_tls_prf],
		[AC_DEFINE([HAVE_MBEDTLS_SSL_TLS_PRF], [1], [yes])],
		[AC_DEFINE([HAVE_MBEDTLS_SSL_TLS_PRF], [0], [no])]
	)

	have_export_keying_material="yes"
	AC_CHECK_FUNC(
		[mbedtls_ssl_conf_export_keys_ext_cb],
		[AC_DEFINE([HAVE_MBEDTLS_SSL_CONF_EXPORT_KEYS_EXT_CB], [1], [yes])],
		[AC_DEFINE([HAVE_MBEDTLS_SSL_CONF_EXPORT_KEYS_EXT_CB], [0], [no])]
	)
	if test "x$ac_cv_func_mbedtls_ssl_conf_export_keys_ext_cb" != xyes; then
		AC_CHECK_FUNC(
			[mbedtls_ssl_set_export_keys_cb],
			[AC_DEFINE([HAVE_MBEDTLS_SSL_SET_EXPORT_KEYS_CB], [1], [yes])],
			[AC_DEFINE([HAVE_MBEDTLS_SSL_SET_EXPORT_KEYS_CB], [0], [no])]
		)
		if test "x$ac_cv_func_mbedtls_ssl_set_export_keys_cb" != xyes; then
			have_export_keying_material="no"
		fi
	fi

	AC_CHECK_FUNC(
		[mbedtls_ctr_drbg_update_ret],
		AC_DEFINE([HAVE_MBEDTLS_CTR_DRBG_UPDATE_RET], [1],
			  [Use mbedtls_ctr_drbg_update_ret from mbed TLS]),
	)

	CFLAGS="${saved_CFLAGS}"
	LIBS="${saved_LIBS}"
	AC_DEFINE([ENABLE_CRYPTO_MBEDTLS], [1], [Use mbed TLS library])
	CRYPTO_CFLAGS="${MBEDTLS_CFLAGS}"
	CRYPTO_LIBS="${MBEDTLS_LIBS}"

elif test "${with_crypto_library}" = "wolfssl"; then
	AC_ARG_VAR([WOLFSSL_CFLAGS], [C compiler flags for wolfssl. The include directory should
								  contain the regular wolfSSL header files but also the
								  wolfSSL OpenSSL header files. Ex: -I/usr/local/include
								  -I/usr/local/include/wolfssl])
	AC_ARG_VAR([WOLFSSL_LIBS], [linker flags for wolfssl])

	saved_CFLAGS="${CFLAGS}"
	saved_LIBS="${LIBS}"

	if test -z "${WOLFSSL_CFLAGS}" -a -z "${WOLFSSL_LIBS}"; then
		# if the user did not explicitly specify flags, try to autodetect
		PKG_CHECK_MODULES(
			[WOLFSSL],
			[wolfssl],
			[],
			[AC_MSG_ERROR([Could not find wolfSSL using pkg-config ${pkg_config_found}])]
		)
		PKG_CHECK_VAR(
			[WOLFSSL_INCLUDEDIR],
			[wolfssl],
			[includedir],
			[],
			[AC_MSG_ERROR([Could not find wolfSSL includedir variable.])]
		)
		WOLFSSL_CFLAGS="${WOLFSSL_CFLAGS} -I${WOLFSSL_INCLUDEDIR}/wolfssl"
	fi
	saved_CFLAGS="${CFLAGS}"
	saved_LIBS="${LIBS}"
	CFLAGS="${CFLAGS} ${WOLFSSL_CFLAGS}"
	LIBS="${LIBS} ${WOLFSSL_LIBS}"

	AC_CHECK_LIB(
		[wolfssl],
		[wolfSSL_Init],
		[],
		[AC_MSG_ERROR([Could not link wolfSSL library.])]
	)
	AC_CHECK_HEADER([wolfssl/options.h],,[AC_MSG_ERROR([wolfSSL header wolfssl/options.h not found!])])

	# wolfSSL signal EKM support
	have_export_keying_material="yes"

	if test "${enable_wolfssl_options_h}" = "yes"; then
		AC_DEFINE([EXTERNAL_OPTS_OPENVPN], [1], [Include options.h from wolfSSL library])
	else
		AC_DEFINE([WOLFSSL_USER_SETTINGS], [1], [Use custom user_settings.h file for wolfSSL library])
	fi

	have_export_keying_material="yes"

	CFLAGS="${saved_CFLAGS}"
	LIBS="${saved_LIBS}"

	AC_DEFINE([ENABLE_CRYPTO_WOLFSSL], [1], [Use wolfSSL crypto library])
	AC_DEFINE([ENABLE_CRYPTO_OPENSSL], [1], [Use wolfSSL openssl compatibility layer])
	CRYPTO_CFLAGS="${WOLFSSL_CFLAGS}"
	CRYPTO_LIBS="${WOLFSSL_LIBS}"
else
	AC_MSG_ERROR([Invalid crypto library: ${with_crypto_library}])
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

dnl
dnl check for LZ4 library
dnl

AC_ARG_VAR([LZ4_CFLAGS], [C compiler flags for lz4])
AC_ARG_VAR([LZ4_LIBS], [linker flags for lz4])
if test "$enable_lz4" = "yes" && test "$enable_comp_stub" = "no"; then
    if test -z "${LZ4_CFLAGS}" -a -z "${LZ4_LIBS}"; then
	# if the user did not explicitly specify flags, try to autodetect
	PKG_CHECK_MODULES([LZ4],
			  [liblz4 >= 1.7.1 liblz4 < 100],
			  [have_lz4="yes"],
			  [LZ4_LIBS="-llz4"] # If this fails, we will do another test next.
					     # We also add set LZ4_LIBS otherwise the
					     # linker will not know about the lz4 library
	)
    fi

    saved_CFLAGS="${CFLAGS}"
    saved_LIBS="${LIBS}"
    CFLAGS="${CFLAGS} ${LZ4_CFLAGS}"
    LIBS="${LIBS} ${LZ4_LIBS}"

    # If pkgconfig check failed or LZ4_CFLAGS/LZ4_LIBS env vars
    # are used, check the version directly in the LZ4 include file
    if test "${have_lz4}" != "yes"; then
	AC_CHECK_HEADERS([lz4.h],
			 [have_lz4h="yes"],
			 [])

	if test "${have_lz4h}" = "yes" ; then
	    AC_MSG_CHECKING([additionally if system LZ4 version >= 1.7.1])
	    AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([[
#include <lz4.h>
				 ]],
				 [[
/* Version encoding: MMNNPP (Major miNor Patch) - see lz4.h for details */
#if LZ4_VERSION_NUMBER < 10701L
#error LZ4 is too old
#endif
				 ]]
				)],
		[
		    AC_MSG_RESULT([ok])
		    have_lz4="yes"
		],
		[AC_MSG_ERROR([system LZ4 library is too old])]
	    )
	fi
    fi

    # Double check we have a few needed functions
    if test "${have_lz4}" = "yes" ; then
	AC_CHECK_LIB([lz4],
		     [LZ4_compress_default],
		     [],
		     [have_lz4="no"])
	AC_CHECK_LIB([lz4],
		     [LZ4_decompress_safe],
		     [],
		     [have_lz4="no"])
    fi

    if test "${have_lz4}" != "yes" ; then
	AC_MSG_ERROR([No compatible LZ4 compression library found. Consider --disable-lz4])
	LZ4_LIBS=""
    fi
    OPTIONAL_LZ4_CFLAGS="${LZ4_CFLAGS}"
    OPTIONAL_LZ4_LIBS="${LZ4_LIBS}"
    AC_DEFINE(ENABLE_LZ4, [1], [Enable LZ4 compression library])
    CFLAGS="${saved_CFLAGS}"
    LIBS="${saved_LIBS}"
fi


dnl
dnl Check for systemd
dnl
AM_CONDITIONAL([ENABLE_SYSTEMD], [test "${enable_systemd}" = "yes"])
if test "$enable_systemd" = "yes" ; then
    PKG_CHECK_MODULES([libsystemd], [systemd libsystemd],
                      [],
                      [PKG_CHECK_MODULES([libsystemd], [libsystemd-daemon])]
                      )

    PKG_CHECK_EXISTS( [libsystemd > 216],
                     [AC_DEFINE([SYSTEMD_NEWER_THAN_216], [1],
                           [systemd is newer than v216])]
                    )

    AC_CHECK_HEADERS(systemd/sd-daemon.h,
       ,
       [
	   AC_MSG_ERROR([systemd development headers not found.])
       ])

    saved_LIBS="${LIBS}"
    LIBS="${LIBS} ${libsystemd_LIBS}"
    AC_CHECK_FUNCS([sd_booted], [], [AC_MSG_ERROR([systemd library is missing sd_booted()])])
    OPTIONAL_SYSTEMD_LIBS="${libsystemd_LIBS}"
    AC_DEFINE(ENABLE_SYSTEMD, 1, [Enable systemd integration])
    LIBS="${saved_LIBS}"

    if test -n "${SYSTEMD_UNIT_DIR}"; then
        systemdunitdir="${SYSTEMD_UNIT_DIR}"
    else
        systemdunitdir="\${libdir}/systemd/system"
    fi

    if test -n "${TMPFILES_DIR}"; then
        tmpfilesdir="${TMPFILES_DIR}"
    else
        tmpfilesdir="\${libdir}/tmpfiles.d"
    fi
fi


AC_MSG_CHECKING([git checkout])
GIT_CHECKOUT="no"
if test -n "${GIT}" -a -d "${srcdir}/.git"; then
	AC_DEFINE([HAVE_CONFIG_VERSION_H], [1], [extra version available in config-version.h])
	GIT_CHECKOUT="yes"
fi
AC_MSG_RESULT([${GIT_CHECKOUT}])

dnl enable --x509-username-field feature if requested
if test "${enable_x509_alt_username}" = "yes"; then
	if test "${with_crypto_library}" = "mbedtls" ; then
		AC_MSG_ERROR([mbed TLS does not support the --x509-username-field feature])
	fi

	AC_DEFINE([ENABLE_X509ALTUSERNAME], [1], [Enable --x509-username-field feature])
fi

test "${enable_management}" = "yes" && AC_DEFINE([ENABLE_MANAGEMENT], [1], [Enable management server capability])
test "${enable_debug}" = "yes" && AC_DEFINE([ENABLE_DEBUG], [1], [Enable debugging support])
test "${enable_small}" = "yes" && AC_DEFINE([ENABLE_SMALL], [1], [Enable smaller executable size])
test "${enable_fragment}" = "yes" && AC_DEFINE([ENABLE_FRAGMENT], [1], [Enable internal fragmentation support])
test "${enable_port_share}" = "yes" && AC_DEFINE([ENABLE_PORT_SHARE], [1], [Enable TCP Server port sharing])

test "${enable_crypto_ofb_cfb}" = "yes" && AC_DEFINE([ENABLE_OFB_CFB_MODE], [1], [Enable OFB and CFB cipher modes])
if test "${have_export_keying_material}" = "yes"; then
	AC_DEFINE(
		[HAVE_EXPORT_KEYING_MATERIAL], [1],
		[Crypto library supports keying material exporter]
	)
fi
OPTIONAL_CRYPTO_CFLAGS="${OPTIONAL_CRYPTO_CFLAGS} ${CRYPTO_CFLAGS}"
OPTIONAL_CRYPTO_LIBS="${OPTIONAL_CRYPTO_LIBS} ${CRYPTO_LIBS}"

if test "${enable_plugins}" = "yes"; then
	OPTIONAL_DL_LIBS="${DL_LIBS}"
	AC_DEFINE([ENABLE_PLUGIN], [1], [Enable plug-in support])
else
	enable_plugin_auth_pam="no"
	enable_plugin_down_root="no"
fi

AM_CONDITIONAL([HAVE_SITNL], [false])

if test "${enable_iproute2}" = "yes"; then
	test "${enable_dco}" = "yes" && AC_MSG_ERROR([iproute2 support cannot be enabled when using DCO])
	test -z "${IPROUTE}" && AC_MSG_ERROR([ip utility is required but missing])
	AC_DEFINE([ENABLE_IPROUTE], [1], [enable iproute2 support])
else if test "${have_sitnl}" = "yes"; then
	AC_DEFINE([ENABLE_SITNL], [1], [enable sitnl support])
	AM_CONDITIONAL([HAVE_SITNL], [true])
else if test "${WIN32}" != "yes" -a "${have_sitnl}" != "yes"; then
	test -z "${ROUTE}" && AC_MSG_ERROR([route utility is required but missing])
	test -z "${IFCONFIG}" && AC_MSG_ERROR([ifconfig utility is required but missing])
fi
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
if test "${enable_comp_stub}" = "yes"; then
	test "${enable_lzo}" = "yes" && AC_MSG_ERROR([Cannot have both comp stub and lzo enabled (use --disable-lzo)])
	test "${enable_lz4}" = "yes" && AC_MSG_ERROR([Cannot have both comp stub and LZ4 enabled (use --disable-lz4)])
	AC_DEFINE([ENABLE_COMP_STUB], [1], [Enable compression stub capability])
fi

if test "${enable_pkcs11}" = "yes"; then
	test "${have_pkcs11_helper}" != "yes" && AC_MSG_ERROR([PKCS11 enabled but libpkcs11-helper is missing])
	OPTIONAL_PKCS11_HELPER_CFLAGS="${PKCS11_HELPER_CFLAGS}"
	OPTIONAL_PKCS11_HELPER_LIBS="${PKCS11_HELPER_LIBS}"
	AC_DEFINE([ENABLE_PKCS11], [1], [Enable PKCS11])
	PKG_CHECK_MODULES(
		[P11KIT],
		[p11-kit-1],
		[proxy_module="`$PKG_CONFIG --variable=proxy_module p11-kit-1`"
		 AC_DEFINE_UNQUOTED([DEFAULT_PKCS11_MODULE], "${proxy_module}", [p11-kit proxy])],
		[]
	)
fi

# When testing a compiler option, we add -Werror to force
# an error when the option is unsupported. This is not
# required for gcc, but some compilers such as clang needs it.
AC_DEFUN([ACL_CHECK_ADD_COMPILE_FLAGS], [
    old_cflags="$CFLAGS"
    CFLAGS="$1 -Werror $CFLAGS"
    AC_MSG_CHECKING([whether the compiler accepts $1])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM()], [AC_MSG_RESULT([yes])]; CFLAGS="$1 $old_cflags",
        [AC_MSG_RESULT([no]); CFLAGS="$old_cflags"])]
)

ACL_CHECK_ADD_COMPILE_FLAGS([-Wno-stringop-truncation])
ACL_CHECK_ADD_COMPILE_FLAGS([-Wall])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -pedantic"
	AC_DEFINE([PEDANTIC], [1], [Enable pedantic mode])
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wsign-compare -Wuninitialized"
fi
if test "${enable_werror}" = "yes"; then
	CFLAGS="${CFLAGS} -Werror"
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

if test "${enable_async_push}" = "yes"; then
	case "$host" in
		*-*-freebsd*)
			PKG_CHECK_MODULES(
				[OPTIONAL_INOTIFY],
				[libinotify],
				[
					AC_DEFINE([HAVE_SYS_INOTIFY_H])
					AC_DEFINE([ENABLE_ASYNC_PUSH], [1], [Enable async push])
				]
			)
		;;
		*)
			AC_CHECK_HEADERS(
				[sys/inotify.h],
				AC_DEFINE([ENABLE_ASYNC_PUSH], [1], [Enable async push]),
				AC_MSG_ERROR([inotify.h not found.])
			)
		;;
	esac
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
AC_SUBST([OPTIONAL_LZ4_CFLAGS])
AC_SUBST([OPTIONAL_LZ4_LIBS])
AC_SUBST([OPTIONAL_SYSTEMD_LIBS])
AC_SUBST([OPTIONAL_PKCS11_HELPER_CFLAGS])
AC_SUBST([OPTIONAL_PKCS11_HELPER_LIBS])
AC_SUBST([OPTIONAL_INOTIFY_CFLAGS])
AC_SUBST([OPTIONAL_INOTIFY_LIBS])

AC_SUBST([PLUGIN_AUTH_PAM_CFLAGS])
AC_SUBST([PLUGIN_AUTH_PAM_LIBS])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([GIT_CHECKOUT], [test "${GIT_CHECKOUT}" = "yes"])
AM_CONDITIONAL([ENABLE_PLUGIN_AUTH_PAM], [test "${enable_plugin_auth_pam}" = "yes"])
AM_CONDITIONAL([ENABLE_PLUGIN_DOWN_ROOT], [test "${enable_plugin_down_root}" = "yes"])
AM_CONDITIONAL([HAVE_LD_WRAP_SUPPORT], [test "${have_ld_wrap_support}" = "yes"])
AM_CONDITIONAL([OPENSSL_ENGINE], [test "${have_openssl_engine}" = "yes"])

sampledir="\$(docdir)/sample"
AC_SUBST([plugindir])
AC_SUBST([sampledir])

AC_SUBST([systemdunitdir])
AC_SUBST([tmpfilesdir])

AC_ARG_ENABLE(
     [unit-tests],
     [AS_HELP_STRING([--disable-unit-tests],
                     [Disables building and running the unit tests suite])],
     [],
     [enable_unit_tests="yes"]
)

# Check if cmocka is available - needed for unit testing
PKG_CHECK_MODULES(
	[CMOCKA], [cmocka],
	[have_cmocka="yes"],
	[AC_MSG_WARN([cmocka.pc not found on the system using pkg-config ${pkg_config_found}.  Unit tests disabled])]
)
AM_CONDITIONAL([ENABLE_UNITTESTS], [test "${enable_unit_tests}" = "yes" -a "${have_cmocka}" = "yes" ])
AC_SUBST([ENABLE_UNITTESTS])

TEST_LDFLAGS="${OPTIONAL_CRYPTO_LIBS} ${OPTIONAL_PKCS11_HELPER_LIBS}"
TEST_LDFLAGS="${TEST_LDFLAGS} ${OPTIONAL_LZO_LIBS} ${CMOCKA_LIBS}"
TEST_CFLAGS="${OPTIONAL_CRYPTO_CFLAGS} ${OPTIONAL_PKCS11_HELPER_CFLAGS}"
TEST_CFLAGS="${TEST_CFLAGS} ${OPTIONAL_LZO_CFLAGS}"
TEST_CFLAGS="${TEST_CFLAGS} -I\$(top_srcdir)/include ${CMOCKA_CFLAGS}"

AC_SUBST([TEST_LDFLAGS])
AC_SUBST([TEST_CFLAGS])

AC_CONFIG_FILES([
	version.sh
	Makefile
	build/Makefile
	distro/Makefile
	distro/systemd/Makefile
	doc/Makefile
	doc/doxygen/Makefile
	doc/doxygen/openvpn.doxyfile
	include/Makefile
	sample/sample-plugins/Makefile
	src/Makefile
	src/compat/Makefile
	src/openvpn/Makefile
	src/openvpnmsica/Makefile
	src/openvpnserv/Makefile
	src/plugins/Makefile
	src/plugins/auth-pam/Makefile
	src/plugins/down-root/Makefile
	src/tapctl/Makefile
	tests/Makefile
        tests/unit_tests/Makefile
        tests/unit_tests/example_test/Makefile
        tests/unit_tests/openvpn/Makefile
        tests/unit_tests/plugins/Makefile
        tests/unit_tests/plugins/auth-pam/Makefile
	sample/Makefile
])
AC_CONFIG_FILES([tests/t_client.sh], [chmod +x tests/t_client.sh])
AC_OUTPUT
