#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

EXTRA_DIST = \
	openvpn.vcxproj \
	openvpn.vcxproj.filters \
	openvpn.manifest

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src/compat

AM_CFLAGS = \
	$(TAP_CFLAGS) \
	$(OPTIONAL_CRYPTO_CFLAGS) \
	$(OPTIONAL_LZO_CFLAGS) \
	$(OPTIONAL_LZ4_CFLAGS) \
	$(OPTIONAL_PKCS11_HELPER_CFLAGS) \
	$(OPTIONAL_INOTIFY_CFLAGS) \
	-DPLUGIN_LIBDIR=\"${plugindir}\"

if WIN32
# we want unicode entry point but not the macro
AM_CFLAGS += -municode -UUNICODE
endif

sbin_PROGRAMS = openvpn

openvpn_SOURCES = \
	argv.c argv.h \
	auth_token.c auth_token.h \
	base64.c base64.h \
	basic.h \
	buffer.c buffer.h \
	circ_list.h \
	clinat.c clinat.h \
	common.h \
	comp.c comp.h compstub.c \
	comp-lz4.c comp-lz4.h \
	crypto.c crypto.h crypto_backend.h \
	crypto_openssl.c crypto_openssl.h \
	crypto_mbedtls.c crypto_mbedtls.h \
	dhcp.c dhcp.h \
	env_set.c env_set.h \
	errlevel.h \
	error.c error.h \
	event.c event.h \
	fdmisc.c fdmisc.h \
	forward.c forward.h \
	fragment.c fragment.h \
	gremlin.c gremlin.h \
	helper.c helper.h \
	httpdigest.c httpdigest.h \
	lladdr.c lladdr.h \
	init.c init.h \
	integer.h \
	interval.c interval.h \
	list.c list.h \
	lzo.c lzo.h \
	manage.c manage.h \
	mbuf.c mbuf.h \
	memdbg.h \
	misc.c misc.h \
	platform.c platform.h \
	console.c console.h console_builtin.c console_systemd.c \
	mroute.c mroute.h \
	mss.c mss.h \
	mstats.c mstats.h \
	mtcp.c mtcp.h \
	mtu.c mtu.h \
	mudp.c mudp.h \
	multi.c multi.h \
	networking_iproute2.c networking_iproute2.h \
	networking_sitnl.c networking_sitnl.h \
	networking.h \
	ntlm.c ntlm.h \
	occ.c occ.h \
	openssl_compat.h \
	pkcs11.c pkcs11.h pkcs11_backend.h \
	pkcs11_openssl.c \
	pkcs11_mbedtls.c \
	openvpn.c openvpn.h \
	options.c options.h \
	otime.c otime.h \
	packet_id.c packet_id.h \
	perf.c perf.h \
	pf.c pf.h \
	ping.c ping.h \
	plugin.c plugin.h \
	pool.c pool.h \
	proto.c proto.h \
	proxy.c proxy.h \
	ps.c ps.h \
	push.c push.h \
	pushlist.h \
	reliable.c reliable.h \
	route.c route.h \
	run_command.c run_command.h \
	schedule.c schedule.h \
	session_id.c session_id.h \
	shaper.c shaper.h \
	sig.c sig.h \
	socket.c socket.h \
	socks.c socks.h \
	ssl.c ssl.h  ssl_backend.h \
	ssl_openssl.c ssl_openssl.h \
	ssl_mbedtls.c ssl_mbedtls.h \
	ssl_ncp.c ssl_ncp.h \
	ssl_common.h \
	ssl_verify.c ssl_verify.h ssl_verify_backend.h \
	ssl_verify_openssl.c ssl_verify_openssl.h \
	ssl_verify_mbedtls.c ssl_verify_mbedtls.h \
	status.c status.h \
	syshead.h \
	tls_crypt.c tls_crypt.h \
	tun.c tun.h \
	vlan.c vlan.h \
	win32.h win32.c \
	cryptoapi.h cryptoapi.c
openvpn_LDADD = \
	$(top_builddir)/src/compat/libcompat.la \
	$(SOCKETS_LIBS) \
	$(OPTIONAL_LZO_LIBS) \
	$(OPTIONAL_LZ4_LIBS) \
	$(OPTIONAL_PKCS11_HELPER_LIBS) \
	$(OPTIONAL_CRYPTO_LIBS) \
	$(OPTIONAL_SELINUX_LIBS) \
	$(OPTIONAL_SYSTEMD_LIBS) \
	$(OPTIONAL_DL_LIBS) \
	$(OPTIONAL_INOTIFY_LIBS)
if WIN32
openvpn_SOURCES += openvpn_win32_resources.rc block_dns.c block_dns.h ring_buffer.h
openvpn_LDADD += -lgdi32 -lws2_32 -lwininet -lcrypt32 -liphlpapi -lwinmm -lfwpuclnt -lrpcrt4 -lncrypt -lsetupapi
endif
