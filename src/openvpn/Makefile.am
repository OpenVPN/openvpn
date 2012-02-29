#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

INCLUDES = -I$(top_srcdir)/include

sbin_PROGRAMS = openvpn

openvpn_SOURCES = \
	base64.c base64.h \
	basic.h \
	buffer.c buffer.h \
	circ_list.h \
	clinat.c clinat.h \
	common.h \
	compat.h compat.c \
	crypto.c crypto.h crypto_backend.h \
	crypto_openssl.c crypto_openssl.h \
	crypto_polarssl.c crypto_polarssl.h \
	dhcp.c dhcp.h \
	errlevel.h \
	error.c error.h \
	event.c event.h \
	fdmisc.c fdmisc.h \
	forward.c forward.h forward-inline.h \
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
	mroute.c mroute.h \
	mss.c mss.h \
	mstats.c mstats.h \
	mtcp.c mtcp.h \
	mtu.c mtu.h \
	mudp.c mudp.h \
	multi.c multi.h \
	ntlm.c ntlm.h \
	occ.c occ.h occ-inline.h \
	pkcs11.c pkcs11.h pkcs11_backend.h \
	pkcs11_openssl.c \
	pkcs11_polarssl.c \
	openvpn.c openvpn.h \
	options.c options.h \
	otime.c otime.h \
	packet_id.c packet_id.h \
	perf.c perf.h \
	pf.c pf.h pf-inline.h \
	ping.c ping.h ping-inline.h \
	plugin.c plugin.h \
	pool.c pool.h \
	proto.c proto.h \
	proxy.c proxy.h \
	ps.c ps.h \
	push.c push.h \
	pushlist.h \
	reliable.c reliable.h \
	route.c route.h \
	schedule.c schedule.h \
	session_id.c session_id.h \
	shaper.c shaper.h \
	sig.c sig.h \
	socket.c socket.h \
	socks.c socks.h \
	ssl.c ssl.h  ssl_backend.h \
	ssl_openssl.c ssl_openssl.h \
	ssl_polarssl.c ssl_polarssl.h \
	ssl_common.h \
	ssl_verify.c ssl_verify.h ssl_verify_backend.h \
	ssl_verify_openssl.c ssl_verify_openssl.h \
	ssl_verify_polarssl.c ssl_verify_polarssl.h \
	status.c status.h \
	syshead.h \
	tun.c tun.h \
	win32.h win32.c \
	cryptoapi.h cryptoapi.c
if WIN32
openvpn_SOURCES += openvpn_win32_resources.rc
openvpn_LDADD = -lgdi32 -lws2_32 -lwininet -lcrypt32 -liphlpapi -lwinmm -lshell32
endif
