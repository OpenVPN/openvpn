#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2021 OpenVPN Inc <sales@openvpn.net>
#  Copyright (C) 2006-2012 Alon Bar-Lev <alon.barlev@gmail.com>
#

include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = \
	openvpnserv.vcxproj \
	openvpnserv.vcxproj.filters

AM_CPPFLAGS = \
	-I$(top_srcdir)/include -I$(top_srcdir)/src/openvpn -I$(top_srcdir)/src/compat

if WIN32
sbin_PROGRAMS = openvpnserv
openvpnserv_CFLAGS = \
	-municode -D_UNICODE \
	-UNTDDI_VERSION -U_WIN32_WINNT \
	-D_WIN32_WINNT=_WIN32_WINNT_VISTA
openvpnserv_LDADD = -ladvapi32 -luserenv -liphlpapi -lfwpuclnt -lrpcrt4 -lshlwapi -lnetapi32 -lws2_32 -lntdll
endif

openvpnserv_SOURCES = \
        common.c \
	automatic.c \
	interactive.c \
	service.c service.h \
	validate.c validate.h \
	$(top_srcdir)/src/openvpn/block_dns.c $(top_srcdir)/src/openvpn/block_dns.h \
	openvpnserv_resources.rc \
	$(top_srcdir)/src/openvpn/ring_buffer.h
