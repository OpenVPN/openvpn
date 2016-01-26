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

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = \
	openvpnserv.vcxproj \
	openvpnserv.vcxproj.filters

AM_CPPFLAGS = \
	-I$(top_srcdir)/include

if WIN32
sbin_PROGRAMS = openvpnserv
openvpnserv_CFLAGS = \
	-municode -D_UNICODE \
	-UNTDDI_VERSION -U_WIN32_WINNT \
	-D_WIN32_WINNT=_WIN32_WINNT_VISTA
openvpnserv_LDADD = -ladvapi32 -luserenv -liphlpapi -lws2_32
endif

openvpnserv_SOURCES = \
        common.c \
	automatic.c \
	interactive.c \
	service.c service.h \
	openvpnserv_resources.rc
