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

if WIN32
sbin_PROGRAMS = openvpnserv
endif

openvpnserv_SOURCES = \
	openvpnserv.c \
	service.h service.c \
	openvpnserv_resources.rc
