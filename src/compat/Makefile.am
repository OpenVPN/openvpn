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

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

EXTRA_DIST = \
	compat.vcxproj \
	compat.vcxproj.filters

noinst_LTLIBRARIES = libcompat.la

libcompat_la_SOURCES = \
	compat.h \
	compat-stdbool.h \
	compat-dirname.c \
	compat-basename.c \
	compat-gettimeofday.c \
	compat-daemon.c \
	compat-inet_ntop.c \
	compat-inet_pton.c
