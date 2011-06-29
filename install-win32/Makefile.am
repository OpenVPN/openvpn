#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program (see the file COPYING included with this
#  distribution); if not, write to the Free Software Foundation, Inc.,
#  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_DATA = \
	openssl \
	GetWindowsVersion.nsi \
	build-pkcs11-helper.sh \
	buildinstaller \
	ddk-common \
	doclean \
	dosname.pl \
	getgui \
	getopenssl \
	getpkcs11helper \
	getprebuilt \
	getxgui \
	ifdef.pl \
	m4todef.pl \
	macro.pl \
	makeopenvpn \
	maketap \
	maketapinstall \
	maketext \
	openvpn.nsi \
	setpath.nsi \
	settings.in \
	trans.pl \
	u2d.c \
	winconfig

if WIN32

nodist_doc_DATA = tmp/license.txt

confdir = $(win32datadir)/config
nodist_conf_DATA = \
	tmp/openssl-1.0.0.cnf \
	tmp/client.ovpn \
	tmp/server.ovpn
dist_conf_DATA = \
	sample.ovpn

easyrsadir = $(win32datadir)/easy-rsa/Windows
nodist_easyrsa_DATA = \
	$(top_srcdir)/easy-rsa/Windows/*

keysdir = $(win32datadir)/sample-keys
nodist_keys_DATA = \
	$(top_srcdir)/sample-keys/*

tmp:
	mkdir tmp

tmp/client.ovpn:	tmp $(top_srcdir)/sample-config-files/client.conf
	cp $(top_srcdir)/sample-config-files/client.conf tmp/client.ovpn

tmp/server.ovpn:	tmp $(top_srcdir)/sample-config-files/server.conf
	cp $(top_srcdir)/sample-config-files/server.conf tmp/server.ovpn

tmp/license.txt:	tmp $(top_srcdir)/COPYING $(top_srcdir)/COPYRIGHT.GPL
	cat $(top_srcdir)/COPYING $(top_srcdir)/COPYRIGHT.GPL > tmp/license.txt

tmp/openssl-1.0.0.cnf:	tmp $(top_srcdir)/easy-rsa/2.0/openssl-1.0.0.cnf
	cp $(top_srcdir)/easy-rsa/2.0/openssl-1.0.0.cnf tmp/openssl-1.0.0.cnf

clean-local:
	-rm -fr tmp

else

dist_noinst_DATA += sample.ovpn

endif

