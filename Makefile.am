#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
#  Copyright (C) 2010      David Sommerseth <dazo@users.sourceforge.net>
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

LDADD = @LIBOBJS@
.PHONY: plugin

# This option prevents autoreconf from overriding our COPYING and
# INSTALL targets:
AUTOMAKE_OPTIONS = foreign

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/openvpn.spec
CLEANFILES = openvpn.8.html configure.h

EXTRA_DIST = \
	easy-rsa \
	sample-config-files \
	sample-keys \
	sample-scripts \
	suse \
	tap-win32 \
	contrib \
	debug \
	plugin \
	win

SUBDIRS = \
	images \
	service-win32 \
	install-win32

TESTS = t_client.sh t_lpback.sh t_cltsrv.sh
sbin_PROGRAMS = openvpn

dist_doc_DATA = \
	management/management-notes.txt

dist_noinst_SCRIPTS = \
	$(TESTS) \
	doclean \
	domake-win \
	t_cltsrv-down.sh \
	configure_h.awk configure_log.awk

dist_noinst_DATA = \
	openvpn.spec \
	COPYRIGHT.GPL \
	PORTS \
	INSTALL-win32.txt \
	service-win32/msvc.mak

openvpn_SOURCES = \
        base64.c base64.h \
	basic.h \
	buffer.c buffer.h \
	circ_list.h \
	common.h \
	crypto.c crypto.h \
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
	mtcp.c mtcp.h \
	mtu.c mtu.h \
	mudp.c mudp.h \
	multi.c multi.h \
        ntlm.c ntlm.h \
	occ.c occ.h occ-inline.h \
	pkcs11.c pkcs11.h \
	openvpn.c openvpn.h \
	openvpn-plugin.h \
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
	ieproxy.h ieproxy.c \
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
	ssl.c ssl.h \
	status.c status.h \
	syshead.h \
	tun.c tun.h \
	win32.h win32.c \
	cryptoapi.h cryptoapi.c

nodist_openvpn_SOURCES = configure.h
options.$(OBJEXT): configure.h

configure.h: Makefile
	awk -f $(srcdir)/configure_h.awk config.h > $@
	awk -f $(srcdir)/configure_log.awk config.log >> $@

dist-hook:
	cd $(distdir) && for i in $(EXTRA_DIST) $(SUBDIRS) ; do find $$i -name .svn -type d -prune -exec rm -rf '{}' ';' ; rm -f `find $$i -type f | grep -E '(^|\/)\.?\#|\~$$|\.s?o$$'` ; done

if WIN32
dist_noinst_DATA += openvpn.8
nodist_html_DATA = openvpn.8.html
openvpn.8.html: $(srcdir)/openvpn.8
	$(MAN2HTML) < $(srcdir)/openvpn.8 > openvpn.8.html
else
dist_man_MANS = openvpn.8
endif
