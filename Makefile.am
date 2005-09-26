#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
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

# This option prevents autoreconf from overriding our COPYING and
# INSTALL targets:
AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = openvpn

nodist_openvpn_SOURCES = config.h

TESTS = t_lpback.sh t_cltsrv.sh
dist_noinst_SCRIPTS = $(TESTS)

openvpn_SOURCES = \
        base64.c base64.h \
	basic.h \
	buffer.c buffer.h \
	circ_list.h \
	common.h \
	crypto.c crypto.h \
	errlevel.h \
	error.c error.h \
	event.c event.h \
	fdmisc.c fdmisc.h \
        forward.c forward.h forward-inline.h \
	fragment.c fragment.h \
	gremlin.c gremlin.h \
	helper.c helper.h \
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
	openvpn.c openvpn.h \
	openvpn-plugin.h \
	options.c options.h \
	otime.c otime.h \
	packet_id.c packet_id.h \
	perf.c perf.h \
	ping.c ping.h ping-inline.h \
	plugin.c plugin.h \
	pool.c pool.h \
	proto.c proto.h \
	proxy.c proxy.h \
	push.c push.h \
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
	thread.c thread.h \
	tun.c tun.h

LDADD = @LIBOBJS@

man_MANS = openvpn.8

EXTRA_DIST = \
	doclean \
	$(man_MANS) \
	COPYRIGHT.GPL \
	PORTS \
	openvpn.spec \
	easy-rsa \
	sample-config-files \
	sample-keys \
	sample-scripts \
	gentoo \
	suse \
	openvpn.spec.in \
	config-win32.h \
	win32.h \
	win32.c \
	cryptoapi.h \
	cryptoapi.c \
	makefile.w32 \
        makefile.w32-vc \
	INSTALL-win32.txt \
	tap-win32 \
	install-win32 \
	service-win32 \
	contrib \
	debug \
	plugin \
        management

dist-hook:
	cd $(distdir) && for i in $(EXTRA_DIST) ; do find $$i -name CVS -type d -prune -exec rm -r '{}' ';' ; rm -f `find $$i -type f | grep -E '(^|\/)\.?\#|\~$$|\.s?o$$'` ; done
