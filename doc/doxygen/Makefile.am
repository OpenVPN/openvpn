#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2017-2021 Fox-IT B.V. <openvpn@foxcrypto.com>
#

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

DISTCLEANFILES = openvpn.doxyfile

DOXYGEN_EXTRA_FILES = \
	doc_compression.h \
	doc_control_processor.h \
	doc_control_tls.h \
	doc_data_control.h \
	doc_data_crypto.h \
	doc_eventloop.h \
	doc_external_multiplexer.h \
	doc_fragmentation.h \
	doc_internal_multiplexer.h \
	doc_key_generation.h \
	doc_mainpage.h \
	doc_memory_management.h \
	doc_protocol_overview.h \
	doc_reliable.h \
	doc_tunnel_state.h

EXTRA_DIST = $(DOXYGEN_EXTRA_FILES)

.PHONY: doxygen
doxygen: openvpn.doxyfile $(DOXYGEN_EXTRA_FILES)
	doxygen openvpn.doxyfile

clean-local:
	-rm -rf html latex
