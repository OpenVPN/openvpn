AUTOMAKE_OPTIONS = foreign

check_PROGRAMS=

if ENABLE_CRYPTO
check_PROGRAMS += packet_id_testdriver
endif

TESTS = $(check_PROGRAMS)

openvpn_includedir = $(top_srcdir)/include
openvpn_srcdir = $(top_srcdir)/src/openvpn
compat_srcdir = $(top_srcdir)/src/compat

packet_id_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_CFLAGS)
packet_id_testdriver_LDFLAGS = @TEST_LDFLAGS@ \
	$(OPTIONAL_CRYPTO_LIBS)
packet_id_testdriver_SOURCES = test_packet_id.c mock_msg.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c
