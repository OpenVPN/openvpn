AUTOMAKE_OPTIONS = foreign

test_binaries=

if HAVE_LD_WRAP_SUPPORT
test_binaries += argv_testdriver buffer_testdriver
endif

test_binaries += crypto_testdriver packet_id_testdriver auth_token_testdriver ncp_testdriver misc_testdriver \
    pkt_testdriver
if HAVE_LD_WRAP_SUPPORT
test_binaries += tls_crypt_testdriver
endif

test_binaries += provider_testdriver

TESTS = $(test_binaries)
check_PROGRAMS = $(test_binaries)

if HAVE_SITNL
check_PROGRAMS += networking_testdriver
endif

openvpn_includedir = $(top_srcdir)/include
openvpn_srcdir = $(top_srcdir)/src/openvpn
compat_srcdir = $(top_srcdir)/src/compat

argv_testdriver_CFLAGS  = @TEST_CFLAGS@ -I$(openvpn_srcdir) -I$(compat_srcdir)
argv_testdriver_LDFLAGS = @TEST_LDFLAGS@ -L$(openvpn_srcdir) -Wl,--wrap=parse_line
argv_testdriver_SOURCES = test_argv.c mock_msg.c mock_msg.h \
	mock_get_random.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/argv.c

buffer_testdriver_CFLAGS  = @TEST_CFLAGS@ -I$(openvpn_srcdir) -I$(compat_srcdir)
buffer_testdriver_LDFLAGS = @TEST_LDFLAGS@ -L$(openvpn_srcdir) -Wl,--wrap=parse_line
buffer_testdriver_SOURCES = test_buffer.c mock_msg.c mock_msg.h \
	mock_get_random.c \
	$(openvpn_srcdir)/platform.c

crypto_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir)
crypto_testdriver_LDFLAGS = @TEST_LDFLAGS@
crypto_testdriver_SOURCES = test_crypto.c mock_msg.c mock_msg.h \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/mtu.c \
	$(openvpn_srcdir)/mss.c

packet_id_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir)
packet_id_testdriver_LDFLAGS = @TEST_LDFLAGS@
packet_id_testdriver_SOURCES = test_packet_id.c mock_msg.c mock_msg.h \
	mock_get_random.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/reliable.c \
	$(openvpn_srcdir)/session_id.c


pkt_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir)
pkt_testdriver_LDFLAGS = @TEST_LDFLAGS@
pkt_testdriver_SOURCES = test_pkt.c mock_msg.c mock_msg.h \
$(openvpn_srcdir)/argv.c \
	$(openvpn_srcdir)/base64.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/env_set.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/reliable.c \
	$(openvpn_srcdir)/run_command.c \
	$(openvpn_srcdir)/session_id.c \
	$(openvpn_srcdir)/ssl_pkt.c \
	$(openvpn_srcdir)/tls_crypt.c


tls_crypt_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir)
tls_crypt_testdriver_LDFLAGS = @TEST_LDFLAGS@ \
	-Wl,--wrap=buffer_read_from_file \
	-Wl,--wrap=buffer_write_file \
	-Wl,--wrap=parse_line \
	-Wl,--wrap=rand_bytes
tls_crypt_testdriver_SOURCES = test_tls_crypt.c mock_msg.c mock_msg.h \
	$(openvpn_srcdir)/argv.c \
	$(openvpn_srcdir)/base64.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/env_set.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/run_command.c

if HAVE_SITNL
networking_testdriver_CFLAGS = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_CFLAGS)
networking_testdriver_LDFLAGS = @TEST_LDFLAGS@ -L$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_LIBS)
networking_testdriver_SOURCES = test_networking.c mock_msg.c \
	$(openvpn_srcdir)/networking_sitnl.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c
endif

provider_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_CFLAGS)
provider_testdriver_LDFLAGS = @TEST_LDFLAGS@ \
	$(OPTIONAL_CRYPTO_LIBS)

provider_testdriver_SOURCES = test_provider.c mock_msg.c \
	$(openvpn_srcdir)/xkey_helper.c \
	$(openvpn_srcdir)/xkey_provider.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/base64.c \
	mock_get_random.c \
	$(openvpn_srcdir)/platform.c

auth_token_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_CFLAGS)
auth_token_testdriver_LDFLAGS = @TEST_LDFLAGS@ \
	$(OPTIONAL_CRYPTO_LIBS)

auth_token_testdriver_SOURCES = test_auth_token.c mock_msg.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/base64.c


ncp_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_CFLAGS)
ncp_testdriver_LDFLAGS = @TEST_LDFLAGS@ \
	$(OPTIONAL_CRYPTO_LIBS)

ncp_testdriver_SOURCES = test_ncp.c mock_msg.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/crypto.c \
	$(openvpn_srcdir)/crypto_mbedtls.c \
	$(openvpn_srcdir)/crypto_openssl.c \
	$(openvpn_srcdir)/otime.c \
	$(openvpn_srcdir)/packet_id.c \
	$(openvpn_srcdir)/platform.c \
	$(openvpn_srcdir)/ssl_util.c

misc_testdriver_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(compat_srcdir) -I$(openvpn_srcdir)

misc_testdriver_LDFLAGS = @TEST_LDFLAGS@

misc_testdriver_SOURCES = test_misc.c mock_msg.c \
    mock_get_random.c \
	$(openvpn_srcdir)/buffer.c \
	$(openvpn_srcdir)/options_util.c \
	$(openvpn_srcdir)/ssl_util.c \
	$(openvpn_srcdir)/platform.c
