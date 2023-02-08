AUTOMAKE_OPTIONS = foreign

check_LTLIBRARIES = libtestengine.la
conffiles = openssl.cnf
EXTRA_DIST = \
	openssl.cnf.in \
	check_engine_keys.sh

TESTS_ENVIRONMENT = srcdir="$(abs_srcdir)"; \
	builddir="$(abs_builddir)"; \
	top_builddir="$(top_builddir)"; \
	top_srcdir="$(top_srcdir)"; \
	export srcdir builddir top_builddir top_srcdir;

if !CROSS_COMPILING
TESTS = check_engine_keys.sh
endif
check_engine_keys.sh: $(conffiles)

CLEANFILES = \
	client.key \
	passwd \
	log.txt \
	$(conffiles)

openssl.cnf: $(srcdir)/openssl.cnf.in
	sed "s|ABSBUILDDIR|$(abs_builddir)|" < $(srcdir)/openssl.cnf.in > $@

libtestengine_la_SOURCES = libtestengine.c
libtestengine_la_LDFLAGS = @TEST_LDFLAGS@ -rpath /lib -shrext .so
libtestengine_la_CFLAGS = @TEST_CFLAGS@ -I$(openvpn_srcdir) -I$(compat_srcdir)
