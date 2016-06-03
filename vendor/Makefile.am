# needs an absolute path bc. of the cmake invocation
cmockasrc     = "@VENDOR_SRC_ROOT@/cmocka"
cmockabuild   = "@VENDOR_BUILD_ROOT@/cmocka"
cmockainstall = "@VENDOR_DIST_ROOT@"

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	"$(cmockabuild)" \
	"$(cmockainstall)" \
	"@VENDOR_BUILD_ROOT@"

libcmocka:
if CMOCKA_INITIALIZED
	mkdir -p $(cmockabuild) $(cmockainstall)
	(cd $(cmockabuild) && cmake -DCMAKE_INSTALL_PREFIX=$(cmockainstall) $(cmockasrc) && make && make install)
endif

check: libcmocka

clean:
	rm -rf $(cmockabuild)
	rm -rf $(cmockainstall)
