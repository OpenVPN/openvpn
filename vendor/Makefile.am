AUTOMAKE_OPTIONS = foreign

cmockasrc     = @VENDOR_ROOT@/cmocka  # needs an absolute path bc. of the cmake invocation
cmockabuild   = @VENDOR_BUILD_ROOT@/cmocka
cmockainstall = @VENDOR_DIST@

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(cmockabuild) \
	$(cmockainstall) \
	@VENDOR_BUILD_ROOT@

distdir:
	mkdir -p $(cmockainstall)

libcmocka: distdir
	mkdir -p $(cmockabuild)
	(cd $(cmockabuild) && cmake -DCMAKE_INSTALL_PREFIX=$(cmockainstall) $(cmockasrc) && make && make install)

check: libcmocka

clean:
	rm -rf $(cmockabuild)
	rm -rf $(cmockainstall)
