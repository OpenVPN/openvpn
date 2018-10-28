cmockasrc   = $(srcdir)/cmocka
# Not just '$(builddir)/cmocka', because cmocka requires an out-of-source build
cmockabuild = $(builddir)/cmocka_build
cmockadist  = $(builddir)/dist

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	"$(cmockabuild)" \
	"$(cmockadist)"

libcmocka:
if CMOCKA_INITIALIZED
	mkdir -p $(cmockabuild) $(cmockadist)
	## Compensate for the cd in the paths
	(cd $(cmockabuild) && cmake -DCMAKE_INSTALL_PREFIX=../$(cmockadist) ../$(cmockasrc) && make && make install)
endif

check: libcmocka

clean:
	rm -rf $(cmockabuild)
	rm -rf $(cmockainstall)
