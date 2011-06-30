
DESTDIR=
PREFIX=

all:
	echo "All done."
	echo "Run make install DESTDIR=/usr/share/somewhere"

install:
	install -d "${DESTDIR}/${PREFIX}"
	install -m 0755 build-* "${DESTDIR}/${PREFIX}"
	install -m 0755 clean-all list-crl inherit-inter pkitool revoke-full sign-req whichopensslcnf "${DESTDIR}/${PREFIX}"
	install -m 0644 openssl-0.9.6.cnf openssl-0.9.8.cnf openssl-1.0.0.cnf README vars "${DESTDIR}/${PREFIX}"
