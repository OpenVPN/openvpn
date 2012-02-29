#
# Build the OpenVPN auth-pam plugin module.
#

# If PAM modules are not linked against libpam.so, set DLOPEN_PAM to 1. This
# must be done on SUSE 9.1, at least.
DLOPEN_PAM=0

ifeq ($(DLOPEN_PAM),1)
	LIBPAM=-ldl
else
	LIBPAM=-lpam
endif

# This directory is where we will look for openvpn-plugin.h
CPPFLAGS=-I../../../include

CC=gcc
CFLAGS=-O2 -Wall
DEFS = -DDLOPEN_PAM=$(DLOPEN_PAM)

openvpn-auth-pam.so : auth-pam.o pamdl.o
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) -Wl,-soname,openvpn-auth-pam.so -o openvpn-auth-pam.so auth-pam.o pamdl.o -lc $(LIBPAM)

auth-pam.o : auth-pam.c pamdl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFS) -fPIC -c auth-pam.c

pamdl.o : pamdl.c pamdl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEFS) -fPIC -c pamdl.c

clean :
	-rm -f *.o *.so
