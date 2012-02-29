#
# Build the OpenVPN down-root plugin module.
#

# This directory is where we will look for openvpn-plugin.h
CPPFLAGS=-I../../../include

CC=gcc
CFLAGS=-O2 -Wall

down-root.so : down-root.o
	$(CC) $(CFLAGS) -fPIC -shared $(LDFLAGS) -Wl,-soname,openvpn-down-root.so -o openvpn-down-root.so down-root.o -lc

down-root.o : down-root.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c down-root.c

clean :
	-rm -f *.o *.so
