#
# Build the OpenVPN down-root plugin module.
#

# This directory is where we will look for openvpn-plugin.h
INCLUDE=-I../..

CC_FLAGS=-O2 -Wall

down-root.so : down-root.o
	gcc ${CC_FLAGS} -fPIC -shared -Wl,-soname,openvpn-down-root.so -o openvpn-down-root.so down-root.o -lc

down-root.o : down-root.c
	gcc ${CC_FLAGS} -fPIC -c ${INCLUDE} down-root.c

clean :
	rm -f *.o *.so
