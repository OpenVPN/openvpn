CFILES = cert_data.c common_osx.c crypto_osx.c main.c
OFILES = $(CFILES:.c=.o) ../../src/openvpn/base64.o
prog = keychain-mcd

CC = gcc
CFLAGS = -Wall
LDFLAGS =  -framework CoreFoundation -framework Security -framework CoreServices

$(prog): $(OFILES)
	$(CC) $(LDFLAGS) $(OFILES) -o $(prog)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
