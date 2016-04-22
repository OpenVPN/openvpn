# -*- mode: sh -*-
# vi: set ft=sh :
#!/bin/sh

cd ~/openvpn && autoreconf -vi --force && ./configure && make clean && make -j3
# optionally: make check
