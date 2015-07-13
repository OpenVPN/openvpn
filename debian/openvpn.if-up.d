#!/bin/sh

OPENVPN=/usr/sbin/openvpn
OPENVPN_INIT=/etc/init.d/openvpn
SYSTEMCTL=/bin/systemctl
SYSTEMD=/run/systemd/system

if [ ! -x $OPENVPN ]; then
  exit 0
fi

if [ -n "$IF_OPENVPN" ]; then
  for vpn in $IF_OPENVPN; do
    ## check systemd present
    if [ -d $SYSTEMD ]; then
      $SYSTEMCTL start openvpn@$vpn
    else
      $OPENVPN_INIT start $vpn
    fi
  done
fi
