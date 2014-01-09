Since 2.3.0, OpenVPN officially supports IPv6, and all widely used
patches floating around for older versions have been integrated.

IPv6 payload support
--------------------

This is for "IPv6 inside OpenVPN", with server-pushed IPv6 configuration
on the client, and support for IPv6 configuration on the tun/tap interface
from within the openvpn config.

The code in 2.3.0 supersedes the IPv6 payload patches from Gert Doering,
formerly located at http://www.greenie.net/ipv6/openvpn.html


The following options have been added to handle IPv6 configuration,
analogous to their IPv4 counterparts (--server <-> --server-ipv6, etc.)

     - server-ipv6
     - ifconfig-ipv6
     - ifconfig-ipv6-pool
     - ifconfig-ipv6-push
     - route-ipv6
     - iroute-ipv6

see "man openvpn" for details how they are used.



IPv6 transport support
----------------------

This is to enable OpenVPN peers or client/servers to talk to each other
over an IPv6 network ("OpenVPN over IPv6").

The code in 2.3.0 supersedes the IPv6 transport patches from JuanJo Ciarlante,
formerly located at http://github.com/jjo/openvpn-ipv6

OpenVPN 2.4.0 includes a big overhaul of the IPv6 transport patches
originally implemented for the Android client (ics-openvpn)

IPv4/IPv6 transport is automatically is selected when resolving addresses.
Use a 6 or 4 suffix to force IPv6/IPv4:

  --proto udp6
  --proto tcp4
  --proto tcp6-client
  --proto tcp4-server
  --proto tcp6 --client / --proto tcp6 --server

On systems that allow IPv4 connections on IPv6 sockets
(all systems supporting IPV6_V6ONLY setsockopt), an OpenVPN server can
handle IPv4 connections on the IPv6 socket as well, making it a true
dual-stacked server. Use bind ipv6only to disable this behaviour.

On other systems, as of 2.3.0, you need to run separate server instances
for IPv4 and IPv6.
