=========
 openvpn
=========
-------------------------
 Secure IP tunnel daemon
-------------------------

:Manual section: 8
:Manual group: System Manager's Manual



SYNOPSIS
========
| ``openvpn`` [ options ... ]
| ``openvpn``  ``--help``



INTRODUCTION
============

OpenVPN is an open source VPN daemon by James Yonan. Because OpenVPN
tries to be a universal VPN tool offering a great deal of flexibility,
there are a lot of options on this manual page. If you're new to
OpenVPN, you might want to skip ahead to the examples section where you
will see how to construct simple VPNs on the command line without even
needing a configuration file.

Also note that there's more documentation and examples on the OpenVPN
web site: https://openvpn.net/

And if you would like to see a shorter version of this manual, see the
openvpn usage message which can be obtained by running **openvpn**
without any parameters.



DESCRIPTION
===========

OpenVPN is a robust and highly flexible VPN daemon. OpenVPN supports
SSL/TLS security, ethernet bridging, TCP or UDP tunnel transport through
proxies or NAT, support for dynamic IP addresses and DHCP, scalability
to hundreds or thousands of users, and portability to most major OS
platforms.

OpenVPN is tightly bound to the OpenSSL library, and derives much of its
crypto capabilities from it.

OpenVPN supports conventional encryption using a pre-shared secret key
**(Static Key mode)** or public key security **(SSL/TLS mode)** using
client & server certificates. OpenVPN also supports non-encrypted
TCP/UDP tunnels.

OpenVPN is designed to work with the **TUN/TAP** virtual networking
interface that exists on most platforms.

Overall, OpenVPN aims to offer many of the key features of IPSec but
with a relatively lightweight footprint.



OPTIONS
=======

OpenVPN allows any option to be placed either on the command line or in
a configuration file. Though all command line options are preceded by a
double-leading-dash ("--"), this prefix can be removed when an option is
placed in a configuration file.

.. include:: man-sections/generic-options.rst
.. include:: man-sections/log-options.rst
.. include:: man-sections/protocol-options.rst
.. include:: man-sections/client-options.rst
.. include:: man-sections/server-options.rst
.. include:: man-sections/encryption-options.rst
.. include:: man-sections/cipher-negotiation.rst
.. include:: man-sections/network-config.rst
.. include:: man-sections/script-options.rst
.. include:: man-sections/management-options.rst
.. include:: man-sections/plugin-options.rst
.. include:: man-sections/windows-options.rst
.. include:: man-sections/advanced-options.rst
.. include:: man-sections/unsupported-options.rst
.. include:: man-sections/connection-profiles.rst
.. include:: man-sections/inline-files.rst
.. include:: man-sections/signals.rst
.. include:: man-sections/examples.rst


FAQ
===

https://community.openvpn.net/openvpn/wiki/FAQ



HOWTO
=====

For a more comprehensive guide to setting up OpenVPN in a production
setting, see the OpenVPN HOWTO at
https://openvpn.net/community-resources/how-to/



PROTOCOL
========

For a description of OpenVPN's underlying protocol, see
https://openvpn.net/community-resources/openvpn-protocol/



WEB
===

OpenVPN's web site is at https://openvpn.net/

Go here to download the latest version of OpenVPN, subscribe to the
mailing lists, read the mailing list archives, or browse the SVN
repository.



BUGS
====

Report all bugs to the OpenVPN team info@openvpn.net



SEE ALSO
========

``dhcpcd``\(8),
``ifconfig``\(8),
``openssl``\(1),
``route``\(8),
``scp``\(1)
``ssh``\(1)



NOTES
=====

This product includes software developed by the OpenSSL Project
(https://www.openssl.org/)

For more information on the TLS protocol, see
http://www.ietf.org/rfc/rfc2246.txt

For more information on the LZO real-time compression library see
https://www.oberhumer.com/opensource/lzo/



COPYRIGHT
=========

Copyright (C) 2002-2020 OpenVPN Inc This program is free software; you
can redistribute it and/or modify it under the terms of the GNU General
Public License version 2 as published by the Free Software Foundation.

AUTHORS
=======

James Yonan james@openvpn.net
