CONNECTION PROFILES
===================

Client configuration files may contain multiple remote servers which
it will attempt to connect against.  But there are some configuration
options which are related to specific ``--remote`` options.  For these
use cases, connection profiles are the solution.

By enacpulating the ``--remote`` option and related options within
``<connection>`` and ``</connection>``, these options are handled as a
group.

An OpenVPN client will try each connection profile sequentially until it
achieves a successful connection.

``--remote-random`` can be used to initially "scramble" the connection
list.

Here is an example of connection profile usage:
::

   client
   dev tun

   <connection>
   remote 198.19.34.56 1194 udp
   </connection>

   <connection>
   remote 198.19.34.56 443 tcp
   </connection>

   <connection>
   remote 198.19.34.56 443 tcp
   http-proxy 192.168.0.8 8080
   </connection>

   <connection>
   remote 198.19.36.99 443 tcp
   http-proxy 192.168.0.8 8080
   </connection>

   persist-key
   persist-tun
   pkcs12 client.p12
   remote-cert-tls server
   verb 3

First we try to connect to a server at 198.19.34.56:1194 using UDP. If
that fails, we then try to connect to 198.19.34.56:443 using TCP. If
that also fails, then try connecting through an HTTP proxy at
192.168.0.8:8080 to 198.19.34.56:443 using TCP. Finally, try to connect
through the same proxy to a server at 198.19.36.99:443 using TCP.

The following OpenVPN options may be used inside of a ``<connection>``
block:

``bind``, ``connect-retry``, ``connect-retry-max``, ``connect-timeout``,
``explicit-exit-notify``, ``float``, ``fragment``, ``http-proxy``,
``http-proxy-option``, ``key-direction``, ``link-mtu``, ``local``,
``lport``, ``mssfix``, ``mtu-disc``, ``nobind``, ``port``, ``proto``,
``remote``, ``rport``, ``socks-proxy``, ``tls-auth``, ``tls-crypt``,
``tun-mtu and``, ``tun-mtu-extra``.

A defaulting mechanism exists for specifying options to apply to all
``<connection>`` profiles. If any of the above options (with the
exception of ``remote`` ) appear outside of a ``<connection>`` block,
but in a configuration file which has one or more ``<connection>``
blocks, the option setting will be used as a default for
``<connection>`` blocks which follow it in the configuration file.

For example, suppose the ``nobind`` option were placed in the sample
configuration file above, near the top of the file, before the first
``<connection>`` block. The effect would be as if ``nobind`` were
declared in all ``<connection>`` blocks below it.
