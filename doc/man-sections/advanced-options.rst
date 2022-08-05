Standalone Debug Options
------------------------

--show-gateway args
  (Standalone) Show current IPv4 and IPv6 default gateway and interface
  towards the gateway (if the protocol in question is enabled).

  Valid syntax:
  ::

     --show-gateway
     --show-gateway IPv6-target

  For IPv6 this queries the route towards ::/128, or the specified IPv6
  target address if passed as argument.
  For IPv4 on Linux, Windows, MacOS and BSD it looks for a 0.0.0.0/0 route.
  If there are more specific routes, the result will not always be matching
  the route of the IPv4 packets to the VPN gateway.


Advanced Expert Options
-----------------------
These are options only required when special tweaking is needed, often
used when debugging or testing out special usage scenarios.

--hash-size args
  Set the size of the real address hash table to ``r`` and the virtual
  address table to ``v``.

  Valid syntax:
  ::

     hash-size r v

  By default, both tables are sized at 256 buckets.

--bcast-buffers n
  Allocate ``n`` buffers for broadcast datagrams (default :code:`256`).

--persist-local-ip
  Preserve initially resolved local IP address and port number across
  ``SIGUSR1`` or ``--ping-restart`` restarts.

--persist-remote-ip
  Preserve most recently authenticated remote IP address and port number
  across :code:`SIGUSR1` or ``--ping-restart`` restarts.

--rcvbuf size
  Set the TCP/UDP socket receive buffer size. Defaults to operating system
  default.

--shaper n
  Limit bandwidth of outgoing tunnel data to ``n`` bytes per second on the
  TCP/UDP port. Note that this will only work if mode is set to
  :code:`p2p`.  If you want to limit the bandwidth in both directions, use
  this option on both peers.

  OpenVPN uses the following algorithm to implement traffic shaping: Given
  a shaper rate of ``n`` bytes per second, after a datagram write of ``b``
  bytes is queued on the TCP/UDP port, wait a minimum of ``(b / n)``
  seconds before queuing the next write.

  It should be noted that OpenVPN supports multiple tunnels between the
  same two peers, allowing you to construct full-speed and reduced
  bandwidth tunnels at the same time, routing low-priority data such as
  off-site backups over the reduced bandwidth tunnel, and other data over
  the full-speed tunnel.

  Also note that for low bandwidth tunnels (under 1000 bytes per second),
  you should probably use lower MTU values as well (see above), otherwise
  the packet latency will grow so large as to trigger timeouts in the TLS
  layer and TCP connections running over the tunnel.

  OpenVPN allows ``n`` to be between 100 bytes/sec and 100 Mbytes/sec.

--sndbuf size
  Set the TCP/UDP socket send buffer size. Defaults to operating system
  default.

--tcp-queue-limit n
  Maximum number of output packets queued before TCP (default :code:`64`).

  When OpenVPN is tunneling data from a TUN/TAP device to a remote client
  over a TCP connection, it is possible that the TUN/TAP device might
  produce data at a faster rate than the TCP connection can support. When
  the number of output packets queued before sending to the TCP socket
  reaches this limit for a given client connection, OpenVPN will start to
  drop outgoing packets directed at this client.

--txqueuelen n
  *(Linux only)* Set the TX queue length on the TUN/TAP interface.
  Currently defaults to operating system default.

--disable-dco
  Disables the opportunistic use of data channel offloading if available.
  Without this option, OpenVPN will opportunistically use DCO mode if
  the config options and the running kernel supports using DCO.

  Data channel offload currently requires data-ciphers to only contain
  AEAD ciphers (AES-GCM and Chacha20-Poly1305) and Linux with the
  ovpn-dco module.

  Note that some options have no effect or cannot be used when DCO mode
  is enabled.

  On platforms that do not support DCO ``disable-dco`` has no effect.
