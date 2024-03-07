Link Options
------------
This link options section covers options related to the connection between
the local and the remote host.

--bind keywords
  Bind to local address and port. This is the default unless any of
  ``--proto tcp-client`` , ``--http-proxy`` or ``--socks-proxy`` are used.

  If the optional :code:`ipv6only` keyword is present OpenVPN will bind only
  to IPv6 (as opposed to IPv6 and IPv4) when a IPv6 socket is opened.

--float
  Allow remote peer to change its IP address and/or port number, such as
  due to DHCP (this is the default if ``--remote`` is not used).
  ``--float`` when specified with ``--remote`` allows an OpenVPN session
  to initially connect to a peer at a known address, however if packets
  arrive from a new address and pass all authentication tests, the new
  address will take control of the session. This is useful when you are
  connecting to a peer which holds a dynamic address such as a dial-in
  user or DHCP client.

  Essentially, ``--float`` tells OpenVPN to accept authenticated packets
  from any address, not only the address which was specified in the
  ``--remote`` option.

--fragment args

  Valid syntax:
  ::

     fragment max
     fragment max mtu

  Enable internal datagram fragmentation so that no UDP datagrams are sent
  which are larger than ``max`` bytes.

  If the :code:`mtu` parameter is present the ``max`` parameter is
  interpreted to include IP and UDP encapsulation overhead. The
  :code:`mtu` parameter is introduced in OpenVPN version 2.6.0.

  If the :code:`mtu` parameter is absent, the ``max`` parameter is
  interpreted in the same way as the ``--link-mtu`` parameter, i.e.
  the UDP packet size after encapsulation overhead has been added in,
  but not including the UDP header itself.

  The ``--fragment`` option only makes sense when you are using the UDP
  protocol (``--proto udp``).

  ``--fragment`` adds 4 bytes of overhead per datagram.

  See the ``--mssfix`` option below for an important related option to
  ``--fragment``.

  It should also be noted that this option is not meant to replace UDP
  fragmentation at the IP stack level. It is only meant as a last resort
  when path MTU discovery is broken. Using this option is less efficient
  than fixing path MTU discovery for your IP link and using native IP
  fragmentation instead.

  Having said that, there are circumstances where using OpenVPN's internal
  fragmentation capability may be your only option, such as tunneling a
  UDP multicast stream which requires fragmentation.

--keepalive args
  A helper directive designed to simplify the expression of ``--ping`` and
  ``--ping-restart``.

  Valid syntax:
  ::

     keepalive interval timeout

  Send ping once every ``interval`` seconds, restart if ping is not received
  for ``timeout`` seconds.

  This option can be used on both client and server side, but it is enough
  to add this on the server side as it will push appropriate ``--ping``
  and ``--ping-restart`` options to the client. If used on both server and
  client, the values pushed from server will override the client local
  values.

  The ``timeout`` argument will be twice as long on the server side. This
  ensures that a timeout is detected on client side before the server side
  drops the connection.

  For example, ``--keepalive 10 60`` expands as follows:
  ::

     if mode server:
         ping 10                    # Argument: interval
         ping-restart 120           # Argument: timeout*2
         push "ping 10"             # Argument: interval
         push "ping-restart 60"     # Argument: timeout
     else
         ping 10                    # Argument: interval
         ping-restart 60            # Argument: timeout

--link-mtu n
  **DEPRECATED** Sets an upper bound on the size of UDP packets which are sent between
  OpenVPN peers. *It's best not to set this parameter unless you know what
  you're doing.*

  Due to variable header size of IP header (20 bytes for IPv4 and 40 bytes
  for IPv6) and dynamically negotiated data channel cipher, this option
  is not reliable. It is recommended to set tun-mtu with enough headroom
  instead.

--local host
  Local host name or IP address for bind. If specified, OpenVPN will bind
  to this address only. If unspecified, OpenVPN will bind to all
  interfaces.

--lport port
  Set local TCP/UDP port number or name. Cannot be used together with
  ``--nobind`` option.

--mark value
  Mark encrypted packets being sent with ``value``. The mark value can be
  matched in policy routing and packetfilter rules. This option is only
  supported in Linux and does nothing on other operating systems.

--mode m
  Set OpenVPN major mode. By default, OpenVPN runs in point-to-point mode
  (:code:`p2p`). OpenVPN 2.0 introduces a new mode (:code:`server`) which
  implements a multi-client server capability.

--mssfix args

  Valid syntax:
  ::

     mssfix max [mtu]

     mssfix max [fixed]

     mssfix

  Announce to TCP sessions running over the tunnel that they should limit
  their send packet sizes such that after OpenVPN has encapsulated them,
  the resulting UDP packet size that OpenVPN sends to its peer will not
  exceed ``max`` bytes. The default value is :code:`1492 mtu`. Use :code:`0`
  as max to disable mssfix.

  If the :code:`mtu` parameter is specified the ``max`` value is interpreted
  as the resulting packet size of VPN packets including the IP and UDP header.
  Support for the :code:`mtu` parameter was added with OpenVPN version 2.6.0.

  If the :code:`mtu` parameter is not specified, the ``max`` parameter
  is interpreted in the same way as the ``--link-mtu`` parameter, i.e.
  the UDP packet size after encapsulation overhead has been added in, but
  not including the UDP header itself. Resulting packet would be at most 28
  bytes larger for IPv4 and 48 bytes for IPv6 (20/40 bytes for IP header and
  8 bytes for UDP header). Default value of 1450 allows OpenVPN packets to be
  transmitted over IPv4 on a link with MTU 1478 or higher without IP level
  fragmentation (and 1498 for IPv6).

  If the :code:`fixed` parameter is specified, OpenVPN will make no attempt
  to calculate the VPN encapsulation overhead but instead will set the MSS to
  limit the size of the payload IP packets to the specified number. IPv4 packets
  will have the MSS value lowered to mssfix - 40 and IPv6 packets to mssfix - 60.

  if ``--mssfix`` is specified is specified without any parameter it
  inherits the parameters of ``--fragment`` if specified or uses the
  default for ``--mssfix`` otherwise.

  The ``--mssfix`` option only makes sense when you are using the UDP
  protocol for OpenVPN peer-to-peer communication, i.e. ``--proto udp``.

  ``--mssfix`` and ``--fragment`` can be ideally used together, where
  ``--mssfix`` will try to keep TCP from needing packet fragmentation in
  the first place, and if big packets come through anyhow (from protocols
  other than TCP), ``--fragment`` will internally fragment them.

  ``--max-packet-size``, ``--fragment``, and ``--mssfix`` are designed to
  work around cases where Path MTU discovery is broken on the network path
  between OpenVPN peers.

  The usual symptom of such a breakdown is an OpenVPN connection which
  successfully starts, but then stalls during active usage.

  If ``--fragment`` and ``--mssfix`` are used together, ``--mssfix`` will
  take its default ``max`` parameter from the ``--fragment max`` option.

  Therefore, one could lower the maximum UDP packet size to 1300 (a good
  first try for solving MTU-related connection problems) with the
  following options:
  ::

     --tun-mtu 1500 --fragment 1300 --mssfix

  If the ``max-packet-size size`` option is used in the configuration
  it will also act as if ``mssfix size mtu`` was specified in the
  configuration.

--mtu-disc type
  Should we do Path MTU discovery on TCP/UDP channel? Only supported on
  OSes such as Linux that supports the necessary system call to set.

  Valid types:

  :code:`no`      Never send DF (Don't Fragment) frames

  :code:`maybe`   Use per-route hints

  :code:`yes`     Always DF (Don't Fragment)

--mtu-test
  To empirically measure MTU on connection startup, add the ``--mtu-test``
  option to your configuration. OpenVPN will send ping packets of various
  sizes to the remote peer and measure the largest packets which were
  successfully received. The ``--mtu-test`` process normally takes about 3
  minutes to complete.

--nobind
  Do not bind to local address and port. The IP stack will allocate a
  dynamic port for returning packets. Since the value of the dynamic port
  could not be known in advance by a peer, this option is only suitable
  for peers which will be initiating connections by using the ``--remote``
  option.

--passtos
  Set the TOS field of the tunnel packet to what the payload's TOS is.

--ping n
  Ping remote over the TCP/UDP control channel if no packets have been
  sent for at least ``n`` seconds (specify ``--ping`` on both peers to
  cause ping packets to be sent in both directions since OpenVPN ping
  packets are not echoed like IP ping packets).

  This option has two intended uses:

  (1)  Compatibility with stateful firewalls. The periodic ping will ensure
       that a stateful firewall rule which allows OpenVPN UDP packets to
       pass will not time out.

  (2)  To provide a basis for the remote to test the existence of its peer
       using the ``--ping-exit`` option.

  When using OpenVPN in server mode see also ``--keepalive``.

--ping-exit n
  Causes OpenVPN to exit after ``n`` seconds pass without reception of a
  ping or other packet from remote. This option can be combined with
  ``--inactive``, ``--ping`` and ``--ping-exit`` to create a two-tiered
  inactivity disconnect.

  For example,
  ::

      openvpn [options...] --inactive 3600 --ping 10 --ping-exit 60

  when used on both peers will cause OpenVPN to exit within 60 seconds if
  its peer disconnects, but will exit after one hour if no actual tunnel
  data is exchanged.

--ping-restart n
  Similar to ``--ping-exit``, but trigger a :code:`SIGUSR1` restart after
  ``n`` seconds pass without reception of a ping or other packet from
  remote.

  This option is useful in cases where the remote peer has a dynamic IP
  address and a low-TTL DNS name is used to track the IP address using a
  service such as https://www.nsupdate.info/ + a dynamic DNS client such as
  ``ddclient``.

  If the peer cannot be reached, a restart will be triggered, causing the
  hostname used with ``--remote`` to be re-resolved (if ``--resolv-retry``
  is also specified).

  In server mode, ``--ping-restart``, ``--inactive`` or any other type of
  internally generated signal will always be applied to individual client
  instance objects, never to whole server itself. Note also in server mode
  that any internally generated signal which would normally cause a
  restart, will cause the deletion of the client instance object instead.

  In client mode, the ``--ping-restart`` parameter is set to 120 seconds
  by default. This default will hold until the client pulls a replacement
  value from the server, based on the ``--keepalive`` setting in the
  server configuration. To disable the 120 second default, set
  ``--ping-restart 0`` on the client.

  See the signals section below for more information on :code:`SIGUSR1`.

  Note that the behavior of ``SIGUSR1`` can be modified by the
  ``--persist-tun``, ``--persist-local-ip`` and
  ``--persist-remote-ip`` options.

  Also note that ``--ping-exit`` and ``--ping-restart`` are mutually
  exclusive and cannot be used together.

--ping-timer-rem
  Run the ``--ping-exit`` / ``--ping-restart`` timer only if we have a
  remote address. Use this option if you are starting the daemon in listen
  mode (i.e. without an explicit ``--remote`` peer), and you don't want to
  start clocking timeouts until a remote peer connects.

--proto p
  Use protocol ``p`` for communicating with remote host. ``p`` can be
  :code:`udp`, :code:`tcp-client`, or :code:`tcp-server`. You can also
  limit OpenVPN to use only IPv4 or only IPv6 by specifying ``p`` as
  :code:`udp4`, :code:`tcp4-client`, :code:`tcp4-server` or :code:`udp6`,
  :code:`tcp6-client`, :code:`tcp6-server`, respectively.

  The default protocol is :code:`udp` when ``--proto`` is not specified.

  For UDP operation, ``--proto udp`` should be specified on both peers.

  For TCP operation, one peer must use ``--proto tcp-server`` and the
  other must use ``--proto tcp-client``. A peer started with
  :code:`tcp-server` will wait indefinitely for an incoming connection. A peer
  started with :code:`tcp-client` will attempt to connect, and if that fails,
  will sleep for 5 seconds (adjustable via the ``--connect-retry`` option)
  and try again infinite or up to N retries (adjustable via the
  ``--connect-retry-max`` option). Both TCP client and server will
  simulate a SIGUSR1 restart signal if either side resets the connection.

  OpenVPN is designed to operate optimally over UDP, but TCP capability is
  provided for situations where UDP cannot be used. In comparison with
  UDP, TCP will usually be somewhat less efficient and less robust when
  used over unreliable or congested networks.

  This article outlines some of problems with tunneling IP over TCP:
  http://sites.inka.de/sites/bigred/devel/tcp-tcp.html

  There are certain cases, however, where using TCP may be advantageous
  from a security and robustness perspective, such as tunneling non-IP or
  application-level UDP protocols, or tunneling protocols which don't
  possess a built-in reliability layer.

--port port
  TCP/UDP port number or port name for both local and remote (sets both
  ``--lport`` and ``--rport`` options to given port). The current default
  of 1194 represents the official IANA port number assignment for OpenVPN
  and has been used since version 2.0-beta17. Previous versions used port
  5000 as the default.

--rport port
  Set TCP/UDP port number or name used by the ``--remote`` option. The
  port can also be set directly using the ``--remote`` option.

--replay-window args
  Modify the replay protection sliding-window size and time window.

  Valid syntaxes::

     replay-window n
     replay-window n t

  Use a replay protection sliding-window of size ``n`` and a time window
  of ``t`` seconds.

  By default ``n`` is :code:`64` (the IPSec default) and ``t`` is
  :code:`15` seconds.

  This option is only relevant in UDP mode, i.e. when either ``--proto
  udp`` is specified, or no ``--proto`` option is specified.

  When OpenVPN tunnels IP packets over UDP, there is the possibility that
  packets might be dropped or delivered out of order. Because OpenVPN,
  like IPSec, is emulating the physical network layer, it will accept an
  out-of-order packet sequence, and will deliver such packets in the same
  order they were received to the TCP/IP protocol stack, provided they
  satisfy several constraints.

  (a)   The packet cannot be a replay.

  (b)   If a packet arrives out of order, it will only be accepted if
        the difference between its sequence number and the highest sequence
        number received so far is less than ``n``.

  (c)   If a packet arrives out of order, it will only be accepted if it
        arrives no later than ``t`` seconds after any packet containing a higher
        sequence number.

  If you are using a network link with a large pipeline (meaning that the
  product of bandwidth and latency is high), you may want to use a larger
  value for ``n``. Satellite links in particular often require this.

  If you run OpenVPN at ``--verb 4``, you will see the message
  "PID_ERR replay-window backtrack occurred [x]" every time the maximum sequence
  number backtrack seen thus far increases. This can be used to calibrate
  ``n``.

  There is some controversy on the appropriate method of handling packet
  reordering at the security layer.

  Namely, to what extent should the security layer protect the
  encapsulated protocol from attacks which masquerade as the kinds of
  normal packet loss and reordering that occur over IP networks?

  The IPSec and OpenVPN approach is to allow packet reordering within a
  certain fixed sequence number window.

  OpenVPN adds to the IPSec model by limiting the window size in time as
  well as sequence space.

  OpenVPN also adds TCP transport as an option (not offered by IPSec) in
  which case OpenVPN can adopt a very strict attitude towards message
  deletion and reordering: Don't allow it. Since TCP guarantees
  reliability, any packet loss or reordering event can be assumed to be an
  attack.

  In this sense, it could be argued that TCP tunnel transport is preferred
  when tunneling non-IP or UDP application protocols which might be
  vulnerable to a message deletion or reordering attack which falls within
  the normal operational parameters of IP networks.

  So I would make the statement that one should never tunnel a non-IP
  protocol or UDP application protocol over UDP, if the protocol might be
  vulnerable to a message deletion or reordering attack that falls within
  the normal operating parameters of what is to be expected from the
  physical IP layer. The problem is easily fixed by simply using TCP as
  the VPN transport layer.

--replay-persist file
  Persist replay-protection state across sessions using ``file`` to save
  and reload the state.

  This option will keep a disk copy of the current replay protection state
  (i.e. the most recent packet timestamp and sequence number received from
  the remote peer), so that if an OpenVPN session is stopped and
  restarted, it will reject any replays of packets which were already
  received by the prior session.

  This option only makes sense when replay protection is enabled (the
  default) and you are using TLS mode with ``--tls-auth``.

--session-timeout n
  Raises :code:`SIGTERM` for the client instance after ``n`` seconds since
  the beginning of the session, forcing OpenVPN to disconnect.
  In client mode, OpenVPN will disconnect and exit, while in server mode
  all client sessions are terminated.

  This option can also be specified in a client instance config file
  using ``--client-config-dir`` or dynamically generated using a
  ``--client-connect`` script. In these cases, only the related client
  session is terminated.

--socket-flags flags
  Apply the given flags to the OpenVPN transport socket. Currently, only
  :code:`TCP_NODELAY` is supported.

  The :code:`TCP_NODELAY` socket flag is useful in TCP mode, and causes the
  kernel to send tunnel packets immediately over the TCP connection without
  trying to group several smaller packets into a larger packet.  This can
  result in a considerably improvement in latency.

  This option is pushable from server to client, and should be used on
  both client and server for maximum effect.

--tcp-nodelay
  This macro sets the :code:`TCP_NODELAY` socket flag on the server as well
  as pushes it to connecting clients. The :code:`TCP_NODELAY` flag disables
  the Nagle algorithm on TCP sockets causing packets to be transmitted
  immediately with low latency, rather than waiting a short period of time
  in order to aggregate several packets into a larger containing packet.
  In VPN applications over TCP, :code:`TCP_NODELAY` is generally a good
  latency optimization.

  The macro expands as follows:
  ::

     if mode server:
         socket-flags TCP_NODELAY
         push "socket-flags TCP_NODELAY"

--max-packet-size size
  This option will instruct OpenVPN to try to limit the maximum on-write packet
  size by restricting the control channel packet size and setting ``--mssfix``.

  OpenVPN will try to keep its control channel messages below this size but
  due to some constraints in the protocol this is not always possible. If the
  option is not set, the control packet maximum size defaults to 1250.
  The control channel packet size will be restricted to values between
  154 and 2048. The maximum packet size includes encapsulation overhead like
  UDP and IP.

  In terms of ``--mssfix`` it will expand to:
  ::

      mssfix size mtu

  If you need to set ``--mssfix`` for data channel and control channel maximum
  packet size independently, use ``--max-packet-size`` first, followed by a
  ``--mssfix`` in the configuration.

  In general the default size of 1250 should work almost universally apart
  from specific corner cases, especially since IPv6 requires a MTU of 1280
  or larger.
