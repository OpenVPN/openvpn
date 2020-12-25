Virtual Network Adapter (VPN interface)
---------------------------------------

Options in this section relates to configuration of the virtual tun/tap
network interface, including setting the VPN IP address and network
routing.

--bind-dev device
  (Linux only) Set ``device`` to bind the server socket to a
  `Virtual Routing and Forwarding`_ device

--block-ipv6
  On the client, instead of sending IPv6 packets over the VPN tunnel, all
  IPv6 packets are answered with an ICMPv6 no route host message. On the
  server, all IPv6 packets from clients are answered with an ICMPv6 no
  route to host message. This options is intended for cases when IPv6
  should be blocked and other options are not available. ``--block-ipv6``
  will use the remote IPv6 as source address of the ICMPv6 packets if set,
  otherwise will use :code:`fe80::7` as source address.

  For this option to make sense you actually have to route traffic to the
  tun interface. The following example config block would send all IPv6
  traffic to OpenVPN and answer all requests with no route to host,
  effectively blocking IPv6 (to avoid IPv6 connections from dual-stacked
  clients leaking around IPv4-only VPN services).

  **Client config**
    ::

       --ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1
       --redirect-gateway ipv6
       --block-ipv6

  **Server config**
    Push a "valid" ipv6 config to the client and block on the server
    ::

       --push "ifconfig-ipv6 fd15:53b6:dead::2/64 fd15:53b6:dead::1"
       --push "redirect-gateway ipv6"
       --block-ipv6

  Note: this option does not influence traffic sent from the server
  towards the client (neither on the server nor on the client side).
  This is not seen as necessary, as such traffic can be most easily
  avoided by not configuring IPv6 on the server tun, or setting up a
  server-side firewall rule.

--dev device
  TUN/TAP virtual network device which can be :code:`tunX`, :code:`tapX`,
  :code:`null` or an arbitrary name string (:code:`X` can be omitted for
  a dynamic device.)

  See examples section below for an example on setting up a TUN device.

  You must use either tun devices on both ends of the connection or tap
  devices on both ends. You cannot mix them, as they represent different
  underlying network layers:

  :code:`tun`
      devices encapsulate IPv4 or IPv6 (OSI Layer 3)

  :code:`tap`
      devices encapsulate Ethernet 802.3 (OSI Layer 2).

  Valid syntaxes:
  ::

     dev tun2
     dev tap4
     dev ovpn

  When the device name starts with :code:`tun` or :code:`tap`, the device
  type is extracted automatically.  Otherwise the ``--dev-type`` option
  needs to be added as well.

--dev-node node
  Explicitly set the device node rather than using :code:`/dev/net/tun`,
  :code:`/dev/tun`, :code:`/dev/tap`, etc. If OpenVPN cannot figure out
  whether ``node`` is a TUN or TAP device based on the name, you should
  also specify ``--dev-type tun`` or ``--dev-type tap``.

  Under Mac OS X this option can be used to specify the default tun
  implementation. Using ``--dev-node utun`` forces usage of the native
  Darwin tun kernel support. Use ``--dev-node utunN`` to select a specific
  utun instance. To force using the :code:`tun.kext` (:code:`/dev/tunX`)
  use ``--dev-node tun``. When not specifying a ``--dev-node`` option
  openvpn will first try to open utun, and fall back to tun.kext.

  On Windows systems, select the TAP-Win32 adapter which is named ``node``
  in the Network Connections Control Panel or the raw GUID of the adapter
  enclosed by braces. The ``--show-adapters`` option under Windows can
  also be used to enumerate all available TAP-Win32 adapters and will show
  both the network connections control panel name and the GUID for each
  TAP-Win32 adapter.

--dev-type device-type
  Which device type are we using? ``device-type`` should be :code:`tun`
  (OSI Layer 3) or :code:`tap` (OSI Layer 2). Use this option only if
  the TUN/TAP device used with ``--dev`` does not begin with :code:`tun`
  or :code:`tap`.

--dhcp-option args
  Set additional network parameters on supported platforms. May be specified
  on the client or pushed from the server. On Windows these options are
  handled by the ``tap-windows6`` driver by default or directly by OpenVPN
  if dhcp is disabled or the ``wintun`` driver is in use. The
  ``OpenVPN for Android`` client also handles them internally.

  On all other platforms these options are only saved in the client's
  environment under the name :code:`foreign_options_{n}` before the
  ``--up`` script is called. A plugin or an ``--up`` script must be used to
  pick up and interpret these as required. Many Linux distributions include
  such scripts and some third-party user interfaces such as tunnelblick also
  come with scripts that process these options.

  Valid syntax:
  ::

     dhcp-options type [parm]

  :code:`DOMAIN` ``name``
        Set Connection-specific DNS Suffix to :code:`name`.

  :code:`ADAPTER_DOMAIN_SUFFIX` ``name``
        Alias to :code:`DOMAIN`. This is a compatibility option, it
        should not be used in new deployments.

  :code:`DOMAIN-SEARCH` ``name``
        Add :code:`name` to the domain search list.
        Repeat this option to add more entries. Up to
        10 domains are supported.

  :code:`DNS` ``address``
        Set primary domain name server IPv4 or IPv6 address.
        Repeat this option to set secondary DNS server addresses.

        Note: DNS IPv6 servers are currently set using netsh (the existing
        DHCP code can only do IPv4 DHCP, and that protocol only permits
        IPv4 addresses anywhere). The option will be put into the
        environment, so an ``--up`` script could act upon it if needed.

  :code:`WINS` ``address``
        Set primary WINS server address (NetBIOS over TCP/IP Name Server).
        Repeat this option to set secondary WINS server addresses.

  :code:`NBDD` ``address``
        Set primary NBDD server address (NetBIOS over TCP/IP Datagram
        Distribution Server). Repeat this option to set secondary NBDD
        server addresses.

  :code:`NTP` ``address``
        Set primary NTP server address (Network Time Protocol).
        Repeat this option to set secondary NTP server addresses.

  :code:`NBT` ``type``
        Set NetBIOS over TCP/IP Node type. Possible options:

        :code:`1`
              b-node (broadcasts)

        :code:`2`
              p-node (point-to-point name queries to a WINS server)

        :code:`4`
              m-node (broadcast then query name server)

        :code:`8`
              h-node (query name server, then broadcast).

  :code:`NBS` ``scope-id``
        Set NetBIOS over TCP/IP Scope. A NetBIOS Scope ID provides an
        extended naming service for the NetBIOS over TCP/IP (Known as NBT)
        module. The primary purpose of a NetBIOS scope ID is to isolate
        NetBIOS traffic on a single network to only those nodes with the
        same NetBIOS scope ID. The NetBIOS scope ID is a character string
        that is appended to the NetBIOS name. The NetBIOS scope ID on two
        hosts must match, or the two hosts will not be able to communicate.
        The NetBIOS Scope ID also allows computers to use the same computer
        name, as they have different scope IDs. The Scope ID becomes a part
        of the NetBIOS name, making the name unique. (This description of
        NetBIOS scopes courtesy of NeonSurge@abyss.com)

  :code:`DISABLE-NBT`
        Disable Netbios-over-TCP/IP.

--ifconfig args
  Set TUN/TAP adapter parameters. It requires the *IP address* of the local
  VPN endpoint. For TUN devices in point-to-point mode, the next argument
  must be the VPN IP address of the remote VPN endpoint. For TAP devices,
  or TUN devices used with ``--topology subnet``, the second argument
  is the subnet mask of the virtual network segment which is being created
  or connected to.

  For TUN devices, which facilitate virtual point-to-point IP connections
  (when used in ``--topology net30`` or ``p2p`` mode), the proper usage of
  ``--ifconfig`` is to use two private IP addresses which are not a member
  of any existing subnet which is in use. The IP addresses may be
  consecutive and should have their order reversed on the remote peer.
  After the VPN is established, by pinging ``rn``, you will be pinging
  across the VPN.

  For TAP devices, which provide the ability to create virtual ethernet
  segments, or TUN devices in ``--topology subnet`` mode (which create
  virtual "multipoint networks"), ``--ifconfig`` is used to set an IP
  address and subnet mask just as a physical ethernet adapter would be
  similarly configured. If you are attempting to connect to a remote
  ethernet bridge, the IP address and subnet should be set to values which
  would be valid on the the bridged ethernet segment (note also that DHCP
  can be used for the same purpose).

  This option, while primarily a proxy for the ``ifconfig``\(8) command,
  is designed to simplify TUN/TAP tunnel configuration by providing a
  standard interface to the different ifconfig implementations on
  different platforms.

  ``--ifconfig`` parameters which are IP addresses can also be specified
  as a DNS or /etc/hosts file resolvable name.

  For TAP devices, ``--ifconfig`` should not be used if the TAP interface
  will be getting an IP address lease from a DHCP server.

  Examples:
  ::

     # tun device in net30/p2p mode
     ifconfig 10.8.0.2 10.8.0.1

     # tun/tap device in subnet mode
     ifconfig 10.8.0.2 255.255.255.0

--ifconfig-ipv6 args
  Configure an IPv6 address on the *tun* device.

  Valid syntax:
  ::

     ifconfig-ipv6 ipv6addr/bits [ipv6remote]

  The ``ipv6addr/bits`` argument is the IPv6 address to use. The
  second parameter is used as route target for ``--route-ipv6`` if no
  gateway is specified.

  The ``--topology`` option has no influence with ``--ifconfig-ipv6``

--ifconfig-noexec
  Don't actually execute ifconfig/netsh commands, instead pass
  ``--ifconfig`` parameters to scripts using environmental variables.

--ifconfig-nowarn
  Don't output an options consistency check warning if the ``--ifconfig``
  option on this side of the connection doesn't match the remote side.
  This is useful when you want to retain the overall benefits of the
  options consistency check (also see ``--disable-occ`` option) while only
  disabling the ifconfig component of the check.

  For example, if you have a configuration where the local host uses
  ``--ifconfig`` but the remote host does not, use ``--ifconfig-nowarn``
  on the local host.

  This option will also silence warnings about potential address conflicts
  which occasionally annoy more experienced users by triggering "false
  positive" warnings.

--lladdr address
  Specify the link layer address, more commonly known as the MAC address.
  Only applied to TAP devices.

--persist-tun
  Don't close and reopen TUN/TAP device or run up/down scripts across
  :code:`SIGUSR1` or ``--ping-restart`` restarts.

  :code:`SIGUSR1` is a restart signal similar to :code:`SIGHUP`, but which
  offers finer-grained control over reset options.

--redirect-gateway flags
  Automatically execute routing commands to cause all outgoing IP traffic
  to be redirected over the VPN. This is a client-side option.

  This option performs three steps:

  (1)  Create a static route for the ``--remote`` address which
       forwards to the pre-existing default gateway. This is done so that
       ``(3)`` will not create a routing loop.

  (2)  Delete the default gateway route.

  (3)  Set the new default gateway to be the VPN endpoint address
       (derived either from ``--route-gateway`` or the second parameter to
       ``--ifconfig`` when ``--dev tun`` is specified).

  When the tunnel is torn down, all of the above steps are reversed so
  that the original default route is restored.

  Option flags:

  :code:`local`
      Add the :code:`local` flag if both OpenVPN peers are directly
      connected via a common subnet, such as with wireless. The
      :code:`local` flag will cause step ``(1)`` above to be omitted.

  :code:`autolocal`
      Try to automatically determine whether to enable :code:`local`
      flag above.

  :code:`def1`
      Use this flag to override the default gateway by using
      :code:`0.0.0.0/1` and :code:`128.0.0.0/1` rather than
      :code:`0.0.0.0/0`. This has the benefit of overriding but not
      wiping out the original default gateway.

  :code:`bypass-dhcp`
      Add a direct route to the DHCP server (if it is non-local) which
      bypasses the tunnel (Available on Windows clients, may not be
      available on non-Windows clients).

  :code:`bypass-dns`
      Add a direct route to the DNS server(s) (if they are non-local)
      which bypasses the tunnel (Available on Windows clients, may
      not be available on non-Windows clients).

  :code:`block-local`
      Block access to local LAN when the tunnel is active, except for
      the LAN gateway itself. This is accomplished by routing the local
      LAN (except for the LAN gateway address) into the tunnel.

  :code:`ipv6`
      Redirect IPv6 routing into the tunnel. This works similar to
      the :code:`def1` flag, that is, more specific IPv6 routes are added
      (:code:`2000::/4`, :code:`3000::/4`), covering the whole IPv6
      unicast space.

  :code:`!ipv4`
      Do not redirect IPv4 traffic - typically used in the flag pair
      :code:`ipv6 !ipv4` to redirect IPv6-only.

--redirect-private flags
  Like ``--redirect-gateway``, but omit actually changing the default gateway.
  Useful when pushing private subnets.

--route args
  Add route to routing table after connection is established. Multiple
  routes can be specified. Routes will be automatically torn down in
  reverse order prior to TUN/TAP device close.

  Valid syntaxes:
  ::

      route network/IP
      route network/IP netmask
      route network/IP netmask gateway
      route network/IP netmask gateway metric

  This option is intended as a convenience proxy for the ``route``\(8)
  shell command, while at the same time providing portable semantics
  across OpenVPN's platform space.

  ``netmask``
        defaults to :code:`255.255.255.255` when not given

  ``gateway``
        default taken from ``--route-gateway`` or the second
        parameter to ``--ifconfig`` when ``--dev tun`` is specified.

  ``metric``
        default taken from ``--route-metric`` if set, otherwise :code:`0`.

  The default can be specified by leaving an option blank or setting it to
  :code:`default`.

  The ``network`` and ``gateway`` parameters can also be specified as a
  DNS or :code:`/etc/hosts` file resolvable name, or as one of three special
  keywords:

  :code:`vpn_gateway`
      The remote VPN endpoint address (derived either from
      ``--route-gateway`` or the second parameter to ``--ifconfig``
      when ``--dev tun`` is specified).

  :code:`net_gateway`
      The pre-existing IP default gateway, read from the
      routing table (not supported on all OSes).

  :code:`remote_host`
      The ``--remote`` address if OpenVPN is being run in
      client mode, and is undefined in server mode.

--route-delay args
  Valid syntaxes:
  ::

       route-delay
       route-delay n
       route-delay n m

  Delay ``n`` seconds (default :code:`0`) after connection establishment,
  before adding routes. If ``n`` is :code:`0`, routes will be added
  immediately upon connection establishment. If ``--route-delay`` is
  omitted, routes will be added immediately after TUN/TAP device open and
  ``--up`` script execution, before any ``--user`` or ``--group`` privilege
  downgrade (or ``--chroot`` execution.)

  This option is designed to be useful in scenarios where DHCP is used to
  set tap adapter addresses. The delay will give the DHCP handshake time
  to complete before routes are added.

  On Windows, ``--route-delay`` tries to be more intelligent by waiting
  ``w`` seconds (default :code:`30` by default) for the TAP-Win32 adapter
  to come up before adding routes.

--route-ipv6 args
  Setup IPv6 routing in the system to send the specified IPv6 network into
  OpenVPN's *tun*.

  Valid syntax:
  ::

     route-ipv6 ipv6addr/bits [gateway] [metric]

  The gateway parameter is only used for IPv6 routes across *tap* devices,
  and if missing, the ``ipv6remote`` field from ``--ifconfig-ipv6`` or
  ``--route-ipv6-gateway`` is used.

--route-gateway arg
  Specify a default *gateway* for use with ``--route``.

  If :code:`dhcp` is specified as the parameter, the gateway address will
  be extracted from a DHCP negotiation with the OpenVPN server-side LAN.

  Valid syntaxes:
  ::

      route-gateway gateway
      route-gateway dhcp

--route-ipv6-gateway gw
  Specify a default gateway ``gw`` for use with ``--route-ipv6``.

--route-metric m
  Specify a default metric ``m`` for use with ``--route``.

--route-noexec
  Don't add or remove routes automatically. Instead pass routes to
  ``--route-up`` script using environmental variables.

--route-nopull
  When used with ``--client`` or ``--pull``, accept options pushed by
  server EXCEPT for routes, block-outside-dns and dhcp options like DNS
  servers.

  When used on the client, this option effectively bars the server from
  adding routes to the client's routing table, however note that this
  option still allows the server to set the TCP/IP properties of the
  client's TUN/TAP interface.

--topology mode
  Configure virtual addressing topology when running in ``--dev tun``
  mode. This directive has no meaning in ``--dev tap`` mode, which always
  uses a :code:`subnet` topology.

  If you set this directive on the server, the ``--server`` and
  ``--server-bridge`` directives will automatically push your chosen
  topology setting to clients as well. This directive can also be manually
  pushed to clients. Like the ``--dev`` directive, this directive must
  always be compatible between client and server.

  ``mode`` can be one of:

  :code:`net30`
    Use a point-to-point topology, by allocating one /30 subnet
    per client. This is designed to allow point-to-point semantics when some
    or all of the connecting clients might be Windows systems. This is the
    default on OpenVPN 2.0.

  :code:`p2p`
    Use a point-to-point topology where the remote endpoint of
    the client's tun interface always points to the local endpoint of the
    server's tun interface. This mode allocates a single IP address per
    connecting client. Only use when none of the connecting clients are
    Windows systems.

  :code:`subnet`
    Use a subnet rather than a point-to-point topology by
    configuring the tun interface with a local IP address and subnet mask,
    similar to the topology used in ``--dev tap`` and ethernet bridging
    mode. This mode allocates a single IP address per connecting client and
    works on Windows as well. Only available when server and clients are
    OpenVPN 2.1 or higher, or OpenVPN 2.0.x which has been manually patched
    with the ``--topology`` directive code. When used on Windows, requires
    version 8.2 or higher of the TAP-Win32 driver. When used on \*nix,
    requires that the tun driver supports an ``ifconfig``\(8) command which
    sets a subnet instead of a remote endpoint IP address.

  *Note:* Using ``--topology subnet`` changes the interpretation of the
  arguments of ``--ifconfig`` to mean "address netmask", no longer "local
  remote".

--tun-mtu n
  Take the TUN device MTU to be **n** and derive the link MTU from it
  (default :code:`1500`). In most cases, you will probably want to leave
  this parameter set to its default value.

  The MTU (Maximum Transmission Units) is the maximum datagram size in
  bytes that can be sent unfragmented over a particular network path.
  OpenVPN requires that packets on the control and data channels be sent
  unfragmented.

  MTU problems often manifest themselves as connections which hang during
  periods of active usage.

  It's best to use the ``--fragment`` and/or ``--mssfix`` options to deal
  with MTU sizing issues.

--tun-mtu-extra n
  Assume that the TUN/TAP device might return as many as ``n`` bytes more
  than the ``--tun-mtu`` size on read. This parameter defaults to 0, which
  is sufficient for most TUN devices. TAP devices may introduce additional
  overhead in excess of the MTU size, and a setting of 32 is the default
  when TAP devices are used. This parameter only controls internal OpenVPN
  buffer sizing, so there is no transmission overhead associated with
  using a larger value.


TUN/TAP standalone operations
-----------------------------
These two standalone operations will require ``--dev`` and optionally
``--user`` and/or ``--group``.

--mktun
  (Standalone) Create a persistent tunnel on platforms which support them
  such as Linux. Normally TUN/TAP tunnels exist only for the period of
  time that an application has them open. This option takes advantage of
  the TUN/TAP driver's ability to build persistent tunnels that live
  through multiple instantiations of OpenVPN and die only when they are
  deleted or the machine is rebooted.

  One of the advantages of persistent tunnels is that they eliminate the
  need for separate ``--up`` and ``--down`` scripts to run the appropriate
  ``ifconfig``\(8) and ``route``\(8) commands. These commands can be
  placed in the the same shell script which starts or terminates an
  OpenVPN session.

  Another advantage is that open connections through the TUN/TAP-based
  tunnel will not be reset if the OpenVPN peer restarts. This can be
  useful to provide uninterrupted connectivity through the tunnel in the
  event of a DHCP reset of the peer's public IP address (see the
  ``--ipchange`` option above).

  One disadvantage of persistent tunnels is that it is harder to
  automatically configure their MTU value (see ``--link-mtu`` and
  ``--tun-mtu`` above).

  On some platforms such as Windows, TAP-Win32 tunnels are persistent by
  default.

--rmtun
  (Standalone) Remove a persistent tunnel.
