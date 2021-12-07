Server Options
--------------
Starting with OpenVPN 2.0, a multi-client TCP/UDP server mode is
supported, and can be enabled with the ``--mode server`` option. In
server mode, OpenVPN will listen on a single port for incoming client
connections. All client connections will be routed through a single tun
or tap interface. This mode is designed for scalability and should be
able to support hundreds or even thousands of clients on sufficiently
fast hardware. SSL/TLS authentication must be used in this mode.

--auth-gen-token args
  Returns an authentication token to successfully authenticated clients.

  Valid syntax:
  ::

     auth-gen-token [lifetime] [external-auth]

  After successful user/password authentication, the OpenVPN server will
  with this option generate a temporary authentication token and push that
  to the client. On the following renegotiations, the OpenVPN client will pass
  this token instead of the users password. On the server side the server
  will do the token authentication internally and it will NOT do any
  additional authentications against configured external user/password
  authentication mechanisms.

  The tokens implemented by this mechanism include an initial timestamp and
  a renew timestamp and are secured by HMAC.

  The ``lifetime`` argument defines how long the generated token is valid.
  The lifetime is defined in seconds. If lifetime is not set or it is set
  to :code:`0`, the token will never expire.

  The token will expire either after the configured ``lifetime`` of the
  token is reached or after not being renewed for more than 2 \*
  ``reneg-sec`` seconds. Clients will be sent renewed tokens on every TLS
  renogiation to keep the client's token updated. This is done to
  invalidate a token if a client is disconnected for a sufficently long
  time, while at the same time permitting much longer token lifetimes for
  active clients.

  This feature is useful for environments which are configured to use One
  Time Passwords (OTP) as part of the user/password authentications and
  that authentication mechanism does not implement any auth-token support.

  When the :code:`external-auth` keyword is present the normal
  authentication method will always be called even if auth-token succeeds.
  Normally other authentications method are skipped if auth-token
  verification suceeds or fails.

  This option postpones this decision to the external authentication
  methods and checks the validity of the account and do other checks.

  In this mode the environment will have a ``session_id`` variable that
  holds the session id from auth-gen-token. Also an environment variable
  ``session_state`` is present. This variable indicates whether the
  auth-token has succeeded or not. It can have the following values:

  :code:`Initial`
      No token from client.

  :code:`Authenticated`
      Token is valid and not expired.

  :code:`Expired`
      Token is valid but has expired.

  :code:`Invalid`
      Token is invalid (failed HMAC or wrong length)

  :code:`AuthenticatedEmptyUser` / :code:`ExpiredEmptyUser`
      The token is not valid with the username sent from the client but
      would be valid (or expired) if we assume an empty username was
      used instead.  These two cases are a workaround for behaviour in
      OpenVPN 3.  If this workaround is not needed these two cases should
      be handled in the same way as :code:`Invalid`.

  **Warning:** Use this feature only if you want your authentication
  method called on every verification. Since the external authentication
  is called it needs to also indicate a success or failure of the
  authentication. It is strongly recommended to return an authentication
  failure in the case of the Invalid/Expired auth-token with the
  external-auth option unless the client could authenticate in another
  acceptable way (e.g. client certificate), otherwise returning success
  will lead to authentication bypass (as does returning success on a wrong
  password from a script).

--auth-gen-token-secret file
  Specifies a file that holds a secret for the HMAC used in
  ``--auth-gen-token`` If ``file`` is not present OpenVPN will generate a
  random secret on startup. This file should be used if auth-token should
  validate after restarting a server or if client should be able to roam
  between multiple OpenVPN servers with their auth-token.

--auth-user-pass-optional
  Allow connections by clients that do not specify a username/password.
  Normally, when ``--auth-user-pass-verify`` or
  ``--management-client-auth`` are specified (or an authentication plugin
  module), the OpenVPN server daemon will require connecting clients to
  specify a username and password. This option makes the submission of a
  username/password by clients optional, passing the responsibility to the
  user-defined authentication module/script to accept or deny the client
  based on other factors (such as the setting of X509 certificate fields).
  When this option is used, and a connecting client does not submit a
  username/password, the user-defined authentication module/script will
  see the username and password as being set to empty strings (""). The
  authentication module/script MUST have logic to detect this condition
  and respond accordingly.

--ccd-exclusive
  Require, as a condition of authentication, that a connecting client has
  a ``--client-config-dir`` file.

--client-config-dir dir
  Specify a directory ``dir`` for custom client config files. After a
  connecting client has been authenticated, OpenVPN will look in this
  directory for a file having the same name as the client's X509 common
  name. If a matching file exists, it will be opened and parsed for
  client-specific configuration options. If no matching file is found,
  OpenVPN will instead try to open and parse a default file called
  "DEFAULT", which may be provided but is not required. Note that the
  configuration files must be readable by the OpenVPN process after it has
  dropped it's root privileges.

  This file can specify a fixed IP address for a given client using
  ``--ifconfig-push``, as well as fixed subnets owned by the client using
  ``--iroute``.

  One of the useful properties of this option is that it allows client
  configuration files to be conveniently created, edited, or removed while
  the server is live, without needing to restart the server.

  The following options are legal in a client-specific context: ``--push``,
  ``--push-reset``, ``--push-remove``, ``--iroute``, ``--ifconfig-push``,
  ``--vlan-pvid`` and ``--config``.

--client-to-client
  Because the OpenVPN server mode handles multiple clients through a
  single tun or tap interface, it is effectively a router. The
  ``--client-to-client`` flag tells OpenVPN to internally route
  client-to-client traffic rather than pushing all client-originating
  traffic to the TUN/TAP interface.

  When this option is used, each client will "see" the other clients which
  are currently connected. Otherwise, each client will only see the
  server. Don't use this option if you want to firewall tunnel traffic
  using custom, per-client rules.

--disable
  Disable a particular client (based on the common name) from connecting.
  Don't use this option to disable a client due to key or password
  compromise. Use a CRL (certificate revocation list) instead (see the
  ``--crl-verify`` option).

  This option must be associated with a specific client instance, which
  means that it must be specified either in a client instance config file
  using ``--client-config-dir`` or dynamically generated using a
  ``--client-connect`` script.

--connect-freq args
  Allow a maximum of ``n`` new connections per ``sec`` seconds from
  clients.

  Valid syntax:
  ::

     connect-freq n sec

  This is designed to contain DoS attacks which flood the server
  with connection requests using certificates which will ultimately fail
  to authenticate.

  This is an imperfect solution however, because in a real DoS scenario,
  legitimate connections might also be refused.

  For the best protection against DoS attacks in server mode, use
  ``--proto udp`` and either ``--tls-auth`` or ``--tls-crypt``.

--duplicate-cn
  Allow multiple clients with the same common name to concurrently
  connect. In the absence of this option, OpenVPN will disconnect a client
  instance upon connection of a new client having the same common name.

--ifconfig-pool args
  Set aside a pool of subnets to be dynamically allocated to connecting
  clients, similar to a DHCP server.

  Valid syntax:
  ::

     ifconfig-pool start-IP end-IP [netmask]

  For tun-style tunnels, each client
  will be given a /30 subnet (for interoperability with Windows clients).
  For tap-style tunnels, individual addresses will be allocated, and the
  optional ``netmask`` parameter will also be pushed to clients.

--ifconfig-ipv6-pool args
  Specify an IPv6 address pool for dynamic assignment to clients.

  Valid args:
  ::

     ifconfig-ipv6-pool ipv6addr/bits

  The pool starts at ``ipv6addr`` and matches the offset determined from
  the start of the IPv4 pool.  If the host part of the given IPv6
  address is ``0``, the pool starts at ``ipv6addr`` +1.

--ifconfig-pool-persist args
  Persist/unpersist ifconfig-pool data to ``file``, at ``seconds``
  intervals (default :code:`600`), as well as on program startup and shutdown.

  Valid syntax:
  ::

     ifconfig-pool-persist file [seconds]

  The goal of this option is to provide a long-term association between
  clients (denoted by their common name) and the virtual IP address
  assigned to them from the ifconfig-pool. Maintaining a long-term
  association is good for clients because it allows them to effectively
  use the ``--persist-tun`` option.

  ``file`` is a comma-delimited ASCII file, formatted as
  :code:`<Common-Name>,<IP-address>`.

  If ``seconds`` = :code:`0`, ``file`` will be treated as read-only. This
  is useful if you would like to treat ``file`` as a configuration file.

  Note that the entries in this file are treated by OpenVPN as
  *suggestions* only, based on past associations between a common name and
  IP address.  They do not guarantee that the given common name will always
  receive the given IP address. If you want guaranteed assignment, use
  ``--ifconfig-push``

--ifconfig-push args
  Push virtual IP endpoints for client tunnel, overriding the
  ``--ifconfig-pool`` dynamic allocation.

  Valid syntax:
  ::

     ifconfig-push local remote-netmask [alias]

  The parameters ``local`` and ``remote-netmask`` are set according to the
  ``--ifconfig`` directive which you want to execute on the client machine
  to configure the remote end of the tunnel. Note that the parameters
  ``local`` and ``remote-netmask`` are from the perspective of the client,
  not the server. They may be DNS names rather than IP addresses, in which
  case they will be resolved on the server at the time of client
  connection.

  The optional ``alias`` parameter may be used in cases where NAT causes
  the client view of its local endpoint to differ from the server view. In
  this case ``local/remote-netmask`` will refer to the server view while
  ``alias/remote-netmask`` will refer to the client view.

  This option must be associated with a specific client instance, which
  means that it must be specified either in a client instance config file
  using ``--client-config-dir`` or dynamically generated using a
  ``--client-connect`` script.

  Remember also to include a ``--route`` directive in the main OpenVPN
  config file which encloses ``local``, so that the kernel will know to
  route it to the server's TUN/TAP interface.

  OpenVPN's internal client IP address selection algorithm works as
  follows:

  1.  Use ``--client-connect script`` generated file for static IP
      (first choice).

  2.  Use ``--client-config-dir`` file for static IP (next choice).

  3.  Use ``--ifconfig-pool`` allocation for dynamic IP (last
      choice).

--ifconfig-ipv6-push args
  for ``--client-config-dir`` per-client static IPv6 interface
  configuration, see ``--client-config-dir`` and ``--ifconfig-push`` for
  more details.

  Valid syntax:
  ::

     ifconfig-ipv6-push ipv6addr/bits ipv6remote

--inetd args
  Valid syntaxes:
  ::

     inetd
     inetd wait
     inetd nowait
     inetd wait progname

  Use this option when OpenVPN is being run from the inetd or ``xinetd``\(8)
  server.

  The :code:`wait` and :code:`nowait` option must match what is specified
  in the inetd/xinetd config file. The :code:`nowait` mode can only be used
  with ``--proto tcp-server`` The default is :code:`wait`.  The
  :code:`nowait` mode can be used to instantiate the OpenVPN daemon as a
  classic TCP server, where client connection requests are serviced on a
  single port number. For additional information on this kind of
  configuration, see the OpenVPN FAQ:
  https://community.openvpn.net/openvpn/wiki/325-openvpn-as-a--forking-tcp-server-which-can-service-multiple-clients-over-a-single-tcp-port

  This option precludes the use of ``--daemon``, ``--local`` or
  ``--remote``.  Note that this option causes message and error output to
  be handled in the same way as the ``--daemon`` option. The optional
  ``progname`` parameter is also handled exactly as in ``--daemon``.

  Also note that in ``wait`` mode, each OpenVPN tunnel requires a separate
  TCP/UDP port and a separate inetd or xinetd entry. See the OpenVPN 1.x
  HOWTO for an example on using OpenVPN with xinetd:
  https://openvpn.net/community-resources/1xhowto/

--multihome
  Configure a multi-homed UDP server. This option needs to be used when a
  server has more than one IP address (e.g. multiple interfaces, or
  secondary IP addresses), and is not using ``--local`` to force binding
  to one specific address only. This option will add some extra lookups to
  the packet path to ensure that the UDP reply packets are always sent
  from the address that the client is talking to. This is not supported on
  all platforms, and it adds more processing, so it's not enabled by
  default.

  *Notes:*
    -  This option is only relevant for UDP servers.
    -  If you do an IPv6+IPv4 dual-stack bind on a Linux machine with
       multiple IPv4 address, connections to IPv4 addresses will not
       work right on kernels before 3.15, due to missing kernel
       support for the IPv4-mapped case (some distributions have
       ported this to earlier kernel versions, though).

--iroute args
  Generate an internal route to a specific client. The ``netmask``
  parameter, if omitted, defaults to :code:`255.255.255.255`.

  Valid syntax:
  ::

     iroute network [netmask]

  This directive can be used to route a fixed subnet from the server to a
  particular client, regardless of where the client is connecting from.
  Remember that you must also add the route to the system routing table as
  well (such as by using the ``--route`` directive). The reason why two
  routes are needed is that the ``--route`` directive routes the packet
  from the kernel to OpenVPN. Once in OpenVPN, the ``--iroute`` directive
  routes to the specific client.

  This option must be specified either in a client instance config file
  using ``--client-config-dir`` or dynamically generated using a
  ``--client-connect`` script.

  The ``--iroute`` directive also has an important interaction with
  ``--push "route ..."``. ``--iroute`` essentially defines a subnet which
  is owned by a particular client (we will call this client *A*). If you
  would like other clients to be able to reach *A*'s subnet, you can use
  ``--push "route ..."`` together with ``--client-to-client`` to effect
  this. In order for all clients to see *A*'s subnet, OpenVPN must push
  this route to all clients EXCEPT for *A*, since the subnet is already
  owned by *A*. OpenVPN accomplishes this by not not pushing a route to
  a client if it matches one of the client's iroutes.

--iroute-ipv6 args
  for ``--client-config-dir`` per-client static IPv6 route configuration,
  see ``--iroute`` for more details how to setup and use this, and how
  ``--iroute`` and ``--route`` interact.

  Valid syntax:
  ::

     iroute-ipv6 ipv6addr/bits

--max-clients n
  Limit server to a maximum of ``n`` concurrent clients.

--max-routes-per-client n
  Allow a maximum of ``n`` internal routes per client (default
  :code:`256`). This is designed to help contain DoS attacks where an
  authenticated client floods the server with packets appearing to come
  from many unique MAC addresses, forcing the server to deplete virtual
  memory as its internal routing table expands. This directive can be used
  in a ``--client-config-dir`` file or auto-generated by a
  ``--client-connect`` script to override the global value for a particular
  client.

  Note that this directive affects OpenVPN's internal routing table, not
  the kernel routing table.

--opt-verify
  Clients that connect with options that are incompatible with those of the
  server will be disconnected.

  Options that will be compared for compatibility include ``dev-type``,
  ``link-mtu``, ``tun-mtu``, ``proto``, ``ifconfig``,
  ``comp-lzo``, ``fragment``, ``keydir``, ``cipher``,
  ``auth``, ``keysize``, ``secret``, ``no-replay``,
  ``tls-auth``, ``key-method``, ``tls-server``
  and ``tls-client``.

  This option requires that ``--disable-occ`` NOT be used.

--port-share args
  Share OpenVPN TCP with another service

  Valid syntax:
  ::

     port-share host port [dir]

  When run in TCP server mode, share the OpenVPN port with another
  application, such as an HTTPS server. If OpenVPN senses a connection to
  its port which is using a non-OpenVPN protocol, it will proxy the
  connection to the server at ``host``:``port``. Currently only designed to
  work with HTTP/HTTPS, though it would be theoretically possible to
  extend to other protocols such as ssh.

  ``dir`` specifies an optional directory where a temporary file with name
  N containing content C will be dynamically generated for each proxy
  connection, where N is the source IP:port of the client connection and C
  is the source IP:port of the connection to the proxy receiver. This
  directory can be used as a dictionary by the proxy receiver to determine
  the origin of the connection. Each generated file will be automatically
  deleted when the proxied connection is torn down.

  Not implemented on Windows.

--push option
  Push a config file option back to the client for remote execution. Note
  that ``option`` must be enclosed in double quotes (:code:`""`). The
  client must specify ``--pull`` in its config file. The set of options
  which can be pushed is limited by both feasibility and security. Some
  options such as those which would execute scripts are banned, since they
  would effectively allow a compromised server to execute arbitrary code
  on the client. Other options such as TLS or MTU parameters cannot be
  pushed because the client needs to know them before the connection to the
  server can be initiated.

  This is a partial list of options which can currently be pushed:
  ``--route``, ``--route-gateway``, ``--route-delay``,
  ``--redirect-gateway``, ``--ip-win32``, ``--dhcp-option``,
  ``--inactive``, ``--ping``, ``--ping-exit``, ``--ping-restart``,
  ``--setenv``, ``--auth-token``, ``--persist-key``, ``--persist-tun``,
  ``--echo``, ``--comp-lzo``, ``--socket-flags``, ``--sndbuf``,
  ``--rcvbuf``

--push-remove opt
  Selectively remove all ``--push`` options matching "opt" from the option
  list for a client. ``opt`` is matched as a substring against the whole
  option string to-be-pushed to the client, so ``--push-remove route``
  would remove all ``--push route ...`` and ``--push route-ipv6 ...``
  statements, while ``--push-remove "route-ipv6 2001:"`` would only remove
  IPv6 routes for :code:`2001:...` networks.

  ``--push-remove`` can only be used in a client-specific context, like in
  a ``--client-config-dir`` file, or ``--client-connect`` script or plugin
  -- similar to ``--push-reset``, just more selective.

  *NOTE*: to *change* an option, ``--push-remove`` can be used to first
  remove the old value, and then add a new ``--push`` option with the new
  value.

  *NOTE 2*: due to implementation details, 'ifconfig' and 'ifconfig-ipv6'
  can only be removed with an exact match on the option (
  :code:`push-remove ifconfig`), no substring matching and no matching on
  the IPv4/IPv6 address argument is possible.

--push-reset
  Don't inherit the global push list for a specific client instance.
  Specify this option in a client-specific context such as with a
  ``--client-config-dir`` configuration file. This option will ignore
  ``--push`` options at the global config file level.

  *NOTE*: ``--push-reset`` is very thorough: it will remove almost
  all options from the list of to-be-pushed options.  In many cases,
  some of these options will need to be re-configured afterwards -
  specifically, ``--topology subnet`` and ``--route-gateway`` will get
  lost and this will break client configs in many cases.  Thus, for most
  purposes, ``--push-remove`` is better suited to selectively remove
  push options for individual clients.

--server args
  A helper directive designed to simplify the configuration of OpenVPN's
  server mode. This directive will set up an OpenVPN server which will
  allocate addresses to clients out of the given network/netmask. The
  server itself will take the :code:`.1` address of the given network for
  use as the server-side endpoint of the local TUN/TAP interface. If the
  optional :code:`nopool` flag is given, no dynamic IP address pool will
  prepared for VPN clients.

  Valid syntax:
  ::

      server network netmask [nopool]

  For example, ``--server 10.8.0.0 255.255.255.0`` expands as follows:
  ::

     mode server
     tls-server
     push "topology [topology]"

     if dev tun AND (topology == net30 OR topology == p2p):
       ifconfig 10.8.0.1 10.8.0.2
       if !nopool:
         ifconfig-pool 10.8.0.4 10.8.0.251
       route 10.8.0.0 255.255.255.0
       if client-to-client:
         push "route 10.8.0.0 255.255.255.0"
       else if topology == net30:
         push "route 10.8.0.1"

     if dev tap OR (dev tun AND topology == subnet):
       ifconfig 10.8.0.1 255.255.255.0
       if !nopool:
         ifconfig-pool 10.8.0.2 10.8.0.253 255.255.255.0
       push "route-gateway 10.8.0.1"
       if route-gateway unset:
         route-gateway 10.8.0.2

  Don't use ``--server`` if you are ethernet bridging. Use
  ``--server-bridge`` instead.

--server-bridge args
  A helper directive similar to ``--server`` which is designed to simplify
  the configuration of OpenVPN's server mode in ethernet bridging
  configurations.

  Valid syntaxes:
  ::

      server-bridge gateway netmask pool-start-IP pool-end-IP
      server-bridge [nogw]

  If ``--server-bridge`` is used without any parameters, it will enable a
  DHCP-proxy mode, where connecting OpenVPN clients will receive an IP
  address for their TAP adapter from the DHCP server running on the
  OpenVPN server-side LAN. Note that only clients that support the binding
  of a DHCP client with the TAP adapter (such as Windows) can support this
  mode. The optional :code:`nogw` flag (advanced) indicates that gateway
  information should not be pushed to the client.

  To configure ethernet bridging, you must first use your OS's bridging
  capability to bridge the TAP interface with the ethernet NIC interface.
  For example, on Linux this is done with the :code:`brctl` tool, and with
  Windows XP it is done in the Network Connections Panel by selecting the
  ethernet and TAP adapters and right-clicking on "Bridge Connections".

  Next you you must manually set the IP/netmask on the bridge interface.
  The ``gateway`` and ``netmask`` parameters to ``--server-bridge`` can be
  set to either the IP/netmask of the bridge interface, or the IP/netmask
  of the default gateway/router on the bridged subnet.

  Finally, set aside a IP range in the bridged subnet, denoted by
  ``pool-start-IP`` and ``pool-end-IP``, for OpenVPN to allocate to
  connecting clients.

  For example, ``server-bridge 10.8.0.4 255.255.255.0 10.8.0.128
  10.8.0.254`` expands as follows:
  ::

    mode server
    tls-server

    ifconfig-pool 10.8.0.128 10.8.0.254 255.255.255.0
    push "route-gateway 10.8.0.4"

  In another example, ``--server-bridge`` (without parameters) expands as
  follows:
  ::

    mode server
    tls-server

    push "route-gateway dhcp"

  Or ``--server-bridge nogw`` expands as follows:
  ::

    mode server
    tls-server

--server-ipv6 args
  Convenience-function to enable a number of IPv6 related options at once,
  namely ``--ifconfig-ipv6``, ``--ifconfig-ipv6-pool`` and
  ``--push tun-ipv6``.

  Valid syntax:
  ::

     server-ipv6 ipv6addr/bits

  Pushing of the ``--tun-ipv6`` directive is done for older clients which
  require an explicit ``--tun-ipv6`` in their configuration.

--stale-routes-check args
  Remove routes which haven't had activity for ``n`` seconds (i.e. the ageing
  time).  This check is run every ``t`` seconds (i.e. check interval).

  Valid syntax:
  ::

     stale-routes-check n [t]

  If ``t`` is not present it defaults to ``n``.

  This option helps to keep the dynamic routing table small. See also
  ``--max-routes-per-client``

--username-as-common-name
  Use the authenticated username as the common-name, rather than the
  common-name from the client certificate. Requires that some form of
  ``--auth-user-pass`` verification is in effect. As the replacement happens
  after ``--auth-user-pass`` verification, the verification script or
  plugin will still receive the common-name from the certificate.

  The common_name environment variable passed to scripts and plugins invoked
  after authentication (e.g, client-connect script) and file names parsed in
  client-config directory will match the username.

--verify-client-cert mode
  Specify whether the client is required to supply a valid certificate.

  Possible ``mode`` options are:

  :code:`none`
      A client certificate is not required. the client needs to
      authenticate using username/password only. Be aware that using this
      directive is less secure than requiring certificates from all
      clients.

      If you use this directive, the entire responsibility of authentication
      will rest on your ``--auth-user-pass-verify`` script, so keep in mind
      that bugs in your script could potentially compromise the security of
      your VPN.

      ``--verify-client-cert none`` is functionally equivalent to
      ``--client-cert-not-required``.

  :code:`optional`
      A client may present a certificate but it is not required to do so.
      When using this directive, you should also use a
      ``--auth-user-pass-verify`` script to ensure that clients are
      authenticated using a certificate, a username and password, or
      possibly even both.

      Again, the entire responsibility of authentication will rest on your
      ``--auth-user-pass-verify`` script, so keep in mind that bugs in your
      script could potentially compromise the security of your VPN.

  :code:`require`
      This is the default option. A client is required to present a
      certificate, otherwise VPN access is refused.

  If you don't use this directive (or use ``--verify-client-cert require``)
  but you also specify an ``--auth-user-pass-verify`` script, then OpenVPN
  will perform double authentication. The client certificate verification
  AND the ``--auth-user-pass-verify`` script will need to succeed in order
  for a client to be authenticated and accepted onto the VPN.

--vlan-tagging
  Server-only option. Turns the OpenVPN server instance into a switch that
  understands VLAN-tagging, based on IEEE 802.1Q.

  The server TAP device and each of the connecting clients is seen as a
  port of the switch. All client ports are in untagged mode and the server
  TAP device is VLAN-tagged, untagged or accepts both, depending on the
  ``--vlan-accept`` setting.

  Ethernet frames with a prepended 802.1Q tag are called "tagged". If the
  VLAN Identifier (VID) field in such a tag is non-zero, the frame is
  called "VLAN-tagged". If the VID is zero, but the Priority Control Point
  (PCP) field is non-zero, the frame is called "prio-tagged". If there is
  no 802.1Q tag, the frame is "untagged".

  Using the ``--vlan-pvid v`` option once per client (see
  --client-config-dir), each port can be associated with a certain VID.
  Packets can only be forwarded between ports having the same VID.
  Therefore, clients with differing VIDs are completely separated from
  one-another, even if ``--client-to-client`` is activated.

  The packet filtering takes place in the OpenVPN server. Clients should
  not have any VLAN tagging configuration applied.

  The ``--vlan-tagging`` option is off by default. While turned off,
  OpenVPN accepts any Ethernet frame and does not perform any special
  processing for VLAN-tagged packets.

  This option can only be activated in ``--dev tap mode``.

--vlan-accept args
  Configure the VLAN tagging policy for the server TAP device.

  Valid syntax:
  ::

     vlan-accept  all|tagged|untagged

  The following modes are available:

  :code:`tagged`
      Admit only VLAN-tagged frames. Only VLAN-tagged packets are accepted,
      while untagged or priority-tagged packets are dropped when entering
      the server TAP device.

  :code:`untagged`
      Admit only untagged and prio-tagged frames.  VLAN-tagged packets are
      not accepted, while untagged or priority-tagged packets entering the
      server TAP device are tagged with the value configured for the global
      ``--vlan-pvid`` setting.

  :code:`all` (default)
      Admit all frames.  All packets are admitted and then treated like
      untagged or tagged mode respectively.

  *Note*:
      Some vendors refer to switch ports running in :code:`tagged` mode
      as "trunk ports" and switch ports running in :code:`untagged` mode
      as "access ports".

  Packets forwarded from clients to the server are VLAN-tagged with the
  originating client's PVID, unless the VID matches the global
  ``--vlan-pvid``, in which case the tag is removed.

  If no *PVID* is configured for a given client (see --vlan-pvid) packets
  are tagged with 1 by default.

--vlan-pvid v
  Specifies which VLAN identifier a "port" is associated with. Only valid
  when ``--vlan-tagging`` is speficied.

  In the client context, the setting specifies which VLAN ID a client is
  associated with. In the global context, the VLAN ID of the server TAP
  device is set. The latter only makes sense for ``--vlan-accept
  untagged`` and ``--vlan-accept all`` modes.

  Valid values for ``v`` go from :code:`1` through to :code:`4094`. The
  global value defaults to :code:`1`. If no ``--vlan-pvid`` is specified in
  the client context, the global value is inherited.

  In some switch implementations, the *PVID* is also referred to as "Native
  VLAN".
