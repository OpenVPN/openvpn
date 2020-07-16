Management Interface Options
----------------------------
OpenVPN provides a feature rich socket based management interface for both
server and client mode operations.

--management args
  Enable a management server on a ``socket-name`` Unix socket on those
  platforms supporting it, or on a designated TCP port.

  Valid syntaxes:
  ::

    management socket-name unix          #
    management socket-name unix pw-file  # (recommended)
    management IP port                   # (INSECURE)
    management IP port pw-file           #

  ``pw-file``, if specified, is a password file where the password must
  be on first line. Instead of a filename it can use the keyword stdin
  which will prompt the user for a password to use when OpenVPN is
  starting.

  For unix sockets, the default behaviour is to create a unix domain
  socket that may be connected to by any process. Use the
  ``--management-client-user`` and ``--management-client-group``
  directives to restrict access.

  The management interface provides a special mode where the TCP
  management link can operate over the tunnel itself. To enable this mode,
  set IP to ``tunnel``. Tunnel mode will cause the management interface to
  listen for a TCP connection on the local VPN address of the TUN/TAP
  interface.

  ***BEWARE*** of enabling the management interface over TCP. In these cases
  you should *ALWAYS* make use of ``pw-file`` to password protect the
  management interface. Any user who can connect to this TCP ``IP:port``
  will be able to manage and control (and interfere with) the OpenVPN
  process. It is also strongly recommended to set IP to 127.0.0.1
  (localhost) to restrict accessibility of the management server to local
  clients.

  While the management port is designed for programmatic control of
  OpenVPN by other applications, it is possible to telnet to the port,
  using a telnet client in "raw" mode. Once connected, type :code:`help`
  for a list of commands.

  For detailed documentation on the management interface, see the
  *management-notes.txt* file in the management folder of the OpenVPN
  source distribution.

--management-client
  Management interface will connect as a TCP/unix domain client to
  ``IP:port`` specified by ``--management`` rather than listen as a TCP
  server or on a unix domain socket.

  If the client connection fails to connect or is disconnected, a SIGTERM
  signal will be generated causing OpenVPN to quit.

--management-client-auth
  Gives management interface client the responsibility to authenticate
  clients after their client certificate has been verified. See
  :code:`management-notes.txt` in OpenVPN distribution for detailed notes.

--management-client-group g
  When the management interface is listening on a unix domain socket, only
  allow connections from group ``g``.

--management-client-pf
  Management interface clients must specify a packet filter file for each
  connecting client. See :code:`management-notes.txt` in OpenVPN
  distribution for detailed notes.

--management-client-user u
  When the management interface is listening on a unix domain socket, only
  allow connections from user ``u``.

--management-external-cert certificate-hint
  Allows usage for external certificate instead of ``--cert`` option
  (client-only). ``certificate-hint`` is an arbitrary string which is
  passed to a management interface client as an argument of
  *NEED-CERTIFICATE* notification. Requires ``--management-external-key``.

--management-external-key args
  Allows usage for external private key file instead of ``--key`` option
  (client-only).

  Valid syntaxes:
  ::

     management-external-key
     management-external-key nopadding
     management-external-key pkcs1
     management-external-key nopadding pkcs1

  The optional parameters :code:`nopadding` and :code:`pkcs1` signal
  support for different padding algorithms. See
  :code:`doc/mangement-notes.txt` for a complete description of this
  feature.

--management-forget-disconnect
  Make OpenVPN forget passwords when management session disconnects.

  This directive does not affect the ``--http-proxy`` username/password.
  It is always cached.

--management-hold
  Start OpenVPN in a hibernating state, until a client of the management
  interface explicitly starts it with the :code:`hold release` command.

--management-log-cache n
  Cache the most recent ``n`` lines of log file history for usage by the
  management channel.

--management-query-passwords
  Query management channel for private key password and
  ``--auth-user-pass`` username/password. Only query the management
  channel for inputs which ordinarily would have been queried from the
  console.

--management-query-proxy
  Query management channel for proxy server information for a specific
  ``--remote`` (client-only).

--management-query-remote
  Allow management interface to override ``--remote`` directives
  (client-only).

--management-signal
  Send SIGUSR1 signal to OpenVPN if management session disconnects. This
  is useful when you wish to disconnect an OpenVPN session on user logoff.
  For ``--management-client`` this option is not needed since a disconnect
  will always generate a :code:`SIGTERM`.

--management-up-down
  Report tunnel up/down events to management interface.
