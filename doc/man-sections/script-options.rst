SCRIPTING INTEGRATION
=====================

OpenVPN can execute external scripts in various phases of the lifetime of
the OpenVPN process.


Script Order of Execution
-------------------------

#. ``--up``

   Executed after TCP/UDP socket bind and TUN/TAP open.

#. ``--tls-verify``

   Executed when we have a still untrusted remote peer.

#. ``--ipchange``

   Executed after connection authentication, or remote IP address change.

#. ``--client-connect``

   Executed in **--mode server** mode immediately after client
   authentication.

#. ``--route-up``

   Executed after connection authentication, either immediately after, or
   some number of seconds after as defined by the **--route-delay** option.

#. ``--route-pre-down``

   Executed right before the routes are removed.

#. ``--client-disconnect``

   Executed in ``--mode server`` mode on client instance shutdown.

#. ``--down``

   Executed after TCP/UDP and TUN/TAP close.

#. ``--learn-address``

   Executed in ``--mode server`` mode whenever an IPv4 address/route or MAC
   address is added to OpenVPN's internal routing table.

#. ``--auth-user-pass-verify``

   Executed in ``--mode server`` mode on new client connections, when the
   client is still untrusted.

#. ``--client-crresponse``

    Execute in ``--mode server`` whenever a client sends a
    :code:`CR_RESPONSE` message

SCRIPT HOOKS
------------

--auth-user-pass-verify args
  Require the client to provide a username/password (possibly in addition
  to a client certificate) for authentication.

  Valid syntax:
  ::

     auth-user-pass-verify cmd method

  OpenVPN will run command ``cmd`` to validate the username/password
  provided by the client.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  If ``method`` is set to :code:`via-env`, OpenVPN will call ``cmd``
  with the environmental variables :code:`username` and :code:`password`
  set to the username/password strings provided by the client. *Beware*
  that this method is insecure on some platforms which make the environment
  of a process publicly visible to other unprivileged processes.

  If ``method`` is set to :code:`via-file`, OpenVPN will write the username
  and password to the first two lines of a temporary file. The filename
  will be passed as an argument to ``cmd``, and the file will be
  automatically deleted by OpenVPN after the script returns. The location
  of the temporary file is controlled by the ``--tmp-dir`` option, and
  will default to the current directory if unspecified. For security,
  consider setting ``--tmp-dir`` to a volatile storage medium such as
  :code:`/dev/shm` (if available) to prevent the username/password file
  from touching the hard drive.

  The script should examine the username and password, returning a success
  exit code (:code:`0`) if the client's authentication request is to be
  accepted, a failure code (:code:`1`) to reject the client, or a that
  the authentication is deferred (:code:`2`). If the authentication is
  deferred, the script must fork/start a background or another non-blocking
  operation to continue the authentication in the background. When finshing
  the authentication, a :code:`1` or :code:`0` must be written to the
  file specified by the :code:`auth_control_file`.

  If the file specified by :code:`auth_failed_reason_file` exists and has
  non-empty content, the content of this file will be used as AUTH_FAILED
  message. To avoid race conditions, this file should be written before
  :code:`auth_control_file`.

  This auth fail reason can be something simple like "User has been permanently
  disabled" but there are also some special auth failed messages.

  The ``TEMP`` message indicates that the authentication
  temporarily failed and that the client should continue to retry to connect.
  The server can optionally give a user readable message and hint the client a
  behavior how to proceed. The keywords of the ``AUTH_FAILED,TEMP`` message
  are comma separated keys/values and provide a hint to the client how to
  proceed. Currently defined keywords are:

  ``backoff`` :code:`s`
        instructs the client to wait at least :code:`s` seconds before the next
        connection attempt. If the client already uses a higher delay for
        reconnection attempt, the delay will not be shortened.

  ``advance addr``
        Instructs the client to reconnect to the next (IP) address of the
        current server.

  ``advance remote``
        Instructs the client to skip the remaining IP addresses of the current
        server and instead connect to the next server specified in the
        configuration file.

  ``advance no``
        Instructs the client to retry connecting to the same server again.

  For example, the message ``TEMP[backoff 42,advance no]: No free IP addresses``
  indicates that the VPN connection can currently not succeed and instructs
  the client to retry in 42 seconds again.

  When deferred authentication is in use, the script can also request
  pending authentication by writing to the file specified by the
  :code:`auth_pending_file`. The first line must be the timeout in
  seconds, the required method on the second line (e.g. crtext) and
  third line must be the EXTRA as documented in the
  ``client-pending-auth`` section of `doc/management.txt`.

  This directive is designed to enable a plugin-style interface for
  extending OpenVPN's authentication capabilities.

  To protect against a client passing a maliciously formed username or
  password string, the username string must consist only of these
  characters: alphanumeric, underbar (':code:`_`'), dash (':code:`-`'),
  dot (':code:`.`'), or at (':code:`@`'). The password string can consist
  of any printable characters except for CR or LF. Any illegal characters
  in either the username or password string will be converted to
  underbar (':code:`_`').

  Care must be taken by any user-defined scripts to avoid creating a
  security vulnerability in the way that these strings are handled. Never
  use these strings in such a way that they might be escaped or evaluated
  by a shell interpreter.

  For a sample script that performs PAM authentication, see
  :code:`sample-scripts/auth-pam.pl` in the OpenVPN source distribution.

--client-crresponse
    Executed when the client sends a text based challenge response.

    Valid syntax:
    ::

        client-crresponse cmd

  OpenVPN will write the response of the client into a temporary file.
  The filename will be passed as an argument to ``cmd``, and the file will be
  automatically deleted by OpenVPN after the script returns.

  The response is passed as is from the client. The script needs to check
  itself if the input is valid, e.g. if the input is valid base64 encoding.

  The script can either directly write the result of the verification to
  :code:`auth_control_file or further defer it. See ``--auth-user-pass-verify``
  for details.

  For a sample script that implement TOTP (RFC 6238) based two-factor
  authentication, see :code:`sample-scripts/totpauth.py`.

--client-connect cmd
  Run command ``cmd`` on client connection.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  The command is passed the common name and IP address of the
  just-authenticated client as environmental variables (see environmental
  variable section below). The command is also passed the pathname of a
  freshly created temporary file as the last argument (after any arguments
  specified in ``cmd`` ), to be used by the command to pass dynamically
  generated config file directives back to OpenVPN.

  If the script wants to generate a dynamic config file to be applied on
  the server when the client connects, it should write it to the file
  named by the last argument.

  See the ``--client-config-dir`` option below for options which can be
  legally used in a dynamically generated config file.

  Note that the return value of ``script`` is significant. If ``script``
  returns a non-zero error status, it will cause the client to be
  disconnected.

  If a ``--client-connect`` wants to defer the generating of the
  configuration then the script needs to use the
  :code:`client_connect_deferred_file` and
  :code:`client_connect_config_file` environment variables, and write
  status accordingly into these files.  See the `Environmental Variables`_
  section for more details.

--client-disconnect cmd
  Like ``--client-connect`` but called on client instance shutdown. Will
  not be called unless the ``--client-connect`` script and plugins (if
  defined) were previously called on this instance with successful (0)
  status returns.

  The exception to this rule is if the ``--client-disconnect`` command or
  plugins are cascaded, and at least one client-connect function
  succeeded, then ALL of the client-disconnect functions for scripts and
  plugins will be called on client instance object deletion, even in cases
  where some of the related client-connect functions returned an error
  status.

  The ``--client-disconnect`` command is not passed any extra arguments
  (only those arguments specified in cmd, if any).

--down cmd
  Run command ``cmd`` after TUN/TAP device close (post ``--user`` UID
  change and/or ``--chroot`` ). ``cmd`` consists of a path to script (or
  executable program), optionally followed by arguments. The path and
  arguments may be single- or double-quoted and/or escaped using a
  backslash, and should be separated by one or more spaces.

  Called with the same parameters and environmental variables as the
  ``--up`` option above.

  Note that if you reduce privileges by using ``--user`` and/or
  ``--group``, your ``--down`` script will also run at reduced privilege.

--down-pre
  Call ``--down`` cmd/script before, rather than after, TUN/TAP close.

--ipchange cmd
  Run command ``cmd`` when our remote ip-address is initially
  authenticated or changes.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  When ``cmd`` is executed two arguments are appended after any arguments
  specified in ``cmd`` , as follows:
  ::

     cmd ip address port number

  Don't use ``--ipchange`` in ``--mode server`` mode. Use a
  ``--client-connect`` script instead.

  See the `Environmental Variables`_ section below for additional
  parameters passed as environmental variables.

  If you are running in a dynamic IP address environment where the IP
  addresses of either peer could change without notice, you can use this
  script, for example, to edit the :code:`/etc/hosts` file with the current
  address of the peer. The script will be run every time the remote peer
  changes its IP address.

  Similarly if *our* IP address changes due to DHCP, we should configure
  our IP address change script (see man page for ``dhcpcd``\(8)) to
  deliver a ``SIGHUP`` or ``SIGUSR1`` signal to OpenVPN. OpenVPN will
  then re-establish a connection with its most recently authenticated
  peer on its new IP address.

--learn-address cmd
  Run command ``cmd`` to validate client virtual addresses or routes.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  Three arguments will be appended to any arguments in ``cmd`` as follows:

  :code:`$1` - [operation]
      :code:`"add"`, :code:`"update"`, or :code:`"delete"` based on whether
      or not the address is being added to, modified, or deleted from
      OpenVPN's internal routing table.

  :code:`$2` - [address]
      The address being learned or unlearned. This can be an IPv4 address
      such as :code:`"198.162.10.14"`, an IPv4 subnet such as
      :code:`"198.162.10.0/24"`, or an ethernet MAC address (when
      ``--dev tap`` is being used) such as :code:`"00:FF:01:02:03:04"`.

  :code:`$3` - [common name]
      The common name on the certificate associated with the client linked
      to this address. Only present for :code:`"add"` or :code:`"update"`
      operations, not :code:`"delete"`.

  On :code:`"add"` or :code:`"update"` methods, if the script returns
  a failure code (non-zero), OpenVPN will reject the address and will not
  modify its internal routing table.

  Normally, the ``cmd`` script will use the information provided above to
  set appropriate firewall entries on the VPN TUN/TAP interface. Since
  OpenVPN provides the association between virtual IP or MAC address and
  the client's authenticated common name, it allows a user-defined script
  to configure firewall access policies with regard to the client's
  high-level common name, rather than the low level client virtual
  addresses.

--route-up cmd
  Run command ``cmd`` after routes are added, subject to ``--route-delay``.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  See the `Environmental Variables`_ section below for additional
  parameters passed as environmental variables.

--route-pre-down cmd
  Run command ``cmd`` before routes are removed upon disconnection.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  See the `Environmental Variables`_ section below for additional
  parameters passed as environmental variables.

--setenv args
  Set a custom environmental variable :code:`name=value` to pass to script.

  Valid syntaxes:
  ::

     setenv name value
     setenv FORWARD_COMPATIBLE 1
     setenv opt config_option

  By setting :code:`FORWARD_COMPATIBLE` to :code:`1`, the config file
  syntax checking is relaxed so that unknown directives will trigger a
  warning but not a fatal error, on the assumption that a given unknown
  directive might be valid in future OpenVPN versions.

  This option should be used with caution, as there are good security
  reasons for having OpenVPN fail if it detects problems in a config file.
  Having said that, there are valid reasons for wanting new software
  features to gracefully degrade when encountered by older software
  versions.

  It is also possible to tag a single directive so as not to trigger a
  fatal error if the directive isn't recognized. To do this, prepend the
  following before the directive: ``setenv opt``

  Versions prior to OpenVPN 2.3.3 will always ignore options set with the
  ``setenv opt`` directive.

  See also ``--ignore-unknown-option``

--setenv-safe args
  Set a custom environmental variable :code:`OPENVPN_name` to :code:`value`
  to pass to scripts.

  Valid syntaxes:
  ::

     setenv-safe name value

  This directive is designed to be pushed by the server to clients, and
  the prepending of :code:`OPENVPN_` to the environmental variable is a
  safety precaution to prevent a :code:`LD_PRELOAD` style attack from a
  malicious or compromised server.

--tls-verify cmd
  Run command ``cmd`` to verify the X509 name of a pending TLS connection
  that has otherwise passed all other tests of certification (except for
  revocation via ``--crl-verify`` directive; the revocation test occurs
  after the ``--tls-verify`` test).

  ``cmd`` should return :code:`0` to allow the TLS handshake to proceed,
  or :code:`1` to fail.

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  When ``cmd`` is executed two arguments are appended after any arguments
  specified in ``cmd``, as follows:
  ::

     cmd certificate_depth subject

  These arguments are, respectively, the current certificate depth and the
  X509 subject distinguished name (dn) of the peer.

  This feature is useful if the peer you want to trust has a certificate
  which was signed by a certificate authority who also signed many other
  certificates, where you don't necessarily want to trust all of them, but
  rather be selective about which peer certificate you will accept. This
  feature allows you to write a script which will test the X509 name on a
  certificate and decide whether or not it should be accepted. For a
  simple perl script which will test the common name field on the
  certificate, see the file ``verify-cn`` in the OpenVPN distribution.

  See the `Environmental Variables`_ section below for additional
  parameters passed as environmental variables.

--tls-export-cert dir
  Adds an environment variable ``peer_cert`` when calling the
  ``--tls-verify`` script or executing the OPENVPN_PLUGIN_TLS_VERIFY plugin
  hook to verify the certificate.

  The environment variable contains the path to a PEM encoded certificate
  of the current peer certificate in the directory ``dir``.

--up cmd
  Run command ``cmd`` after successful TUN/TAP device open (pre ``--user``
  UID change).

  ``cmd`` consists of a path to a script (or executable program), optionally
  followed by arguments. The path and arguments may be single- or
  double-quoted and/or escaped using a backslash, and should be separated
  by one or more spaces.

  The up command is useful for specifying route commands which route IP
  traffic destined for private subnets which exist at the other end of the
  VPN connection into the tunnel.

  For ``--dev tun`` execute as:
  ::

      cmd tun_dev tun_mtu 0 ifconfig_local_ip ifconfig_remote_ip [init | restart]

  For ``--dev tap`` execute as:
  ::

       cmd tap_dev tap_mtu 0 ifconfig_local_ip ifconfig_netmask [init | restart]

  See the `Environmental Variables`_ section below for additional
  parameters passed as environmental variables.  The ``0`` argument
  used to be ``link_mtu`` which is no longer passed to scripts - to
  keep the argument order, it was replaced with ``0``.

  Note that if ``cmd`` includes arguments, all OpenVPN-generated arguments
  will be appended to them to build an argument list with which the
  executable will be called.

  Typically, ``cmd`` will run a script to add routes to the tunnel.

  Normally the up script is called after the TUN/TAP device is opened. In
  this context, the last command line parameter passed to the script will
  be *init.* If the ``--up-restart`` option is also used, the up script
  will be called for restarts as well. A restart is considered to be a
  partial reinitialization of OpenVPN where the TUN/TAP instance is
  preserved (the ``--persist-tun`` option will enable such preservation).
  A restart can be generated by a SIGUSR1 signal, a ``--ping-restart``
  timeout, or a connection reset when the TCP protocol is enabled with the
  ``--proto`` option. If a restart occurs, and ``--up-restart`` has been
  specified, the up script will be called with *restart* as the last
  parameter.

  *NOTE:*
     On restart, OpenVPN will not pass the full set of environment
     variables to the script. Namely, everything related to routing and
     gateways will not be passed, as nothing needs to be done anyway - all
     the routing setup is already in place. Additionally, the up-restart
     script will run with the downgraded UID/GID settings (if configured).

  The following standalone example shows how the ``--up`` script can be
  called in both an initialization and restart context. (*NOTE:* for
  security reasons, don't run the following example unless UDP port 9999
  is blocked by your firewall. Also, the example will run indefinitely, so
  you should abort with control-c).

  ::

      openvpn --dev tun --port 9999 --verb 4 --ping-restart 10 \
              --up 'echo up' --down 'echo down' --persist-tun  \
              --up-restart

  Note that OpenVPN also provides the ``--ifconfig`` option to
  automatically ifconfig the TUN device, eliminating the need to define an
  ``--up`` script, unless you also want to configure routes in the
  ``--up`` script.

  If ``--ifconfig`` is also specified, OpenVPN will pass the ifconfig
  local and remote endpoints on the command line to the ``--up`` script so
  that they can be used to configure routes such as:

  ::

      route add -net 10.0.0.0 netmask 255.255.255.0 gw $5

--up-delay
  Delay TUN/TAP open and possible ``--up`` script execution until after
  TCP/UDP connection establishment with peer.

  In ``--proto udp`` mode, this option normally requires the use of
  ``--ping`` to allow connection initiation to be sensed in the absence of
  tunnel data, since UDP is a "connectionless" protocol.

  On Windows, this option will delay the TAP-Win32 media state
  transitioning to "connected" until connection establishment, i.e. the
  receipt of the first authenticated packet from the peer.

--up-restart
  Enable the ``--up`` and ``--down`` scripts to be called for restarts as
  well as initial program start. This option is described more fully above
  in the ``--up`` option documentation.

String Types and Remapping
--------------------------

In certain cases, OpenVPN will perform remapping of characters in
strings. Essentially, any characters outside the set of permitted
characters for each string type will be converted to underbar ('\_').

*Q: Why is string remapping necessary?*
    It's an important security feature to prevent the malicious
    coding of strings from untrusted sources to be passed as parameters to
    scripts, saved in the environment, used as a common name, translated to
    a filename, etc.

*Q: Can string remapping be disabled?*
    Yes, by using the ``--no-name-remapping`` option, however this
    should be considered an advanced option.

Here is a brief rundown of OpenVPN's current string types and the
permitted character class for each string:

*X509 Names*
   Alphanumeric, underbar ('\_'), dash ('-'), dot ('.'), at
   ('@'), colon (':'), slash ('/'), and equal ('='). Alphanumeric is
   defined as a character which will cause the C library isalnum() function
   to return true.

*Common Names*
   Alphanumeric, underbar ('\_'), dash ('-'), dot ('.'), and at ('@').

*--auth-user-pass username*
   Same as Common Name, with one exception:
   starting with OpenVPN 2.0.1, the username is passed to the
   :code:`OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY` plugin in its raw form,
   without string remapping.

*--auth-user-pass password*
   Any "printable" character except CR or LF. Printable is defined to be
   a character which will cause the C library isprint() function to
   return true.

*--client-config-dir filename as derived from common name or`username*
   Alphanumeric, underbar ('\_'), dash ('-'), and dot ('.') except for "."
   or ".." as standalone strings. As of v2.0.1-rc6, the at ('@') character
   has been added as well for compatibility with the common name character
   class.

*Environmental variable names*
   Alphanumeric or underbar ('\_').

*Environmental variable values*
   Any printable character.

For all cases, characters in a string which are not members of the legal
character class for that string type will be remapped to underbar
('\_').  


Environmental Variables
-----------------------

Once set, a variable is persisted indefinitely until it is reset by a
new value or a restart,

As of OpenVPN 2.0-beta12, in server mode, environmental variables set by
OpenVPN are scoped according to the client objects they are associated
with, so there should not be any issues with scripts having access to
stale, previously set variables which refer to different client
instances.

:code:`bytes_received`
    Total number of bytes received from client during VPN session. Set prior
    to execution of the ``--client-disconnect`` script.

:code:`bytes_sent`
    Total number of bytes sent to client during VPN session. Set prior to
    execution of the ``--client-disconnect`` script.

:code:`client_connect_config_file`
    The path to the configuration file that should be written to by the
    ``--client-connect`` script (optional, if per-session configuration
    is desired).  This is the same file name as passed via command line
    argument on the call to the ``--client-connect`` script.

:code:`client_connect_deferred_file`
    This file can be optionally written to in order to to communicate a
    status code of the ``--client-connect`` script or plgin.  Only the
    first character in the file is relevant.  It must be either :code:`1`
    to indicate normal script execution, :code:`0` indicates an error (in
    the same way that a non zero exit status does) or :code:`2` to indicate
    that the script deferred returning the config file.

    For deferred (background) handling, the script or plugin MUST write
    :code:`2` to the file to indicate the deferral and then return with
    exit code :code:`0` to signal ``deferred handler started OK``.

    A background process or similar must then take care of writing the
    configuration to the file indicated by the
    :code:`client_connect_config_file` environment variable and when
    finished, write the a :code:`1` to this file (or :code:`0` in case of
    an error).

    The absence of any character in the file when the script finishes
    executing is interpreted the same as :code:`1`. This allows scripts
    that are not written to support the defer mechanism to be used
    unmodified.

:code:`common_name`
    The X509 common name of an authenticated client. Set prior to execution
    of ``--client-connect``, ``--client-disconnect`` and
    ``--auth-user-pass-verify`` scripts.

:code:`config`
    Name of first ``--config`` file. Set on program initiation and reset on
    SIGHUP.


:code:`daemon`
    Set to "1" if the ``--daemon`` directive is specified, or "0" otherwise.
    Set on program initiation and reset on SIGHUP.

:code:`daemon_log_redirect`
    Set to "1" if the ``--log`` or ``--log-append`` directives are
    specified, or "0" otherwise. Set on program initiation and reset on
    SIGHUP.

:code:`dev`
    The actual name of the TUN/TAP device, including a unit number if it
    exists. Set prior to ``--up`` or ``--down`` script execution.

:code:`dev_idx`
    On Windows, the device index of the TUN/TAP adapter (to be used in
    netsh.exe calls which sometimes just do not work right with interface
    names). Set prior to ``--up`` or ``--down`` script execution.

:code:`dns_*`
    The ``--dns`` configuration options will be made available to script
    execution through this set of environment variables. Variables appear
    only if the corresponding option has a value assigned. For the semantics
    of each individual variable, please refer to the documentation for ``--dns``.

    ::

       dns_search_domain_{n}
       dns_server_{n}_address_{m}
       dns_server_{n}_port_{m}
       dns_server_{n}_resolve_domain_{m}
       dns_server_{n}_dnssec
       dns_server_{n}_transport
       dns_server_{n}_sni

:code:`foreign_option_{n}`
    An option pushed via ``--push`` to a client which does not natively
    support it, such as ``--dhcp-option`` on a non-Windows system, will be
    recorded to this environmental variable sequence prior to ``--up``
    script execution.

:code:`ifconfig_ipv6_local`
    The local VPN endpoint IPv6 address specified in the
    ``--ifconfig-ipv6`` option (first parameter). Set prior to OpenVPN
    calling the :code:`ifconfig` or code:`netsh` (windows version of
    ifconfig) commands which normally occurs prior to ``--up`` script
    execution.

:code:`ifconfig_ipv6_netbits`
    The prefix length of the IPv6 network on the VPN interface. Derived
    from the /nnn parameter of the IPv6 address in the ``--ifconfig-ipv6``
    option (first parameter). Set prior to OpenVPN calling the
    :code:`ifconfig` or :code:`netsh` (windows version of ifconfig)
    commands which normally occurs prior to ``--up`` script execution.

:code:`ifconfig_ipv6_remote`
    The remote VPN endpoint IPv6 address specified in the
    ``--ifconfig-ipv6`` option (second parameter). Set prior to OpenVPN
    calling the :code:`ifconfig` or :code:`netsh` (windows version of
    ifconfig) commands which normally occurs prior to ``--up`` script
    execution.

:code:`ifconfig_local`
    The local VPN endpoint IP address specified in the ``--ifconfig``
    option (first parameter). Set prior to OpenVPN calling the
    :code:`ifconfig` or :code:`netsh` (windows version of ifconfig)
    commands which normally occurs prior to ``--up`` script execution.

:code:`ifconfig_remote`
    The remote VPN endpoint IP address specified in the ``--ifconfig``
    option (second parameter) when ``--dev tun`` is used. Set prior to
    OpenVPN calling the :code:`ifconfig` or :code:`netsh` (windows version
    of ifconfig) commands which normally occurs prior to ``--up`` script
    execution.

:code:`ifconfig_netmask`
    The subnet mask of the virtual ethernet segment that is specified as
    the second parameter to ``--ifconfig`` when ``--dev tap`` is being
    used. Set prior to OpenVPN calling the :code:`ifconfig` or
    :code:`netsh` (windows version of ifconfig) commands which normally
    occurs prior to ``--up`` script execution.

:code:`ifconfig_pool_local_ip`
    The local virtual IPv4 address for the TUN/TAP tunnel taken from an
    ``--ifconfig-push`` directive if specified, or otherwise from the
    ifconfig pool (controlled by the ``--ifconfig-pool`` config file
    directive). Only set for ``--dev tun`` tunnels. This option is set on
    the server prior to execution of the ``--client-connect`` and
    ``--client-disconnect`` scripts.

:code:`ifconfig_pool_local_ip6`
    The local virtual IPv6 address for the TUN/TAP tunnel taken from an
    ``--ifconfig-ipv6-push`` directive if specified, or otherwise from the
    ifconfig pool (controlled by the ``--ifconfig-ipv6-pool`` config file
    directive). Only set for ``--dev tun`` tunnels. This option is set on
    the server prior to execution of the ``--client-connect`` and
    ``--client-disconnect`` scripts.

:code:`ifconfig_pool_netmask`
    The virtual IPv4 netmask for the TUN/TAP tunnel taken from an
    ``--ifconfig-push`` directive if specified, or otherwise from the
    ifconfig pool (controlled by the ``--ifconfig-pool`` config file
    directive). Only set for ``--dev tap`` tunnels. This option is set on
    the server prior to execution of the ``--client-connect`` and
    ``--client-disconnect`` scripts.

:code:`ifconfig_pool_ip6_netbits`
    The virtual IPv6 prefix length for the TUN/TAP tunnel taken from an
    ``--ifconfig-ipv6-push`` directive if specified, or otherwise from the
    ifconfig pool (controlled by the ``--ifconfig-ipv6-pool`` config file
    directive). Only set for ``--dev tap`` tunnels. This option is set on
    the server prior to execution of the ``--client-connect`` and
    ``--client-disconnect`` scripts.

:code:`ifconfig_pool_remote_ip`
    The remote virtual IPv4 address for the TUN/TAP tunnel taken from an
    ``--ifconfig-push`` directive if specified, or otherwise from the
    ifconfig pool (controlled by the ``--ifconfig-pool`` config file
    directive). This option is set on the server prior to execution of the
    ``--client-connect`` and ``--client-disconnect`` scripts.

:code:`ifconfig_pool_remote_ip6`
    The remote virtual IPv6 address for the TUN/TAP tunnel taken from an
    ``--ifconfig-ipv6-push`` directive if specified, or otherwise from the
    ifconfig pool (controlled by the ``--ifconfig-ipv6-pool`` config file
    directive). This option is set on the server prior to execution of the
    ``--client-connect`` and ``--client-disconnect`` scripts.

:code:`link_mtu`
    *REMOVED* No longer passed to scripts since OpenVPN 2.6.0.  Used to be the
    maximum packet size (not including the IP header) of tunnel data in
    UDP tunnel transport mode.

:code:`local`
    The ``--local`` parameter. Set on program initiation and reset on
    SIGHUP.

:code:`local_port`
    The local port number or name, specified by ``--port`` or ``--lport``.
    Set on program initiation and reset on SIGHUP.

:code:`password`
    The password provided by a connecting client. Set prior to
    ``--auth-user-pass-verify`` script execution only when the ``via-env``
    modifier is specified, and deleted from the environment after the script
    returns.

:code:`peer_cert`
    If the option ``--tls-export-cert`` is enabled, this option contains
    the path to the current peer certificate to be verified in PEM format.
    See also the argument certificate_depth to the ``--tls-verify`` command.

:code:`proto`
    The ``--proto`` parameter. Set on program initiation and reset on
    SIGHUP.

:code:`remote_{n}`
    The ``--remote`` parameter. Set on program initiation and reset on
    SIGHUP.

:code:`remote_port_{n}`
    The remote port number, specified by ``--port`` or ``--rport``. Set on
    program initiation and reset on SIGHUP.

:code:`route_net_gateway`
    The pre-existing default IP gateway in the system routing table. Set
    prior to ``--up`` script execution.

:code:`route_vpn_gateway`
    The default gateway used by ``--route`` options, as specified in either
    the ``--route-gateway`` option or the second parameter to
    ``--ifconfig`` when ``--dev tun`` is specified. Set prior to ``--up``
    script execution.

:code:`route_{parm}_{n}`
    A set of variables which define each route to be added, and are set
    prior to ``--up`` script execution.

    ``parm`` will be one of :code:`network`, :code:`netmask"`,
    :code:`gateway`, or :code:`metric`.

    ``n`` is the OpenVPN route number, starting from 1.

    If the network or gateway are resolvable DNS names, their IP address
    translations will be recorded rather than their names as denoted on the
    command line or configuration file.

:code:`route_ipv6_{parm}_{n}`
    A set of variables which define each IPv6 route to be added, and are
    set prior to **--up** script execution.

    ``parm`` will be one of :code:`network`, :code:`gateway` or
    :code:`metric`. ``route_ipv6_network_{n}`` contains :code:`netmask`
    as :code:`/nnn`, unlike IPv4 where it is passed in a separate environment
    variable.

    ``n`` is the OpenVPN route number, starting from 1.

    If the network or gateway are resolvable DNS names, their IP address
    translations will be recorded rather than their names as denoted on the
    command line or configuration file.

:code:`script_context`
    Set to "init" or "restart" prior to up/down script execution. For more
    information, see documentation for ``--up``.

:code:`script_type`
    Prior to execution of any script, this variable is set to the type of
    script being run. It can be one of the following: :code:`up`,
    :code:`down`, :code:`ipchange`, :code:`route-up`, :code:`tls-verify`,
    :code:`auth-user-pass-verify`, :code:`client-connect`,
    :code:`client-disconnect` or :code:`learn-address`. Set prior to
    execution of any script.

:code:`signal`
    The reason for exit or restart. Can be one of :code:`sigusr1`,
    :code:`sighup`, :code:`sigterm`, :code:`sigint`, :code:`inactive`
    (controlled by ``--inactive`` option), :code:`ping-exit` (controlled
    by ``--ping-exit`` option), :code:`ping-restart` (controlled by
    ``--ping-restart`` option), :code:`connection-reset` (triggered on TCP
    connection reset), :code:`error` or :code:`unknown` (unknown signal).
    This variable is set just prior to down script execution.

:code:`time_ascii`
    Client connection timestamp, formatted as a human-readable time string.
    Set prior to execution of the ``--client-connect`` script.

:code:`time_duration`
    The duration (in seconds) of the client session which is now
    disconnecting. Set prior to execution of the ``--client-disconnect``
    script.

:code:`time_unix`
    Client connection timestamp, formatted as a unix integer date/time
    value. Set prior to execution of the ``--client-connect`` script.

:code:`tls_digest_{n}` / :code:`tls_digest_sha256_{n}`
    Contains the certificate SHA1 / SHA256 fingerprint, where ``n`` is the
    verification level. Only set for TLS connections. Set prior to execution
    of ``--tls-verify`` script.

:code:`tls_id_{n}`
    A series of certificate fields from the remote peer, where ``n`` is the
    verification level. Only set for TLS connections. Set prior to execution
    of ``--tls-verify`` script.

:code:`tls_serial_{n}`
    The serial number of the certificate from the remote peer, where ``n``
    is the verification level. Only set for TLS connections. Set prior to
    execution of ``--tls-verify`` script. This is in the form of a decimal
    string like "933971680", which is suitable for doing serial-based OCSP
    queries (with OpenSSL, do not prepend "0x" to the string) If something
    goes wrong while reading the value from the certificate it will be an
    empty string, so your code should check that. See the
    :code:`contrib/OCSP_check/OCSP_check.sh` script for an example.

:code:`tls_serial_hex_{n}`
    Like :code:`tls_serial_{n}`, but in hex form (e.g.
    :code:`12:34:56:78:9A`).

:code:`tun_mtu`
    The MTU of the TUN/TAP device. Set prior to ``--up`` or ``--down``
    script execution.

:code:`trusted_ip` / :code:`trusted_ip6`)
    Actual IP address of connecting client or peer which has been
    authenticated. Set prior to execution of ``--ipchange``,
    ``--client-connect`` and ``--client-disconnect`` scripts. If using ipv6
    endpoints (udp6, tcp6), :code:`trusted_ip6` will be set instead.

:code:`trusted_port`
    Actual port number of connecting client or peer which has been
    authenticated. Set prior to execution of ``--ipchange``,
    ``--client-connect`` and ``--client-disconnect`` scripts.

:code:`untrusted_ip` / :code:`untrusted_ip6`
    Actual IP address of connecting client or peer which has not been
    authenticated yet. Sometimes used to *nmap* the connecting host in a
    ``--tls-verify`` script to ensure it is firewalled properly. Set prior
    to execution of ``--tls-verify`` and ``--auth-user-pass-verify``
    scripts. If using ipv6 endpoints (udp6, tcp6), :code:`untrusted_ip6`
    will be set instead.

:code:`untrusted_port`
    Actual port number of connecting client or peer which has not been
    authenticated yet. Set prior to execution of ``--tls-verify`` and
    ``--auth-user-pass-verify`` scripts.

:code:`username`
    The username provided by a connecting client. Set prior to
    ``--auth-user-pass-verify`` script execution only when the
    :code:`via-env` modifier is specified.

:code:`X509_{n}_{subject_field}`
    An X509 subject field from the remote peer certificate, where ``n`` is
    the verification level. Only set for TLS connections. Set prior to
    execution of ``--tls-verify`` script. This variable is similar to
    :code:`tls_id_{n}` except the component X509 subject fields are broken
    out, and no string remapping occurs on these field values (except for
    remapping of control characters to ":code:`_`"). For example, the
    following variables would be set on the OpenVPN server using the sample
    client certificate in sample-keys (client.crt). Note that the
    verification level is 0 for the client certificate and 1 for the CA
    certificate.

    You can use the ``--x509-track`` option to export more or less information
    from the certificates.

    ::

       X509_0_emailAddress=me@myhost.mydomain
       X509_0_CN=Test-Client
       X509_0_O=OpenVPN-TEST
       X509_0_ST=NA
       X509_0_C=KG
       X509_1_emailAddress=me@myhost.mydomain
       X509_1_O=OpenVPN-TEST
       X509_1_L=BISHKEK
       X509_1_ST=NA
       X509_1_C=KG
