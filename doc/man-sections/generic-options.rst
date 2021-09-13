Generic Options
---------------
This section covers generic options which are accessible regardless of
which mode OpenVPN is configured as.

--help

  Show options.

--auth-nocache
  Don't cache ``--askpass`` or ``--auth-user-pass`` username/passwords in
  virtual memory.

  If specified, this directive will cause OpenVPN to immediately forget
  username/password inputs after they are used. As a result, when OpenVPN
  needs a username/password, it will prompt for input from stdin, which
  may be multiple times during the duration of an OpenVPN session.

  When using ``--auth-nocache`` in combination with a user/password file
  and ``--chroot`` or ``--daemon``, make sure to use an absolute path.

  This directive does not affect the ``--http-proxy`` username/password.
  It is always cached.

--cd dir
  Change directory to ``dir`` prior to reading any files such as
  configuration files, key files, scripts, etc. ``dir`` should be an
  absolute path, with a leading "/", and without any references to the
  current directory such as :code:`.` or :code:`..`.

  This option is useful when you are running OpenVPN in ``--daemon`` mode,
  and you want to consolidate all of your OpenVPN control files in one
  location.

--chroot dir
  Chroot to ``dir`` after initialization. ``--chroot`` essentially
  redefines ``dir`` as being the top level directory tree (/). OpenVPN
  will therefore be unable to access any files outside this tree. This can
  be desirable from a security standpoint.

  Since the chroot operation is delayed until after initialization, most
  OpenVPN options that reference files will operate in a pre-chroot
  context.

  In many cases, the ``dir`` parameter can point to an empty directory,
  however complications can result when scripts or restarts are executed
  after the chroot operation.

  Note: The SSL library will probably need /dev/urandom to be available
  inside the chroot directory ``dir``. This is because SSL libraries
  occasionally need to collect fresh random. Newer linux kernels and some
  BSDs implement a getrandom() or getentropy() syscall that removes the
  need for /dev/urandom to be available.

--compat-mode version
  This option provides a way to alter the default of OpenVPN to be more
  compatible with the version ``version`` specified. All of the changes
  this option does can also be achieved using individual configuration
  options.

  Note: Using this option reverts defaults to no longer recommended
  values and should be avoided if possible.

  The following table details what defaults are changed depending on the
  version specified.

  - 2.5.x or lower: ``--allow-compression asym`` is automatically added
    to the configuration if no other compression options are present.
  - 2.4.x or lower: The cipher in ``--cipher`` is appended to
    ``--data-ciphers``
  - 2.3.x or lower: ``--data-cipher-fallback`` is automatically added with
    the same cipher as ``--cipher``
  - 2.3.6 or lower: ``--tls-version-min 1.0`` is added to the configuration
    when ``--tls-version-min`` is not explicitly set.

--config file
  Load additional config options from ``file`` where each line corresponds
  to one command line option, but with the leading '--' removed.

  If ``--config file`` is the only option to the openvpn command, the
  ``--config`` can be removed, and the command can be given as ``openvpn
  file``

  Note that configuration files can be nested to a reasonable depth.

  Double quotation or single quotation characters ("", '') can be used to
  enclose single parameters containing whitespace, and "#" or ";"
  characters in the first column can be used to denote comments.

  Note that OpenVPN 2.0 and higher performs backslash-based shell escaping
  for characters not in single quotations, so the following mappings
  should be observed:
  ::

      \\       Maps to a single backslash character (\).
      \"       Pass a literal doublequote character ("), don't
               interpret it as enclosing a parameter.
      \[SPACE] Pass a literal space or tab character, don't
               interpret it as a parameter delimiter.

  For example on Windows, use double backslashes to represent pathnames:
  ::

      secret "c:\\OpenVPN\\secret.key"


  For examples of configuration files, see
  https://openvpn.net/community-resources/how-to/

  Here is an example configuration file:
  ::

      #
      # Sample OpenVPN configuration file for
      # using a pre-shared static key.
      #
      # '#' or ';' may be used to delimit comments.

      # Use a dynamic tun device.
      dev tun

      # Our remote peer
      remote mypeer.mydomain

      # 10.1.0.1 is our local VPN endpoint
      # 10.1.0.2 is our remote VPN endpoint
      ifconfig 10.1.0.1 10.1.0.2

      # Our pre-shared static key
      secret static.key

--daemon progname
  Become a daemon after all initialization functions are completed. This
  option will cause all message and error output to be sent to the syslog
  file (such as :code:`/var/log/messages`), except for the output of
  scripts and ifconfig commands, which will go to :code:`/dev/null` unless
  otherwise redirected. The syslog redirection occurs immediately at the
  point that ``--daemon`` is parsed on the command line even though the
  daemonization point occurs later. If one of the ``--log`` options is
  present, it will supersede syslog redirection.

  The optional ``progname`` parameter will cause OpenVPN to report its
  program name to the system logger as ``progname``. This can be useful in
  linking OpenVPN messages in the syslog file with specific tunnels. When
  unspecified, ``progname`` defaults to "openvpn".

  When OpenVPN is run with the ``--daemon`` option, it will try to delay
  daemonization until the majority of initialization functions which are
  capable of generating fatal errors are complete. This means that
  initialization scripts can test the return status of the openvpn command
  for a fairly reliable indication of whether the command has correctly
  initialized and entered the packet forwarding event loop.

  In OpenVPN, the vast majority of errors which occur after initialization
  are non-fatal.

  Note: as soon as OpenVPN has daemonized, it can not ask for usernames,
  passwords, or key pass phrases anymore. This has certain consequences,
  namely that using a password-protected private key will fail unless the
  ``--askpass`` option is used to tell OpenVPN to ask for the pass phrase
  (this requirement is new in v2.3.7, and is a consequence of calling
  daemon() before initializing the crypto layer).

  Further, using ``--daemon`` together with ``--auth-user-pass`` (entered
  on console) and ``--auth-nocache`` will fail as soon as key
  renegotiation (and reauthentication) occurs.

--disable-occ
  Don't output a warning message if option inconsistencies are detected
  between peers. An example of an option inconsistency would be where one
  peer uses ``--dev tun`` while the other peer uses ``--dev tap``.

  Use of this option is discouraged, but is provided as a temporary fix in
  situations where a recent version of OpenVPN must connect to an old
  version.

--engine engine-name
  Enable OpenSSL hardware-based crypto engine functionality.

  If ``engine-name`` is specified, use a specific crypto engine. Use the
  ``--show-engines`` standalone option to list the crypto engines which
  are supported by OpenSSL.

--fast-io
  (Experimental) Optimize TUN/TAP/UDP I/O writes by avoiding a call to
  poll/epoll/select prior to the write operation. The purpose of such a
  call would normally be to block until the device or socket is ready to
  accept the write. Such blocking is unnecessary on some platforms which
  don't support write blocking on UDP sockets or TUN/TAP devices. In such
  cases, one can optimize the event loop by avoiding the poll/epoll/select
  call, improving CPU efficiency by 5% to 10%.

  This option can only be used on non-Windows systems, when ``--proto
  udp`` is specified, and when ``--shaper`` is NOT specified.

--group group
  Similar to the ``--user`` option, this option changes the group ID of
  the OpenVPN process to ``group`` after initialization.

--ignore-unknown-option args
  Valid syntax:
  ::

     ignore-unknown-options opt1 opt2 opt3 ... optN

  When one of options ``opt1 ... optN`` is encountered in the configuration
  file the configuration file parsing does not fail if this OpenVPN version
  does not support the option. Multiple ``--ignore-unknown-option`` options
  can be given to support a larger number of options to ignore.

  This option should be used with caution, as there are good security
  reasons for having OpenVPN fail if it detects problems in a config file.
  Having said that, there are valid reasons for wanting new software
  features to gracefully degrade when encountered by older software
  versions.

  ``--ignore-unknown-option`` is available since OpenVPN 2.3.3.

--iproute cmd
  Set alternate command to execute instead of default ``iproute2`` command.
  May be used in order to execute OpenVPN in unprivileged environment.

--keying-material-exporter args
  Save Exported Keying Material [RFC5705] of len bytes (must be between 16
  and 4095 bytes) using ``label`` in environment
  (:code:`exported_keying_material`) for use by plugins in
  :code:`OPENVPN_PLUGIN_TLS_FINAL` callback.

  Valid syntax:
  ::

    keying-material-exporter label len

  Note that exporter ``labels`` have the potential to collide with existing
  PRF labels. In order to prevent this, labels *MUST* begin with
  :code:`EXPORTER`.

--mlock
  Disable paging by calling the POSIX mlockall function. Requires that
  OpenVPN be initially run as root (though OpenVPN can subsequently
  downgrade its UID using the ``--user`` option).

  Using this option ensures that key material and tunnel data are never
  written to disk due to virtual memory paging operations which occur
  under most modern operating systems. It ensures that even if an attacker
  was able to crack the box running OpenVPN, he would not be able to scan
  the system swap file to recover previously used ephemeral keys, which
  are used for a period of time governed by the ``--reneg`` options (see
  below), then are discarded.

  The downside of using ``--mlock`` is that it will reduce the amount of
  physical memory available to other applications.

  The limit on how much memory can be locked and how that limit
  is enforced are OS-dependent. On Linux the default limit that an
  unprivileged process may lock (RLIMIT_MEMLOCK) is low, and if
  privileges are dropped later, future memory allocations will very
  likely fail. The limit can be increased using ulimit or systemd
  directives depending on how OpenVPN is started.

  If the platform has the getrlimit(2) system call, OpenVPN will check
  for the amount of mlock-able memory before calling mlockall(2), and
  tries to increase the limit to 100 MB if less than this is configured.
  100 Mb is somewhat arbitrary - it is enough for a moderately-sized
  OpenVPN deployment, but the memory usage might go beyond that if the
  number of concurrent clients is high.

--nice n
  Change process priority after initialization (``n`` greater than 0 is
  lower priority, ``n`` less than zero is higher priority).

--persist-key
  Don't re-read key files across :code:`SIGUSR1` or ``--ping-restart``.

  This option can be combined with ``--user nobody`` to allow restarts
  triggered by the :code:`SIGUSR1` signal. Normally if you drop root
  privileges in OpenVPN, the daemon cannot be restarted since it will now
  be unable to re-read protected key files.

  This option solves the problem by persisting keys across :code:`SIGUSR1`
  resets, so they don't need to be re-read.

--remap-usr1 signal
  Control whether internally or externally generated :code:`SIGUSR1` signals
  are remapped to :code:`SIGHUP` (restart without persisting state) or
  SIGTERM (exit).

  ``signal`` can be set to :code:`SIGHUP` or :code:`SIGTERM`. By default,
  no remapping occurs.

--script-security level
  This directive offers policy-level control over OpenVPN's usage of
  external programs and scripts. Lower ``level`` values are more
  restrictive, higher values are more permissive. Settings for ``level``:

  :code:`0`
      Strictly no calling of external programs.

  :code:`1`
      (Default) Only call built-in executables such as ifconfig,
      ip, route, or netsh.

  :code:`2`
      Allow calling of built-in executables and user-defined
      scripts.

  :code:`3`
      Allow passwords to be passed to scripts via environmental
      variables (potentially unsafe).

  OpenVPN releases before v2.3 also supported a ``method`` flag which
  indicated how OpenVPN should call external commands and scripts. This
  could be either :code:`execve` or :code:`system`. As of OpenVPN 2.3, this
  flag is no longer accepted. In most \*nix environments the execve()
  approach has been used without any issues.

  Some directives such as ``--up`` allow options to be passed to the
  external script. In these cases make sure the script name does not
  contain any spaces or the configuration parser will choke because it
  can't determine where the script name ends and script options start.

  To run scripts in Windows in earlier OpenVPN versions you needed to
  either add a full path to the script interpreter which can parse the
  script or use the ``system`` flag to run these scripts. As of OpenVPN
  2.3 it is now a strict requirement to have full path to the script
  interpreter when running non-executables files. This is not needed for
  executable files, such as .exe, .com, .bat or .cmd files. For example,
  if you have a Visual Basic script, you must use this syntax now:

  ::

     --up 'C:\\Windows\\System32\\wscript.exe C:\\Program\ Files\\OpenVPN\\config\\my-up-script.vbs'

  Please note the single quote marks and the escaping of the backslashes
  (\\) and the space character.

  The reason the support for the :code:`system` flag was removed is due to
  the security implications with shell expansions when executing scripts
  via the :code:`system()` call.

--setcon context
  Apply SELinux ``context`` after initialization. This essentially
  provides the ability to restrict OpenVPN's rights to only network I/O
  operations, thanks to SELinux. This goes further than ``--user`` and
  ``--chroot`` in that those two, while being great security features,
  unfortunately do not protect against privilege escalation by
  exploitation of a vulnerable system call. You can of course combine all
  three, but please note that since setcon requires access to /proc you
  will have to provide it inside the chroot directory (e.g. with mount
  --bind).

  Since the setcon operation is delayed until after initialization,
  OpenVPN can be restricted to just network-related system calls, whereas
  by applying the context before startup (such as the OpenVPN one provided
  in the SELinux Reference Policies) you will have to allow many things
  required only during initialization.

  Like with chroot, complications can result when scripts or restarts are
  executed after the setcon operation, which is why you should really
  consider using the ``--persist-key`` and ``--persist-tun`` options.

--status args
  Write operational status to ``file`` every ``n`` seconds.

  Valid syntaxes:
  ::

    status file
    status file n

  Status can also be written to the syslog by sending a :code:`SIGUSR2`
  signal.

  With multi-client capability enabled on a server, the status file
  includes a list of clients and a routing table. The output format can be
  controlled by the ``--status-version`` option in that case.

  For clients or instances running in point-to-point mode, it will contain
  the traffic statistics.

--status-version n
  Set the status file format version number to ``n``.

  This only affects the status file on servers with multi-client
  capability enabled.  Valid status version values:

  :code:`1`
      Traditional format (default). The client list contains the
      following fields comma-separated: Common Name, Real Address, Bytes
      Received, Bytes Sent, Connected Since.

  :code:`2`
      A more reliable format for external processing. Compared to
      version :code:`1`, the client list contains some additional fields:
      Virtual Address, Virtual IPv6 Address, Username, Client ID, Peer ID,
      Data Channel Cipher. Future versions may extend the number of fields.

  :code:`3`
      Identical to :code:`2`, but fields are tab-separated.

--test-crypto
  Do a self-test of OpenVPN's crypto options by encrypting and decrypting
  test packets using the data channel encryption options specified above.
  This option does not require a peer to function, and therefore can be
  specified without ``--dev`` or ``--remote``.

  The typical usage of ``--test-crypto`` would be something like this:
  ::

     openvpn --test-crypto --secret key

  or

  ::

     openvpn --test-crypto --secret key --verb 9

  This option is very useful to test OpenVPN after it has been ported to a
  new platform, or to isolate problems in the compiler, OpenSSL crypto
  library, or OpenVPN's crypto code. Since it is a self-test mode,
  problems with encryption and authentication can be debugged
  independently of network and tunnel issues.

--tmp-dir dir
  Specify a directory ``dir`` for temporary files. This directory will be
  used by openvpn processes and script to communicate temporary data with
  openvpn main process. Note that the directory must be writable by the
  OpenVPN process after it has dropped it's root privileges.

  This directory will be used by in the following cases:

  * ``--client-connect`` scripts and :code:`OPENVPN_PLUGIN_CLIENT_CONNECT`
    plug-in hook to dynamically generate client-specific configuration
    :code:`client_connect_config_file` and return success/failure via
    :code:`client_connect_deferred_file` when using deferred client connect
    method

  * :code:`OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY` plug-in hooks returns
    success/failure via :code:`auth_control_file` when using deferred auth
    method and pending authentification via :code:`pending_auth_file`.

--use-prediction-resistance
  Enable prediction resistance on mbed TLS's RNG.

  Enabling prediction resistance causes the RNG to reseed in each call for
  random. Reseeding this often can quickly deplete the kernel entropy
  pool.

  If you need this option, please consider running a daemon that adds
  entropy to the kernel pool.

--user user
  Change the user ID of the OpenVPN process to ``user`` after
  initialization, dropping privileges in the process. This option is
  useful to protect the system in the event that some hostile party was
  able to gain control of an OpenVPN session. Though OpenVPN's security
  features make this unlikely, it is provided as a second line of defense.

  By setting ``user`` to :code:`nobody` or somebody similarly unprivileged,
  the hostile party would be limited in what damage they could cause. Of
  course once you take away privileges, you cannot return them to an
  OpenVPN session. This means, for example, that if you want to reset an
  OpenVPN daemon with a :code:`SIGUSR1` signal (for example in response to
  a DHCP reset), you should make use of one or more of the ``--persist``
  options to ensure that OpenVPN doesn't need to execute any privileged
  operations in order to restart (such as re-reading key files or running
  ``ifconfig`` on the TUN device).

--writepid file
  Write OpenVPN's main process ID to ``file``.
