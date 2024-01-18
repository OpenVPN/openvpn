--http-proxy args
  Connect to remote host through an HTTP proxy.  This requires at least an
  address ``server`` and ``port`` argument.  If HTTP Proxy-Authenticate
  is required, a file name to an ``authfile`` file containing a username
  and password on 2 lines can be given, or :code:`stdin` to prompt from
  console. Its content can also be specified in the config file with the
  ``--http-proxy-user-pass`` option (See `INLINE FILE SUPPORT`_).

  The last optional argument is an ``auth-method`` which should be one
  of :code:`none`, :code:`basic`, or :code:`ntlm`.

  HTTP Digest authentication is supported as well, but only via the
  :code:`auto` or :code:`auto-nct` flags (below).  This must replace
  the ``authfile`` argument.

  The :code:`auto` flag causes OpenVPN to automatically determine the
  ``auth-method`` and query stdin or the management interface for
  username/password credentials, if required. This flag exists on OpenVPN
  2.1 or higher.

  The ``auto-nct`` flag (no clear-text auth) instructs OpenVPN to
  automatically determine the authentication method, but to reject weak
  authentication protocols such as HTTP Basic Authentication.

  Examples:
  ::

     # no authentication
     http-proxy proxy.example.net 3128
     # basic authentication, load credentials from file
     http-proxy proxy.example.net 3128 authfile.txt
     # basic authentication, ask user for credentials
     http-proxy proxy.example.net 3128 stdin
     # NTLM authentication, load credentials from file
     http-proxy proxy.example.net 3128 authfile.txt ntlm2
     # determine which authentication is required, ask user for credentials
     http-proxy proxy.example.net 3128 auto
     # determine which authentication is required, but reject basic
     http-proxy proxy.example.net 3128 auto-nct
     # determine which authentication is required, but set credentials
     http-proxy proxy.example.net 3128 auto
     http-proxy-user-pass authfile.txt
     # basic authentication, specify credentials inline
     http-proxy proxy.example.net 3128 "" basic
     <http-proxy-user-pass>
     username
     password
     </http-proxy-user-pass>

--http-proxy-user-pass userpass
  Overwrite the username/password information for ``--http-proxy``. If specified
  as an inline option (see `INLINE FILE SUPPORT`_), it will be interpreted as
  username/password separated by a newline. When specified on the command line
  it is interpreted as a filename same as the third argument to ``--http-proxy``.

  Example::

    <http-proxy-user-pass>
    username
    password
    </http-proxy-user-pass>

--http-proxy-option args
  Set extended HTTP proxy options. Requires an option ``type`` as argument
  and an optional ``parameter`` to the type.  Repeat to set multiple
  options.

  :code:`VERSION` ``version``
      Set HTTP version number to ``version`` (default :code:`1.0`).

  :code:`AGENT` ``user-agent``
      Set HTTP "User-Agent" string to ``user-agent``.

  :code:`CUSTOM-HEADER` ``name`` ``content``
      Adds the custom Header with ``name`` as name and ``content`` as
      the content of the custom HTTP header.

  Examples:
  ::

     http-proxy-option VERSION 1.1
     http-proxy-option AGENT OpenVPN/2.4
     http-proxy-option X-Proxy-Flag some-flags

--socks-proxy args
  Connect to remote host through a Socks5 proxy.  A required ``server``
  argument is needed.  Optionally a ``port`` (default :code:`1080`) and
  ``authfile`` can be given.  The ``authfile`` is a file containing a
  username and password on 2 lines, or :code:`stdin` can be used to
  prompt from console.
