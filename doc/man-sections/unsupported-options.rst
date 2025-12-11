
UNSUPPORTED OPTIONS
===================

Options listed in this section have been removed from OpenVPN and are no
longer supported

--client-cert-not-required
  Removed in OpenVPN 2.5.  This should be replaced with
  ``--verify-client-cert none``.

--fast-io
  Ignored since OpenVPN 2.7. This option became broken due to changes
  to the event loop.

--http-proxy-retry
  Removed in OpenVPN 2.4.  All retries are controlled by ``--max-connect-retry``.

--http-proxy-timeout
  Removed in OpenVPN 2.4.  Connection timeout is controlled by
  ``--connect-timeout``.

--ifconfig-pool-linear
  Removed in OpenVPN 2.5.  This should be replaced with ``--topology p2p``.

--key-method
  Removed in OpenVPN 2.5.  This option should not be used, as using the old
  ``key-method`` weakens the VPN tunnel security.  The old ``key-method``
  was also only needed when the remote side was older than OpenVPN 2.0.

--management-client-pf
  Removed in OpenVPN 2.6.  The built-in packet filtering (pf) functionality
  has been removed.

--max-routes
  Removed in OpenVPN 2.4.  The limit was removed.

--ncp-disable
  Removed in OpenVPN 2.6.  This option mainly served a role as debug option
  when NCP was first introduced.  It should no longer be necessary.

--no-iv
  Removed in OpenVPN 2.5.  This option should not be used as it weakens the
  VPN tunnel security.  This has been a NOOP option since OpenVPN 2.4.

--no-replay
  Removed in OpenVPN 2.7.  This option should not be used as it weakens the
  VPN tunnel security.  Previously we claimed to have removed this in
  OpenVPN 2.5, but this wasn't actually the case.

--prng
  Removed in OpenVPN 2.6.  We now always use the PRNG of the SSL library.

--persist-key
  Ignored since OpenVPN 2.7. Keys are now always persisted across restarts.

--opt-verify
  Removed in OpenVPN 2.7.  This option does not make sense anymore as option
  strings may not match due to the introduction of parameters negotiation.

--socks-proxy-retry
  Removed in OpenVPN 2.4.  All retries are controlled by ``--max-connect-retry``.

--windows-driver
  Removed in OpenVPN 2.7. OpenVPN will always use ovpn-dco as the default
  driver on Windows. It will fall back to tap-windows6 if options are used
  that are incompatible with ovpn-dco.
