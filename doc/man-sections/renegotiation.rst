Data Channel Renegotiation
--------------------------

When running OpenVPN in client/server mode, the data channel will use a
separate ephemeral encryption key which is rotated at regular intervals.

--reneg-bytes n
  Renegotiate data channel key after ``n`` bytes sent or received
  (disabled by default with an exception, see below). OpenVPN allows the
  lifetime of a key to be expressed as a number of bytes
  encrypted/decrypted, a number of packets, or a number of seconds. A key
  renegotiation will be forced if any of these three criteria are met by
  either peer.

  If using ciphers with cipher block sizes less than 128-bits,
  ``--reneg-bytes`` is set to 64MB by default, unless it is explicitly
  disabled by setting the value to :code:`0`, but this is
  **HIGHLY DISCOURAGED** as this is designed to add some protection against
  the SWEET32 attack vector. For more information see the ``--cipher``
  option.

--reneg-pkts n
  Renegotiate data channel key after **n** packets sent and received
  (disabled by default).

--reneg-sec args
  Renegotiate data channel key after at most ``max`` seconds
  (default :code:`3600`) and at least ``min`` seconds (default is 90% of
  ``max`` for servers, and equal to ``max`` for clients).
  ::

     reneg-sec max [min]

  The effective ``--reneg-sec`` value used is per session
  pseudo-uniform-randomized between ``min`` and ``max``.

  With the default value of :code:`3600` this results in an effective per
  session value in the range of :code:`3240`..:code:`3600` seconds for
  servers, or just 3600 for clients.

  When using dual-factor authentication, note that this default value may
  cause the end user to be challenged to reauthorize once per hour.

  Also, keep in mind that this option can be used on both the client and
  server, and whichever uses the lower value will be the one to trigger
  the renegotiation. A common mistake is to set ``--reneg-sec`` to a
  higher value on either the client or server, while the other side of the
  connection is still using the default value of :code:`3600` seconds,
  meaning that the renegotiation will still occur once per :code:`3600`
  seconds. The solution is to increase --reneg-sec on both the client and
  server, or set it to :code:`0` on one side of the connection (to
  disable), and to your chosen value on the other side.
