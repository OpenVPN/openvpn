Version 2.3.9
=============


New features
------------

Peer ID support
    Added new packet format P_DATA_V2, which includes peer-id. If
    server and client  support it, client sends all data packets in
    the new format. When data packet arrives, server identifies peer
    by peer-id. If peer's ip/port has changed, server assumes that
    client has floated, verifies HMAC and updates ip/port in internal structs.

    (2.3.x has client-side functionality only, server needs 2.4)


User-visible Changes
--------------------

- sndbuf and recvbuf default now to OS default instead of 64k

- Removed --enable-password-save from configure. This option is now
  always enabled.
