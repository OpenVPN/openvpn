OpenVPN data channel offload
============================
2.6.0+ implements support for data-channel offloading where the data packets
are directly processed and forwarded in kernel space thanks to the ovpn-dco
kernel module. The userspace openvpn program acts purely as a control plane
application.


Overview of current release
---------------------------
- See the "Limitations by design" and "Current limitations" sections for
  features that are not and/or will not be supported by OpenVPN + ovpn-dco


Getting started (Linux)
-----------------------

- Use a recent Linux kernel. Ubuntu 20.04 (Linux 5.4.0) and Ubuntu 20.10
  (Linux 5.8.0) are known to work with ovpn-dco.

Get the ovpn-dco module from one these urls and build it:

* https://gitlab.com/openvpn/ovpn-dco
* https://github.com/OpenVPN/ovpn-dco

e.g.

    git clone https://github.com/OpenVPN/ovpn-dco
    cd ovpn-dco
    make
    sudo make install

If you want to report bugs please ensure to compile ovpn-dco with
`make DEBUG=1` and include any debug message being printed by the
kernel (you can view those messages with `dmesg`).

Clone OpenVPN and build dco branch. For example:

    git clone -b dco https://github.com/openvpn/openvpn.git
    cd openvpn
    autoreconf -vi
    ./configure --enable-dco
    make
    sudo make install # Or run just src/openvpn/openvpn

If you start openvpn it should automatically detect DCO support and use the
kernel module. Add the option `--disable-dco` to disable data channel offload
support. If the configuration contains an option that is incompatible with
data channel offloading OpenVPN will automatically disable DCO support and
warn the user.

Should OpenVPN be configured to use a feature that is not supported by ovpn-dco
or should the ovpn-dco kernel module not be available on the system, you will
see a message like

    Note: Kernel support for ovpn-dco missing, disabling data channel offload.

in your log.


Getting started (Windows)
-------------------------
Getting started under windows is currently for brave people having experience
with windows development. You need to compile openvpn yourself and also need 
to get the test driver installed on your system.


DCO and P2P mode
----------------
DCO is also available when running OpenVPN in P2P mode without --pull/--client option.
The P2P mode is useful for scenarios when the OpenVPN tunnel should not interfere with
overall routing and behave more like a "dumb" tunnel like GRE.

However, DCO requires DATA_V2 to be enabled this requires P2P with NCP capability, which
is only available in OpenVPN 2.6 and later.

OpenVPN prints a diagnostic message for the P2P NCP result when running in P2P mode:

    P2P mode NCP negotiation result: TLS_export=1, DATA_v2=1, peer-id 9484735, cipher=AES-256-GCM

Double check that your have `DATA_v2=1` in your output and a supported AEAD cipher
(AES-XXX-GCM or CHACHA20POLY1305).


Routing with ovpn-dco
---------------------
The ovpn-dco kernel module implements a more transparent approach to
configuring routes to clients (aka 'iroutes') and consults the kernel
routing tables for forwarding decisions.

- Each client has an IPv4 VPN IP and/or an IPv6 assigned to it.
- Additional IP ranges can be routed to a client by adding a route with
  a client VPN IP as the gateway/nexthop (i.e. ip route add a.b.c.d/24 via $VPNIP).
- Due to the point above, there is no real need to add a companion --route for
  each --iroute directive, unless you want to blackhole traffic when the specific
  client is not connected.
- No internal routing is available. If you need truly internal routes, this can be
  achieved either with filtering using `iptables` or using `ip rule`.
- client-to-client behaviour, as implemented in userspace, does not exist: packets
  are always sent up to the tunnel interface and then back in to be routed to the
  destination peer.


Limitations by design
----------------------
- Layer 3 (dev tun only)
- only AEAD ciphers are supported and currently only
  Chacha20-Poly1305 and AES-GCM-128/192/256
- no support for compression or compression framing
  - see also `--compress migrate` option to move to a setup with compression
- various features not implemented since have better replacements
  - --shaper, use tc instead
  - packet manipulation, use nftables/iptables instead
- OpenVPN 2.4.0 is the minimum peer version.
  - older version are missing support for the AEAD ciphers
- topology subnet is the only supported `--topology` for servers
- iroute directives install routes on the host operating system, see also
  routing with ovpn-dco
- (ovpn-dco-win) client and p2p mode only
- (ovpn-dco-win) only AES-GCM-128/192/256 cipher support


Current implementation limitations
-------------------
- --persistent-tun not tested/supported
- fallback to non-dco in client mode missing
- IPv6 mapped IPv4 addresses need Linux 5.12 to properly work
- Some incompatible options may not properly fallback to non-dco
- TCP performance with ovpn-dco can still exhibit bad behaviour and drop to a
  few megabits per seconds.
- Not all options that should trigger disabling DCO as they are incompatible
  are currently identified. Some options that do not trigger disabling DCO
  are ignored while other might yield unexpected results.
- ovpn-dco currently does not implement RPF checks and will accept any source
  IP from any client.
- If a peer VPN IP is outside the default device subnet, the route needs to be
  added manually.
- No per client statistics. Only total statistics available on the interface.
