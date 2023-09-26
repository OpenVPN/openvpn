OpenVPN data channel offload
============================
2.6.0+ implements support for data-channel offloading where the data packets
are directly processed and forwarded in kernel space thanks to the ovpn-dco
kernel module. The userspace openvpn program acts purely as a control plane
application.


Overview of current release
---------------------------
- See the "Limitations by design" and "Current limitations" sections for
  features that are not and/or will not be supported by OpenVPN + ovpn-dco.


Getting started (Linux)
-----------------------
- Use a recent Linux kernel. Linux 5.4.0 and newer are known to work with
  ovpn-dco.

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

Clone and build OpenVPN (or use OpenVPN 2.6+). For example:

    git clone https://github.com/openvpn/openvpn.git
    cd openvpn
    autoreconf -vi
    ./configure --enable-dco
    make
    sudo make install # Or just run src/openvpn/openvpn

When starting openvpn it will automatically detect DCO support and use the
kernel module. Add the option `--disable-dco` to disable data channel offload
support. If the configuration contains an option that is incompatible with
data channel offloading, OpenVPN will automatically disable DCO support and
warn the user.

Should OpenVPN be configured to use a feature that is not supported by ovpn-dco
or should the ovpn-dco kernel module not be available on the system, you will
see a message like

    Note: Kernel support for ovpn-dco missing, disabling data channel offload.

in your log.


Getting started (Windows)
-------------------------
Official releases published at https://openvpn.net/community-downloads/
include ovpn-dco-win driver since 2.6.0.

There are also snapshot releases available at
https://build.openvpn.net/downloads/snapshots/github-actions/openvpn2/ .
This installer contains the latest OpenVPN code and the ovpn-dco-win driver.


DCO and P2P mode
----------------
DCO is also available when running OpenVPN in P2P mode without `--pull` /
`--client` option. P2P mode is useful for scenarios when the OpenVPN tunnel
should not interfere with overall routing and behave more like a "dumb" tunnel,
like GRE.

However, DCO requires DATA_V2 to be enabled, which is available for P2P mode
only in OpenVPN 2.6 and later.

OpenVPN prints a diagnostic message for the P2P NCP result when running in P2P
mode:

    P2P mode NCP negotiation result: TLS_export=1, DATA_v2=1, peer-id 9484735, cipher=AES-256-GCM

Double check that you have `DATA_v2=1` in your output and a supported AEAD
cipher (AES-XXX-GCM or CHACHA20POLY1305).


Routing with ovpn-dco
---------------------
The ovpn-dco kernel module implements a more transparent approach to
configuring routes to clients (aka "iroutes") and consults the main kernel
routing tables for forwarding decisions.

- Each client has a VPN IPv4 and/or a VPN IPv6 assigned to it;
- additional IP ranges can be routed to a client by adding a route with
  a client VPN IP as the gateway/nexthop (i.e. ip route add a.b.c.d/24 via
  $VPNIP);
- due to the point above, there is no real need to add a companion `--route` for
  each `--iroute` directive, unless you want to blackhole traffic when the
  specific client is not connected;
- no internal routing is available. If you need truly internal routes, this can
  be achieved either with filtering using `iptables` or using `ip rule`;
- client-to-client behaviour, as implemented in userspace, does not exist:
  packets always reach the tunnel interface and are then re-routed to the
  destination peer based on the system routing table.


Limitations by design
----------------------
- Layer 3 (dev tun) only;
- only the following AEAD ciphers are currently supported: Chacha20-Poly1305
  and AES-GCM-128/192/256;
- no support for compression or compression framing:
  - see also the `--compress migrate` option to move to a setup without
    compression;
- various features not implemented since they have better replacements:
  - `--shaper`, use tc instead;
  - packet manipulation, use nftables/iptables instead;
- OpenVPN 2.4.0 is the minimum version required for peers to connect:
  - older versions are missing support for the AEAD ciphers;
- topology subnet is the only supported `--topology` for servers;
- iroute directives install routes on the host operating system, see also
  Routing with ovpn-dco;
- (ovpn-dco-win) client and p2p mode only;
- (ovpn-dco-win) Chacha20-Poly1305 support available starting with Windows 11.


Current implementation limitations
-------------------
- `--persist-tun` not tested;
- IPv6 mapped IPv4 addresses need Linux 5.4.189+/5.10.110+/5.12+ to work;
- some incompatible options may not properly fallback to non-dco;
- no per client statistics. Only total statistics available on the interface.
