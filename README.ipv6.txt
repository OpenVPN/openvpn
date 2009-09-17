[ Last updated: 17-Sep-2009. ]
This README covers UDP/IPv6 v0.4.x ( --udp6 and --tcp6-xxxxxx  ) support
for openvpn-2.1.

Available under GPLv2 from 
  http://github.com/jjo/openvpn-ipv6

* Working:
  - tcp6->tcp6; tested on GNU/Linux
  - upd6->upd6; tested on GNU/Linux
  - upd4->upd6 (ipv6 bound)

* Setup:
  ./configure --enable-ipv6        (by default)

* Usage:
  For IPv6 just specify "-p upd6" an proper IPv6 hostnames, adapting the example
  from man page ...

  On may:
    openvpn --proto udp6 --remote <june_IPv6_addr> --dev tun1 \
      --ifconfig 10.4.0.1 10.4.0.2 --verb 5 --secret key

  On june:
    openvpn --proto udp6 --remote <may_IPv6_addr>  --dev tun1 \
      --ifconfig 10.4.0.2 10.4.0.1 --verb 5 --secret key
  
  Same for --proto tcp6-client, tcp6-server.

* Main code changes summary:
  - socket.h: New struct openvpn_sockaddr type that holds sockaddrs and pktinfo, 
    (here I omitted #ifdef USE_PF_xxxx, see socket.h )

    struct openvpn_sockaddr {
    	union {
    		struct sockaddr sa;
    		struct sockaddr_in in;
    		struct sockaddr_in6 in6;
    	} addr;
    };
    
    struct link_socket_addr
    {
            struct openvpn_sockaddr local;
            struct openvpn_sockaddr remote;
            struct openvpn_sockaddr actual;
    };
    
    PRO: allows simple type overloading: local.addr.sa, local.addr.in, local.addr.in6 ... etc
    (also local.pi.in and local.pi.in6)

  - several function prototypes moved from sockaddr_in to openvpn_sockaddr 
  - several new sockaddr functions needed to "generalize" AF_xxxx operations:
    addr_copy(), addr_zero(), ...etc
    proto_is_udp(), proto_is_dgram(), proto_is_net()

* TODO:
  -  Implement comparison for mapped addesses: server in dual stack
     listening IPv6 must permit incoming streams from allowed IPv4 peer,
     currently you need to pass eg:  --remote ffff::1.2.3.4

--
JuanJo Ciarlante   jjo () google () com
:                                                                  :
.                                         Linux IP Aliasing author .
.   Modular algo (AES et all) support for FreeSWAN/OpenSWAN author .
:...       plus  other scattered free software bits in the wild ...:
