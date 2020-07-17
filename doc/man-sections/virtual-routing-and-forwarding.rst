Virtual Routing and Forwarding
------------------------------

Options in this section relates to configuration of virtual routing and
forwarding in combination with the underlying operating system.

As of today this is only supported on Linux, a kernel >= 4.9 is
recommended.

This could come in handy when for example the external network should be
only used as a means to connect to some VPN endpoints and all regular
traffic should only be routed through any tunnel(s).  This could be
achieved by setting up a VRF and configuring the interface connected to
the external network to be part of the VRF. The examples below will cover
this setup.

Another option would be to put the tun/tap interface into a VRF. This could
be done by an up-script which uses the :code:`ip link set` command shown
below.


VRF setup with iproute2
```````````````````````

Create VRF :code:`vrf_external` and map it to routing table :code:`1023`
::

      ip link add vrf_external type vrf table 1023

Move :code:`eth0` into :code:`vrf_external`
::

      ip link set master vrf_external dev eth0

Any prefixes configured on :code:`eth0` will be moved from the :code`main`
routing table into routing table `1023`


VRF setup with ifupdown
```````````````````````

For Debian based Distributions :code:`ifupdown2` provides an almost drop-in
replacement for :code:`ifupdown` including VRFs and other features.
A configuration for an interface :code:`eth0` being part of VRF
code:`vrf_external` could look like this:
::

      auto eth0
      iface eth0
          address 192.0.2.42/24
          address 2001:db8:08:15::42/64
          gateway 192.0.2.1
          gateway 2001:db8:08:15::1
          vrf vrf_external

      auto vrf_external
      iface vrf_external
          vrf-table 1023


OpenVPN configuration
`````````````````````
The OpenVPN configuration needs to contain this line:
::

      bind-dev vrf_external


Further reading
```````````````

Wikipedia has nice page one VRFs: https://en.wikipedia.org/wiki/Virtual_routing_and_forwarding

This talk from the Network Track of FrOSCon 2018 provides an overview about
advanced layer 2 and layer 3 features of Linux

  - Slides: https://www.slideshare.net/BarbarossaTM/l2l3-fr-fortgeschrittene-helle-und-dunkle-magie-im-linuxnetzwerkstack
  - Video (german): https://media.ccc.de/v/froscon2018-2247-l2\_l3\_fur\_fortgeschrittene\_-\_helle\_und\_dunkle\_magie\_im\_linux-netzwerkstack
