Small OpenVPN setup with peer-fingerprint
=========================================
This section consists of instructions how to build a small OpenVPN setup with the
:code:`peer-fingerprint` option. This has the advantage of being easy to setup
and should be suitable for most small lab and home setups without the need for a PKI.
For bigger scale setup setting up a PKI (e.g. via easy-rsa) is still recommended.

Both server and client configuration can be further modified to customise the
setup.

Server setup
------------
1. Install openvpn

   Compile from source-code (see `INSTALL` file) or install via a distribution (apt/yum/ports)
   or via installer (Windows).

2. Generate a self-signed certificate for the server:
   ::

    openssl req -x509 -newkey ec:<(openssl ecparam -name secp384r1) -keyout server.key -out server.crt -nodes -sha256 -days 3650 -subj '/CN=server'

3. Generate SHA256 fingerprint of the server certificate

   Use the OpenSSL command line utility to view the fingerprint of just
   created certificate:
   ::

    openssl x509 -fingerprint -sha256 -in server.crt -noout

   This output something similar to:
   ::

     SHA256 Fingerprint=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff


4. Write a server configuration (`server.conf`)::

    # The server certificate we created in step 1
    cert server.crt
    key server.key

    dh none
    dev tun

    # Listen on IPv6+IPv4 simultaneously
    proto udp6

    # The ip address the server will distribute
    server 10.8.0.0 255.255.255.0
    server-ipv6 fd00:6f76:706e::/64

    # A tun-mtu of 1400 avoids problems of too big packets after VPN encapsulation
    tun-mtu 1400

    # The fingerprints of your clients. After adding/removing one here restart the
    # server
    <peer-fingerprint>
    </peer-fingerprint>

    # Notify clients when you restart the server to reconnect quickly
    explicit-exit-notify 1

    # Ping every 60s, restart if no data received for 5 minutes
    keepalive 60 300

5. Add at least one client as described in the client section.

6. Start the server.
    - On systemd based distributions move `server.crt`, `server.key` and
      `server.conf` to :code:`/etc/openvpn/server` and start it via systemctl

      ::

          sudo mv server.conf server.key server.crt /etc/openvpn/server

          sudo systemctl start openvpn-server@server

Adding a client
---------------
1. Install OpenVPN

2. Generate a self-signed certificate for the client. In this example the client
   name is alice. Each client should have a unique name. Replace alice with a
   different name for each client.
   ::

      openssl req -x509 -newkey ec:<(openssl ecparam -name secp384r1) -nodes -sha256 -days 3650 -subj '/CN=alice'

   This generate a certificate and a key for the client. The output of the command will look
   something like this:
   ::

      -----BEGIN PRIVATE KEY-----
      [base64 content]
      -----END PRIVATE KEY-----
      -----
      -----BEGIN CERTIFICATE-----
      [base 64 content]
      -----END CERTIFICATE-----


3. Create a new client configuration file. In this example we will name the file
   `alice.ovpn`:

   ::

      # The name of your server to connect to
      remote yourserver.example.net
      client
      # use a random source port instead the fixed 1194
      nobind

      # Uncomment the following line if you want to route
      # all traffic via the VPN
      # redirect-gateway def1 ipv6

      # To set a DNS server
      # dhcp-option DNS 192.168.234.1

      <key>
      -----BEGIN PRIVATE KEY-----
      [Insert here the key created in step 2]
      -----END PRIVATE KEY-----
      </key>
      <cert>
      -----BEGIN CERTIFICATE-----
      [Insert here the certificate created in step 2]
      -----END CERTIFICATE-----
      </cert>

      # This is the fingerprint of the server that we trust. We generated this fingerprint
      # in step 2 of the server setup
      peer-fingerprint 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff

      # The tun-mtu of the client should match the server MTU
      tun-mtu 1400
      dev tun


4. Generate the fingerprint of the client certificate. For that we will
   let OpenSSL read the client configuration file as the x509 command will
   ignore anything that is not between the begin and end markers of the certificate:

   ::

      openssl x509 -fingerprint -sha256 -noout -in alice.ovpn

   This will again output something like
   ::

        SHA256 Fingerprint=ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00

5. Edit the `server.conf` configuration file and add this new client
   fingerprint as additional line  between :code:`<peer-fingerprint>`
   and :code:`</peer-fingerprint>`

   After adding *two* clients the part of configuration would look like this:

   ::

      <peer-fingerprint>
      ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00
      99:88:77:66:55:44:33:22:11:00:ff:ee:dd:cc:bb:aa:99:88:77:66:55:44:33:22:11:00:88:77:66:55:44:33
      </peer-fingperint>

6. (optional) if the client is an older client that does not support the
   :code:`peer-fingerprint` (e.g. OpenVPN 2.5 and older, OpenVPN Connect 3.3
   and older), the client config `alice.ovpn` can be modified to still work with
   these clients.

   Remove the line starting with :code:`peer-fingerprint`. Then
   add a new :code:`<ca>` section at the end of the configuration file
   with the contents of the :code:`server.crt` created in step 2 of the
   server setup. The end of `alice.ovpn` file should like:

   ::

      [...]  # Beginning of the file skipped
      </cert>

      # The tun-mtu of the client should match the server MTU
      tun-mtu 1400
      dev tun

      <ca>
      [contents of the server.crt]
      </ca>

   Note that we put the :code:`<ca>` section after the :code:`<cert>` section
   to make the fingerprint generation from step 4 still work since it will
   only use the first certificate it finds.

7. Import the file into the OpenVPN client or just use the
   :code:`openvpn alice.ovpn` to start the VPN.
