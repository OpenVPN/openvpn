Notes for the --dev null test suite
===================================

Introduction
------------

The *--dev null test suite* is primary targeted at testing client connections
to the "just compiled" version of OpenVPN. The name is derived from "null"
device type in OpenVPN. In particular, when *--dev null --ifconfig-noexec* is
used in OpenVPN client configuration one does not need to run OpenVPN with root
privileges because interface, routing, etc. configuration is not done at all.
This is still enough to ensure that the OpenVPN client can connect to a server
instance.

The main features of the test suite:

* Parallelized for fairly high performance
* Mostly operating-system agnostic
* Tested on Fedora Linux 38/39/40 and FreeBSD 14
* POSIX-compliant
* Tested and known to work with Bash, Dash, Ksh, Yash and FreeBSD's default /bin/sh
* Uses the sample certificates and keys
* Supports running multiple servers and clients
* Supports running servers directly as root and with sudo
* Supports using different OpenVPN client versions

  * The "current" (just compiled) version
  * Any other OpenVPN versions that is present on the filesystem

* Support testing for success as well as failure
* Test cases (client configurations) and server setups (server configurations) are stored in a configuration file, i.e. data and code have been separated
* Configuration file format is nearly identical to t_client.rc configuration
* Supports a set of default tests, overriding default test settings and adding local tests

Prerequisites
-------------

Running the test suite requires the following:

* *bash* for running the tests
* root-level privileges for launching the servers

  * run as root
  * a privilege escalation tool (sudo, doas, su) and the permission to become root

If you use "doas" you should enable nopass feature in */etc/doas.conf*. For
example to allow users in the *wheel* group to run commands without a password
prompt::

    permit nopass keepenv :wheel

Technical implementation
------------------------

The test suite is completely parallelized to allow running a large number of
server and client combinations quickly.

A normal test run looks like this:

#. Server instances start
#. Brief wait
#. Client instances start
#. Tests run
#. Client instances stop
#. Brief wait
#. Server instances stop

The tests suite is launched via "make check":

* make check

  * t_server_null.sh

    * t_server_null_server.sh

      * Launches the compiled OpenVPN server instances as root (if necessary with sudo or su) in the background. The servers are killed using their management interface once all clients have exited.

    * t_server_null_client.sh

      * Waits until servers have launched. Then launch all clients, wait for them to exit and then check test results by parsing the client log files. Each client kills itself after some delay using an "--up" script.

Configuration
-------------

The test suite reads its configuration from two files:

* *tests/t_server_null_defaults.rc:* default test configuration that should work on any system
* *tests/t_server_null.rc:* a local configuration file; can be used to add additional tests or override settings from the default test configuration. Must be present or tests will be skipped, but can be an empty file.

The configuration syntax is very similar to *t_client.rc*. New server instances can be
defined like this::

  SERVER_NAME_5="t_server_null_server-11195_udp"
  SERVER_MGMT_PORT_5="11195"
  SERVER_EXEC_5="${SERVER_EXEC}"
  SERVER_CONF_5="${SERVER_CONF_BASE} --lport 11195 --proto udp --management 127.0.0.1 ${SERVER_MGMT_PORT_5}"

In this case the server instance identifier is **5**. Variables such as
*SERVER_EXEC* and *SERVER_CONF_BASE* are defined in
*t_server_null_defaults.rc*. To enable this server instance add it to the
server list::

  TEST_SERVER_LIST="1 2 5"

The client instances are added similarly::

  TEST_NAME_9="t_server_null_client.sh-openvpn_current_udp_custom"
  SHOULD_PASS_9="yes"
  CLIENT_EXEC_9="${CLIENT_EXEC}"
  CLIENT_CONF_9="${CLIENT_CONF_BASE} --remote 127.0.0.1 1194 udp --proto udp"

In this case the test identifier is **9**. *CLIENT_EXEC* and *CLIENT_CONF_BASE*
are defined in *t_server_null_defaults.rc*. The variable *SHOULD_PASS*
determines that this particular test is supposed to succeed and not fail.  To
enable this client instance add it to the test list::

  TEST_RUN_LIST="1 2 5 9"

Stress-testing the --dev null test suite
----------------------------------------

It is very easy to introduce subtle, difficult to debug issues to the --dev
null tests when you make changes to it. These issues can be difficult to spot:
based on practical experience a bad change can make the test failure rate go
from 0% (normal) to anywhere between 1% and 20%. You can spot these issues with
the provided stress-test script, *t_server_null_stress.sh*. It calls *make check*
over and over again in a loop and when failures occur it saves the output under
*tests/make-check*.

To follow the test flow on Linux you can run this while stress-testing::

    watch -n 0.5 "ps aux|grep -E '(openvpn|t_server_null_server.sh)'|grep -vE '(suppress|grep|tail)'"

Regarding privilege escalation
------------------------------

The --dev null test servers need to be launched as root. Either run the tests
as root directly, or configure a privilege escalation tool of your choice in
*t_server_null.rc*. For example, to use sudo::

    SUDO_EXEC=`which sudo`
    RUN_SUDO="${SUDO_EXEC} -E"

If you do stress-testing with *t_server_null_stress.sh* make sure your
privilege escalation authorization does not time out: if it does, then a
reauthorization prompt will interrupt your tests.
