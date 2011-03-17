down-root -- an OpenVPN Plugin Module

SYNOPSIS

The down-root module allows an OpenVPN configuration to
call a down script with root privileges, even when privileges
have been dropped using --user/--group/--chroot.

This module uses a split privilege execution model which will
fork() before OpenVPN drops root privileges, at the point where
the --up script is usually called.  The module will then remain
in a wait state until it receives a message from OpenVPN via
pipe to execute the down script.  Thus, the down script will be
run in the same execution environment as the up script.

BUILD

Build this module with the "make" command.  The plugin
module will be named openvpn-down-root.so

USAGE

To use this module, add to your OpenVPN config file:

  plugin openvpn-down-root.so "command ..."

CAVEATS

This module will only work on *nix systems, not Windows.
