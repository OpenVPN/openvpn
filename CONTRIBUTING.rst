CONTRIBUTING TO THE OPENVPN PROJECT
===================================

Patches should be written against the Git "master" branch. Some patches may get
backported to a release branch.

We do not currently accept GitHub pull requests for the core OpenVPN project.
Instead, all patches must be sent to "openvpn-devel" mailing list for review:

- https://lists.sourceforge.net/lists/listinfo/openvpn-devel

The subject line should preferably be prefixed with [PATCH]. To avoid merging
issues the patches should be generated with git-format-patch or sent using
git-send-email. Try to split large patches into small, atomic pieces to make
reviews easier.

If you want quick feedback on a patch before sending it to openvpn-devel mailing
list, you can visit the #openvpn-devel channel on irc.freenode.net. Note that
you need to be logged in to Freenode to join the channel:

- http://freenode.net/faq.shtml#nicksetup

More detailed contribution instructions are available here:

- https://community.openvpn.net/openvpn/wiki/DeveloperDocumentation

Note that the process for contributing to other OpenVPN projects such as
openvpn-build, openvpn-gui, tap-windows6 and easy-rsa may differ from what was
described above. Please refer to the contribution instructions of each
respective project.
