CONTRIBUTING TO THE OPENVPN PROJECT
===================================

Patches should be written against the Git "master" branch. Some patches may get
backported to a release branch.

The preferred procedure to send patches to the "openvpn-devel" mailing list:

- https://lists.sourceforge.net/lists/listinfo/openvpn-devel

While we do not merge GitHub pull requests as-is, we do allow their use for code
review purposes. After the patch has been ACKed (reviewed and accepted), it must
be sent to the mailing list. This last step does not necessarily need to be done
by the patch author, although that is definitely recommended.

When sending patches to "openvpn-devel" the subject line should be prefixed with
[PATCH]. To avoid merging issues the patches should be generated with
git-format-patch or sent using git-send-email. Try to split large patches into
small, atomic pieces to make reviews easier.

Please make sure that the source code formatting follows the guidelines at
https://community.openvpn.net/openvpn/wiki/CodeStyle. Automated checking can be
done with uncrustify (http://uncrustify.sourceforge.net/) and the configuration
file which can be found in the git repository at dev-tools/uncrustify.conf.
There is also a git pre-commit hook script, which runs uncrustify automatically
each time you commit and lets you format your code conveniently, if needed.
To install the hook simply run: dev-tools/git-pre-commit-uncrustify.sh install

If you want quick feedback on a patch before sending it to openvpn-devel mailing
list, you can visit the #openvpn-devel channel on irc.libera.chat. Note that
you need to be logged in to Libera to join the channel:

- https://libera.chat/guides/registration

More detailed contribution instructions are available here:

- https://community.openvpn.net/openvpn/wiki/DeveloperDocumentation

Note that the process for contributing to other OpenVPN projects such as
openvpn-build, openvpn-gui, tap-windows6 and easy-rsa may differ from what was
described above. Please refer to the contribution instructions of each
respective project.
