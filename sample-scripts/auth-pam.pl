#!/usr/bin/perl -t

# OpenVPN PAM AUTHENTICATON
#   This script can be used to add PAM-based authentication
#   to OpenVPN 2.0.  The OpenVPN client must provide
#   a username/password, using the --auth-user-pass directive.
#   The OpenVPN server should specify --auth-user-pass-verify
#   with this script as the argument and the 'via-file' method
#   specified.  The server can also optionally specify
#   --client-cert-not-required and/or --username-as-common-name.

# SCRIPT OPERATION
#   Return success or failure status based on whether or not a
#   given username/password authenticates using PAM.
#   Caller should write username/password as two lines in a file
#   which is passed to this script as a command line argument.

# CAVEATS
#   * Requires Authen::PAM module, which may also
#     require the pam-devel package.
#   * May need to be run as root in order to
#     access username/password file.

# NOTES
#   * This script is provided mostly as a demonstration of the
#     --auth-user-pass-verify script capability in OpenVPN.
#     For real world usage, see the auth-pam module in the plugin
#     folder.

use Authen::PAM;
use POSIX;

# This "conversation function" will pass
# $password to PAM when it asks for it.

sub my_conv_func {
    my @res;
    while ( @_ ) {
        my $code = shift;
        my $msg = shift;
        my $ans = "";

        $ans = $password if $msg =~ /[Pp]assword/;

        push @res, (PAM_SUCCESS(),$ans);
    }
    push @res, PAM_SUCCESS();
    return @res;
}

# Identify service type to PAM
$service = "login";

# Get username/password from file

if ($ARG = shift @ARGV) {
    if (!open (UPFILE, "<$ARG")) {
	print "Could not open username/password file: $ARG\n";
	exit 1;
    }
} else {
    print "No username/password file specified on command line\n";
    exit 1;
}

$username = <UPFILE>;
$password = <UPFILE>;

if (!$username || !$password) {
    print "Username/password not found in file: $ARG\n";
    exit 1;
}

chomp $username;
chomp $password;

close (UPFILE);

# Initialize PAM object

if (!ref($pamh = new Authen::PAM($service, $username, \&my_conv_func))) {
    print "Authen::PAM init failed\n";
    exit 1;
}

# Authenticate with PAM

$res = $pamh->pam_authenticate;

# Return success or failure

if ($res == PAM_SUCCESS()) {
    exit 0;
} else {
    print "Auth '$username' failed, PAM said: ", $pamh->pam_strerror($res), "\n";
    exit 1;
}
