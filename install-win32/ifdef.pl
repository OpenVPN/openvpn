#!/usr/bin/perl

# Simple ifdef/else/endif processor.

die "usage: ifdef [-C<command-prefix>] [-Dname ...] [control-file ...] " if (@ARGV[0] =~ /^(-h|--help)$/);

%Parms = ();

$pre = "!";
while ($arg=shift(@ARGV)) {
    if ($arg =~ /^-/) {
	if ($arg =~ /^-D(\w+)$/) {
	    $Parms{$1} = 1;
	} elsif ($arg =~ /-C(.*)$/) {
	  $pre = $1;
	} else {
	    die "unrecognized option: $arg";
	}
    } else {
	open(CONTROL, "< $arg") or die "cannot open $arg";
	while (<CONTROL>) {
	    if (/^!define\s+(\w+)/) {
                $Parms{$1} = 1;
            }
        }
    }
}

sub ifdef {
  my ($var, $enabled) = @_;
  my $def = 0;
  $def = 1 if (defined $Parms{$var}) || ($var eq "true");
  $def = 0 if $var eq "false";
  while (<STDIN>) {
    if (/^\s*\Q$pre\Eifdef\s+(\w+)\s*$/) {
      return 1 if ifdef ($1, $def & $enabled);
    } elsif (/^\s*\Q$pre\Eelseif\s+(\w+)\s*$/) {
      $def = $def ^ 1;
      return ifdef ($1, $def & $enabled);
    } elsif (/^\s*\Q$pre\Eelse\s*$/) {
      $def = $def ^ 1;
    } elsif (/^\s*\Q$pre\Eendif\s*$/) {
      return 0;
    } elsif (/^\s*\Q$pre\E/) {
      die "unrecognized command: $_";
    } else {
      print if $def && $enabled;
    }
  }
  return 1;
}

ifdef("true", 1);
