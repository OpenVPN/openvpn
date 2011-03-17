#!/usr/bin/perl

# Simple macro processor.

# Macros are defined in a control file that follows
# a simple definition-based grammar as documented in the
# trans script.  Stdin is then copied to stdout, and any
# occurrence of @@MACRO@@ is substituted.  Macros can also
# be specified on the command line.

die "usage: macro [-O<openquote>] [-C<closequote>] [-Dname=var ...] [control-file ...] " if (@ARGV < 1);

%Parms = ();
$open_quote = "@@";
$close_quote = "@@";

while ($arg=shift(@ARGV)) {
  if ($arg =~ /^-/) {
    if ($arg =~ /^-D(\w+)(?:=(.*))?$/) {
      $Parms{$1} = $2
    } elsif ($arg =~ /-O(.*)$/) {
      $open_quote = $1;
    } elsif ($arg =~ /-C(.*)$/) {
      $close_quote = $1;
    } else {
      die "unrecognized option: $arg";
    }
  } else {
    open(CONTROL, "< $arg") or die "cannot open $arg";
    while (<CONTROL>) {
      if (/^!define\s+(\w+)(?:\s+['"]?(.*?)['"]?)?\s*$/) {
	$Parms{$1} = $2;
      }
    }
  }
}

sub print_symbol_table {
  foreach my $k (sort (keys(%Parms))) {
    my $v = $Parms{$k};
    print "[$k] -> \"$v\"\n";
  }
}

#print_symbol_table ();
#exit 0;

while (<STDIN>) {
  s{
    \Q$open_quote\E
    \s*
    (
    \w+
   )
    \s*
    \Q$close_quote\E
  }{
    $Parms{$1}
  }xge;
  print;
}
