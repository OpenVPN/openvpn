#!/usr/bin/perl

# convert a unix filename to a DOS filename

while ($unixname = shift(@ARGV)) {
  $unixname =~ s#^/([a-zA-Z])(/|$)#$1:\\#g;
  $unixname =~ s#/#\\#g;
  print "$unixname\n";
}
