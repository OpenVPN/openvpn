#!/usr/bin/perl

while ($unixname = shift(@ARGV)) {
  $unixname =~ s#^/([a-zA-Z])(/|$)#$1:\\#g;
  $unixname =~ s#/#\\#g;
  print "$unixname\n";
}
