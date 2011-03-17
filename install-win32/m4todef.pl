#!/usr/bin/perl

# used to convert version.m4 to simple
# definition format

while (<STDIN>) {
  chomp;
  if (/^\s*$/) {
    print "\n";
  } elsif (/^define\((\w+),\[(.*?)\]\)/) {
    print "!define $1 \"$2\"\n";
  } elsif (/^dnl(.*)$/) {
    print "#$1\n";
  }
}
