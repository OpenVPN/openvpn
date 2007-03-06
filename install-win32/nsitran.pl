($mode) = @ARGV;

while (<STDIN>) {
  chomp;
  if (/^\s*$/) {
    print "\n";
  } elsif (/^[#;](.*)$/) {
    print "//$1\n" if ($mode eq "c");
    print "#$1\n" if ($mode eq "sh");
    print "//$1\n" if ($mode eq "js");
  } elsif (/^!define\s+(\w+)\s+(.+)$/) {
    print "#define $1 $2\n" if ($mode eq "c");
    print "export $1=$2\n" if ($mode eq "sh");
    print "var $1=$2;\n" if ($mode eq "js");
  }
}
