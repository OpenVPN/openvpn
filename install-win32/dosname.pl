($unixname) = @ARGV;
$unixname =~ s#^/c##g;
$unixname =~ s#/#\\#g;
print "$unixname\n";
