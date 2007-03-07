# Simple macro processor.

# Macros are defined in a control file that follows
# NSIS format such as version.nsi.  Stdin is then
# copied to stdout, and any occurrence of @@MACRO@@ is
# substituted.

die "usage: macro.pl <control-file>" if (@ARGV < 1);
($control_file) = @ARGV;

open(CONTROL, "< $control_file") or die "cannot open $control_file";

%Parms = ();

while (<CONTROL>) {
  chomp;
  if (/^!define\s+(\w+)\s+['"]?(.+?)['"]?\s*$/) {
    $Parms{$1} = $2
  }
}

while (<STDIN>) {
  s{
    @@
    \s*
    (
      \w+
    )
    \s*
    @@
  }{
    $Parms{$1}
   }xge;
  print;
}
