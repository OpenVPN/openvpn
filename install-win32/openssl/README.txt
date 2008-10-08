Rebuild OpenSSL tarball without symbolic links, so
it can be extracted on Windows (run on Unix):

  [download tarball and .asc sig]
  gpg --verify openssl-0.9.8i.tar.gz.asc
  tar xfz openssl-0.9.8i.tar.gz
  tar cfzh openssl-0.9.8i-nolinks.tar.gz openssl-0.9.8i

To apply patch (in MSYS shell):

  cd /c/src/openssl-0.9.8i
  patch -p1 <../21/install-win32/openssl/openssl098.patch

To build OpenSSL, open a command prompt window, then:

  cd \src\openssl-0.9.8i
  ms\mw

To build a new patch (optional):

  diff -urw openssl-0.9.8i.orig openssl-0.9.8i | grep -v '^Only in' >openssl098.patch
