Rebuild OpenSSL tarball without symbolic links, so
it can be extracted on Windows (run on Unix):

  [download tarball and .asc sig]
  gpg --verify openssl-0.9.8h.tar.gz.asc
  tar xfz openssl-0.9.8h.tar.gz
  rm openssl-0.9.8h.tar.gz
  tar cfzh openssl-0.9.8h.tar.gz openssl-0.9.8h

To apply patch (in MSYS shell):

  cd /c/src/openssl-0.9.8h
  patch -p1 <../21/install-win32/openssl/openssl098.patch

To build OpenSSL, open a command prompt window, then:

  cd \src\openssl-0.9.8h
  ms\mw

To build a new patch (optional):

  diff -urw openssl-0.9.8h.orig openssl-0.9.8h | grep -v '^Only in' >openssl098.patch
