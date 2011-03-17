Rebuild OpenSSL tarball without symbolic links, so
it can be extracted on Windows (run on Unix):

  [download tarball and .asc sig]
  gpg --verify openssl-0.9.8k.tar.gz.asc
  tar xfz openssl-0.9.8k.tar.gz
  tar cfzh openssl-0.9.8k-nolinks.tar.gz openssl-0.9.8k

To apply patch (in MSYS shell):

  cd /c/src/openssl-0.9.8k
  patch -p1 <../21/install-win32/openssl/openssl098.patch

To build OpenSSL, open a command prompt window, then:

  cd \src\openssl-0.9.8k
  ms\mw

To build a new patch (optional):

  diff -urw openssl-0.9.8k.orig openssl-0.9.8k | grep -v '^Only in' >openssl098.patch
