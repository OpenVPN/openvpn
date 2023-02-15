with import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/e58a7747db96c23b8a977e7c1bbfc5753b81b6fa.tar.gz") {};

let llvmPackages = llvmPackages_14;
in llvmPackages.stdenv.mkDerivation {
  name = "openvpn-fuzz";
  buildInputs = [
    autoconf
    automake
    m4
    libtool
    pkg-config
    openssl_1_1
    lz4
    lzo
    pam
    llvmPackages.llvm
    python3Packages.pwntools
  ] ++ lib.optional (!stdenv.isDarwin) libcap_ng;
}
