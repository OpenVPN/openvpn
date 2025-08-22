{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-22.11";
    devenv.url = "github:cachix/devenv";
  };

  outputs = { self, nixpkgs, devenv, ... } @ inputs:
    let
      systems = [ "x86_64-linux" "i686-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = f: builtins.listToAttrs (map (name: { inherit name; value = f name; }) systems);
    in
    {
      devShells = forAllSystems
        (system:
          let
            pkgs = import nixpkgs {
              inherit system;
            };
          in
          {
            default = devenv.lib.mkShell {
              inherit inputs pkgs;
              modules = [
                {
                  # https://devenv.sh/reference/options/
                  packages = [ 
                    pkgs.autoconf 
                    pkgs.automake 
                    pkgs.libtool 
                    pkgs.openssl_1_1 
                    pkgs.lz4 
                    pkgs.lzo 
                    pkgs.pam 
                    pkgs.cmocka 
                  ];

                  languages.c.enable = true;

                  enterShell = ''
                    # Allows autreconf to find libtool.
                    export ACLOCAL_PATH=${pkgs.libtool}/share/aclocal:$ACLOCAL_PATH
                  '';
                }
              ];
            };
          });
    };
}
