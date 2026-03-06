{
  description = "pkcs11-proxy mTLS demo (NixOS containers)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      pkcs11Proxy = pkgs.stdenv.mkDerivation {
        pname = "pkcs11-proxy";
        version = "dev";
        src = pkgs.lib.cleanSourceWith {
          # Use builtins.path to include untracked files from the working tree.
          src = builtins.path {
            path = ../.;
            name = "pkcs11-proxy-src";
          };
          filter = path: type:
            let
              root = toString ../.;
              p = toString path;
            in
              !(pkgs.lib.hasPrefix (root + "/build") p) &&
              !(pkgs.lib.hasPrefix (root + "/mtls-demo/volumes") p);
        };

        nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config pkgs.bash ];
        buildInputs = [ pkgs.openssl pkgs.libseccomp ];

        prePatch = ''
          patchShebangs mksyscalls.sh
        '';

        cmakeFlags = [
          "-DCMAKE_BUILD_TYPE=Release"
        ];

        installPhase = ''
          mkdir -p $out/bin $out/lib
          cp pkcs11-daemon $out/bin/
          cp libpkcs11-proxy.so $out/lib/
        '';
      };

      server = nixpkgs.lib.nixosSystem {
        inherit system pkgs;
        specialArgs = { inherit pkcs11Proxy nixpkgs; };
        modules = [ ./nixos/server.nix ];
      };

      client = nixpkgs.lib.nixosSystem {
        inherit system pkgs;
        specialArgs = { inherit pkcs11Proxy nixpkgs; };
        modules = [ ./nixos/client.nix ];
      };
    in
    {
      packages.${system} = {
        pkcs11-proxy = pkcs11Proxy;
        mtls-server-image = server.config.system.build.tarball;
        mtls-client-image = client.config.system.build.tarball;
      };
    };
}
