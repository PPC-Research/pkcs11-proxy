{
  description = "Dev shell for pkcs11-proxy + PyKCS11 testing";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in
    {
      devShells = forAllSystems (
        pkgs:
        let
          pythonEnv = pkgs.python312.withPackages (ps: [
            ps.asn1crypto
            ps.cached-property
            ps.cffi
            ps.cryptography
            ps.iniconfig
            ps.packaging
            ps.pluggy
            ps.pykcs11
            ps.pycparser
            ps.python-pkcs11
            ps.pytest
          ]);
        in
        {
          default = pkgs.mkShell {
            name = "pkcs11-proxy-dev";

            nativeBuildInputs = [
              pkgs.cmake
              pkgs.pkg-config
            ];

            buildInputs = [
              pkgs.openssl
              pkgs.libseccomp
            ];

            packages = [
              pythonEnv
              pkgs.softhsm
              pkgs.opensc
            ];

            shellHook = ''
              echo "pkcs11-proxy dev shell with PyKCS11"
              echo "Python with PyKCS11: $(python --version)"
              echo "Try: python -c 'import PyKCS11; print(PyKCS11.__version__)'"
              echo
              echo "Building instructions:"
              echo "  cmake . -B build -DCMAKE_BUILD_TYPE=Release"
              echo "  cd build"
              echo "  make -j$(nproc)"
              echo
            '';
          };
        }
      );
    };
}
