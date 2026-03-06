{ pkgs, pkcs11Proxy, nixpkgs, ... }:
{
  imports = [ "${nixpkgs}/nixos/modules/virtualisation/docker-image.nix" ];

  boot.isContainer = true;
  networking.hostName = "pkcs11-client";
  networking.useHostResolvConf = true;
  system.stateVersion = "24.05";

  environment.systemPackages =
    let
      pkcs11ProxyEnum = pkgs.writeShellScriptBin "pkcs11-proxy-enum" ''
        exec /etc/pkcs11-proxy/enum.sh "$@"
      '';
      pkcs11ProxySign = pkgs.writeShellScriptBin "pkcs11-proxy-sign" ''
        exec /etc/pkcs11-proxy/sign.sh "$@"
      '';
    in
    [
    pkcs11Proxy
    pkgs.bash
    pkgs.coreutils
    pkgs.openssl
    pkgs.opensc
    pkgs.tcpdump
    pkgs.wireshark-cli
    pkgs.xxd
    pkgs.iproute2
    pkcs11ProxyEnum
    pkcs11ProxySign
  ];


  # /etc/mtls is bind-mounted by docker-compose.

  environment.etc."pkcs11-proxy/enum.sh".source = ../client/enum.sh;
  environment.etc."pkcs11-proxy/sign.sh".source = ../client/sign.sh;
  environment.etc."profile.d/pkcs11-proxy.sh".text = ''
    export PKCS11_PROXY_SOCKET=tls://pkcs11-server:4511
    export PKCS11_PROXY_LIB=/opt/pkcs11-proxy/lib/libpkcs11-proxy.so
    export OPENSSL_MODULES=/run/current-system/sw/lib/ossl-modules
  '';

  systemd.tmpfiles.rules =
    let
      pkcs11Provider = pkgs.pkcs11-provider.overrideAttrs (_: { doCheck = false; });
    in
    [
    "d /opt/pkcs11-proxy/lib 0755 root root -"
    "L+ /opt/pkcs11-proxy/lib/libpkcs11-proxy.so - - - - ${pkcs11Proxy}/lib/libpkcs11-proxy.so"
    "d /opt/pkcs11-proxy/ossl-modules 0755 root root -"
    "L+ /opt/pkcs11-proxy/ossl-modules/pkcs11.so - - - - ${pkcs11Provider}/lib/ossl-modules/pkcs11.so"
  ];

  systemd.services.demo-idle = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
  };

}
