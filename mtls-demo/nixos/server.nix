{ pkgs, pkcs11Proxy, nixpkgs, ... }:
{
  imports = [ "${nixpkgs}/nixos/modules/virtualisation/docker-image.nix" ];

  boot.isContainer = true;
  networking.hostName = "pkcs11-server";
  networking.useHostResolvConf = true;
  system.stateVersion = "24.05";

  environment.systemPackages = [
    pkcs11Proxy
    pkgs.bash
    pkgs.coreutils
    pkgs.openssl
    pkgs.opensc
    pkgs.softhsm
    pkgs.tcpdump
    pkgs.wireshark-cli
    pkgs.xxd
    pkgs.iproute2
  ];

  # /etc/mtls and /etc/pkcs11-proxy/authz.json are bind-mounted by docker-compose.
  environment.etc."pkcs11-proxy/init-softhsm.sh".source = ../server/init-softhsm.sh;
  environment.etc."softhsm2.conf".text = ''
    directories.tokendir = /var/lib/softhsm/tokens
    objectstore.backend = file
    slots.removable = true
  '';

  systemd.tmpfiles.rules = [
    "d /var/lib/softhsm/tokens 0700 root root -"
    "d /var/log/pkcs11-proxy 0755 root root -"
    "d /opt/pkcs11-proxy/lib 0755 root root -"
    "L+ /opt/pkcs11-proxy/lib/libpkcs11-proxy.so - - - - ${pkcs11Proxy}/lib/libpkcs11-proxy.so"
  ];

  systemd.services.pkcs11-daemon = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "simple";
      ExecStartPre = "/etc/pkcs11-proxy/init-softhsm.sh";
      ExecStart = "${pkcs11Proxy}/bin/pkcs11-daemon ${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
      Restart = "always";
      RestartSec = "2";
    };
    environment = {
      SOFTHSM2_CONF = "/etc/softhsm2.conf";
      SOFTHSM2_MODULE = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
      PKCS11_DAEMON_SOCKET = "tls://0.0.0.0:4511";
      PKCS11_PROXY_TLS_MODE = "cert";
      PKCS11_PROXY_TLS_CERT_FILE = "/etc/mtls/server.crt";
      PKCS11_PROXY_TLS_KEY_FILE = "/etc/mtls/server.key";
      PKCS11_PROXY_TLS_CA_FILE = "/etc/mtls/ca.crt";
      PKCS11_PROXY_TLS_VERIFY_PEER = "true";
      PKCS11_PROXY_AUTHZ_MODE = "enforce";
      PKCS11_PROXY_AUTHZ_FILE = "/etc/pkcs11-proxy/authz.json";
      PKCS11_PROXY_AUTHZ_DEFAULT = "deny";
      PKCS11_PROXY_AUTHZ_LOG_LEVEL = "info";
    };
  };

}
