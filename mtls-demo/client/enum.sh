#!/usr/bin/env bash
set -euo pipefail

proxy_socket=${PKCS11_PROXY_SOCKET:-tls://pkcs11-server:4511}
proxy_lib=${PKCS11_PROXY_LIB:-/opt/pkcs11-proxy/lib/libpkcs11-proxy.so}
client_cert=${PKCS11_PROXY_TLS_CERT_FILE:-/etc/mtls/clientA.crt}
client_key=${PKCS11_PROXY_TLS_KEY_FILE:-/etc/mtls/clientA.key}
ca_cert=${PKCS11_PROXY_TLS_CA_FILE:-/etc/mtls/ca.crt}

export PKCS11_PROXY_SOCKET="$proxy_socket"
export PKCS11_PROXY_TLS_MODE=cert
export PKCS11_PROXY_TLS_CERT_FILE="$client_cert"
export PKCS11_PROXY_TLS_KEY_FILE="$client_key"
export PKCS11_PROXY_TLS_CA_FILE="$ca_cert"
export PKCS11_PROXY_TLS_VERIFY_PEER=true

pkcs11-tool --module "$proxy_lib" -L
