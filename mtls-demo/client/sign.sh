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

export OPENSSL_MODULES=${OPENSSL_MODULES:-"/opt/pkcs11-proxy/ossl-modules"}
export PKCS11_PROVIDER_MODULE="$proxy_lib"

msg="${1:-Hello from pkcs11-proxy mTLS demo}"
work_dir="${2:-/tmp}"

printf "%s" "$msg" > "$work_dir/message.bin"

openssl pkeyutl -sign -provider pkcs11 -provider default \
  -inkey "pkcs11:token=ProxyTestToken;object=ProxyTestExistingECKey;type=private" \
  -in "$work_dir/message.bin" -out "$work_dir/signature.bin"

echo "Signature written to $work_dir/signature.bin"
