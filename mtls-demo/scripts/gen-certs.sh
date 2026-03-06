#!/usr/bin/env bash
set -euo pipefail

out_dir="$(cd "${1:-mtls-demo/certs}" && pwd)"
mkdir -p "$out_dir"

ca_key="$out_dir/ca.key"
ca_crt="$out_dir/ca.crt"
server_key="$out_dir/server.key"
server_csr="$out_dir/server.csr"
server_crt="$out_dir/server.crt"
clientA_key="$out_dir/clientA.key"
clientA_csr="$out_dir/clientA.csr"
clientA_crt="$out_dir/clientA.crt"
clientB_key="$out_dir/clientB.key"
clientB_csr="$out_dir/clientB.csr"
clientB_crt="$out_dir/clientB.crt"

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -subj "/CN=pkcs11-proxy-demo-ca" \
  -keyout "$ca_key" -out "$ca_crt"

cat > "$out_dir/server.ext" <<'EXT'
subjectAltName = DNS:pkcs11-server,DNS:localhost,IP:127.0.0.1
extendedKeyUsage = serverAuth
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
EXT

openssl req -new -newkey rsa:4096 -nodes \
  -subj "/CN=pkcs11-proxy-server" \
  -keyout "$server_key" -out "$server_csr"

openssl x509 -req -in "$server_csr" -CA "$ca_crt" -CAkey "$ca_key" \
  -CAcreateserial -days 3650 -sha256 -extfile "$out_dir/server.ext" \
  -out "$server_crt"

cat > "$out_dir/client.ext" <<'EXT'
extendedKeyUsage = clientAuth
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = URI:spiffe://pkcs11-proxy/demo/client
EXT

openssl req -new -newkey rsa:4096 -nodes \
  -subj "/CN=clientA" \
  -keyout "$clientA_key" -out "$clientA_csr"

openssl x509 -req -in "$clientA_csr" -CA "$ca_crt" -CAkey "$ca_key" \
  -CAcreateserial -days 3650 -sha256 -extfile "$out_dir/client.ext" \
  -out "$clientA_crt"

openssl req -new -newkey rsa:4096 -nodes \
  -subj "/CN=clientB" \
  -keyout "$clientB_key" -out "$clientB_csr"

openssl x509 -req -in "$clientB_csr" -CA "$ca_crt" -CAkey "$ca_key" \
  -CAcreateserial -days 3650 -sha256 -extfile "$out_dir/client.ext" \
  -out "$clientB_crt"

rm -f "$server_csr" "$clientA_csr" "$clientB_csr" "$out_dir"/*.srl "$out_dir"/*.ext

echo "Generated certs in $out_dir"
