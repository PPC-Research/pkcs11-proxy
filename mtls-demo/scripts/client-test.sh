#!/usr/bin/env bash
set -euo pipefail

client=${1:-pkcs11-proxy-client}
server=${2:-pkcs11-proxy-server}

server_ip=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
if [ -z "$server_ip" ]; then
  echo "Failed to resolve server IP for $server" >&2
  exit 1
fi

docker exec -it "$client" /run/current-system/sw/bin/bash -lc "echo '$server_ip pkcs11-server' >> /etc/hosts"

docker exec -it "$client" /run/current-system/sw/bin/bash -lc '
export PKCS11_PROXY_SOCKET=tls://pkcs11-server:4511
pkcs11-proxy-enum
'

docker exec -it "$client" /run/current-system/sw/bin/bash -lc '
export PKCS11_PROXY_SOCKET=tls://pkcs11-server:4511
pkcs11-proxy-sign "hello world"
'
