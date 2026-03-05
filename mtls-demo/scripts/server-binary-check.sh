#!/usr/bin/env bash
set -euo pipefail

server=${1:-pkcs11-proxy-server}

# Check if the running daemon binary contains the new authz debug strings

docker exec -it "$server" /run/current-system/sw/bin/bash -lc '
if command -v strings >/dev/null 2>&1; then
  strings /run/current-system/sw/bin/pkcs11-daemon | grep -q "policy raw" && echo "authz-debug-strings: present" || echo "authz-debug-strings: missing"
else
  echo "strings not available in container"
fi
'
