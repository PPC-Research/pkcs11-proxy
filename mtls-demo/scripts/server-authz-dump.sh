#!/usr/bin/env bash
set -euo pipefail

server=${1:-pkcs11-proxy-server}
path=${2:-/etc/pkcs11-proxy/authz.json}

docker exec -it "$server" /run/current-system/sw/bin/bash -lc "ls -l $path; wc -c $path; /run/current-system/sw/bin/xxd -g1 -l 256 $path; echo '---'; /run/current-system/sw/bin/od -An -t x1 -N 64 $path"
