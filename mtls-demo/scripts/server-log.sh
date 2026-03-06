#!/usr/bin/env bash
set -euo pipefail

server=${1:-pkcs11-proxy-server}

# Show last authz-related lines

docker exec -it "$server" /run/current-system/sw/bin/journalctl -u pkcs11-daemon -n 200 --no-pager -l
