#!/usr/bin/env bash
set -euo pipefail

container=${1:-pkcs11-proxy-server}
lines=${2:-200}
mode=${3:-all}

if [ "$mode" = "deny" ]; then
  docker exec -it "$container" /run/current-system/sw/bin/journalctl \
    -u pkcs11-daemon -f -n "$lines" --no-pager -l | \
    awk '/AUTHZ DENY/'
else
  docker exec -it "$container" /run/current-system/sw/bin/journalctl \
    -u pkcs11-daemon -f -n "$lines" --no-pager -l
fi
