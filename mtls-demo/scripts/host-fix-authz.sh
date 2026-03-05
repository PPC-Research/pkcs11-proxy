#!/usr/bin/env bash
set -euo pipefail

container=${1:-pkcs11-proxy-server}

root="$(cd "$(dirname "$0")/.." && pwd)"
"$root/scripts/gen-authz.sh"

docker exec -it "$container" /run/current-system/sw/bin/bash -lc '
/run/current-system/sw/bin/systemctl restart pkcs11-daemon
/run/current-system/sw/bin/journalctl -u pkcs11-daemon -n 5 --no-pager -l
'
