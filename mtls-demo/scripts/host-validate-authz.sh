#!/usr/bin/env bash
set -euo pipefail

server=${1:-pkcs11-proxy-server}
path=${2:-/var/lib/pkcs11-proxy/authz.json}

tmp=$(mktemp)
docker cp "$server:$path" "$tmp"

python3 - <<'PY' "$tmp"
import json, sys
p = sys.argv[1]
with open(p, 'rb') as f:
    data = f.read()
print(f"bytes={len(data)}")
try:
    j = json.loads(data.decode('utf-8'))
    print("json_ok")
except Exception as e:
    print("json_error", e)
PY

rm -f "$tmp"
