#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cert="${1:-$root/certs/clientA.crt}"
out="${2:-$root/authz.json}"
template="${3:-$root/authz.example.json}"

if [ ! -f "$cert" ]; then
  echo "Missing cert: $cert" >&2
  exit 1
fi
if [ ! -f "$template" ]; then
  echo "Missing template: $template" >&2
  exit 1
fi

fp=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')
if [ -z "$fp" ]; then
  echo "Failed to read fingerprint from $cert" >&2
  exit 1
fi

sed "s/PUT_CLIENT_CERT_SHA256_FINGERPRINT_HERE/$fp/" "$template" > "$out"
echo "Wrote $out (fingerprint $fp)"
