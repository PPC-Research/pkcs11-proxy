#!/usr/bin/env bash
set -euo pipefail

container=${1:-pkcs11-proxy-server}
host_dir=${2:-}
iface=${3:-any}
port=${4:-4511}
ts=$(date +%Y%m%d-%H%M%S)
cap_name="pkcs11-proxy-${ts}.pcap"

if [ -z "$host_dir" ]; then
  host_dir="$(pwd)"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

mkdir -p "$host_dir"

echo "Capturing on $container ($iface, port $port). Press Ctrl+C to stop..."
set +e
docker exec -it "$container" /run/current-system/sw/bin/tcpdump \
  -i "$iface" -nn -s0 -w "/tmp/${cap_name}" "port ${port}"
status=$?
set -e

if docker exec -it "$container" /run/current-system/sw/bin/which tshark >/dev/null 2>&1; then
  echo "Capture summary (tshark):"
  docker exec -it "$container" /run/current-system/sw/bin/tshark -r "/tmp/${cap_name}" -q -z conv,tcp || true
  docker exec -it "$container" /run/current-system/sw/bin/tshark -r "/tmp/${cap_name}" -Y "tls.handshake" \
    -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.type -e tls.handshake.ciphersuite \
    2>/dev/null | head -n 50 || true
fi

echo "Copying capture to host: ${host_dir}/${cap_name}"
docker cp "${container}:/tmp/${cap_name}" "${host_dir}/${cap_name}"
docker exec -it "$container" /run/current-system/sw/bin/rm -f "/tmp/${cap_name}"

exit $status
