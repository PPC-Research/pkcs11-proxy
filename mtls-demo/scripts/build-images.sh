#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

nix build "$root_dir"#mtls-server-image --out-link "$root_dir/.nix-server-image" --builders ''
nix build "$root_dir"#mtls-client-image --out-link "$root_dir/.nix-client-image" --builders ''

server_tar=$(ls "$root_dir/.nix-server-image"/tarball/*.tar.xz)
client_tar=$(ls "$root_dir/.nix-client-image"/tarball/*.tar.xz)

docker import "$server_tar" pkcs11-proxy-server:dev
docker import "$client_tar" pkcs11-proxy-client:dev

printf "Loaded images:\n"
docker images | awk 'NR==1 || /pkcs11-proxy-(server|client)/'
