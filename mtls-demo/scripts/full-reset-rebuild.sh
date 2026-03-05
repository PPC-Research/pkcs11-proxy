#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

cd "$project_dir"

echo "Stopping compose stack (remove orphans)..."
docker compose down --remove-orphans || true

echo "Stopping all running containers..."
if [ -n "$(docker ps -q)" ]; then
  docker stop $(docker ps -q)
fi

echo "Removing all containers..."
if [ -n "$(docker ps -aq)" ]; then
  docker rm -f $(docker ps -aq)
fi

echo "Removing demo images..."
docker rmi -f pkcs11-proxy-server:dev pkcs11-proxy-client:dev || true

echo "Pruning dangling images..."
docker image prune -f || true

echo "Building and loading images..."
"$project_dir/scripts/build-images.sh"

echo "Starting compose stack..."
docker compose up -d --force-recreate

echo "Done."
