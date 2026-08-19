#!/usr/bin/env bash
# 00_up.sh — bring up a disposable, version-pinned PostgreSQL for the lab.
# Usage: ./00_up.sh [PGVER]   (default 16; run again with 14)
# Everything is localhost-only and throwaway. Synthetic data only.
set -euo pipefail

PGVER="${1:-16}"                 # major version: 14 or 16
IMAGE="postgres:${PGVER}-alpine" # alpine variant (functionally identical engine)
CID="sda_pg${PGVER}"
PORT="55432"                     # host port -> container 5432 (single container at a time)

docker rm -f "$CID" >/dev/null 2>&1 || true
docker run -d --name "$CID" \
  -e POSTGRES_PASSWORD=labonly_superpw \
  -p ${PORT}:5432 \
  "$IMAGE" >/dev/null

# wait until the server accepts connections
echo "Waiting for postgres:${PGVER} to accept connections..."
for i in $(seq 1 60); do
  if docker exec "$CID" pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

# record the exact image digest for reproducibility
DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || echo 'digest-unavailable')"

echo "Postgres ${PGVER} up as container ${CID} on localhost:${PORT}"
echo "Image digest: ${DIGEST}"
echo "${PGVER} ${CID} ${DIGEST}" >> "$(dirname "$0")/../results/_image_digests.txt"
