#!/usr/bin/env bash
# 00_up.sh — disposable MariaDB (MySQL-family) container for the audit lab.
# Usage: ./00_up.sh [VER]   (default 10.11; e.g. 11)
# Local/throwaway/synthetic only. Binary log enabled so the engine-log defense is testable.
set -euo pipefail
VER="${1:-10.11}"
IMAGE="mariadb:${VER}"
CID="sda_maria_${VER//./_}"
PORT="55433"

docker rm -f "$CID" >/dev/null 2>&1 || true
docker run -d --name "$CID" \
  -e MARIADB_ROOT_PASSWORD=labonly_rootpw \
  -p ${PORT}:3306 \
  "$IMAGE" --log-bin --server-id=1 --log-bin-trust-function-creators=1 >/dev/null
# (trust_function_creators=1 isolates the TRIGGER-privilege variable under test; setting it
#  to 0 with binlog on is itself an incidental barrier — recorded as a defense in FINDINGS.)

echo "Waiting for ${IMAGE} to accept connections..."
for i in $(seq 1 60); do
  if docker exec -e MYSQL_PWD=labonly_rootpw "$CID" mysqladmin ping -uroot --silent >/dev/null 2>&1; then break; fi
  sleep 1
done
# ping can succeed before the grant tables finish initialising on first boot; wait until a
# real authenticated query works AND the mysql.user grant table is queryable, then settle.
for i in $(seq 1 30); do
  if docker exec -e MYSQL_PWD=labonly_rootpw "$CID" mysql -uroot -N -B \
       -e "SELECT 1 FROM mysql.user LIMIT 1" >/dev/null 2>&1; then break; fi
  sleep 1
done
sleep 2
DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || echo 'digest-unavailable')"
echo "${IMAGE} up as ${CID} on localhost:${PORT}"
echo "Image digest: ${DIGEST}"
echo "${VER} ${CID} ${DIGEST}" >> "$(dirname "$0")/../../results/_image_digests.txt"
