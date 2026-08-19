#!/usr/bin/env bash
# 00_up.sh — disposable SQL Server (Linux) container for the audit lab.
# Usage: ./00_up.sh [VER]   (default 2022; e.g. 2019)
# Local/throwaway/synthetic only.
set -euo pipefail
VER="${1:-2022}"
IMAGE="mcr.microsoft.com/mssql/server:${VER}-latest"
CID="sda_mssql_${VER}"
PORT="14330"
SA_PW='Labonly_Str0ng!pw'

docker rm -f "$CID" >/dev/null 2>&1 || true
docker run -d --name "$CID" \
  -e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=${SA_PW}" -e "MSSQL_PID=Developer" \
  -p ${PORT}:1433 \
  "$IMAGE" >/dev/null

# locate sqlcmd (2022 uses mssql-tools18 and needs -C; 2019 uses mssql-tools)
echo "Waiting for ${IMAGE} to accept connections..."
BIN=""; CFLAG=""
for i in $(seq 1 90); do
  BIN="$(docker exec "$CID" bash -lc 'ls /opt/mssql-tools18/bin/sqlcmd 2>/dev/null || ls /opt/mssql-tools/bin/sqlcmd 2>/dev/null' 2>/dev/null || true)"
  if [ -n "$BIN" ]; then
    echo "$BIN" | grep -q tools18 && CFLAG="-C" || CFLAG=""
    if docker exec "$CID" "$BIN" -S localhost -U sa -P "$SA_PW" $CFLAG -Q "SELECT 1" >/dev/null 2>&1; then break; fi
  fi
  sleep 2
done
DIGEST="$(docker inspect --format '{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || echo 'digest-unavailable')"
echo "${IMAGE} up as ${CID} on localhost:${PORT} (sqlcmd=${BIN} ${CFLAG})"
echo "Image digest: ${DIGEST}"
echo "${VER} ${CID} ${DIGEST}" >> "$(dirname "$0")/../../results/_image_digests.txt"
