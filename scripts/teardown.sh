#!/usr/bin/env bash
# teardown.sh — remove all lab containers. Leaves nothing running.
set -uo pipefail
for v in 14 16; do
  docker rm -f "sda_pg${v}" >/dev/null 2>&1 && echo "removed sda_pg${v}" || echo "sda_pg${v} not present"
done
echo "teardown complete"
docker ps --filter 'name=sda_pg' --format '{{.Names}}' | grep -q sda_pg && echo "WARNING: lab containers still present" || echo "no lab containers running"
