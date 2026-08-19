#!/usr/bin/env bash
# teardown.sh — remove all lab containers. Leaves nothing running.
set -uo pipefail
for v in 14 16; do
  docker rm -f "sda_pg${v}" >/dev/null 2>&1 && echo "removed sda_pg${v}" || echo "sda_pg${v} not present"
done
for v in 10_6 10_11 11; do
  docker rm -f "sda_maria_${v}" >/dev/null 2>&1 && echo "removed sda_maria_${v}" || echo "sda_maria_${v} not present"
done
echo "teardown complete"
docker ps --filter 'name=sda_' --format '{{.Names}}' | grep -q sda_ && echo "WARNING: lab containers still present" || echo "no lab containers running"
