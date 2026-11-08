#!/usr/bin/env bash
#
# connection_burst.sh - Aegis IDS/IPS, Module 1 (TC-19, FR-15)
# Opens many short TCP connections from one source in a short time, to test
# the anomaly (connection-rate) rule. LAB ONLY (NFR-3). Capped at 2000.
#
# Usage:   ./connection_burst.sh <victim_ip> [port=80] [count=300] --confirm-lab

set -euo pipefail
TARGET="${1:-}"; PORT="${2:-80}"; COUNT="${3:-300}"; CONFIRM="${4:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <victim_ip> [port=80] [count=300] --confirm-lab"; exit 1; }
[ "$CONFIRM" != "--confirm-lab" ] && { echo "Refusing: pass --confirm-lab as 4th argument."; exit 1; }
if ! [[ "$TARGET" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
  echo "ERROR: $TARGET is not a private/lab address. This script will not target it."; exit 1
fi
[ "$COUNT" -gt 2000 ] && { echo "count capped at 2000"; COUNT=2000; }

echo "=== Connection burst: $COUNT connections to $TARGET:$PORT ==="
echo "Start (epoch): $(date +%s.%N)"
ok=0
for i in $(seq 1 "$COUNT"); do
  if (exec 3<>"/dev/tcp/$TARGET/$PORT") 2>/dev/null; then ok=$((ok+1)); fi
done
echo "End   (epoch): $(date +%s.%N)   connections opened: $ok/$COUNT"
echo "Now check for an anomaly alert (TC-19)."
