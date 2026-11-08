#!/usr/bin/env bash
#
# normal_traffic.sh - Aegis IDS/IPS, Module 1 (TC-20, FR-6, NFR-8)
# Generates ONLY normal traffic (ping, HTTP page loads, optional SSH login)
# so you can count false alarms. LAB ONLY (NFR-3).
#
# Usage:   ./normal_traffic.sh <victim_ip> [rounds=5] --confirm-lab
# Optional real login (needs sshpass): NORMAL_SSH_USER=testuser NORMAL_SSH_PASS=... ./normal_traffic.sh ...

set -euo pipefail
TARGET="${1:-}"; ROUNDS="${2:-5}"; CONFIRM="${3:-}"
if [ "$ROUNDS" = "--confirm-lab" ]; then CONFIRM="$ROUNDS"; ROUNDS=5; fi
[ -z "$TARGET" ] && { echo "Usage: $0 <victim_ip> [rounds=5] --confirm-lab"; exit 1; }
[ "$CONFIRM" != "--confirm-lab" ] && { echo "Refusing: pass --confirm-lab."; exit 1; }
if ! [[ "$TARGET" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
  echo "ERROR: $TARGET is not a private/lab address. This script will not target it."; exit 1
fi

echo "=== Normal traffic: target=$TARGET rounds=$ROUNDS ==="
echo "Start (epoch): $(date +%s.%N)"
for i in $(seq 1 "$ROUNDS"); do
  echo "[round $i] ping"
  ping -c 3 "$TARGET" >/dev/null 2>&1 || echo "  (ping got no reply)"
  if command -v curl >/dev/null; then
    echo "[round $i] HTTP page load"
    curl -s -o /dev/null -m 5 "http://$TARGET/" || echo "  (HTTP failed)"
  fi
  if [ -n "${NORMAL_SSH_USER:-}" ] && [ -n "${NORMAL_SSH_PASS:-}" ] && command -v sshpass >/dev/null; then
    echo "[round $i] one normal SSH login"
    sshpass -p "$NORMAL_SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "$NORMAL_SSH_USER@$TARGET" exit 2>/dev/null || echo "  (ssh failed)"
  fi
  sleep 3
done
echo "End (epoch): $(date +%s.%N)"
echo "Now count alerts: python3 testing/check_false_alarms.py --src <attacker_ip> --since-epoch <start>"
