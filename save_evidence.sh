#!/usr/bin/env bash
#
# save_evidence.sh - Aegis IDS/IPS (all tests)
# Runs any command and saves the full output, with date/host/command, to
# tests/evidence/<TC-id>/<timestamp>.txt in the repo.
#
# Usage:   ./save_evidence.sh TC-16 python3 testing/check_eve_events.py --src 192.168.56.10
# Example: ./save_evidence.sh TC-12 ./testing/packet_loss_test.sh 192.168.56.11

TC="${1:-}"; shift || true
[ -z "$TC" ] || [ $# -eq 0 ] && { echo "Usage: $0 TC-nn <command...>"; exit 1; }
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DIR="$ROOT/tests/evidence/$TC"; mkdir -p "$DIR"
OUT="$DIR/$(date +%Y%m%d_%H%M%S).txt"
{
  echo "# $TC   host=$(hostname)   date=$(date -Iseconds 2>/dev/null || date)"
  echo "# command: $*"
  echo
} > "$OUT"
"$@" 2>&1 | tee -a "$OUT"
CODE=${PIPESTATUS[0]}
echo >> "$OUT"; echo "# exit code: $CODE" >> "$OUT"
echo "Saved evidence -> $OUT (exit code $CODE)"
exit "$CODE"
