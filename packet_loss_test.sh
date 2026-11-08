#!/usr/bin/env bash
#
# packet_loss_test.sh - Aegis IDS/IPS, Module 1 (Bishika Pokharel)
#
# Measures packet loss at 10, 25, 50 and 100 Mbps (NFR-1, TC-12) using
# iperf3 between the Attacker VM (client) and the Victim VM (server).
#
# On the Victim VM first:   iperf3 -s
# Then on the Attacker VM:  ./packet_loss_test.sh <victim_ip> [duration_sec=15]
#
# Writes results to packet_loss_results.csv next to this script, and prints
# a summary table. Fill the same numbers into the Reflection Report and
# Requirements Document (NFR-1 status) once you've run this for real.

set -euo pipefail

TARGET="${1:-}"
DURATION="${2:-15}"
OUT_CSV="$(dirname "$0")/packet_loss_results.csv"
SPEEDS_MBPS=(10 25 50 100)

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <victim_ip> [duration_sec=15]"
  exit 1
fi

if ! command -v iperf3 >/dev/null; then
  echo "iperf3 not found. Install it first: sudo apt install iperf3"
  exit 1
fi

echo "target_mbps,sent_packets,lost_packets,loss_percent,run_timestamp" > "$OUT_CSV"

for mbps in "${SPEEDS_MBPS[@]}"; do
  echo "=== Testing at ${mbps} Mbps for ${DURATION}s ==="
  # -u: UDP so iperf3 reports real packet loss; -b: target bandwidth; -J: JSON output
  result=$(iperf3 -c "$TARGET" -u -b "${mbps}M" -t "$DURATION" -J)

  sent=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['end']['sum']['packets'])")
  lost=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['end']['sum']['lost_packets'])")
  loss_pct=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(round(d['end']['sum']['lost_percent'], 3))")

  echo "${mbps} Mbps -> sent=$sent lost=$lost loss=${loss_pct}%"
  echo "${mbps},${sent},${lost},${loss_pct},$(date -Iseconds)" >> "$OUT_CSV"
done

echo
echo "=== Summary (target: below 1% loss at every step, NFR-1) ==="
column -s, -t "$OUT_CSV"
echo
echo "Saved to $OUT_CSV. Copy the evidence (this output + the CSV) into"
echo "/tests/evidence/TC-12 in the repo."
