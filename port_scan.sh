#!/usr/bin/env bash
#
# port_scan.sh - Aegis IDS/IPS, Module 1 (TC-16, FR-6, FR-14)
# Runs an nmap SYN scan from the Attacker VM against the Victim VM so the
# port-scan signature rule has traffic to detect. LAB ONLY (NFR-3).
#
# Usage:   ./port_scan.sh <victim_ip> --confirm-lab
# Needs:   nmap (sudo apt install nmap), run with sudo for -sS
# Prints the start time (epoch) so you can pass it to alert_time.py --attack-start

set -euo pipefail
TARGET="${1:-}"; CONFIRM="${2:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <victim_ip> --confirm-lab"; exit 1; }
[ "$CONFIRM" != "--confirm-lab" ] && { echo "Refusing: pass --confirm-lab as 2nd argument."; exit 1; }
if ! [[ "$TARGET" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
  echo "ERROR: $TARGET is not a private/lab address. This script will not target it."; exit 1
fi
command -v nmap >/dev/null || { echo "nmap not found: sudo apt install nmap"; exit 1; }

echo "=== Port scan: target=$TARGET ==="
echo "Attack start (epoch): $(date +%s.%N)"
sudo nmap -sS -p 1-1024 "$TARGET"
echo "Attack end   (epoch): $(date +%s.%N)"
echo "Now check for a port-scan alert (TC-16): python3 testing/check_eve_events.py --src <attacker_ip> --expect-signature scan"
