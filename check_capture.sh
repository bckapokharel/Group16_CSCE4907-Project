#!/usr/bin/env bash
#
# check_capture.sh - Aegis IDS/IPS, Module 1 (TC-03, FR-3)
# Run on the MONITOR VM. While it listens, ping the Victim from the Attacker.
# PASS = packets between Attacker and Victim (not addressed to the Monitor) are seen.
#
# Usage: sudo ./check_capture.sh <iface> <attacker_ip> <victim_ip> [seconds=10]

IFACE="${1:-}"; A="${2:-}"; V="${3:-}"; SECS="${4:-10}"
[ -z "$IFACE" ] || [ -z "$A" ] || [ -z "$V" ] && { echo "Usage: sudo $0 <iface> <attacker_ip> <victim_ip> [seconds=10]"; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump not found: sudo apt install tcpdump"; exit 1; }

echo "=== TC-03 on $(hostname) @ $(date) ==="
echo "--- promiscuous mode on $IFACE (should say PROMISC) ---"
ip -d link show "$IFACE" | grep -o -i "promisc[a-z]*" | head -1 || echo "PROMISC flag not shown (tcpdump enables it while running)"
echo ">>> Now ping $V from the Attacker VM. Listening ${SECS}s..."
OUT=$(timeout "$SECS" tcpdump -l -nn -i "$IFACE" "host $A and host $V" 2>/dev/null)
N=$(echo -n "$OUT" | grep -c .)
echo "$OUT" | head -10
echo "Packets seen between $A and $V: $N"
if [ "$N" -gt 0 ]; then echo "RESULT: PASS - Monitor sees Attacker<->Victim traffic"; exit 0
else echo "RESULT: FAIL - no packets seen (check promiscuous mode and adapter 'Allow All')"; exit 1; fi
