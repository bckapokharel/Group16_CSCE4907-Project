#!/usr/bin/env bash
#
# check_sensor_state.sh - Aegis IDS/IPS, Module 1 (TC-09, FR-9)
# Run on the MONITOR VM right after turning a sensor ON or OFF in the backend.
# While it waits, send some traffic (e.g. ping the Victim from the Attacker).
#   on  -> Suricata running AND eve.json grows
#   off -> Suricata not running OR eve.json does not grow
#
# Usage: ./check_sensor_state.sh on|off [eve_path=/var/log/suricata/eve.json] [seconds=8]

EXPECT="${1:-}"; EVE="${2:-/var/log/suricata/eve.json}"; SECS="${3:-8}"
[ "$EXPECT" != "on" ] && [ "$EXPECT" != "off" ] && { echo "Usage: $0 on|off [eve_path] [seconds=8]"; exit 1; }

echo "=== TC-09 expect sensor $EXPECT on $(hostname) @ $(date) ==="
# match the process NAME only (Suricata shows as "Suricata-Main"), not any command line containing the word
if pgrep -i -x "suricata.*" >/dev/null; then RUN=yes; else RUN=no; fi
S1=$(stat -c %s "$EVE" 2>/dev/null || echo 0)
echo "Suricata running: $RUN   eve.json size: $S1  -> send traffic now, waiting ${SECS}s"
sleep "$SECS"
S2=$(stat -c %s "$EVE" 2>/dev/null || echo 0)
[ "$S2" -gt "$S1" ] && GROW=yes || GROW=no
echo "eve.json size after: $S2   growing: $GROW"

if [ "$EXPECT" = "on" ] && [ "$RUN" = yes ] && [ "$GROW" = yes ]; then echo "RESULT: PASS - capture is ON"; exit 0; fi
if [ "$EXPECT" = "off" ] && { [ "$RUN" = no ] || [ "$GROW" = no ]; }; then echo "RESULT: PASS - capture is OFF"; exit 0; fi
echo "RESULT: FAIL - state does not match '$EXPECT'"; exit 1
