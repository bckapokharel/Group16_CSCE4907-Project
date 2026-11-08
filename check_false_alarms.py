#!/usr/bin/env python3
"""
check_false_alarms.py - Aegis IDS/IPS, Module 1 (TC-20, NFR-8)
Counts alerts raised while ONLY normal traffic was running. Expected: 0.

Run on the Monitor VM after attacker_scripts/normal_traffic.sh:
  python3 check_false_alarms.py --src 192.168.56.10 --since-epoch 1762569000.5 --label run1
Append the count to a CSV so you can report false alarms per run:
  ... --csv ../../tests/results/false_alarms.csv
Exit 0 = no alerts (PASS), 1 = alerts found (false alarms).
"""
import argparse, csv, json, os, sys
from collections import Counter
from datetime import datetime


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--src", help="only count alerts from this source IP")
    ap.add_argument("--since-epoch", type=float, default=0, help="start of the normal-traffic run")
    ap.add_argument("--label", default="run", help="name of this run, e.g. run1")
    ap.add_argument("--csv", help="append a row to this CSV")
    a = ap.parse_args()

    sigs = Counter()
    with open(a.eve) as f:
        for line in f:
            try:
                e = json.loads(line); t = ts(e["timestamp"])
            except (ValueError, KeyError):
                continue
            if e.get("event_type") != "alert" or t < a.since_epoch:
                continue
            if a.src and e.get("src_ip") != a.src:
                continue
            sigs[e.get("alert", {}).get("signature", "?")] += 1

    total = sum(sigs.values())
    print(f"=== False-alarm check ({a.label}) ===")
    for k, v in sigs.most_common():
        print(f"  {v:>4} x {k}")
    print(f"False alarms: {total}")
    if a.csv:
        new = not os.path.exists(a.csv)
        os.makedirs(os.path.dirname(os.path.abspath(a.csv)), exist_ok=True)
        with open(a.csv, "a", newline="") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(["label", "checked_at", "false_alarms", "signatures"])
            w.writerow([a.label, datetime.now().isoformat(timespec="seconds"), total, "; ".join(sigs)])
        print(f"Row added to {a.csv}")
    print("RESULT:", "PASS - no false alarms" if total == 0 else "FAIL - normal traffic raised alerts")
    sys.exit(0 if total == 0 else 1)


if __name__ == "__main__":
    main()
