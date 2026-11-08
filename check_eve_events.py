#!/usr/bin/env python3
"""
check_eve_events.py - Aegis IDS/IPS, Module 1
For TC-14, TC-16, TC-17, TC-18 (and TC-19): shows what Suricata wrote to
eve.json for the Attacker IP and checks the events you expect.

Run on the Monitor VM after an attack:
  python3 check_eve_events.py --src 192.168.56.10                    # just summarise
  python3 check_eve_events.py --src 192.168.56.10 --expect-signature scan     # TC-16
  python3 check_eve_events.py --src 192.168.56.10 --expect-signature syn      # TC-17
  python3 check_eve_events.py --src 192.168.56.10 --expect-signature ssh      # TC-18
  python3 check_eve_events.py --src 192.168.56.10 --expect-types flow,alert   # TC-14

--expect-signature is a case-insensitive substring of the alert signature.
Use --since-epoch to ignore older events. Exit 0 = everything expected was found.
Match the substring to the real rule names Sugam wrote (see the rules file).
"""
import argparse, json, sys
from collections import Counter
from datetime import datetime


def ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", default="/var/log/suricata/eve.json")
    ap.add_argument("--src", required=True, help="Attacker IP")
    ap.add_argument("--since-epoch", type=float, default=0)
    ap.add_argument("--expect-types", default="", help="comma list, e.g. flow,alert")
    ap.add_argument("--expect-signature", action="append", default=[], help="substring; repeatable")
    a = ap.parse_args()

    types, sigs = Counter(), Counter()
    with open(a.eve) as f:
        for line in f:
            try:
                e = json.loads(line); t = ts(e["timestamp"])
            except (ValueError, KeyError):
                continue
            if e.get("src_ip") != a.src or t < a.since_epoch:
                continue
            types[e.get("event_type", "?")] += 1
            if e.get("event_type") == "alert":
                sigs[e.get("alert", {}).get("signature", "?")] += 1

    print(f"=== eve.json events from {a.src} ({a.eve}) ===")
    if not types:
        print("No events found for this source IP.")
    for k, v in types.most_common():
        print(f"  event_type {k:<10} {v}")
    for k, v in sigs.most_common():
        print(f"  alert      {v:>5} x {k}")

    ok = True
    for t in [x.strip() for x in a.expect_types.split(",") if x.strip()]:
        hit = types.get(t, 0) > 0
        print(f"[{'OK' if hit else 'MISSING'}] event type '{t}'"); ok &= hit
    for s in a.expect_signature:
        hit = any(s.lower() in k.lower() for k in sigs)
        print(f"[{'OK' if hit else 'MISSING'}] alert containing '{s}'"); ok &= hit
    if not types:
        ok = False
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
