#!/usr/bin/env python3
"""
eve_feed.py - Aegis IDS/IPS, Module 1 (Bishika Pokharel)

Tails Suricata's eve.json on the Monitor VM and forwards each event to the
detection engine AS IT IS WRITTEN, so the engine no longer has to wait for a
PCAP file to be saved and opened by hand. This implements FR-10 (stream
events live) and is what feeds Sugam's detection rules (FR-14, FR-15) and
the 5-second alert target (NFR-2).

Usage examples:

    # Just print events to the screen (good for a demo / sanity check)
    python3 eve_feed.py --eve /var/log/suricata/eve.json --mode stdout

    # Forward events to the detection engine over TCP (one JSON line per event)
    python3 eve_feed.py --eve /var/log/suricata/eve.json --mode tcp \
        --host 192.168.56.20 --port 5140

    # Forward events to the detection engine as HTTP POSTs
    python3 eve_feed.py --eve /var/log/suricata/eve.json --mode http \
        --url http://192.168.56.20:8080/ingest

Sugam / Brayden: point --host/--port or --url at whatever the detection
engine is actually listening on, and update DETECTION_* below as a default
so the rest of the team can run this with no flags.
"""

import argparse
import json
import socket
import sys
import time

# ---- Defaults the team can fill in so `python3 eve_feed.py` just works ----
DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"
DETECTION_HOST = "192.168.56.20"   # [UPDATE] Monitor-visible IP of the detection engine
DETECTION_PORT = 5140              # [UPDATE] port the detection engine listens on
DETECTION_URL = "http://192.168.56.20:8080/ingest"  # [UPDATE] HTTP ingest endpoint
RECONNECT_DELAY_SEC = 2
POLL_INTERVAL_SEC = 0.25


def tail_lines(path):
    """Yield new lines appended to `path`, like `tail -f`. Starts at end of file."""
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to end so we only forward NEW events
        while True:
            line = f.readline()
            if not line:
                time.sleep(POLL_INTERVAL_SEC)
                continue
            yield line


def send_tcp(host, port, line):
    while True:
        try:
            with socket.create_connection((host, port), timeout=3) as s:
                while True:
                    s.sendall(line.encode("utf-8"))
                    return
        except OSError as e:
            print(f"[eve_feed] TCP send failed ({e}); retrying in {RECONNECT_DELAY_SEC}s",
                  file=sys.stderr)
            time.sleep(RECONNECT_DELAY_SEC)


def send_http(url, event):
    import urllib.request
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"[eve_feed] HTTP post failed: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description="Tail Suricata eve.json and forward events live.")
    ap.add_argument("--eve", default=DEFAULT_EVE_PATH, help="path to eve.json on the Monitor VM")
    ap.add_argument("--mode", choices=["stdout", "tcp", "http"], default="stdout")
    ap.add_argument("--host", default=DETECTION_HOST, help="detection engine host (tcp mode)")
    ap.add_argument("--port", type=int, default=DETECTION_PORT, help="detection engine port (tcp mode)")
    ap.add_argument("--url", default=DETECTION_URL, help="detection engine ingest URL (http mode)")
    ap.add_argument("--event-types", default="", help="comma list to filter, e.g. alert,flow (default: all)")
    args = ap.parse_args()

    wanted_types = {t.strip() for t in args.event_types.split(",") if t.strip()}

    print(f"[eve_feed] tailing {args.eve} -> mode={args.mode}", file=sys.stderr)
    sent, skipped_bad_json = 0, 0

    for raw_line in tail_lines(args.eve):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            skipped_bad_json += 1
            continue

        if wanted_types and event.get("event_type") not in wanted_types:
            continue

        if args.mode == "stdout":
            print(raw_line)
        elif args.mode == "tcp":
            send_tcp(args.host, args.port, raw_line + "\n")
        elif args.mode == "http":
            send_http(args.url, event)

        sent += 1
        if sent % 100 == 0:
            print(f"[eve_feed] forwarded {sent} events ({skipped_bad_json} bad lines skipped)",
                  file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[eve_feed] stopped", file=sys.stderr)
