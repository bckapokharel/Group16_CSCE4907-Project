#!/usr/bin/env python3
"""
test_add_sensor.py - Aegis IDS/IPS, Module 1 (TC-08, FR-8)
Checks the backend's add-sensor rule: a valid sensor is accepted; a sensor with
a missing or invalid IP is rejected with a message.

[UPDATE] Ask Brayden for the real URL and field names, then run:
  python3 test_add_sensor.py --url http://127.0.0.1:5000/api/sensors \\
      --fields name,interface,ip
  python3 test_add_sensor.py --self-test      # runs against a built-in demo server

Passing = valid gets HTTP 2xx; both invalid cases get HTTP 4xx with a message.
If the backend has no HTTP API, do TC-08 by hand in the admin view and
screenshot both cases.
"""
import argparse, json, sys, threading, urllib.request, urllib.error, ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer


def post(url, body):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=5); return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return None, str(e)


class Demo(BaseHTTPRequestHandler):  # stand-in for the real backend, --self-test only
    def do_POST(self):
        d = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        try:
            ipaddress.ip_address(d.get("ip", "")); code, msg = 201, {"ok": True}
        except ValueError:
            code, msg = 400, {"error": "IP address is missing or invalid"}
        self.send_response(code); self.end_headers(); self.wfile.write(json.dumps(msg).encode())
    def log_message(self, *a): pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5000/api/sensors", help="[UPDATE] add-sensor endpoint")
    ap.add_argument("--fields", default="name,interface,ip", help="[UPDATE] name,interface,ip field names")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        srv = HTTPServer(("127.0.0.1", 0), Demo); a.url = f"http://127.0.0.1:{srv.server_port}/"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print("(self-test: built-in demo server)")
    n, i, ip = a.fields.split(",")
    cases = [
        ("valid sensor", {n: "sensor-test", i: "eth1", ip: "192.168.56.20"}, True),
        ("missing IP", {n: "sensor-noip", i: "eth1"}, False),
        ("invalid IP 999.1.1.1", {n: "sensor-badip", i: "eth1", ip: "999.1.1.1"}, False),
    ]
    ok = True
    print(f"=== TC-08 against {a.url} ===")
    for label, body, should_pass in cases:
        code, text = post(a.url, body)
        good = code is not None and ((200 <= code < 300) if should_pass else (400 <= code < 500 and text.strip() != ""))
        print(f"[{'OK' if good else 'BAD'}] {label:<22} HTTP {code}  {text[:80]}")
        ok &= good
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
