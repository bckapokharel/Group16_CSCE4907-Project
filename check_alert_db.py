#!/usr/bin/env python3
"""
check_alert_db.py - Aegis IDS/IPS, Module 1 (TC-21, FR-16)
Checks that stored alerts have all five required fields:
time, source IP, destination IP, attack type, sensor name.

Works with a SQLite database file. [UPDATE] Ask Brayden for the real
database file, table name and column names, then pass them with --db,
--table and --map. If the backend uses another database (MySQL, Postgres,
MongoDB), tell the team and this script can be changed.

  python3 check_alert_db.py --db backend/aegis.db --table alerts \\
      --map time=timestamp,src=src_ip,dst=dest_ip,type=attack_type,sensor=sensor_name --last 5

  python3 check_alert_db.py --demo      # builds a sample database so you can see the output
Exit 0 = newest alert(s) have every field filled in.
"""
import argparse, sqlite3, sys, os, tempfile

FIELDS = ["time", "src", "dst", "type", "sensor"]
LABELS = {"time": "time", "src": "source IP", "dst": "destination IP", "type": "attack type", "sensor": "sensor name"}


def demo_db():
    path = os.path.join(tempfile.gettempdir(), "aegis_demo.db")
    if os.path.exists(path):
        os.remove(path)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, timestamp TEXT, src_ip TEXT, dest_ip TEXT, attack_type TEXT, sensor_name TEXT)")
    c.execute("INSERT INTO alerts (timestamp,src_ip,dest_ip,attack_type,sensor_name) VALUES ('2026-11-07T21:00:03','192.168.56.10','192.168.56.11','port_scan','monitor-eth1')")
    c.commit(); c.close()
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="backend/aegis.db", help="[UPDATE] path to the SQLite database")
    ap.add_argument("--table", default="alerts", help="[UPDATE] alert table name")
    ap.add_argument("--map", default="time=timestamp,src=src_ip,dst=dest_ip,type=attack_type,sensor=sensor_name",
                    help="[UPDATE] field=column pairs")
    ap.add_argument("--last", type=int, default=5, help="how many newest rows to check")
    ap.add_argument("--demo", action="store_true")
    a = ap.parse_args()

    if a.demo:
        a.db, a.table = demo_db(), "alerts"
        print(f"(demo database: {a.db})")
    cols = dict(p.split("=") for p in a.map.split(","))
    missing_map = [f for f in FIELDS if f not in cols]
    if missing_map:
        sys.exit(f"--map is missing: {missing_map}")
    if not os.path.exists(a.db):
        sys.exit(f"Database not found: {a.db}  (ask Brayden for the path)")

    con = sqlite3.connect(a.db); con.row_factory = sqlite3.Row
    sel = ", ".join(f'"{cols[f]}" AS {f}' for f in FIELDS)
    try:
        rows = con.execute(f'SELECT {sel} FROM "{a.table}" ORDER BY rowid DESC LIMIT ?', (a.last,)).fetchall()
    except sqlite3.Error as e:
        sys.exit(f"Database error: {e}\nCheck --table and --map names.")

    print(f"=== Newest {a.last} alerts in {a.table} ===")
    if not rows:
        print("No alerts stored.\nRESULT: FAIL"); sys.exit(1)
    ok = True
    for r in rows:
        empty = [LABELS[f] for f in FIELDS if r[f] in (None, "")]
        print("  " + " | ".join(str(r[f]) for f in FIELDS) + ("   <-- missing: " + ", ".join(empty) if empty else ""))
        ok &= not empty
    print("RESULT:", "PASS - all five fields stored" if ok else "FAIL - some fields are empty")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
