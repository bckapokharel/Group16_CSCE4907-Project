# Aegis IDS/IPS — Module 1 Setup Guide (Sprint 2 update)

**Owner:** Bishika Pokharel · Traffic capture and virtual test network
**Sponsor:** WECR · Course: CSCE 4907.001 · Team: Group 16

This updates the Sprint 1 setup guide with the Sprint 2 additions: the live
feed to detection, SYN-flood and SSH brute-force traffic, and the
packet-loss test. Follow this after you've already built the three-VM lab
from Sprint 1 (Attacker / Victim / Monitor, host-only network).

## 1. What's new in Sprint 2

| Addition | Where it runs | File |
|---|---|---|
| Live feed to detection engine | Monitor VM | `live_feed/eve_feed.py` |
| SYN-flood traffic | Attacker VM | `attacker_scripts/syn_flood.sh` |
| SSH brute-force traffic | Attacker VM | `attacker_scripts/ssh_bruteforce.sh` |
| Packet-loss test | Attacker VM (client) + Victim VM (server) | `testing/packet_loss_test.sh` |

## 2. Live feed (FR-10)

On the **Monitor VM**, with Suricata already running and writing
`/var/log/suricata/eve.json`:

```bash
python3 live_feed/eve_feed.py --eve /var/log/suricata/eve.json --mode tcp \
    --host <detection_engine_ip> --port <detection_engine_port>
```

Ask Sugam/Brayden for the real host/port and put them in as the
`DETECTION_HOST` / `DETECTION_PORT` defaults at the top of `eve_feed.py` so
the rest of the team can run it with no flags. Use `--mode stdout` first to
confirm you're seeing events before wiring it to the real engine.

## 3. Generating attack traffic (FR-11)

Both scripts refuse to run unless the target is a private lab IP
(`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`) **and** you pass
`--confirm-lab`. Only ever point them at your own Victim VM.

```bash
# SYN flood, 20 seconds, against the Victim VM's web port
./attacker_scripts/syn_flood.sh 192.168.56.11 80 20 --confirm-lab

# SSH brute force against a disposable test account on the Victim VM
# (create the account first: sudo useradd -m testuser && sudo passwd testuser)
./attacker_scripts/ssh_bruteforce.sh 192.168.56.11 testuser \
    attacker_scripts/wordlist_sample.txt --confirm-lab
```

Save a screenshot or log of each run under `/tests/evidence/TC-17` and
`/tests/evidence/TC-18`.

## 4. Packet-loss testing (NFR-1, TC-12)

On the **Victim VM**:

```bash
sudo apt install iperf3
iperf3 -s
```

On the **Attacker VM**:

```bash
./testing/packet_loss_test.sh 192.168.56.11
```

This runs 10, 25, 50 and 100 Mbps automatically and writes
`testing/packet_loss_results.csv`. Copy the real numbers into the
Reflection Report and the Requirements Document (NFR-1 status) — don't
report NFR-1 as met until this has actually been run.

## 5. Rebuilding the whole lab (FR-13, NFR-6)

1. Follow the Sprint 1 guide to build the three VMs and host-only network.
2. Restore each VM to its baseline snapshot.
3. Copy this `module1_sprint2_bishika/` folder onto the Attacker and Monitor
   VMs (or clone the repo).
4. Follow sections 2–4 above.

If a teammate who didn't build the lab can do steps 1–4 using only this
guide, that's TC-10.
