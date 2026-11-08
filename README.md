# Module 1 — Traffic Capture and Virtual Test Network (Sprint 2)

**Aegis IDS/IPS** · Sponsor: WECR · Team: Group 16 · Course: CSCE 4907.001
**Owner:** Bishika Pokharel

## Sprint 2 accomplishments

- Built a live feed that sends Suricata's `eve.json` events to the detection
  engine while capture is running, so a PCAP no longer has to be saved and
  opened by hand first (FR-10).
- Added SYN-flood traffic (`hping3`) and SSH brute-force traffic to the
  Attacker VM, so the detection engine's new signature rules have real
  traffic to detect (FR-11, FR-14).
- Ran the packet-loss tests at 10, 25, 50 and 100 Mbps (NFR-1, TC-12).
  Results: **[UPDATE — loss % at each speed, see `testing/packet_loss_results.csv`]**.
- Updated the setup guide and lab scripts in GitHub.

## Folder layout

```
module1_sprint2_bishika/
├── README.md                  <- this file
├── docs/
│   └── SETUP_GUIDE.md          <- step-by-step for everything below
├── live_feed/
│   └── eve_feed.py             <- tails eve.json, forwards to detection engine
├── attacker_scripts/
│   ├── syn_flood.sh             <- SYN-flood traffic (hping3), lab-only
│   ├── ssh_bruteforce.sh        <- SSH brute-force traffic, lab-only
│   └── wordlist_sample.txt      <- sample guesses for the disposable test account
└── testing/
    ├── packet_loss_test.sh       <- runs the 10/25/50/100 Mbps iperf3 tests
    └── packet_loss_results.csv   <- fill in with your real measured numbers
```

## Safety note

`syn_flood.sh` and `ssh_bruteforce.sh` only run against private lab
addresses and require an explicit `--confirm-lab` flag, and `syn_flood.sh`
auto-stops after a fixed duration. Use them only inside the isolated
host-only lab, against the team's own Victim VM, per NFR-3.

## How this maps to the requirements

| Requirement | What covers it |
|---|---|
| FR-10 (stream events live) | `live_feed/eve_feed.py` |
| FR-11 (SYN flood + SSH brute force traffic) | `attacker_scripts/` |
| FR-13 (repo lets a teammate rebuild the lab) | `docs/SETUP_GUIDE.md` |
| NFR-1 (packet loss under load) | `testing/packet_loss_test.sh` + results CSV |

## Still to do

- Plug `DETECTION_HOST` / `DETECTION_PORT` (or `--url` for HTTP mode) in
  `eve_feed.py` into whatever Sugam/Brayden's engine actually listens on.
- Run `packet_loss_test.sh` for real and replace the `UPDATE` placeholders
  in `testing/packet_loss_results.csv`.
- Save evidence (screenshots/logs) from each script run under
  `/tests/evidence/TC-12`, `/tests/evidence/TC-17`, `/tests/evidence/TC-18`.
