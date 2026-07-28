# Victim Agent — Setup Guide

Run this on any PC connected to the same Wi-Fi as the HP Monitoring PC.  
It detects attacks targeting this machine and reports them live to the HP dashboard.

---

## Step 1 — Find HP Monitoring PC's Local IP

On the HP PC, open Command Prompt and run:
```
ipconfig
```
Note the **IPv4 Address** (e.g. `192.168.1.50`).

---

## Step 2 — Edit agent.py

Open `agent.py` and update these 2 lines at the top:
```python
MONITOR_PC_IP = "192.168.1.50"   # <- Replace with HP's IP
VICTIM_NAME   = "PC-Lab-02"      # <- Give this PC a label (shown on dashboard)
```

---

## Step 3 — Run the Agent

```bash
python agent.py
```

You should see:
```
==============================================================
  IDS Victim Agent  -  Multi-Device Network Monitor
==============================================================
  Victim PC IP    : 192.168.1.55
  Victim Name     : PC-Lab-02
  Reporting To    : 192.168.1.50:9999  (HP Monitoring PC)
  HTTP Honeypot   : 0.0.0.0:8888
  UDP Monitor     : 0.0.0.0:9998
==============================================================
```

---

## What It Detects

| Attack Type | Detection Method | Dashboard Severity |
|---|---|---|
| SQL Injection (HTTP) | Pattern matching on request payload | HIGH |
| HTTP Brute Force | Connection rate threshold (5+ req/2s) | HIGH |
| UDP Flood / DDoS | Packet rate threshold (100+ pkt/s) | HIGH |
| UDP Probe / Scan | Low-rate UDP from same source | MEDIUM |

---

## How to Attack This PC (for demo)

From the **Attacker PC**, run the attack simulator targeting this victim's IP:

```bash
# Full 7-scenario attack simulation
python simulate_attacks.py 192.168.1.55

# Manual SQL Injection via browser or curl
curl "http://192.168.1.55:8888/login?email=admin' OR 1=1--"
```

All alerts will appear **live** on the HP Monitoring PC dashboard at `http://192.168.1.50:5000`.

---

## No Extra Dependencies Required

The agent uses only Python standard library modules:
`socket`, `json`, `threading`, `re`, `http.server`, `urllib`

Works on **Windows** and **Linux**.
