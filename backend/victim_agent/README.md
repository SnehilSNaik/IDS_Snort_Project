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
| Protected-file access (Windows) | Security Event ID 4663 for an explicitly audited folder | MEDIUM |

---

## Protected Dummy-File Access Demo (Windows)

This optional feature uses a local protected-asset policy. It monitors only
folders selected by an administrator; it does **not** monitor all files.

1. Edit `protected_paths.json` and enable/add the folders you want to protect.
   Each entry has a display name, asset class, and alert severity. For a lab,
   you might use `C:\IDS_Lab_Demo` with the asset class `Lab data`.
2. Create a harmless test file in each selected folder.
3. Open **PowerShell as Administrator** and enable auditing once per folder:

```powershell
cd C:\IDS_Agent
.\setup_file_audit.ps1 -Path C:\IDS_Lab_Demo
```

4. Start the agent; it automatically loads `protected_paths.json`:

```powershell
python agent.py --server <IDS_SERVER_IP> --name Lab-PC-01
```

When Windows records a successful read of a file under a policy folder, the
agent sends a `FILE_ACCESS` endpoint alert with the asset label and class. The dashboard maps it to MITRE ATT&CK
`T1005 — Data from Local System`.

For a one-off test without editing the policy, `--watch-path C:\IDS_Lab_Demo`
adds that folder for the current run only.

This alert proves protected-file access, not that data was exfiltrated. A
separate outbound-flow signal is required to claim possible exfiltration.

---

## How to Attack This PC (for demo)

From the **Attacker PC**, run the attack simulator targeting this victim's IP:

```bash
# Run a safe lab scenario from the IDS project
python simulate_attack.py --scenario 1

# Manual SQL Injection via browser or curl
curl "http://192.168.1.55:8888/login?email=admin' OR 1=1--"
```

All alerts will appear **live** on the HP Monitoring PC dashboard at `http://192.168.1.50:5000`.

---

## No Extra Dependencies Required

The agent uses only Python standard library modules:
`socket`, `json`, `threading`, `re`, `http.server`, `urllib`

Works on **Windows** and **Linux**.
