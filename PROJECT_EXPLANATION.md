# IDS_Snort_Project — Complete Explanation
## Hybrid Intrusion Detection System (Academic Project)
### Python + Scapy + Scikit-learn + **Real Snort 2.9.x C Binary** + Flask

---

## 1. Overall Architecture

```
Other Machine (Attacker)
        │
        │  sends packets (ping, nmap, ssh, hping3, etc.)
        ▼
[Your Machine — IDS Running]
        │
        ├── packet_capture/capture.py
        │       └── records ALL packets to captured_packets.csv (like CCTV)
        │
        ├── snort/snort_reader.py  ← REAL Snort C Binary
        │       │
        │       ├── Launches C:\Snort\bin\snort.exe as subprocess
        │       │   (with snort/ids_project.conf + snort/local.rules)
        │       │
        │       ├── Snort writes fast-alerts → C:\Snort\log\alert
        │       │
        │       └── snort_reader tails alert file, parses each alert,
        │               writes → alerts/alerts.json (type: SNORT_SIGNATURE)
        │               sends  → Email alert
        │
        └── ml_model/detect.py  ← ML Anomaly Engine (Scapy + Decision Tree)
                │
                └── Sniffs live packets, extracts features,
                    runs ML model → if anomaly:
                        writes → alerts/alerts.json (type: ML_ANOMALY)
                        sends  → Email alert

                        alerts/alerts.json  (shared alert store)
                                │
                        dashboard/app.py  (Flask web server)
                                │
                        http://localhost:5000/dashboard
                        (auto-refreshes every 2 seconds)
```

> **Key difference from Python-only Snort engine:**
> The real C Snort binary performs deep packet inspection against `local.rules`.
> No Python reimplementation — this is the actual security tool used in production.

---

## 2. What Each File Does

| File | Role | Description |
|---|---|---|
| `ml_model/train_model.py` | Training | Teaches the ML model using 2000 synthetic packets modelled on CIC-IDS-2017 |
| `ml_model/detect.py` | ML Engine | Live anomaly detection only — Snort handles signature detection separately |
| `packet_capture/capture.py` | Logger | Writes every packet's details to CSV (timestamp, size, protocol, IPs) |
| `snort/snort_reader.py` | Snort Bridge | Launches real Snort binary, tails its alert log, parses alerts into JSON |
| `snort/local.rules` | Snort Rules | Custom Snort 2.9.x rules for ICMP flood, port scan, SSH brute force, etc. |
| `snort/ids_project.conf` | Snort Config | Minimal Snort config — sets HOME_NET, enables fast-alert output, includes local.rules |
| `dashboard/app.py` | Web Server | Flask app: login, live alerts, stats, "Engage IDS Engine" button |
| `email_alert/send_alert.py` | Alerting | Gmail SMTP alerts (throttled: max 1 per 60 seconds) |
| `start_ids.py` | Launcher | Menu-based script to start all components individually or all at once |
| `alerts/alerts.json` | Shared Store | JSON file written by both Snort reader and ML engine; read by dashboard |

---

## 3. Snort Alert Types vs ML Anomaly Types

Every alert in `alerts/alerts.json` has a `type` field:

| `type` field | Source | What it means |
|---|---|---|
| `SNORT_SIGNATURE` | `snort/snort_reader.py` | Real Snort C binary matched a rule |
| `ML_ANOMALY` | `ml_model/detect.py` | ML model detected anomalous traffic not matching any Snort rule |

Both write to the same `alerts.json` and appear on the dashboard in the same table.

---

## 4. How Severity Levels Are Decided

### Snort (Signature-Based) — from `local.rules` `priority:` keyword

| Attack Type | Rule Trigger | Snort Priority | Severity |
|---|---|---|---|
| ICMP Ping Flood | > 10 ICMP Echo Requests from same source in 1 second | 1 | 🔴 HIGH |
| Large TCP Packet | TCP payload > 5000 bytes | 2 | 🟡 MEDIUM |
| Large UDP Packet (Flood) | UDP payload > 5000 bytes | 1 | 🔴 HIGH |
| Port Scan | > 20 TCP SYN packets from same source in 5 seconds | 2 | 🟡 MEDIUM |
| SSH Brute Force | > 5 TCP SYN to port 22 from same source in 60 seconds | 1 | 🔴 HIGH |
| Single External ICMP Ping | 1 ICMP Echo Request per 5 seconds (limit) | 3 | 🟢 LOW |

**Priority → Severity mapping (in `snort_reader.py`):**
```
Priority 1 → HIGH
Priority 2 → MEDIUM
Priority 3 → LOW
```

### ML Engine (Anomaly-Based) — from `detect.py`

| Condition | Severity |
|---|---|
| ML predicts anomaly AND packet_rate < 50 pps | 🟢 LOW |
| ML predicts anomaly AND packet_rate 50–500 pps | 🟡 MEDIUM |
| ML predicts anomaly AND packet_rate > 500 pps | 🔴 HIGH |

---

## 5. Confidence Values

### Snort Confidence (fixed per severity)

Snort doesn't produce probabilistic scores. Fixed values are assigned:

| Severity | Confidence |
|---|---|
| HIGH | 95.0% |
| MEDIUM | 75.0% |
| LOW | 52.0% |

### ML Confidence

```
Confidence = model.predict_proba(features)[anomaly_class] × 100
```

The Decision Tree returns a probability score for each packet.  
Example: `packet_size=60, protocol=ICMP, rate=1500 pps → ~91.5%`

---

## 6. ML Model Details

### Training Modes

The ML model supports **two training modes**, auto-detected based on dataset availability:

#### Mode 1: REAL DATA — CIC-IDS-2017 Dataset (Recommended)

Download and train on the genuine CIC-IDS-2017 dataset from the University of New Brunswick / Canadian Institute for Cybersecurity.

```
python ml_model/download_dataset.py    # Download (~700 MB)
python ml_model/train_model.py         # Train on real data
```

**Dataset Details:**
| Day | Attack Types | Samples |
|---|---|---|
| Monday | Benign only (baseline) | ~529K |
| Tuesday | FTP-Patator, SSH-Patator (Brute Force) | ~445K |
| Wednesday | DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest, Heartbleed | ~692K |
| Thursday AM | Web Attack (Brute Force, XSS, SQL Injection) | ~170K |
| Thursday PM | Infiltration | ~288K |
| Friday AM | Botnet | ~191K |
| Friday PM 1 | Port Scan | ~286K |
| Friday PM 2 | DDoS (LOIT) | ~225K |

**Selected Features (15)** — chosen to bridge flow-level training with packet-level detection:

| Feature | Description | Live Extraction |
|---|---|---|
| `Destination Port` | Target port number | Direct from packet |
| `Flow Duration` | Duration in microseconds | Sliding window (10s) |
| `Total Fwd Packets` | Forward packet count | Count in window |
| `Total Length of Fwd Packets` | Sum of forward packet sizes | Sum in window |
| `Fwd Packet Length Max` | Max forward packet size | Max in window |
| `Fwd Packet Length Mean` | Mean forward packet size | Mean in window |
| `Fwd Packet Length Std` | Std dev of forward packet sizes | Std dev in window |
| `Flow Bytes/s` | Bytes per second | Total bytes / duration |
| `Flow Packets/s` | Packets per second | Count / duration |
| `Fwd IAT Mean` | Mean inter-arrival time | Mean of IATs in window |
| `Average Packet Size` | Mean packet size | Mean in window |
| `SYN Flag Count` | TCP SYN flags seen | Count in window |
| `PSH Flag Count` | TCP PSH flags seen | Count in window |
| `ACK Flag Count` | TCP ACK flags seen | Count in window |
| `Init_Win_bytes_forward` | Initial TCP window size | From first TCP packet |

**Algorithm:** Random Forest Classifier (100 trees, max_depth=15, balanced class weights)

#### Mode 2: SYNTHETIC DATA (Fallback)

If the CIC-IDS-2017 dataset is not downloaded, the model falls back to synthetic data:

| Traffic Type | Samples | Label |
|---|---|---|
| Normal web browsing (0.1–30 pps, mixed size) | 750 | Normal (0) |
| Normal video streaming (30–120 pps, large size) | 450 | Normal (0) |
| Normal TCP ACKs (1–30 pps, tiny 54–66 bytes) | 300 | Normal (0) |
| ICMP Ping Flood (5–5000 pps, 64–128 bytes) | 750 | Attack (1) |
| TCP SYN Flood / Port Scan (10–5000 pps, <60 bytes) | 750 | Attack (1) |

**Features (3):** `packet_size`, `protocol_enc`, `packet_rate`
**Algorithm:** Decision Tree Classifier (max_depth=5)

---

## 7. Why Hybrid? (Snort + ML Together)

| | Real Snort Only | ML Only | Hybrid (This Project) |
|---|---|---|---|
| Known attacks (ICMP flood) | ✅ Detects | ❌ May miss | ✅ Detects |
| Unknown / new attacks | ❌ Misses | ✅ Detects | ✅ Detects |
| False positives | Low | Higher | Lowest |
| Confidence scoring | Fixed | Probabilistic | Both |
| Coverage | Partial | Partial | Full |
| Engine | C binary (production-grade) | Python ML | Both together |

**Snort** runs as a separate process — it captures and analyses packets at C speed, then writes alerts. **ML** sniffs simultaneously and catches anomalies that have no Snort rule. **Together** they cover both known and unknown threats.

---

## 8. How Snort Reader Works (Technical)

```
snort_reader.py
│
├── detect_snort_interface()
│       Runs `snort -W` to list interfaces, picks Wi-Fi adapter index
│
├── launch_snort(iface_idx)
│       Copies local.rules → C:\Snort\rules\local.rules
│       Copies ids_project.conf → C:\Snort\etc\ids_project.conf
│       Runs: snort.exe -A fast -q -c ids_project.conf -i <idx> -l C:\Snort\log
│
└── tail_alert_file()
        Waits for C:\Snort\log\alert to appear
        Seeks to end (ignores old alerts)
        Reads new lines as Snort appends them
        Buffers multi-line alert blocks (blank line = block separator)
        parse_alert_block() → extracts timestamp, SID, message, priority, IPs
        save_alert() → appends to alerts/alerts.json
        send_email_alert() → dispatches email in background thread
```

**Snort Fast-Alert Format:**
```
04/13-10:22:01.123456  [**] [1:1000001:1] ICMP Ping Flood Detected [**]
[Classification: Attempted Denial of Service] [Priority: 1]
{ICMP} 192.168.1.5 -> 192.168.1.1
```

---

## 9. Dashboard Features

| Feature | Description |
|---|---|
| Login / Signup | User authentication — only registered users access the dashboard |
| Attack counter cards | Total, HIGH, MEDIUM, LOW counts with animated numbers |
| Avg Confidence | Rolling average confidence across all detected attacks |
| Protocol breakdown | How many alerts were TCP / UDP / ICMP / Other |
| Type breakdown | `SNORT_SIGNATURE` vs `ML_ANOMALY` alert counts |
| Live alert table | All alerts sorted newest-first with full details |
| Engage IDS Engine | Button to launch capture.py + detect.py + snort_reader.py |
| Clear All | Wipes the alert log (uses a `clear.flag` to prevent re-population) |
| Auto-refresh | Dashboard polls `/api/alerts` every 2 seconds — no manual refresh needed |

---

## 10. Email Alert System

- Uses **Gmail SMTP** (port 587, STARTTLS)
- Triggered by: any Snort signature alert OR any ML anomaly alert
- **Throttle**: max 1 email per 60 seconds globally (prevents spam during flood attacks)
- Email contains: timestamp, severity, type, src/dst IP, protocol, confidence, message
- Configured via environment variables:
  - `IDS_SENDER_EMAIL` — Gmail address to send from
  - `IDS_EMAIL_PASSWORD` — Gmail App Password (not your regular password)
  - `IDS_RECEIVER_EMAIL` — address to receive alerts

---

## 11. Live Demo Flow (for Viva / Presentation)

```
Prerequisite: Snort 2.9.x installed at C:\Snort\
              Run start_ids.py as Administrator

Step 1: python start_ids.py
        → Main menu appears

Step 2: Choose [4] Start Flask Dashboard
        → Opens http://localhost:5000

Step 3: Sign up / Log in
        → Redirected to Security Command Center dashboard

Step 4: Click "Engage IDS Engine"
        → Spawns capture.py + detect.py + snort_reader.py in separate windows
        → snort_reader.py launches the real Snort C binary

Step 5: From attacker machine, run:

  LOW    → ping <your_ip> -n 1
           (single ping → Snort rule 1000006 → LOW, 52% confidence)

  MEDIUM → nmap -sS <your_ip> -p 1-100
           (port scan → Snort rule 1000004 → MEDIUM, 75% confidence)

  HIGH   → ping <your_ip> -t -l 65500
           (ICMP flood + oversized → Snort rule 1000001 → HIGH, 95% confidence)

Step 6: Dashboard updates within 2 seconds
        → Alert appears with type=SNORT_SIGNATURE, severity, source IP

Step 7: Email arrives automatically at configured Gmail address

Step 8: Click "Clear All" to reset → alert log wiped, dashboard resets to zero
```

---

## 12. How to Install & Run

### Prerequisites

```
pip install -r requirements.txt
```

### Install Snort 2.9.20 (Windows)

1. Download: https://www.snort.org/downloads#snort-downloads → `Snort_2_9_20_Installer.exe`
2. Run installer as Administrator → installs to `C:\Snort\`
3. Npcap: already required (install from https://npcap.com if needed)

### Run

```
# Must be in an Administrator terminal
python start_ids.py

# Or run all at once:
python start_ids.py 7
```

---

## 13. Project Technologies

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.x | Core language |
| Scapy | ≥ 2.5.0 | Live packet capture for ML engine |
| Snort | 2.9.20 (C binary) | Signature-based IDS engine |
| Scikit-learn | ≥ 1.3.0 | Decision Tree classifier + StandardScaler |
| Pandas | ≥ 2.0.0 | Data manipulation for training |
| NumPy | ≥ 1.24.0 | Numerical features for ML |
| Flask | ≥ 2.3.0 | Web dashboard and REST API |
| Werkzeug | (Flask dep.) | Password hashing for user auth |
| smtplib | stdlib | Gmail SMTP email alerts |
| threading | stdlib | Non-blocking email dispatch |
| json | stdlib | Alert storage and API responses |
| subprocess | stdlib | Launching Snort and engine processes |

---

*Generated by IDS Shield — Hybrid Intrusion Detection System*
*Python + Scapy + Scikit-learn + Real Snort 2.9.x C Binary + Flask*
