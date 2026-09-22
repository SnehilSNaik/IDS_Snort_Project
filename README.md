# 🛡️ Advanced Hybrid IDS (Snort + Flow ML + Threat Intelligence)

A comprehensive, state-of-the-art **Intrusion Detection & Automated Incident Response System** featuring a **React Single-Page Application (SPA)** frontend and a multi-engine **Python/Flask** backend.

> 📖 For detailed detection theory, CIC-IDS-2017 feature selection, and correlation math, see [docs/PROJECT_ARCHITECTURE.md](docs/PROJECT_ARCHITECTURE.md).

---

## 📁 Project Architecture

```
IDS_Snort_Project/
├── 🎨 frontend/                     # React 18 + Vite Single Page Application
│   ├── src/
│   │   ├── components/
│   │   │   ├── Header.jsx           # SOC header & Web Audio controls
│   │   │   ├── LiveRadar.jsx        # Real-time metrics & Alert stream
│   │   │   ├── IncidentResponse.jsx # Threat scores, playbooks & firewall
│   │   │   ├── AuditLog.jsx         # Cryptographic SHA-256 attacker ledger & verifier
│   │   │   ├── AttackTimeline.jsx   # Interactive incident attack timeline
│   │   │   └── Endpoints.jsx        # Multi-device agent fleet status
│   │   ├── utils/soundEngine.js     # Web Audio API alert sound engine
│   │   ├── App.jsx                  # Main layout & API polling
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js               # Vite build config & Flask API proxy
│
├── ⚙️ backend/                      # Python Core Detection & REST APIs
│   ├── start_ids.py                 # Main backend server launcher
│   ├── simulate_attack.py           # Safe attack simulator (6 scenarios)
│   ├── .env                         # API key configuration (ipinfo.io)
│   ├── requirements.txt             # Python dependencies
│   ├── correlator/                  # Multi-engine deduplication & correlation (UDP 9999)
│   ├── ml_model/                    # Random Forest + LSTM Autoencoder engines
│   ├── network_monitor/             # DNS tunneling detector
│   ├── threat_intel/                # ipinfo.io network-context enrichment
│   ├── response/                    # Playbook Engine & threat scoring system
│   ├── firewall/                    # Windows OS firewall IP blocker
│   ├── persistence/                 # SQLite store + SHA-256 hash-chained audit log
│   ├── dashboard/                   # Flask REST API server & authentication
│   ├── snort/                       # Snort C binary log reader
│   ├── telegram_alert/              # Real-time Telegram bot notifier
│   └── email_alert/                 # Automated email notifier
│
├── 📚 docs/                         # Extended Architecture & Research Docs
│   └── PROJECT_ARCHITECTURE.md
├── docker-compose.yml               # Multi-container deployment config
└── start_windows_demo.ps1           # Windows single-click launcher
```

---

## 🚀 Quick Start Guide

### 1. Backend Setup & Run

```powershell
# Navigate to backend
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Start the Flask Backend Server (starts on http://localhost:5000)
python start_ids.py
```

### 2. Frontend Setup (React Dev Server)

```powershell
# Navigate to frontend (in a new terminal)
cd frontend

# Install Node dependencies (first time only)
npm install

# Start Vite React Dev Server (starts on http://localhost:5173)
npm run dev
```

> Open your browser to **`http://localhost:5173`** for the modern SOC interface.
> *(Alternatively, run `.\start_windows_demo.ps1` from an elevated PowerShell to launch both simultaneously).*

---

## 🎤 5-Minute Presentation & Demo Guide (For Viva / Defense)

Use this step-by-step walkthrough to demonstrate the system effectively in presentations:

### Step 1: Show the Central SOC Dashboard
* Open **`http://localhost:5173`**.
* **Highlight:** Clean dark-mode SOC dashboard with live metrics: Total Alerts, High/Medium/Low counts, Average Confidence, and Active Engines.
* Point out the **Audio Alerts** toggle in the top-right header (powered by the HTML5 Web Audio API).

### Step 2: Engage the Detection Engines
* Click **"Engage IDS Engine"** in the top banner.
* This launches Snort, the 5-tuple flow ML detector, LSTM autoencoder, DNS monitor, and UDP alert correlator.

### Step 3: Trigger Attack Scenarios
Open an elevated terminal and run the interactive simulator:
```powershell
cd backend
python simulate_attack.py
```
Run any of the 6 safe built-in lab scenarios:
* **Option [1] SYN Flood:** Triggers Snort rule + ML anomaly → merged by Correlator into a `CORRELATED_ATTACK` (99% confidence) with an audible alarm.
* **Option [2] ICMP Ping Flood:** Volumetric ICMP flood detection.
* **Option [3] UDP Flood:** ML anomaly detection for unusual UDP traffic.
* **Option [4] Port Scan:** Snort signature detection for repeated TCP probes.
* **Option [5] LSTM Anomaly:** Sequence-based anomaly detection using the autoencoder.
* **Option [6] DNS Tunneling / Exfiltration:** High-entropy DNS queries are flagged.

### Step 4: Demonstrate Multi-Engine Correlation
* Return to the **Live Radar** tab.
* Show the newly arrived alert labeled **`CORRELATED_ATTACK`**.
* **Key Point to Explain:** When Snort and ML detect activity from the same IP within the correlation window, the correlator deduplicates the evidence and raises a high-confidence correlated alert.

### Step 5: Automated Incident Response & Firewall Block
* Click the **"Incident Response"** tab.
* Show the automated playbook execution (`PB-001` or `PB-005`).
* Show the attacker's IP quarantined with a dynamically elevated Threat Score.
* Under **Active Firewall Blocks**, show the attacker IP blocked via Windows `netsh` firewall rule.

### Step 6: Verify the Hash-Chained Audit Log
* Click the **"Hash-Chained Audit Log"** tab.
* Show the local SQLite audit record, its previous hash, and SHA-256 record hash.
* Click **"Verify hashes"** to verify the complete tamper-evident sequence.

---

## 🖥️ Multi-Endpoint Lab Mode

The central dashboard supports lightweight endpoint agents running on separate machines. Each agent registers with its hostname, IP, and OS, and transmits heartbeats every 30 seconds:

```powershell
cd backend/victim_agent
python agent.py --server <IDS_SERVER_IP> --name Lab-PC-01
```

* Endpoint-originated telemetry and alerts are highlighted in the **Endpoints** tab.

---

## 🐳 Docker Deployment (Optional)

To spin up the dashboard, correlator, and React frontend in isolated containers:

```powershell
docker compose up --build
```

Access the UI at `http://localhost:5173`.

---

## 🛡️ Core Feature Summary

| Component | Technology | Role |
|---|---|---|
| **Frontend** | React 18, Vite, Lucide Icons, Web Audio API | Live SOC interface, interactive playbooks, audit verification |
| **Signature Engine** | Real Snort 2.9.x C Binary | Rule-based detection of configured known threat patterns |
| **Anomaly Engine** | Flow-based Random Forest + TensorFlow LSTM | CIC-IDS-2017 benchmark classifier and sequence anomaly detection |
| **Correlator** | Python Socket UDP Daemon (Port 9999) | Deduplication, temporal windowing, multi-engine synergy |
| **Enrichment** | Threat Intel (`ipinfo.io`) | Geolocation, ASN, and network context |
| **Firewall** | Windows Firewall (`netsh`) | Real-time OS-level IP blacklisting and containment |
| **Audit Log** | SQLite + SHA-256 hash chain | Local tamper-evident record of detections and firewall actions |

## 📊 Model Evaluation — Accurate Interpretation

The current Random Forest model achieved **99.52% accuracy**, **99.79% precision**, **99.02% recall**, and **99.40% F1** on a held-out portion of the CIC-IDS-2017 benchmark (168,246 test flows).

These figures demonstrate benchmark performance only. Real lab or production accuracy can differ because live traffic, capture interfaces, flow completion, and normal workloads differ from the benchmark. The dashboard labels these values as held-out evaluation metrics and does not infer accuracy from live alerts.
