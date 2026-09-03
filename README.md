# 🛡️ Advanced Hybrid IDS (Snort + Machine Learning + Threat Intel + Blockchain)

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
│   ├── simulate_attack.py           # Comprehensive attack simulator (7 scenarios)
│   ├── .env                         # API key configuration (ipinfo.io)
│   ├── requirements.txt             # Python dependencies
│   ├── correlator/                  # Multi-engine deduplication & correlation (UDP 9999)
│   ├── ml_model/                    # Random Forest + LSTM Autoencoder engines
│   ├── network_monitor/             # ARP Spoof / MITM & DNS Tunneling detectors
│   ├── threat_intel/                # ipinfo.io network-context enrichment
│   ├── response/                    # Playbook Engine & threat scoring system
│   ├── firewall/                    # Windows OS firewall IP blocker
│   ├── blockchain/                  # SHA-256 attacker ledger
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
* This automatically launches the packet capture, Snort C-binary reader, Random Forest anomaly detector, and UDP alert correlator.

### Step 3: Trigger Attack Scenarios
Open an elevated terminal and run the interactive simulator:
```powershell
cd backend
python simulate_attack.py
```
Run any of the 7 built-in realistic attacks:
* **Option [1] SYN Flood:** Triggers Snort rule + ML anomaly → merged by Correlator into a `CORRELATED_ATTACK` (99% confidence) with an audible alarm.
* **Option [3] ICMP Ping Flood:** Volumetric flood detected by Snort signature matching.
* **Option [5] DNS Tunneling / Exfiltration:** High Shannon entropy subdomain queries flagged immediately.
* **Option [6] ARP Cache Poisoning / MITM:** Detects MAC address spoofing against the default gateway.

### Step 4: Demonstrate Multi-Engine Correlation
* Return to the **Live Radar** tab.
* Show the newly arrived alert labeled **`CORRELATED_ATTACK`**.
* **Key Point to Explain:** Neither Snort nor ML works in isolation. When both detect an attack from the same IP within 2 seconds, the Correlator eliminates duplicate noise and confirms a verified intrusion with 99% confidence.

### Step 5: Automated Incident Response & Firewall Block
* Click the **"Incident Response"** tab.
* Show the automated playbook execution (`PB-001` or `PB-005`).
* Show the attacker's IP quarantined with a dynamically elevated Threat Score.
* Under **Active Firewall Blocks**, show the attacker IP blocked via Windows `netsh` firewall rule.

### Step 6: Verify the Blockchain Audit Trail
* Click the **"Audit Log / Blockchain"** tab.
* Show the cryptographic block containing the attacker's metadata, SHA-256 previous hash, and nonce.
* Click **"Verify Blockchain Integrity"** — the dashboard re-computes all hashes sequentially and confirms the evidence is untampered.

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
| **Signature Engine** | Real Snort 2.9.x C Binary | High-speed, 100% precision known-threat detection |
| **Anomaly Engine** | Scikit-learn Random Forest + TensorFlow LSTM | Zero-day attack and pattern deviation detection (CIC-IDS-2017) |
| **Correlator** | Python Socket UDP Daemon (Port 9999) | Deduplication, temporal windowing, multi-engine synergy |
| **Enrichment** | Threat Intel (`ipinfo.io`) | Geolocation, ASN, and abuse context |
| **Firewall** | Windows Firewall (`netsh`) | Real-time OS-level IP blacklisting and containment |
| **Audit Ledger** | SHA-256 Proof-of-Work Blockchain | Tamper-proof, verifiable evidence store for legal/forensic review |
