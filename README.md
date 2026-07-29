# 🛡️ Hybrid Intrusion Detection System & Immutable Blockchain Ledger (IDS_Snort_Project)

A hybrid **Signature-Based + Anomaly-Based Intrusion Detection System (IDS)** combining **Snort 2.9**, **Machine Learning (CIC-IDS-2017)**, an **Alert Correlator Engine**, an **Immutable SHA-256 Blockchain Ledger**, **Real-time Telegram Bot Alerts**, **OS-Level IP Firewall Blocking**, and a modern **Flask Web Security Command Center**.

---

## 🌟 Key Features

- **Hybrid Detection Engine**:
  - 🎯 **Signature Detection**: Integrates directly with the official C-based **Snort 2.9.x** engine for deep packet inspection using custom rules (`snort/local.rules`).
  - 🤖 **ML Anomaly Detection**: Uses **Random Forest / Decision Tree** models trained on **CIC-IDS-2017** network flow profiles to spot unknown/zero-day attacks.
- **Alert Correlator Engine**: UDP middleman service listening on port `9999` that deduplicates alerts and merges signature + anomaly triggers for identical IPs into high-confidence **`CORRELATED_ATTACK`** events (99% confidence).
- **⛓️ Immutable Blockchain Ledger (`blockchain/`)**: Every detected attack is mined into a **SHA-256 Proof-of-Work blockchain** (`chain.json`), guaranteeing non-repudiation and cryptographic proof of incidents.
- **📱 Real-Time Telegram Bot Alerts (`telegram_alert/`)**: Asynchronous, rate-limited Telegram notifications sent instantly to your phone for HIGH/MEDIUM threats.
- **📡 Multi-Device / Network-Wide Victim Agent (`victim_agent/`)**: Lightweight, zero-dependency Python agent that runs on any victim PC on the Wi-Fi network, detects local attacks, and reports them back to the central HP Monitoring PC.
- **🛡️ WAF SQL Injection Inspection**: Built-in Web Application Firewall (`dashboard/app.py`) inspecting incoming HTTP payloads for SQL Injection syntax across mobile apps, browsers, and API endpoints.
- **🚫 Dynamic IP Blocker & OS Firewall (`firewall/`)**: One-click IP blocking from the UI with persistent JSON storage and real **Windows Firewall (`netsh`)** rule application.
- **💻 Interactive Command Center Dashboard**: Modern glassmorphic web dashboard with fixed scrollable windows, sticky headers, origin badges (`📡 VICTIM`, `🛡️ WAF`, `🖥 DIRECT`), live stats, and blockchain integrity verification.
- **🎬 One-Click Demo Launcher (`start_demo.py`)**: Auto-detects local LAN IP, starts correlator and dashboard, and prints exact commands for panel presentations.

---

## 🏗️ Multi-Device System Architecture

```
                    ┌─────────────────────────────────┐
                    │       Wi-Fi Network (LAN)       │
                    └──────────────┬──────────────────┘
                                   │
         ┌─────────────────────────┼──────────────────────────┐
         ▼                         ▼                          ▼
┌─────────────────┐    ┌──────────────────────┐   ┌─────────────────┐
│  ATTACKER PC    │    │   HP MONITORING PC   │   │   VICTIM PC     │
│                 │──► │  (IDS + Blockchain)  │   │ (victim_agent)  │
│  Simulates/sends│    │  Detects own attacks │   │ Detects & sends │
│  attacks        │    │  & hosts Dashboard   │   │ to HP:9999      │
└─────────────────┘    └──────────────────────┘   └─────────────────┘
                                   │                       │
                                   └───────────┬───────────┘
                                               ▼
                                   ┌───────────────────────┐
                                   │  correlator/ (UDP9999)│
                                   └───────────┬───────────┘
                                               │
                         ┌─────────────────────┼─────────────────────┐
                         ▼                     ▼                     ▼
              ┌─────────────────────┐┌───────────────────┐┌───────────────────┐
              │ blockchain/         ││ telegram_alert/   ││ dashboard/        │
              │ (SHA-256 Ledger)    ││ (Telegram Bot)    ││ http://<HP_IP>:5000│
              └─────────────────────┘└───────────────────┘└───────────────────┘
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python 3.9+**
- **Npcap / WinPcap** (Required for live packet sniffing on Windows)
- **Snort 2.9.x** installed at `C:\Snort\` (optional for ML-only testing, required for signature detection)

### 2. Installation

Clone the repository and install required dependencies:

```bash
git clone https://github.com/SnehilSNaik/IDS_Snort_Project.git
cd IDS_Snort_Project
pip install -r requirements.txt
```

### 3. Training the Machine Learning Model

Train the ML anomaly classifier:

```bash
# Optional: Download full CIC-IDS-2017 dataset
python ml_model/download_dataset.py

# Train the model (Auto-detects CIC-IDS-2017 dataset or uses synthetic fallback)
python ml_model/train_model.py
```

### 4. Running the One-Click Demo (`start_demo.py`)

Run on the **HP Monitoring PC**:

```bash
python start_demo.py
```

The launcher will:
1. Auto-detect your local LAN IP (e.g. `192.168.1.50`).
2. Start the Correlator and Web Dashboard.
3. Print a ready banner with connection URLs for the panel and secondary devices.

---

## 📱 Setting Up Telegram Notifications

1. Search for **`@BotFather`** on Telegram and create a new bot via `/newbot`.
2. Copy the HTTP API token provided by BotFather.
3. Open your new bot in Telegram and send `/start`.
4. Edit [`telegram_alert/telegram_bot.py`](file:///c:/Users/snehil/Desktop/IDS_Snort_Project/telegram_alert/telegram_bot.py):
   ```python
   TELEGRAM_BOT_TOKEN = "YOUR_BOT_TOKEN"
   TELEGRAM_CHAT_ID   = "YOUR_CHAT_ID"
   ```
5. Test your bot:
   ```bash
   python telegram_alert/telegram_bot.py
   ```

---

## 📡 Setting Up Victim PCs (Multi-Device Setup)

To monitor attacks targeted at another PC on the same Wi-Fi:

1. Copy [`victim_agent/agent.py`](file:///c:/Users/snehil/Desktop/IDS_Snort_Project/victim_agent/agent.py) to the Victim PC.
2. Edit lines 21–23:
   ```python
   MONITOR_PC_IP = "192.168.1.50"   # HP Monitoring PC's LAN IP
   VICTIM_NAME   = "PC-Lab-02"      # Label for dashboard
   ```
3. Run the agent on the Victim PC:
   ```bash
   python agent.py
   ```

---

## 🎯 Simulating Attacks

From an Attacker device or terminal, run the 7-scenario attack simulator:

```bash
# Attack HP Monitoring PC directly
python simulate_attacks.py <HP_IP>

# Attack a Victim PC on the network
python simulate_attacks.py <VICTIM_IP>

# Test WAF SQL Injection manually in browser/curl
curl "http://<HP_IP>:5000/login?email=admin' OR 1=1--"
```

---

## 🧪 System Verification

Run the full system verification test suite:

```bash
python test_full_system.py
```

---

## 📁 Repository Structure

```
IDS_Snort_Project/
├── alerts/                # Runtime alert logs (alerts.json)
├── blockchain/            # SHA-256 Proof-of-Work blockchain ledger (chain.json)
│   ├── blockchain.py
│   └── test_blockchain.py
├── correlator/            # UDP 9999 correlation engine
│   └── correlator.py
├── dashboard/             # Flask Web Security Command Center
│   ├── app.py             # Server + WAF middleware
│   └── templates/         # UI templates (index.html, login.html)
├── email_alert/           # Gmail SMTP alert dispatcher
├── firewall/              # Persistent IP blocker & Windows Firewall netsh interface
│   └── ip_blocker.py
├── ml_model/              # Machine learning training & Scapy anomaly detector
│   ├── detect.py
│   └── train_model.py
├── packet_capture/        # Live packet logger
├── snort/                 # Snort 2.9 C-binary integration & rules
├── telegram_alert/        # Real-time Telegram bot dispatcher
│   └── telegram_bot.py
├── victim_agent/          # Multi-device victim agent
│   ├── agent.py
│   └── README.md
├── PROJECT_EXPLANATION.md # Detailed technical specification & viva documentation
├── README.md              # Project documentation
├── simulate_attacks.py    # 7-scenario attack simulator
├── start_demo.py          # One-click master launcher
└── test_full_system.py    # System verification test suite
```

---

## 📜 License

This project is open-source and intended for educational, research, and presentation purposes.
