# 🛡️ Hybrid Intrusion Detection System (IDS_Snort_Project)

A hybrid **Signature-Based + Anomaly-Based Intrusion Detection System** combining the **Real Snort 2.9 C Binary**, **Machine Learning (Scikit-Learn / Scapy)**, an **Alert Correlator Engine**, and a modern **Flask Web Dashboard**.

---

## 🌟 Key Features

- **Hybrid Detection Engine**:
  - 🎯 **Signature Detection**: Integrates directly with the official C-based **Snort 2.9.x** engine for deep packet inspection using custom rules (`snort/local.rules`).
  - 🤖 **ML Anomaly Detection**: Uses **Random Forest / Decision Tree** models trained on **CIC-IDS-2017** network flow profiles to spot unknown/zero-day attacks.
- **Alert Correlator**: UDP middleman service listening on port 9999 that deduplicates alerts and merges signature + anomaly triggers for identical IPs into high-confidence **`CORRELATED_ATTACK`** events.
- **Interactive Security Dashboard**: Real-time Flask dashboard featuring user authentication, threat severity metrics (High, Medium, Low), live alert tables, and process management.
- **Automatic Email Alerts**: Automated Gmail SMTP notification pipeline with rate throttling to prevent email spamming during high-volume flood attacks.
- **Dataset Integration**: Built-in dataset pipeline with automatic synthetic fallback and `download_dataset.py` for training on genuine **CIC-IDS-2017** data (15 flow features).

---

## 🏗️ System Architecture

```
                      Attacker / Live Network Traffic
                                     │
                                     ▼
                    ┌─────────────────────────────────┐
                    │      Your Host Machine (IDS)    │
                    └────────────────┬────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
┌───────────────────┐      ┌───────────────────┐      ┌───────────────────┐
│ packet_capture/   │      │   snort/          │      │   ml_model/       │
│ capture.py        │      │   snort_reader.py │      │   detect.py       │
│ (Logs to CSV)     │      │ (Real Snort C Bin)│      │ (ML Anomalies)    │
└───────────────────┘      └─────────┬─────────┘      └─────────┬─────────┘
                                     │                          │
                                     └───────────┬──────────────┘
                                                 ▼
                                     ┌───────────────────────┐
                                     │  correlator/          │
                                     │  correlator.py        │
                                     │  (UDP 9999 Deduper)   │
                                     └───────────┬───────────┘
                                                 │
                                                 ▼
                                     ┌───────────────────────┐
                                     │  alerts/alerts.json   │
                                     └───────────┬───────────┘
                                                 │
                                                 ▼
                                     ┌───────────────────────┐
                                     │  dashboard/app.py     │
                                     │  http://localhost:5000│
                                     └───────────────────────┘
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Python 3.9+**
- **Npcap / WinPcap** (Required for live packet sniffing on Windows)
- **Snort 2.9.x** installed at `C:\Snort\` (optional for ML-only testing, required for full hybrid signature detection)

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

# Train the model (Auto-detects real CIC-IDS-2017 dataset or uses synthetic fallback)
python ml_model/train_model.py
```

### 4. Running the System

Start the IDS Dashboard Launcher (Run in an **Administrator** terminal on Windows for packet capture privileges):

```bash
python start_ids.py
```

1. Open your browser and navigate to **`http://localhost:5000`**.
2. Register an account and sign in.
3. Click **"Engage IDS Engine"** in the dashboard to spin up the Correlator, ML Detection, and Snort Reader processes automatically.

---

## 📊 Snort Rules & Alert Classification

Custom Snort rules defined in `snort/local.rules`:

| Attack Type | Trigger Condition | Priority | Dashboard Severity |
|---|---|---|---|
| **ICMP Ping Flood** | > 10 ICMP Echo Requests / sec | 1 | 🔴 **HIGH** |
| **Large UDP Flood** | UDP payload size > 1000 bytes | 1 | 🔴 **HIGH** |
| **SSH Brute Force** | > 5 SYN attempts to port 22 in 60s | 1 | 🔴 **HIGH** |
| **Port Scan** | > 20 TCP SYN packets in 5s | 2 | 🟡 **MEDIUM** |
| **Large TCP Anomaly**| TCP payload size > 5000 bytes | 2 | 🟡 **MEDIUM** |
| **Single External Ping** | ICMP Echo Request | 3 | 🟢 **LOW** |

---

## 📁 Repository Structure

```
IDS_Snort_Project/
├── alerts/                # Runtime alert log output & state flags
├── correlator/            # UDP 9999 Alert correlation & deduplication engine
│   └── correlator.py
├── dashboard/             # Flask dashboard web application
│   ├── app.py
│   └── templates/         # UI HTML templates (Home, Index, Login, Signup)
├── email_alert/           # Gmail SMTP email alert dispatcher
│   └── send_alert.py
├── ml_model/              # Machine learning training & live anomaly detection
│   ├── detect.py          # Live Scapy anomaly detector
│   ├── download_dataset.py# CIC-IDS-2017 downloader helper
│   └── train_model.py     # Model training script
├── packet_capture/        # Live packet logger
│   └── capture.py
├── snort/                 # Real Snort integration bridge
│   ├── ids_project.conf   # Snort configuration file
│   ├── local.rules        # Custom signature rules
│   └── snort_reader.py    # Snort subprocess launcher & alert log tailer
├── PROJECT_EXPLANATION.md # Detailed technical specification & viva documentation
├── requirements.txt       # Python dependencies
└── start_ids.py           # Master CLI launcher
```

---

## 🔒 Environment Variables (Optional)

To enable email notifications, set the following environment variables prior to running:

```bash
set IDS_SENDER_EMAIL=your_email@gmail.com
set IDS_EMAIL_PASSWORD=your_gmail_app_password
set IDS_RECEIVER_EMAIL=alert_recipient@gmail.com
```

---

## 📜 License

This project is open-source and intended for educational and security research purposes.
