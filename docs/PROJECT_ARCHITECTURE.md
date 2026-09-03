# 🛡️ IDS Snort Project — Architecture & Detection Theory

This document details the underlying engineering, detection mathematics, feature selection, and correlation algorithms of the Hybrid Intrusion Detection System.

---

## 1. Core Engineering: Hybrid Multi-Engine Model

Traditional intrusion detection systems suffer from a fundamental tradeoff:
* **Signature Detection (Snort):** 100% precision on known attack patterns, but completely blind to 0-day exploits, novel obfuscations, or polymorphic floods.
* **Anomaly Detection (Machine Learning):** Highly adaptable to novel deviations, but susceptible to false positives during bursty legitimate network traffic.

Our architecture integrates both approaches simultaneously and unifies them through an alert correlation pipeline:

```
                  +--------------------------------+
                  |    Incoming Network Traffic    |
                  +---------------+----------------+
                                  |
            +---------------------+---------------------+
            |                                           |
            v                                           v
+-----------------------+                   +-----------------------+
|   Real Snort Engine   |                   |   AI / ML Engine      |
|  (C-Binary Sniffer)   |                   |  - Random Forest      |
|  Strict Rules Matching|                   |  - LSTM Autoencoder   |
+-----------+-----------+                   +-----------+-----------+
            |                                           |
            | UDP Alert (Port 9999)                     | UDP Alert (Port 9999)
            |                                           |
            +---------------------+---------------------+
                                  |
                                  v
                    +---------------------------+
                    |  Correlation & Deduplic.  |
                    |      (correlator.py)      |
                    +-------------+-------------+
                                  |
                 +----------------+----------------+
                 |                                 |
                 v                                 v
   [CORRELATED_ATTACK (99%)]            [Automated Response]
   - Web Audio Siren                    - Windows Firewall Rule
   - Telegram Alert                     - IP Quarantine Score
   - Immutable Blockchain Ledger        - SQLite Audit Store
```

---

## 2. Detection Engines

### A. Real Snort Engine (`snort.exe` + `snort_reader.py`)
- **Engine:** Snort 2.9.x C binary operating in packet capture/alert mode.
- **Rule Definitions:** Curated signatures in `backend/snort/local.rules` covering:
  - ICMP ping flood (`SID: 1000001`)
  - TCP SYN floods on port 80/443 (`SID: 1000002`)
  - Aggressive port scans (`SID: 1000004`)
  - SSH/FTP brute force attempts (`SID: 1000005`)
- **Integration:** The Python reader spawns Snort with Npcap binding, follows `C:\Snort\log\alert` in real-time, parses fast-alert structures, and forwards detections to the correlator via UDP.

### B. Random Forest Anomaly Detector (`detect.py` + `train_model.py`)
- **Training Data:** Canadian Institute for Cybersecurity **CIC-IDS-2017** benchmark dataset.
- **Feature Pipeline (15 Features):**
  1. `Destination Port`
  2. `Flow Duration`
  3. `Total Fwd Packets`
  4. `Total Length of Fwd Packets`
  5. `Fwd Packet Length Max`
  6. `Fwd Packet Length Mean`
  7. `Fwd Packet Length Std`
  8. `Flow Bytes/s`
  9. `Flow Packets/s`
  10. `Fwd IAT Mean` (Inter-Arrival Time)
  11. `Average Packet Size`
  12. `SYN Flag Count`
  13. `PSH Flag Count`
  14. `ACK Flag Count`
  15. `Init_Win_bytes_forward`
- **Inference:** A sliding 5-tuple bidirectional flow collector tracks live TCP/UDP bursts, standardizes features using `StandardScaler`, and executes probabilistic predictions.

### C. Deep Learning LSTM Autoencoder (`autoencoder.py`)
- **Architecture:** Multi-layer LSTM Autoencoder trained strictly on normal baseline sequences.
- **Anomaly Scoring:** Computes Mean Squared Error (MSE) reconstruction loss across consecutive packets. When `MSE > threshold`, the sequence is flagged as an evasion or volumetric anomaly.

### D. Network Monitors
- **ARP Spoofing / MITM (`network_monitor/`):** Tracks MAC-to-IP bindings; alerts when duplicate MAC addresses claim the default gateway.
- **DNS Tunneling Detector:** Evaluates Shannon entropy on subdomains. High-entropy queries (e.g., base64/hex data exfiltration) trigger immediate alerts.

---

## 3. Correlation Synergy (`correlator.py`)

When an attacker launches a sustained campaign, both engines fire independently:
1. Snort flags the known signature (e.g. SYN pattern).
2. ML flags the anomalous arrival rate and flow duration.
3. If both alerts originate from the **same Source IP within a 2-second time window**, the correlator synthesizes them into a **`CORRELATED_ATTACK`**:
   - Severity: `HIGH`
   - Confidence: `99.0%`
   - Action: Immediate firewall quarantine + audio alert + Telegram push + blockchain commit.

---

## 4. SHA-256 Attacker Blockchain Ledger

Every high-severity alert is hashed and committed to an append-only cryptographic ledger (`backend/blockchain/chain.json`):
- **Genesis Block:** Initializes the chain.
- **Block Content:** Index, UTC timestamp, attacker metadata (IP, attack type, confidence, payload size), previous hash, nonce, and current SHA-256 hash.
- **Proof-of-Work:** Requires leading zero bits for tamper resistance.
- **Live Verification:** The React dashboard provides a 1-click ledger audit that recalculates all block hashes sequentially to prove the evidence has not been altered.
