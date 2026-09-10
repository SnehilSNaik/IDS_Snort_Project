# 🛡️ IDS Snort Project — Architecture & Detection Theory

This document details the underlying engineering, detection mathematics, feature selection, and correlation algorithms of the Hybrid Intrusion Detection System.

---

## 1. Core Engineering: Hybrid Multi-Engine Model

Traditional intrusion detection systems suffer from a fundamental tradeoff:
* **Signature Detection (Snort):** Fast matching against configured known-threat rules; rule tuning is still needed to manage false positives.
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
   - Hash-Chained Audit Log             - SQLite Event Store
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
- **Inference:** A bidirectional 5-tuple collector finalizes TCP/UDP flows on FIN/RST, packet cap, or idle timeout, then standardizes the same 15 features with the saved `StandardScaler` before probabilistic inference.
- **Evaluation scope:** The saved 99.52% accuracy / 99.40% F1 figures are held-out CIC-IDS-2017 benchmark results, not a promise of live-network accuracy.

### C. Deep Learning LSTM Autoencoder (`autoencoder.py`)
- **Architecture:** Multi-layer LSTM Autoencoder trained strictly on normal baseline sequences.
- **Anomaly Scoring:** Computes Mean Squared Error (MSE) reconstruction loss across consecutive packets. When `MSE > threshold`, the sequence is flagged as an evasion or volumetric anomaly.

### D. DNS Monitor
- **DNS Tunneling Detector:** Evaluates Shannon entropy on subdomains. High-entropy queries (e.g., base64/hex data exfiltration) trigger immediate alerts.

---

## 3. Correlation Synergy (`correlator.py`)

When an attacker launches a sustained campaign, both engines fire independently:
1. Snort flags the known signature (e.g. SYN pattern).
2. ML flags the anomalous arrival rate and flow duration.
3. If both alerts originate from the **same Source IP within a 2-second time window**, the correlator synthesizes them into a **`CORRELATED_ATTACK`**:
   - Severity: `HIGH`
   - Confidence: `99.0%`
   - Action: Playbook-based response, alerting, and a hash-chained SQLite audit record. Firewall blocking follows the active playbook.

---

## 4. SHA-256 Hash-Chained Audit Log

Security events are appended to SQLite (`backend/data/ids.db`) with a SHA-256 link to the preceding record:
- **Record content:** UTC timestamp, action, subject, detail, previous hash, and record hash.
- **Tamper evidence:** The verifier recomputes each record hash and validates the previous-hash sequence.
- **Scope:** This is a lightweight local audit trail for the lab prototype, not a distributed blockchain or proof-of-work system.
