# IDS_Snort_Project: System Overview & Detection Architecture

This document provides a comprehensive summary of how the Hybrid Intrusion Detection System (IDS) works, how attacks are detected, and the philosophy behind integrating Machine Learning with Snort.

## 1. The Core Concept: A Hybrid Approach
Traditional security systems usually rely on either **Signatures** (looking for known bad things) or **Anomalies** (looking for weird behavior). Your system uses **both simultaneously**, covering the weaknesses of one with the strengths of the other.

---

## 2. The Two Detection Engines

### Engine A: Real Snort (Signature-Based)
*   **What it is:** The system runs the actual, industry-standard C-based Snort binary (`snort.exe`) in the background.
*   **How it detects:** It monitors network traffic and compares every packet against strict rules defined in `local.rules`. 
*   **Example:** "If an IP tries to connect to port 22 (SSH) 5 times in 60 seconds, flag it as a Brute Force."
*   **Strength:** **100% Precision.** If Snort fires, you know exactly what the attack is because it matched a specific rule perfectly.
*   **Weakness:** **Rigid.** If an attacker changes their behavior slightly (e.g., trying port 2222 instead of 22), Snort will completely miss it unless you write a new rule.

### Engine B: Machine Learning (Anomaly-Based)
*   **What it is:** A custom Python script (`detect.py`) running a trained Random Forest AI model alongside specialized rule-logic.
*   **How it detects:** It extracts features from live traffic (packet size, protocol, and packet arrival rate) and asks the AI, *"Does this look like normal traffic, or does this look like a flood/scan?"* It also includes direct logic for ICMP floods (classifying severity purely by payload size).
*   **Example:** "I've never seen this exact attack signature before, but 100 large TCP packets per second from an unknown IP is highly suspicious."
*   **Strength:** **Adaptable.** It can detect brand-new (zero-day) attacks that Snort doesn't have rules for.
*   **Weakness:** **Noisy.** It can generate false positives, occasionally flagging a heavy file download or strange router traffic as a low-severity attack.

---

## 3. The "Brain": The Correlator (`correlator.py`)
This is why the two systems are integrated. Both Snort and the ML Engine operate independently, but they don't write directly to the dashboard. Instead, they send their findings to the **Correlator**.

*   **Deduplication:** If both engines detect an attack from `192.168.1.50` at the exact same time, you don't want two separate alerts on your dashboard.
*   **The Synergy (Correlated Attacks):** If the Correlator receives an alert from Snort AND an alert from the ML Engine for the same IP within a **0.5-second window**, it merges them into a **`CORRELATED_ATTACK`**.
*   **Why this matters:** A Correlated Attack is the "Holy Grail" of IDS alerts. It means the traffic is structurally a known threat (Snort) AND is behaving maliciously at volume (ML). When this happens, the system assigns it **99% confidence** and immediately dispatches a high-priority email alert.

---

## 4. The Data Flow Summary
1.  **Traffic Arrives:** A malicious packet hits your network adapter.
2.  **Dual Sniffing:** Both `snort.exe` and `detect.py` (via Scapy) read the packet simultaneously.
3.  **Analysis:**
    *   Snort checks it against `local.rules`.
    *   ML Engine checks its size/rate against the baseline.
4.  **Reporting:** If either engine flags it, they shoot a UDP packet to `localhost:9999`.
5.  **Correlation:** `correlator.py` receives the UDP packets. It merges duplicates, checks for correlated matches, updates the severity counters (`count.json`), and writes the final alert log (`alerts.json`).
6.  **Visualization:** The Flask Dashboard (`app.py`) instantly reads those JSON files and displays the sleek UI, showing the real-time tick counters and the live alert stream.
