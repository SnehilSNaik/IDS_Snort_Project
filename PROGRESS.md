# IDS_Snort_Project — Progress & Architecture Summary

> **Generated automatically** — load this file at the start of any new session to restore full context.
> In future sessions: say "read PROGRESS.md and continue"

---

## Project Status: COMPLETE & ALL TESTS PASSING

**Last full audit:** 2026-09-30  
**Test result:** 28/28 passed, 0 warnings, 0 failures

---

## Start Commands

### Backend
```
cd backend
python start_ids.py          # http://localhost:5000
```

### Frontend
```
cd frontend
npm run dev                  # http://localhost:5173
```

### One-Click Windows Launcher
```
.\start_windows_demo.ps1
```

### Run Tests
```
cd backend
python -m pytest test_block_grouping.py test_suite.py -v -W error
```

### Simulate Attacks
```
cd backend
python simulate_attack.py    # Interactive, 6 attack scenarios
```

---

## Bugs Fixed (2026-09-30)

1. **SECURITY BUG — Missing @login_required on Reachability Route**
   - File: backend/dashboard/app.py (line 689)
   - Fix: Added @login_required to /api/firewall/reachability/<ip>
   - Previously allowed unauthenticated access; now returns HTTP 401

2. **SyntaxWarning in snort_reader.py**
   - File: backend/snort/snort_reader.py (line 155)
   - Fix: Changed docstring from triple-quotes to raw r-string (r\"\"\"...\"\"\")
   - Suppresses \S escape warning on Python 3.12+

3. **DeprecationWarning — Date Parsing Without Year**  
   - File: backend/snort/snort_reader.py (line 127)
   - Fix: Prepend year to format string instead of .replace(year=...)
   - Avoids Python 3.15 breaking change around leap-day ambiguity

4. **Forward Reference for File Path Constants**
   - File: backend/dashboard/app.py
   - Fix: Moved RESPONSE_DIR, INCIDENT_LOG_FILE, THREAT_SCORE_FILE, PLAYBOOKS_FILE
     from line ~715 to line ~84 (near other file-path constants)
   - Constants now defined before api_reset_all_data() references them

---

## Architecture: Detection Pipeline

    [Live Network]
          |
          +--[Snort C Binary]     -> snort/snort_reader.py   -> UDP 9999
          +--[RF ML detector]     -> ml_model/detect.py      -> UDP 9999
          +--[LSTM Autoencoder]   -> ml_model/autoencoder.py -> UDP 9999
          +--[DNS Monitor]        -> network_monitor/dns_monitor.py -> UDP 9999
                                             |
                                   [Correlator @ UDP 9999]
                                   correlator/correlator.py
                                             |
                           +----------------+----------------+
                           |                |                |
                   [alerts.json]      [SQLite DB]    [Playbook Engine]
                           |           data/ids.db
                   [Flask Dashboard]
                   dashboard/app.py
                           |
                   [React SPA Frontend]
                   frontend/src/ (Vite)

---

## ML Models (all trained and present)

- Random Forest:  ml_model/model.pkl (13.8 MB) — 99.52% accuracy
- RF Scaler:      ml_model/scaler.pkl
- RF Metrics:     ml_model/metrics.json
- LSTM AE Model:  ml_model/autoencoder_model.keras (866 KB)
- AE Scaler:      ml_model/autoencoder_scaler.pkl
- AE Threshold:   ml_model/autoencoder_threshold.pkl

---

## Test Coverage: 28 Tests

test_block_grouping.py (15 tests):
- Alert correlator block-grouping regression tests
- Firewall rule verification logic
- Operator reachability tests
- Auth enforcement on /api/firewall/reachability/<ip>

test_suite.py (13 tests):
- Random Forest model artifacts
- LSTM Autoencoder artifacts
- IP Blocker lifecycle
- Threat intelligence private-IP detection
- Playbook Engine scoring
- Dashboard API routes
- Snort reader alert parser
- DNS monitor entropy
- CIC-IDS FlowCollector features
- Correlator alert types
- Victim agent SQLi detection
- Windows file audit event parser
- Protected asset policy matching

---

## Key Files

backend/start_ids.py             Main launcher
backend/dashboard/app.py         Flask REST API (770 lines)
backend/correlator/correlator.py Alert correlator on UDP 9999
backend/ml_model/detect.py       Random Forest CIC-IDS-2017 engine
backend/ml_model/autoencoder.py  LSTM Autoencoder engine
backend/network_monitor/dns_monitor.py  DNS tunneling detector
backend/firewall/ip_blocker.py   Windows Firewall manager
backend/response/playbook_engine.py     Playbook trigger engine
backend/persistence/event_store.py      SQLite + audit log
backend/threat_intel/threat_intel.py    ipinfo.io enrichment
backend/snort/snort_reader.py    Real Snort C binary reader
backend/victim_agent/agent.py    Remote endpoint agent
backend/simulate_attack.py       Lab attack simulator
backend/.env                     API keys (ipinfo.io configured)
frontend/src/App.jsx             React SPA root
frontend/src/components/         LiveRadar, IncidentResponse, etc.

## Future Roadmap (V2 Architecture)
**Goal: Implement a 3-Machine Setup (Attacker, Victim, IDS)**

For the ultimate demonstration, the IDS can be adapted to block attacks directly on a separate Victim machine using **Remote Execution (SSH/WinRM)**.

### Why this is the best approach:
1. **Zero Network Changes:** No complex routing, virtual switches, or gateway router setup required.
2. **Minimal Code Changes:** The current codebase already generates the 
etsh firewall command. You just need to prepend ssh Administrator@<victim_ip> to the command string.
3. **Realistic Architecture:** Modern SIEMs (Security Information and Event Management systems) work this way—passively monitoring traffic and sending automated commands via SSH/APIs to isolate compromised endpoints.

### Implementation Steps (For Later):
1. **Enable SSH/WinRM** on the Victim Machine so it accepts remote commands.
2. **Generate an SSH key** on the IDS machine to allow passwordless login to the Victim Machine.
3. **Update ackend/firewall/ip_blocker.py**: Modify the _apply_firewall_rule function to run ssh user@victim_ip netsh advfirewall... instead of executing 
etsh locally.
