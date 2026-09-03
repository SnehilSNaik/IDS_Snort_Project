"""
=============================================================
backend/test_suite.py  —  IDS_Snort_Project Automated Test Suite
=============================================================
Runs automated unit and integration tests across all system components:
  1. Random Forest ML Model & Scaler
  2. LSTM Autoencoder & Anomaly Threshold
  3. Blockchain Ledger (commit, verification & anti-tamper)
  4. IP Firewall Blocker
  5. Threat Intelligence Module
  6. Automated Playbook Engine & Threat Scoring
  7. Flask Dashboard API Endpoints
=============================================================
"""

import os
import sys
import json
import unittest
import pickle
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Import components
from firewall.ip_blocker import IPBlocker
from response.playbook_engine import PlaybookEngine
from threat_intel.threat_intel import enrich_alert_async, _is_private
from dashboard.app import app
from snort.snort_reader import parse_alert_block, PRIORITY_MAP
from network_monitor.dns_monitor import shannon_entropy
from ml_model.flow_collector import FlowCollector
from correlator.correlator import KNOWN_ALERT_TYPES
from simulate_attack import ATTACKER_IPS
from victim_agent.agent import check_sqli


class TestIDSComponents(unittest.TestCase):

    def setUp(self):
        self.app_client = app.test_client()
        self.app_client.testing = True
        with self.app_client.session_transaction() as sess:
            sess["user_email"] = "admin@ids.local"

    # -------------------------------------------------------------
    # 1. Random Forest ML Model Tests
    # -------------------------------------------------------------
    def test_random_forest_model_artifacts(self):
        model_path = os.path.join(BASE_DIR, "ml_model", "model.pkl")
        scaler_path = os.path.join(BASE_DIR, "ml_model", "scaler.pkl")
        cfg_path    = os.path.join(BASE_DIR, "ml_model", "feature_config.pkl")

        self.assertTrue(os.path.exists(model_path), "model.pkl must exist")
        self.assertTrue(os.path.exists(scaler_path), "scaler.pkl must exist")
        self.assertTrue(os.path.exists(cfg_path), "feature_config.pkl must exist")

        with open(model_path, "rb") as f:
            model = pickle.load(f)
        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        with open(cfg_path, "rb") as f:
            cfg = pickle.load(f)

        self.assertEqual(cfg["mode"], "cicids2017")
        self.assertEqual(len(cfg["features"]), 15)

        # Test dummy prediction (15 features)
        dummy_input = np.zeros((1, 15))
        scaled_input = scaler.transform(dummy_input)
        pred = model.predict(scaled_input)
        self.assertIn(pred[0], [0, 1])

    # -------------------------------------------------------------
    # 2. LSTM Autoencoder Model Tests
    # -------------------------------------------------------------
    def test_lstm_autoencoder_artifacts(self):
        model_path = os.path.join(BASE_DIR, "ml_model", "autoencoder_model.keras")
        scaler_path = os.path.join(BASE_DIR, "ml_model", "autoencoder_scaler.pkl")
        thresh_path = os.path.join(BASE_DIR, "ml_model", "autoencoder_threshold.pkl")

        self.assertTrue(os.path.exists(model_path), "autoencoder_model.keras must exist")
        self.assertTrue(os.path.exists(scaler_path), "autoencoder_scaler.pkl must exist")
        self.assertTrue(os.path.exists(thresh_path), "autoencoder_threshold.pkl must exist")

        with open(scaler_path, "rb") as f:
            scaler = pickle.load(f)
        with open(thresh_path, "rb") as f:
            threshold = pickle.load(f)

        self.assertGreater(threshold, 0.0)

    # -------------------------------------------------------------
    # -------------------------------------------------------------
    # 4. IP Blocker Tests
    # -------------------------------------------------------------
    def test_ip_blocker(self):
        blocker = IPBlocker()
        test_ip = "203.0.113.99"

        # Ensure starting clean for test IP
        if blocker.is_blocked(test_ip):
            blocker.unblock_ip(test_ip)

        self.assertFalse(blocker.is_blocked(test_ip))

        success = blocker.block_ip(test_ip, reason="Unit test block", blocked_by="TestRunner")
        self.assertTrue(success)
        self.assertTrue(blocker.is_blocked(test_ip))

        unblock_success = blocker.unblock_ip(test_ip)
        self.assertTrue(unblock_success)
        self.assertFalse(blocker.is_blocked(test_ip))

    # -------------------------------------------------------------
    # 5. Threat Intelligence Module Tests
    # -------------------------------------------------------------
    def test_threat_intel(self):
        self.assertTrue(_is_private("127.0.0.1"))
        self.assertTrue(_is_private("192.168.1.50"))
        self.assertTrue(_is_private("10.0.0.1"))
        self.assertFalse(_is_private("8.8.8.8"))
        self.assertFalse(_is_private("1.1.1.1"))

    # -------------------------------------------------------------
    # 6. Playbook Engine & Threat Scoring Tests
    # -------------------------------------------------------------
    def test_playbook_engine_scoring(self):
        engine = PlaybookEngine()
        test_ip = "198.51.100.77"

        test_alert = {
            "id": 88888,
            "timestamp": "2026-08-13 23:45:00",
            "type": "TEST_HIGH_ATTACK",
            "severity": "HIGH",
            "src_ip": test_ip,
            "dst_ip": "192.168.1.100",
            "protocol": "TCP",
            "packet_size": 100,
            "packet_rate": 50,
            "confidence": 90.0,
            "message": "Unit Test Playbook High Severity",
        }

        # Evaluate alert
        actions = engine.evaluate(test_alert)
        self.assertIsInstance(actions, list)

        # Check threat score updated (+3 for HIGH)
        scores = engine.get_threat_scores()
        self.assertIn(test_ip, scores)
        self.assertGreaterEqual(scores[test_ip]["score"], 3)

    # -------------------------------------------------------------
    # 6. Dashboard API Endpoint Tests
    # -------------------------------------------------------------
    def test_dashboard_api_routes(self):
        # Health / status endpoints
        res = self.app_client.get("/api/stats")
        self.assertEqual(res.status_code, 200)

        res = self.app_client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)

        res = self.app_client.get("/api/audit")
        self.assertEqual(res.status_code, 200)

        res = self.app_client.get("/api/response/playbooks")
        self.assertEqual(res.status_code, 200)

        res = self.app_client.get("/api/response/threat_scores")
        self.assertEqual(res.status_code, 200)

        res = self.app_client.get("/api/firewall/blocked")
        self.assertEqual(res.status_code, 200)

    # -------------------------------------------------------------
    # 7. Snort Alert Log Reader Tests
    # -------------------------------------------------------------
    def test_snort_reader_parser(self):
        sample_block = (
            "08/14-00:15:30.123456 [**] [1:1000001:1] ICMP Ping Flood Detected [**] "
            "[Classification: Attempted Denial of Service] [Priority: 1] "
            "{ICMP} 198.51.100.99 -> 192.168.1.1"
        )
        parsed = parse_alert_block(sample_block)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["severity"], "HIGH")
        self.assertEqual(parsed["src_ip"], "198.51.100.99")
        self.assertEqual(parsed["dst_ip"], "192.168.1.1")
        self.assertEqual(parsed["protocol"], "ICMP")
        self.assertEqual(parsed["type"], "SNORT_SIGNATURE")

        # Invalid block returns None
        self.assertIsNone(parse_alert_block("Invalid log line without pattern"))

    # -------------------------------------------------------------
    # 8. Network Monitor Tests (DNS Entropy & ARP Alert)
    # -------------------------------------------------------------
    def test_network_monitors(self):
        # Normal domain low entropy vs high entropy payload
        low_ent = shannon_entropy("google.com")
        high_ent = shannon_entropy("a8f9x0z1q9w8e7r6t5y4z3a2b1c.c2exfil.org")
        self.assertLess(low_ent, 3.5)
        self.assertGreater(high_ent, 3.5)

    def test_cicids_flow_collector(self):
        collector = FlowCollector(idle_seconds=1, min_packets=2)
        collector.add("203.0.113.10", "192.0.2.20", 51000, 443, "TCP", 60,
                      syn=1, window=64240, now=100.0)
        flow = collector.add("203.0.113.10", "192.0.2.20", 51000, 443, "TCP", 120,
                             ack=1, fin_or_rst=True, now=101.0)
        features, duration = flow.features()
        self.assertEqual(features.shape, (1, 15))
        self.assertEqual(features[0, 0], 443)       # destination port
        self.assertEqual(features[0, 2], 2)         # forward packet count
        self.assertEqual(features[0, 3], 180)       # forward byte count
        self.assertEqual(features[0, 1], 1_000_000) # duration is microseconds
        self.assertEqual(duration, 1.0)


    # -------------------------------------------------------------
    # 9. Alert Correlator & Attack Simulator Tests
    # -------------------------------------------------------------
    def test_correlator_and_attack_sim(self):
        self.assertIn("SNORT_SIGNATURE", KNOWN_ALERT_TYPES)
        self.assertIn("ML_ANOMALY", KNOWN_ALERT_TYPES)
        self.assertIn("CORRELATED_ATTACK", KNOWN_ALERT_TYPES)
        self.assertGreater(len(ATTACKER_IPS), 0)

    # -------------------------------------------------------------
    # 10. Victim Agent SQL Injection Detector Tests
    # -------------------------------------------------------------
    def test_victim_agent_sqli(self):
        self.assertTrue(check_sqli("SELECT * FROM users WHERE '1'='1'", "198.51.100.1"))
        self.assertTrue(check_sqli("admin' OR 1=1 --", "198.51.100.1"))
        self.assertFalse(check_sqli("normal user request login query", "198.51.100.1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
