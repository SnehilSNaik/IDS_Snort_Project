"""Isolated regression suite: no real firewall rules, notifications or live DB writes."""
import os
import json
import tempfile
import unittest
from collections import deque
from unittest.mock import patch, Mock

_temp = tempfile.TemporaryDirectory(prefix="ids-block-tests-")
os.environ["IDS_DATA_DIR"] = _temp.name
os.environ["IDS_ALERTS_JSON"] = os.path.join(_temp.name, "legacy.json")
os.environ["IDS_ENDPOINTS_JSON"] = os.path.join(_temp.name, "endpoints.json")

from persistence import event_store as store
from correlator import correlator as c
from firewall import ip_blocker as fw
from dashboard.app import app


class InlineThread:
    def __init__(self, target, args=(), **kwargs):
        self.target, self.args = target, args
    def start(self):
        self.target(*self.args)


class GroupingTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(store.DB_DIR, _temp.name)
        store.clear_alert_history()
        c.alerts_list = deque(maxlen=500)
        c.ip_cache.clear()
        c.dedup_cache.clear()
        self.blocker = Mock()
        self.blocker.get_entry.return_value = None
        self.patches = [
            patch.object(c, "_blocker", self.blocker),
            patch.object(c, "ALERTS_JSON", os.path.join(_temp.name, "feed.json")),
            patch.object(c, "COUNT_JSON", os.path.join(_temp.name, "counts.json")),
            patch.object(c, "_TI_AVAILABLE", False),
            patch.object(c, "_PLAYBOOK_AVAILABLE", False),
            patch.object(c, "touch_alert"), patch.object(c, "_sound_alert"),
            patch.object(c, "send_email_alert"), patch.object(c, "send_telegram_in_background"),
            patch.object(c.threading, "Thread", InlineThread),
            patch("correlator.incident_identity.local_addresses", return_value={"192.0.2.10"}),
            patch.object(c, "DEDUP_WINDOW", 0),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def alert(self, **changes):
        a = dict(src_ip="198.51.100.7", dst_ip="192.0.2.10", type="SNORT_SIGNATURE",
                 snort_sid="1:100:1", protocol="TCP", severity="HIGH", confidence=90,
                 message="Test scan", timestamp="2026-09-29 10:00:00")
        a.update(changes)
        return a

    def block(self, **changes):
        entry = dict(ip="198.51.100.7", firewall_rule=True, blocked_at="block-one")
        entry.update(changes)
        self.blocker.get_entry.return_value = entry

    def test_repeats_update_one_incident_and_preserve_evidence(self):
        c.process_alert(self.alert())
        original_id = c.alerts_list[0]["id"]
        self.block()
        for _ in range(10):
            c.process_alert(self.alert())
        self.assertEqual(len(c.alerts_list), 1)
        self.assertEqual(c.alerts_list[0]["id"], original_id)
        self.assertEqual(c.alerts_list[0]["attempts_after_block"], 10)
        c.send_email_alert.assert_called_once()
        c.send_telegram_in_background.assert_called_once()
        c._sound_alert.assert_called_once()
        with store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM post_block_attempts").fetchone()[0], 10)
        self.assertTrue(store.verify_audit()[0])
        with open(c.COUNT_JSON) as handle:
            self.assertEqual(json.load(handle)["total"], 1)

    def test_grouping_runs_before_short_dedup(self):
        with patch.object(c, "DEDUP_WINDOW", 2):
            c.process_alert(self.alert())
            self.block()
            c.process_alert(self.alert())
        self.assertEqual(c.alerts_list[0]["attempts_after_block"], 1)

    def test_first_observation_with_existing_block_is_counted(self):
        self.block()
        c.process_alert(self.alert())
        self.assertEqual(c.alerts_list[0]["attempts_after_block"], 1)
        c.process_alert(self.alert())
        self.assertEqual(c.alerts_list[0]["attempts_after_block"], 2)

    def test_separate_endpoint_identifiers_stay_separate(self):
        c.process_alert(self.alert(endpoint_id="victim-a"))
        self.block()
        c.process_alert(self.alert(endpoint_id="victim-b"))
        self.assertEqual(len(c.alerts_list), 2)

    def test_failed_rule_does_not_suppress(self):
        self.block(firewall_rule=False)
        c.process_alert(self.alert())
        c.process_alert(self.alert())
        self.assertEqual(len(c.alerts_list), 2)
        self.assertEqual(c.send_email_alert.call_count, 2)

    def test_different_signature_and_victim_are_separate(self):
        c.process_alert(self.alert())
        self.block()
        c.process_alert(self.alert(snort_sid="1:200:1"))
        c.process_alert(self.alert(dst_ip="192.0.2.20"))
        c.process_alert(self.alert(dst_ip="192.0.2.20"))
        self.assertEqual(len(c.alerts_list), 4)

    def test_correlation_keeps_both_identities(self):
        c.process_alert(self.alert())
        c.process_alert(self.alert(type="ML_ANOMALY", snort_sid=None))
        self.assertEqual(len(c.alerts_list), 1)
        self.block()
        c.process_alert(self.alert())
        c.process_alert(self.alert(type="ML_ANOMALY", snort_sid=None))
        self.assertEqual(c.alerts_list[0]["attempts_after_block"], 2)
        c.process_alert(self.alert(snort_sid="1:200:1"))
        self.assertEqual(len(c.alerts_list), 2)

    def test_different_victims_never_correlate(self):
        c.process_alert(self.alert())
        c.process_alert(self.alert(type="ML_ANOMALY", dst_ip="192.0.2.20", snort_sid=None))
        self.assertEqual(len(c.alerts_list), 2)

    def test_reload_retains_identity_and_attempt_count(self):
        c.process_alert(self.alert())
        self.block()
        c.process_alert(self.alert())
        c.load_alerts()
        c.process_alert(self.alert())
        self.assertEqual(len(c.alerts_list), 1)
        self.assertEqual(c.alerts_list[0]["attempts_after_block"], 2)

    def test_unblock_reblock_opens_new_lifecycle(self):
        c.process_alert(self.alert())
        self.block()
        c.process_alert(self.alert())
        self.block(blocked_at="block-two")
        c.process_alert(self.alert())
        self.assertEqual(len(c.alerts_list), 2)
        self.blocker.get_entry.return_value = None
        c.process_alert(self.alert())
        self.assertEqual(len(c.alerts_list), 3)

    def test_reachable_service_disables_suppression(self):
        c.process_alert(self.alert())
        self.block(reachability_checks={"192.0.2.10": {"reachable": True}})
        c.process_alert(self.alert())
        self.assertEqual(len(c.alerts_list), 2)


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        p = patch.object(fw, "BLOCKED_IPS_FILE", os.path.join(self.temp.name, "blocks.json"))
        p.start()
        self.addCleanup(p.stop)

    def test_success_exit_alone_is_not_confirmation(self):
        with patch.object(fw.IPBlocker, "_apply_firewall_rule", return_value=True), patch.object(fw.IPBlocker, "_verify_firewall_rule", return_value=False):
            b = fw.IPBlocker()
            self.assertFalse(b.block_ip("198.51.100.7")["firewall_rule"])
            self.assertEqual(b.get_stats()["blocked_ips"], [])

    def test_removed_rule_becomes_unverified(self):
        with patch.object(fw.IPBlocker, "_apply_firewall_rule", return_value=True), patch.object(fw.IPBlocker, "_verify_firewall_rule", return_value=True) as verify:
            b = fw.IPBlocker()
            self.assertTrue(b.block_ip("198.51.100.7")["firewall_rule"])
            verify.return_value = False
            b._verification.clear()
            self.assertFalse(b.get_entry("198.51.100.7")["firewall_rule"])

    def test_batch_verification_rejects_disabled_firewall_and_wrong_remote(self):
        records = [dict(ip="198.51.100.7", enabled=True, active=False, action=0, direction=1, remote="198.51.100.7"),
                   dict(ip="198.51.100.8", enabled=True, active=True, action=0, direction=1, remote="198.51.100.9"),
                   dict(ip="198.51.100.9", enabled=True, active=True, action=0, direction=1, remote="198.51.100.9")]
        for record in records:
            record.update(protocol=256, local="*", application="", service="", interfaces="All")
        with patch.object(fw.os, "name", "nt"), patch.object(fw.subprocess, "run", return_value=Mock(returncode=0, stdout=json.dumps(records))):
            result = fw.IPBlocker._verify_many([r["ip"] for r in records])
        self.assertEqual(result, {"198.51.100.7": False, "198.51.100.8": False, "198.51.100.9": True})

    def test_operator_result_is_authenticated_and_target_scoped(self):
        import dashboard.app as dashboard
        client = app.test_client()
        blocker = Mock()
        blocker.is_blocked.return_value = False
        with patch.object(dashboard, "_blocker", blocker), patch.object(dashboard, "local_addresses", return_value={"192.0.2.10"}):
            response = client.post('/api/firewall/reachability/198.51.100.7', json={})
            self.assertIn(response.status_code, (302, 401))
            with client.session_transaction() as session:
                session['user_email'] = 'test@local'
            response = client.post('/api/firewall/reachability/198.51.100.7', json={"target_ip": "192.0.2.20", "reachable": True, "note": "TCP 80 connected"})
            self.assertEqual(response.status_code, 400)
            blocker.record_reachability.return_value = {"ip": "198.51.100.7", "firewall_rule": True}
            with patch.object(dashboard, "_record_stage") as stage:
                response = client.post('/api/firewall/reachability/198.51.100.7', json={"target_ip": "192.0.2.10", "reachable": True, "note": "TCP 80 connected from Kali"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(stage.call_args.args[1], 'BLOCK_INEFFECTIVE')


if __name__ == '__main__':
    try:
        unittest.main(verbosity=2)
    finally:
        _temp.cleanup()
