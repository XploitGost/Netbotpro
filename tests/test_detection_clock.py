from datetime import datetime, timezone
import os
import unittest
from unittest.mock import patch
from core.detection_clock import detection_time
from core.ids_signature import SignatureIDS
from core.incident_engine import IncidentCorrelator
from core.ids_rules_engine import RuleEngine
import tempfile
from pathlib import Path


class DetectionClockTests(unittest.TestCase):
    def test_rules_and_incidents_use_captured_windows(self):
        with tempfile.TemporaryDirectory() as folder:
            rules = RuleEngine(str(Path(folder)/'missing.json'))
            rules.rules = [dict(name='test', dport=22, window_sec=3, count_threshold=2)]
            incidents = IncidentCorrelator(window_sec=3)
            with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='1'):
                first = dict(src='192.0.2.1', dst='192.0.2.2', dport=22, ts='2000-01-01T00:00:00Z')
                second = dict(first, ts='2000-01-01T00:00:04Z')
                self.assertIsNone(rules.analyze(first))
                self.assertIsNone(rules.analyze(second))
                a, b = dict(attack_type='test', score=.5), dict(attack_type='test', score=.5)
                incidents.enrich_alert(first, a)
                incidents.enrich_alert(second, b)
                self.assertNotEqual(a['incident_id'], b['incident_id'])
                self.assertEqual(b['incident_count'], 1)
    def test_journal_replay_uses_event_windows_not_replay_speed(self):
        detector = SignatureIDS()
        detector.flood_threshold = 2
        detector.custom_rules = []
        with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='1'):
            for ts in ('2000-01-01T00:00:00Z', '2000-01-01T00:00:04Z'):
                self.assertIsNone(detector.analyze_packet(dict(src='192.0.2.1', proto='ICMP', ts=ts)))
            alert = detector.analyze_packet(dict(src='192.0.2.1', proto='ICMP', ts='2000-01-01T00:00:05Z'))
            self.assertEqual(alert['attack_type'], 'Generic Flood / High Rate')
            self.assertEqual(alert['score'], 2)

    def test_fallback_and_normal_mode_and_utc_conversion(self):
        fallback = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='0'):
            self.assertEqual(detection_time({'ts':'2000-01-01T00:00:00Z'}, fallback), fallback)
        with patch.dict(os.environ, NETBOT_CAPTURE_JOURNAL='1'):
            for value in (None, 'bad', '12:00:00', float('inf')):
                self.assertEqual(detection_time({'ts':value}, fallback), fallback)
            self.assertEqual(detection_time({'ts':'2026-01-01T03:30:00+03:30'}, fallback), fallback)
            self.assertEqual(detection_time({'ts':0}, fallback), datetime(1970,1,1,tzinfo=timezone.utc))
