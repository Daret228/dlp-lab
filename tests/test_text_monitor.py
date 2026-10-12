import io
import json
from pathlib import Path
import unittest
from dlp.analysis import ContentAnalyzer
from dlp.policy import load_policy
from dlp.audit import JsonAudit
from dlp.text_monitor import DraftMonitor

ROOT = Path(__file__).resolve().parents[1]


class DraftTests(unittest.TestCase):
    def test_changes_analyzed_without_claiming_send_block(self):
        output = io.StringIO()
        notifications = []
        monitor = DraftMonitor(ContentAnalyzer(load_policy(ROOT/'config/policy.yaml')), JsonAudit(output), notifications.append)
        for text in ['Открытый текст', 'test@example.org', 'коммерческая тайна']:
            monitor.check(text, 'telegram', 1)
            self.assertIsNone(monitor.check(text, 'telegram', 1))
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([e['result']['decision'] for e in events if e['event'] == 'draft_analysis'], ['ALLOW','WARN','BLOCK'])
        self.assertEqual(notifications, ['WARN','BLOCK'])
        self.assertTrue(all(not e['send_blocked'] and e['enforcement']=='observe_only' for e in events if e['event'] == 'draft_analysis'))
        self.assertNotIn('коммерческая тайна', output.getvalue())
        self.assertNotIn('test@example.org', output.getvalue())

    def test_deletion_is_not_send_confirmation(self):
        output = io.StringIO()
        monitor = DraftMonitor(ContentAnalyzer(load_policy(ROOT/'config/policy.yaml')), JsonAudit(output))
        monitor.check('top secret', 'telegram', 1)
        monitor.check('', 'telegram', 1)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertFalse(events[-1]['send_confirmed'])
        self.assertEqual(events[-1]['result']['decision'], 'ALLOW')

class BindingWaitTests(unittest.TestCase):
    def test_waits_for_late_field(self):
        from unittest.mock import Mock, patch
        from dlp.text_monitor import wait_for_binding
        scan = Mock(side_effect=[[], [('identity', 'field')]])
        with patch('dlp.text_monitor.time.sleep'):
            self.assertEqual(wait_for_binding(scan), [('identity', 'field')])

    def test_missing_field_explains_accessibility(self):
        from dlp.text_monitor import wait_for_binding
        with self.assertRaisesRegex(ValueError, 'QT_LINUX_ACCESSIBILITY_ALWAYS_ON'):
            wait_for_binding(lambda: [], seconds=0)

    def test_multiple_fields_not_selected_arbitrarily(self):
        from dlp.text_monitor import wait_for_binding
        with self.assertRaisesRegex(ValueError, 'нескольких'):
            wait_for_binding(lambda: [('one', 'a'), ('two', 'b')])
