import io
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from dlp.audit import JsonAudit
from dlp.file_notifications import FileWarnings
from dlp.notifications import desktop_file_warning


class FileWarningContextTests(unittest.TestCase):
    def test_history_warning_suppressed_but_denial_delivered(self):
        out = io.StringIO()
        calls = []
        worker = FileWarnings(JsonAudit(out), lambda event: calls.append(event) or 'accepted')
        record = {'path': str(Path.home()/'.local/share/recently-used.xbel'),
                  'enforcement': 'ALLOW', 'result': {'decision': 'WARN', 'metadata': {
                      'sensitive_alerts': {'categories': ['credentials']}}}}
        worker.submit(record)
        worker.submit(dict(record, enforcement='DENY'))
        worker.close()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['enforcement'], 'DENY')
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(events[0]['status'], 'suppressed_desktop_history')

    def test_public_allow_silent_and_confirmed_denial_notifies(self):
        out = io.StringIO()
        calls = []
        worker = FileWarnings(JsonAudit(out), lambda event: calls.append(event) or 'accepted')
        worker.submit({'path': '/tmp/public.pdf', 'enforcement': 'ALLOW', 'result': {'decision': 'ALLOW'}})
        worker.submit({'path': '/tmp/secret.pdf', 'enforcement': 'DENY', 'result': {'decision': 'BLOCK'}})
        worker.close()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['filename'], 'secret.pdf')
        self.assertFalse(calls[0]['send_blocked'])

    def test_message_uses_actual_enforcement_and_escapes_filename(self):
        with patch('dlp.notifications.deliver_notification', return_value='accepted') as deliver:
            desktop_file_warning({'filename': '<file>\n.pdf', 'enforcement': 'DENY', 'decision': 'WARN'})
            title, body = deliver.call_args.args
            self.assertIn('заблокировано', title)
            self.assertIn('&lt;file&gt;?.pdf', body)
            self.assertNotIn('НЕ заблокирована', body)
            desktop_file_warning({'filename': 'file.pdf', 'enforcement': 'ALLOW', 'decision': 'WARN'})
            self.assertIn('разрешён', deliver.call_args.args[1])

    def test_notification_requests_normal_urgency_and_finite_timeout(self):
        from types import SimpleNamespace
        from dlp.notifications import deliver_notification
        for use_notify in (True, False):
            def which(name):
                return '/usr/bin/'+name if name == ('notify-send' if use_notify else 'gdbus') else None
            with patch('dlp.notifications.shutil.which', side_effect=which), patch(
                    'dlp.notifications.subprocess.run', return_value=SimpleNamespace(returncode=0)) as run:
                self.assertEqual(deliver_notification('DLP test', 'synthetic'), 'accepted')
                command=run.call_args.args[0]
                if use_notify:
                    self.assertEqual(command[command.index('-u')+1],'normal')
                    self.assertEqual(command[command.index('-t')+1],'10000')
                else:
                    self.assertIn("{'urgency': <byte 1>}",command)
                    self.assertEqual(command[-1],'10000')
