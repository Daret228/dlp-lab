import io
import json
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from dlp.audit import JsonAudit
from dlp import local_job, notifications, service
from dlp.telegram_local import StorageError
from test_telegram_local import fixture


class LocalJobTests(unittest.TestCase):
    def test_real_worker_and_journal_safe_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture(Path(tmp))
            args=SimpleNamespace(root=Path(tmp),marker='DLP_STORAGE_TEST',expected_path=None,policy='config/policy.yaml')
            out=io.StringIO()
            with patch.object(local_job,'require_telegram_closed'), patch('dlp.notifications.desktop_warning'):
                with patch.object(local_job,'report_warning',return_value='accepted') as notify:
                    code=local_job.run_local(args,JsonAudit(out))
            self.assertEqual(code,0)
            events=[json.loads(s) for s in out.getvalue().splitlines()]
            self.assertEqual(events[1]['result']['decision'],'BLOCK')
            self.assertEqual(len({e['run_id'] for e in events}),1)
            self.assertNotIn('коммерческая тайна',out.getvalue())
            notify.assert_called_once()

    def test_running_telegram_prevents_all_reads(self):
        out=io.StringIO()
        with patch.object(local_job,'require_telegram_closed',side_effect=StorageError('telegram_is_running_close_application')), patch.object(local_job.subprocess,'run') as run:
            self.assertEqual(local_job.run_local(SimpleNamespace(),JsonAudit(out)),2)
            run.assert_not_called()
        self.assertFalse(json.loads(out.getvalue().splitlines()[-1])['complete'])

    def test_notification_statuses(self):
        with patch('shutil.which',return_value=None):
            self.assertEqual(notifications.desktop_warning('BLOCK'),'unavailable')
        with patch('shutil.which',return_value='/usr/bin/notify-send'):
            for code,status in ((0,'accepted'),(1,'failed')):
                with patch('subprocess.run',return_value=subprocess.CompletedProcess([],code)):
                    self.assertEqual(notifications.desktop_warning('WARN'),status)
            with patch('subprocess.run',side_effect=subprocess.TimeoutExpired([],5)):
                self.assertEqual(notifications.desktop_warning('BLOCK'),'timeout')

    def test_dbus_fallback_uses_fixed_method(self):
        with patch('shutil.which',side_effect=[None,'/usr/bin/gdbus']), patch('subprocess.run',return_value=subprocess.CompletedProcess([],0)) as run:
            self.assertEqual(notifications.desktop_warning('BLOCK'),'accepted')
            command=run.call_args.args[0]
            self.assertIn('org.freedesktop.Notifications.Notify',command)
            self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_delivery_does_not_claim_display(self):
        out=io.StringIO()
        notifications.report_warning(JsonAudit(out),'BLOCK','test',lambda _: 'accepted')
        self.assertFalse(json.loads(out.getvalue())['display_confirmed'])

    def test_service_local_and_test_are_bounded_journal_jobs(self):
        command=service.launch_command('local','config/policy.yaml',root=Path('/tmp/own profile'),marker='DLP_STORAGE_TEST')
        self.assertIn('--wait',command)
        self.assertIn('local-check',command)
        self.assertIn('/tmp/own profile',command)
        self.assertIn('--property=StandardOutput=journal',command)
        self.assertIn('notification-test-worker',service.launch_command('notification-test','config/policy.yaml'))
