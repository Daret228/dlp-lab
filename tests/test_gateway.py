"""Unprivileged harness for the separately installed, narrowly authorized gateway."""
import json
import os
from pathlib import Path
import select
import subprocess
import unittest
import uuid
import tempfile


@unittest.skipUnless(os.environ.get('DLP_RUN_GATEWAY') == '1',
                     'Opt in with make privileged-test after installing gateway')
class InstalledGatewayTest(unittest.TestCase):
    def test_allow_warn_block(self):
        self.assertGreater(os.geteuid(), 0, 'Run harness as the target user, not root')
        legacy_watch = Path('/var/lib/dlp-lab/watch')
        gateway = Path('/usr/local/libexec/dlp-lab/fanotify-gateway')
        self.assertTrue(gateway.is_file(), 'Install scripts/install-fanotify-access.sh first')
        prefix = 'dlp-test-' + uuid.uuid4().hex
        cases = [('allow', 'public', 0), ('warn', 'test@example.org', 0), ('block', 'top secret', 1)]
        paths = []
        worker = None
        outside = tempfile.TemporaryDirectory(prefix='dlp-gateway-outside-')
        watch = legacy_watch if legacy_watch.is_dir() and os.access(legacy_watch,os.W_OK) else Path(outside.name)
        try:
            for name, text, _ in cases:
                path = watch / (prefix + '-' + name)
                path.write_text(text, encoding='utf-8')
                paths.append(path)
            worker = subprocess.Popen(['/usr/bin/sudo', '-n', str(gateway)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      bufsize=0)
            def event():
                ready, _, _ = select.select([worker.stdout], [], [], 5)
                self.assertTrue(ready, 'No event within 5 seconds')
                line = worker.stdout.readline()
                if not line:
                    self.fail('Gateway failed: ' + worker.stderr.read().decode())
                return json.loads(line)
            started = event()
            if started['event'] == 'policy_loaded':
                started = event()
            self.assertEqual(started['event'], 'monitor_started')
            self.assertEqual(started['uid'], os.getuid())
            # Worker PID is used only to stop our own unprivileged process.
            worker_pid = started['pid']
            broad = started.get('scope') == 'local_filesystems'
            if broad:
                # In the new architecture the privileged group FD never reaches Python.
                links = [os.readlink(fd) for fd in Path(f'/proc/{worker_pid}/fd').iterdir()]
                self.assertFalse(any('fanotify' in link for link in links))
                self.assertTrue(started['filesystem_roots'])
                for name, text, _ in cases:
                    nested = Path(outside.name)/'nested'/(name+'.txt')
                    nested.parent.mkdir(exist_ok=True)
                    nested.write_text(text)
                    probe = subprocess.run(['/usr/bin/cat',str(nested)], capture_output=True, timeout=5)
                    self.assertEqual(probe.returncode, 0, 'Unrelated cat must not be blocked')
            try:
                status = Path(f'/proc/{worker_pid}/status').read_text()
                values = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
                self.assertEqual(int(values['CapEff'].strip(), 16), 0)
                self.assertEqual(values['NoNewPrivs'].strip(), '1')
                for (name, _, expected), path in zip(cases, paths):
                    if started.get('filter_mode') == 'messengers':
                        expected = 0  # /usr/bin/cat is deliberately not a messenger.
                    probe = subprocess.run(['/usr/bin/cat', str(path)], capture_output=True, timeout=5)
                    self.assertEqual(probe.returncode, expected, probe.stderr.decode())
                    if broad:
                        continue  # Unrelated processes are filtered in the native broker.
                    record = event()
                    self.assertEqual(record['enforcement'], 'DENY' if expected else 'ALLOW')
                    if started.get('filter_mode') == 'messengers':
                        self.assertEqual(record['result']['reason'], 'process_out_of_scope')
                    self.assertFalse(record['send_confirmed'])
            finally:
                import signal
                os.kill(worker_pid, signal.SIGTERM)
            worker.communicate(timeout=5)
            probe = subprocess.run(['/usr/bin/cat', str(paths[-1])], capture_output=True, timeout=5)
            self.assertEqual(probe.returncode, 0, 'Group was not released after worker exit')
        finally:
            if worker is not None:
                # sudo may be a privileged parent; do not assume we can signal it.
                for stream in (worker.stdout, worker.stderr):
                    stream.close()
            for path in paths:
                path.unlink(missing_ok=True)
            outside.cleanup()
