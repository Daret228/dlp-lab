"""Opt-in real Linux permission-event test, never enabled by ordinary make test."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('DLP_RUN_PRIVILEGED') == '1' and os.geteuid() == 0,
                     'Requires explicit DLP_RUN_PRIVILEGED=1 and root on test host')
class KernelIntegration(unittest.TestCase):
    def test_allow_warn_deny_and_release(self):
        uid = int(os.environ.get('DLP_TEST_UID', '1000'))
        gid = int(os.environ.get('DLP_TEST_GID', '1000'))
        self.assertGreater(uid, 0)
        self.assertGreater(gid, 0)
        def demote():
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
        with tempfile.TemporaryDirectory(prefix='dlp-kernel-') as tmp:
            base = Path(tmp)
            base.chmod(0o755)
            watch = base/'watch'
            watch.mkdir(mode=0o700)
            os.chown(watch, uid, gid)
            for name, text in [('allow', 'public'), ('warn', 'test@example.org'), ('deny', 'top secret')]:
                p = watch/name
                p.write_text(text)
                os.chown(p, uid, gid)
            env = {**os.environ, 'PYTHONPATH': str(ROOT/'src')+':'+str(ROOT/'.deps')}
            worker = subprocess.Popen([str(ROOT/'build/fanotify-launcher'), str(watch), str(uid), str(gid),
                                       '/usr/bin/python3', '-m', 'dlp.cli', '--policy', str(ROOT/'config/policy.yaml'), 'monitor'],
                                      env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      start_new_session=True)
            try:
                ready, _, _ = select.select([worker.stdout], [], [], 5)
                self.assertTrue(ready, 'Worker did not become ready')
                first = worker.stdout.readline()
                self.assertTrue(first, 'Worker exited before startup; check capabilities')
                self.assertEqual(json.loads(first)['uid'], uid)
                for name, expected in [('allow', 0), ('warn', 0), ('deny', 1)]:
                    probe = subprocess.run(['/usr/bin/cat', str(watch/name)], preexec_fn=demote,
                                           capture_output=True, timeout=5)
                    self.assertEqual(probe.returncode, expected, probe.stderr.decode())
                    ready, _, _ = select.select([worker.stdout], [], [], 5)
                    self.assertTrue(ready, 'Missing audit event')
                    record = json.loads(worker.stdout.readline())
                    self.assertEqual(record['enforcement'], 'DENY' if expected else 'ALLOW')
            finally:
                if worker.poll() is None:
                    os.killpg(worker.pid, signal.SIGTERM)
                worker.communicate(timeout=5)
            released = subprocess.run(['/usr/bin/cat', str(watch/'deny')], preexec_fn=demote,
                                      capture_output=True, timeout=5)
            self.assertEqual(released.returncode, 0)
