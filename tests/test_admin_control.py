from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from dlp import admin_control
from dlp.admin_control import execute, validate_job, authorized_peer, installed_version

VALID = Path(__file__).resolve().parents[1] / 'config/policy.yaml'


class BrokerTests(unittest.TestCase):
    def job(self, kind='restart_files'):
        return {'id':'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa','kind':kind,'expires':time.time()+60}

    def test_fixed_unit_and_replay_does_not_repeat_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            runner=Mock()
            db=Path(folder)/'actions.sqlite'
            self.assertEqual(execute(self.job(),db,runner)['status'],'completed')
            execute(self.job(),db,runner)
            self.assertEqual(runner.call_count,2)
            self.assertEqual(runner.call_args_list[0].args[0],['/usr/bin/systemctl','restart','dlp-lab-files.service'])
            with self.assertRaises(ValueError):execute(self.job('restart_session'),db,runner)

    def test_unknown_or_expired_or_extra_payload_never_executes(self):
        for patch in [{'kind':'shell'},{'kind':'restart_ssh'},{'kind':'apply_policy'},{'expires':0},{'id':'../../etc/passwd'},{'command':'id'}]:
            with self.assertRaises((ValueError,TypeError)):validate_job({**self.job(),**patch})

    def test_failed_and_uncertain_actions_not_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Path(folder)/'db';runner=Mock(side_effect=subprocess.TimeoutExpired('systemctl',20))
            self.assertEqual(execute(self.job(),db,runner)['status'],'failed')
            execute(self.job(),db,runner);self.assertEqual(runner.call_count,1)
            with closing(sqlite3.connect(db)) as c, c:c.execute("UPDATE actions SET status='running'")
            self.assertEqual(execute(self.job(),db,runner)['status'],'failed')
            self.assertEqual(runner.call_count,1)

    def test_unix_peer_uses_kernel_uid(self):
        left,right=socket.socketpair()
        with left,right:
            self.assertTrue(authorized_peer(left,os.getuid()))
            if os.getuid()!=0:self.assertFalse(authorized_peer(left,os.getuid()+1))


class PolicyInstallTests(unittest.TestCase):
    def job(self):
        return {'id':'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb','kind':'install_policy','expires':time.time()+60}

    def install(self, folder, staged, installed=b'old: policy\n'):
        policy = Path(folder)/'etc'/'policy.yaml'
        policy.parent.mkdir()
        policy.write_bytes(installed)
        incoming = Path(folder)/'incoming.yaml'
        incoming.write_bytes(staged if isinstance(staged, bytes) else staged.encode())
        return policy, incoming, Path(folder)/'backups'

    def test_install_validates_backs_up_replaces_and_restarts(self):
        with tempfile.TemporaryDirectory() as folder:
            policy,incoming,backups = self.install(folder, VALID.read_bytes())
            runner = Mock()
            with patch.object(admin_control,'POLICY',str(policy)), \
                 patch.object(admin_control,'INCOMING',str(incoming)), \
                 patch.object(admin_control,'BACKUPS',str(backups)):
                self.assertEqual(execute(self.job(), Path(folder)/'db', runner)['status'],'completed')
                self.assertEqual(policy.read_bytes(), VALID.read_bytes())
                self.assertEqual(policy.stat().st_mode & 0o777, 0o644)
                saved = backups/(hashlib.sha256(b'old: policy\n').hexdigest()+'.yaml')
                self.assertEqual(saved.read_bytes(), b'old: policy\n')
                self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
                self.assertEqual(backups.stat().st_mode & 0o777, 0o700)
                self.assertEqual(runner.call_count, 4)
                self.assertEqual([c.args[0] for c in runner.call_args_list],
                                 [['/usr/bin/systemctl','restart','dlp-lab-files.service'],
                                  ['/usr/bin/systemctl','is-active','--quiet','dlp-lab-files.service'],
                                  ['/usr/bin/systemctl','restart','dlp-lab-session.service'],
                                  ['/usr/bin/systemctl','is-active','--quiet','dlp-lab-session.service']])
                self.assertEqual(installed_version(), hashlib.sha256(VALID.read_bytes()).hexdigest())

    def test_invalid_or_oversized_staged_policy_fails_without_touching_installed(self):
        for staged in (b'this is not yaml: [', b'a'*(262145)):
            with tempfile.TemporaryDirectory() as folder:
                policy,incoming,backups = self.install(folder, staged)
                runner = Mock()
                with patch.object(admin_control,'POLICY',str(policy)), \
                     patch.object(admin_control,'INCOMING',str(incoming)), \
                     patch.object(admin_control,'BACKUPS',str(backups)):
                    self.assertEqual(execute(self.job(), Path(folder)/'db', runner)['status'],'failed')
                self.assertEqual(policy.read_bytes(), b'old: policy\n')
                runner.assert_not_called()
                self.assertFalse(backups.exists() and any(backups.iterdir()))

    def test_install_replay_and_missing_staged_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            policy,incoming,backups = self.install(folder, VALID.read_bytes())
            db = Path(folder)/'db'
            with patch.object(admin_control,'POLICY',str(policy)), \
                 patch.object(admin_control,'INCOMING',str(incoming)), \
                 patch.object(admin_control,'BACKUPS',str(backups)):
                self.assertEqual(execute(self.job(), db, Mock())['status'],'completed')
                runner = Mock()
                self.assertEqual(execute(self.job(), db, runner)['status'],'completed')
                runner.assert_not_called()  # recorded intent is never repeated
                incoming.unlink()
                other = {'id':'cccccccc-cccc-4ccc-cccc-cccccccccccc','kind':'install_policy','expires':time.time()+60}
                self.assertEqual(execute(other, db, Mock())['status'],'failed')

    def test_restart_failure_restores_previous_policy_and_recovers_both_units(self):
        import subprocess
        with tempfile.TemporaryDirectory() as folder:
            previous=VALID.read_bytes()
            policy,incoming,backups=self.install(folder, previous+b'\n', previous)
            runner=Mock(side_effect=[subprocess.CalledProcessError(1,'systemctl'),None,None,None,None])
            with patch.object(admin_control,'POLICY',str(policy)), patch.object(admin_control,'INCOMING',str(incoming)), patch.object(admin_control,'BACKUPS',str(backups)):
                self.assertEqual(execute(self.job(),Path(folder)/'db',runner)['status'],'failed')
            self.assertEqual(policy.read_bytes(),previous)
            self.assertEqual(runner.call_count,5)

    def test_symlink_and_fifo_staging_rejected_without_blocking(self):
        for kind in ('symlink','fifo'):
            with tempfile.TemporaryDirectory() as folder:
                policy,incoming,backups=self.install(folder,VALID.read_bytes())
                incoming.unlink()
                if kind=='symlink':incoming.symlink_to(policy)
                else:os.mkfifo(incoming)
                runner=Mock()
                with patch.object(admin_control,'POLICY',str(policy)), patch.object(admin_control,'INCOMING',str(incoming)), patch.object(admin_control,'BACKUPS',str(backups)):
                    self.assertEqual(execute(self.job(),Path(folder)/'db',runner)['status'],'failed')
                runner.assert_not_called()
