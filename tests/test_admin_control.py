from contextlib import closing
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock
from dlp.admin_control import execute, validate_job, authorized_peer


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
        for patch in [{'kind':'shell'},{'kind':'restart_ssh'},{'expires':0},{'id':'../../etc/passwd'},{'command':'id'}]:
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
