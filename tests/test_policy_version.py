import hashlib
from pathlib import Path
import tempfile
import unittest
from dlp.policy import load_policy_snapshot
from dlp.policy_store import ROOT
from dlp.journal_view import attach_policy_versions, project
import json


class PolicyVersionTests(unittest.TestCase):
    def test_loaded_snapshot_survives_file_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'policy.yaml'
            raw=(ROOT/'config/policy.yaml').read_bytes();path.write_bytes(raw)
            policy,version=load_policy_snapshot(path)
            path.write_bytes(raw+b'\n')
            self.assertEqual(version,hashlib.sha256(raw).hexdigest())
            self.assertNotEqual(version,load_policy_snapshot(path)[1])
            self.assertEqual(policy,load_policy_snapshot(path)[0])

    def test_only_current_running_invocation_confirms_version(self):
        module={'unit':'dlp-lab-files.service','active':'active','invocation':'a'*32}
        event={'event':'policy_loaded','unit':module['unit'],'invocation':'b'*32,'policy_version':'c'*64}
        attach_policy_versions([module],[event],'c'*64)
        self.assertIsNone(module['policy_version'])
        event['invocation']='a'*32
        attach_policy_versions([module],[event],'c'*64)
        self.assertTrue(module['policy_matches_disk'])
        attach_policy_versions([module],[event],'d'*64)
        self.assertFalse(module['policy_matches_disk'])
        module['active']='inactive'
        attach_policy_versions([module],[event],'c'*64)
        self.assertIsNone(module['policy_version'])

    def test_version_projection_rejects_arbitrary_strings(self):
        raw={'MESSAGE':json.dumps({'event':'policy_loaded','policy_version':'secret'}),
             '_SYSTEMD_INVOCATION_ID':'invalid','__REALTIME_TIMESTAMP':'1791958500000000'}
        event=project(raw)
        self.assertIsNone(event['policy_version']);self.assertIsNone(event['invocation'])
