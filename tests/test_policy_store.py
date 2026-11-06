import copy
import io
import json
from email.message import Message
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
from dlp.policy_store import PolicyStore, Conflict, ROOT
from dlp.policy import load_policy, PolicyError


class PolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'policy.yaml'
        self.raw=(ROOT/'config/policy.yaml').read_bytes();self.path.write_bytes(self.raw)
        self.store=PolicyStore(self.path,Path(self.temp.name)/'backups')
        view=self.store.get();self.body=dict(view);self.body['expected_version']=self.body.pop('version')

    def test_preview_noop_and_save_preserve_other_settings_and_backup(self):
        self.assertFalse(self.store.update(self.body)['saved'])
        self.assertEqual(self.path.read_bytes(),self.raw)
        original=load_policy(self.path)
        self.body['thresholds']={'warn':0.2,'block':0.8}
        self.assertTrue(self.store.update(self.body,preview=True)['changes'])
        self.assertEqual(self.path.read_bytes(),self.raw)
        result=self.store.update(self.body)
        self.assertTrue(result['saved']);self.assertTrue(result['restart_required'])
        backup=self.store.backups/result['backup']
        self.assertEqual(backup.read_bytes(),self.raw);self.assertEqual(backup.stat().st_mode&0o777,0o600)
        changed=load_policy(self.path)
        for k in original:
            if k!='thresholds':self.assertEqual(changed[k],original[k])
        with self.assertRaises(Conflict):self.store.update(self.body)

    def test_invalid_values_cannot_write(self):
        for change in [{'thresholds':{'warn':0.8,'block':0.7}}, {'thresholds':{'warn':True,'block':1}},
                       {'thresholds':{'warn':0,'block':float('nan')}}, {'on_error':'other'}, {'sensitive_enabled':1}, {'rules':[]}]:
            body=copy.deepcopy(self.body);body.update(change)
            with self.assertRaises(PolicyError):self.store.update(body)
            self.assertEqual(self.path.read_bytes(),self.raw)

    def test_external_edit_and_backup_failure(self):
        self.path.write_bytes(self.raw+b'\n')
        with self.assertRaises(Conflict):self.store.update(self.body)
        self.path.write_bytes(self.raw);self.body['sensitive_enabled']=False
        with patch('dlp.policy_store.os.replace',side_effect=OSError('disk')):
            with self.assertRaises(OSError):self.store.update(self.body)
        self.assertEqual(self.path.read_bytes(),self.raw)
