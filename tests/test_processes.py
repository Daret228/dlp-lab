import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dlp.processes import identify, ProcessIdentity, TelegramAdapter, ProcessFilter, load_process_config
from dlp.policy import load_policy, PolicyError
from dlp.analysis import ContentAnalyzer
from dlp.audit import JsonAudit
from dlp.fanotify import process_event, OPEN_PERM, RESPONSE
from dlp.correlation import AccessCorrelator

ROOT = Path(__file__).resolve().parents[1]


class ProcessTests(unittest.TestCase):
    def test_current_identity_and_wrong_name(self):
        identity = identify(os.getpid())
        self.assertEqual(identity.uid, os.getuid())
        self.assertGreater(identity.start_ticks, 0)
        self.assertTrue(TelegramAdapter('test', [identity.executable]).matches(identity))
        self.assertFalse(TelegramAdapter('telegram', ['/opt/telegram-desktop/Telegram']).matches(identity))
        self.assertIsNone(identify(-1))
        self.assertIsNone(identify(99999999))

    def test_inode_mismatch(self):
        identity = identify(os.getpid())
        fake = ProcessIdentity(identity.pid, identity.uid, identity.executable, identity.start_ticks, identity.device, identity.inode+1)
        self.assertFalse(TelegramAdapter('test', [identity.executable]).matches(fake))

    def test_same_messenger_processes_merge(self):
        identity = identify(os.getpid())
        st = (ROOT/'examples/secret.txt').stat()
        corr = AccessCorrelator(capacity=1)
        first = corr.observe(identity, st)
        self.assertEqual(corr.observe(identity, st)['repeat_count'], 2)
        restarted = ProcessIdentity(identity.pid, identity.uid, identity.executable, identity.start_ticks+1, identity.device, identity.inode)
        self.assertEqual(corr.observe(restarted, st)['group_id'], first['group_id'])
        self.assertEqual(len(corr.groups), 1)

    def test_expiry(self):
        corr = AccessCorrelator()
        with patch('dlp.correlation.time.monotonic', side_effect=[1, 31]):
            a = corr.observe(identify(os.getpid()), (ROOT/'examples/secret.txt').stat())
            b = corr.observe(identify(os.getpid()), (ROOT/'examples/secret.txt').stat())
        self.assertNotEqual(a['group_id'], b['group_id'])

    def test_window_is_bounded_from_first_open(self):
        identity=identify(os.getpid());st=(ROOT/'examples/secret.txt').stat()
        corr=AccessCorrelator()
        with patch('dlp.correlation.time.monotonic',side_effect=[0,4,8,12,16,20,24,28,30]):
            groups=[corr.observe(identity,st) for _ in range(9)]
        self.assertEqual([g['repeat_count'] for g in groups],[1,2,3,4,5,6,7,8,1])
        self.assertNotEqual(groups[0]['group_id'],groups[-1]['group_id'])

    def test_file_version_user_and_messenger_stay_separate(self):
        from dataclasses import replace
        from types import SimpleNamespace
        identity=identify(os.getpid());st=(ROOT/'examples/secret.txt').stat()
        values={k:getattr(st,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')}
        corr=AccessCorrelator();first=corr.observe(identity,st)['group_id']
        for field in values:
            changed=SimpleNamespace(**{**values,field:values[field]+1})
            self.assertNotEqual(first,corr.observe(identity,changed)['group_id'])
        for changed in (replace(identity,uid=identity.uid+1),replace(identity,executable='/different'),replace(identity,inode=identity.inode+1)):
            self.assertNotEqual(first,corr.observe(changed,st)['group_id'])
        self.assertIsNone(corr.observe(None,st)['group_id'])

    def test_filter_enforcement(self):
        identity = identify(os.getpid())
        analyzer = ContentAnalyzer(load_policy(ROOT/'config/policy.yaml'))
        for observed, executable, mode, expected, reason in [
            (identity, identity.executable, 'messengers', 2, None),
            (identity, '/not/telegram', 'messengers', 1, 'process_out_of_scope'),
            (None, identity.executable, 'messengers', 2, 'process_identity_unknown'),
            (identity, '/not/telegram', 'all', 2, None),
        ]:
            config = {'mode': mode, 'uid': os.getuid(), 'messengers': {'test': {'enabled': True, 'executables': [executable]}}}
            fd = os.open(ROOT/'examples/secret.txt', os.O_RDONLY)
            r, w = os.pipe()
            stream = io.StringIO()
            try:
                with patch('dlp.fanotify.identify', return_value=observed):
                    process_event(w, OPEN_PERM, fd, os.getpid(), analyzer, JsonAudit(stream), ProcessFilter(config), AccessCorrelator())
                self.assertEqual(RESPONSE.unpack(os.read(r, 8))[1], expected)
                record = json.loads(stream.getvalue())
                self.assertEqual(record['result']['reason'], reason)
                self.assertEqual(record['correlation']['status'], 'access_only')
            finally:
                os.close(r)
                os.close(w)

    def test_wrong_uid_does_not_match(self):
        identity = identify(os.getpid())
        filt = ProcessFilter({'mode': 'messengers', 'uid': identity.uid+1, 'messengers': {'test': {'enabled': True, 'executables': [identity.executable]}}})
        self.assertIsNone(filt.match(identity))

    def test_config_validation(self):
        import yaml
        config = load_process_config(ROOT/'config/processes.yaml')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'processes.yaml'
            for key, value in [('uid', 0), ('mode', 'oops'), ('messengers', {'telegram': {'enabled': True, 'executables': ['relative']}})]:
                p = {**config, key: value}
                path.write_text(yaml.safe_dump(p))
                with self.assertRaises(PolicyError):
                    load_process_config(path)
