import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from dlp.filesystem_scope import configured_exclusions, default_exclusions, excluded

ROOT = Path(__file__).resolve().parents[1]
BASE = 'uid=2042\ngid=2043\nhome=/home/test operator\nproject=/srv/dlp project\ntelegram=/opt/client/Telegram\nexclude=/home/test operator/.cache\n'


@unittest.skipUnless(shutil.which('cc'), 'C compiler needed')
class ConfigParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='dlp-config-tests-')
        cls.binary = Path(cls.tmp.name)/'parser'
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                        str(ROOT/'tests/native_config_harness.c'),'-o',str(cls.binary)],check=True,capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def parse(self, data):
        file = Path(self.tmp.name)/'config'
        file.write_bytes(data.encode() if isinstance(data,str) else data)
        return subprocess.run([str(self.binary),str(file)],capture_output=True,text=True,timeout=3)

    def test_other_account_paths_with_spaces_and_protected_metadata(self):
        result = self.parse(BASE)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.splitlines()[:5],['2042','2043','/home/test operator','/srv/dlp project','/opt/client/Telegram'])

    def test_rejects_unknown_duplicate_missing_and_privileged_ids(self):
        for value in [BASE+'uid=2042\n',BASE+'command=/bin/sh\n',BASE.replace('gid=2043\n',''),
                      BASE.replace('uid=2042','uid=0'), BASE.replace('gid=2043','gid=0'),
                      BASE.replace('uid=2042','uid=-1'), BASE.replace('uid=2042','uid=4294967295'),
                      BASE.replace('uid=2042','uid=12x'), BASE.rstrip('\n')]:
            with self.subTest(value=value[:20]):
                self.assertEqual(self.parse(value).returncode,2)

    def test_rejects_bad_paths_and_oversized_config(self):
        for path in ['relative','/a/../b','/a/./b','/a//b','/a/..','/a/.','/a/', '/a:b','/a\\b','/a\tb','/a\x00b','/'+'x'*4096]:
            with self.subTest(path=path[:20]):
                self.assertEqual(self.parse(BASE.replace('/srv/dlp project',path)).returncode,2)
        self.assertEqual(self.parse(BASE+'exclude=/\n').returncode,2)
        self.assertEqual(self.parse(BASE+'exclude=/data\n'*33).returncode,2)
        self.assertEqual(self.parse(BASE+('#'+'x'*2000+'\n')*40).returncode,2)

    def test_optional_signal_and_legacy_config(self):
        self.assertEqual(self.parse(BASE+'signal=/opt/Signal/signal-desktop\n').returncode,0)
        for extra in ('signal=relative\n', 'signal=/opt/client/Telegram\n',
                      'signal=/opt/Signal/signal-desktop\nsignal=/other/path\n'):
            self.assertEqual(self.parse(BASE+extra).returncode,2)

    def test_empty_exclusions_are_explicitly_supported(self):
        self.assertEqual(self.parse(BASE.replace('exclude=/home/test operator/.cache\n','')).returncode,0)


class ScopeConfigTests(unittest.TestCase):
    def test_home_is_not_hardcoded(self):
        roots=default_exclusions('/srv/alice')
        self.assertTrue(excluded('/srv/alice/.cache/file',roots))
        self.assertFalse(excluded('/home/roman/.cache/file',roots))
        self.assertFalse(excluded('/srv/alice/.cache-other/file',roots))

    def test_administrative_exclusions_replace_defaults(self):
        with patch.dict(os.environ,{'DLP_EXCLUDED_ROOTS':'/data/runtime\n'}):
            self.assertEqual(configured_exclusions(),('/data/runtime',))
        with patch.dict(os.environ,{'DLP_EXCLUDED_ROOTS':''}):
            self.assertEqual(configured_exclusions(),())
        with patch.dict(os.environ,{'DLP_EXCLUDED_ROOTS':'/\n'}):
            with self.assertRaises(ValueError): configured_exclusions()

class HostSetupTests(unittest.TestCase):
    def test_relocates_process_adapter_and_preserves_original(self):
        import yaml
        from dlp.host_setup import configure_processes
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'processes.yaml'
            original={'version':1,'uid':2042,'mode':'all','messengers':{
                'telegram':{'enabled':False,'executables':['/old/client']},
                'express':{'enabled':False,'executables':[]}}}
            path.write_text(yaml.safe_dump(original))
            old=path.read_bytes()
            self.assertTrue(configure_processes(path,'/usr/bin/cat'))
            changed=yaml.safe_load(path.read_text())
            self.assertEqual(changed['uid'],os.getuid())
            self.assertEqual(changed['mode'],'messengers')
            self.assertEqual(changed['messengers']['express'],original['messengers']['express'])
            self.assertEqual(path.with_suffix('.yaml.previous').read_bytes(),old)
            self.assertFalse(configure_processes(path,'/usr/bin/cat'))

    def test_failure_does_not_replace_config(self):
        from dlp.host_setup import configure_processes
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'processes.yaml'
            path.write_text('broken: true\n')
            with self.assertRaises(ValueError): configure_processes(path,'/usr/bin/cat')
            self.assertEqual(path.read_text(),'broken: true\n')
