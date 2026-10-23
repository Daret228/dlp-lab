"""Two explicit messenger targets; no live profiles or root operations."""
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dlp.filesystem_scope import run_filesystems
from dlp.processes import ProcessFilter

ROOT=Path(__file__).resolve().parents[1]

class SignalGatewayTests(unittest.TestCase):
    def test_packaged_configuration_is_optional_and_distinct(self):
        spec=importlib.util.spec_from_file_location('admin_configure',ROOT/'packaging/admin_configure.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        account=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_dir='/home/test')
        gateway,processes=module.configuration(account,'/opt/Telegram','/opt/Signal/signal-desktop')
        self.assertIn(b'signal=/opt/Signal/signal-desktop\n',gateway)
        self.assertEqual(set(json.loads(processes)['messengers']),{'telegram','signal','express'})
        self.assertNotIn(b'signal=',module.configuration(account,'/opt/Telegram')[0])
        with self.assertRaises(ValueError):module.configuration(account,'/same','/same')

    def test_worker_rejects_missing_or_misnamed_signal_before_handshake(self):
        for messengers in (
            {'telegram':{'enabled':True,'executables':['/usr/bin/cat']}},
            {'telegram':{'enabled':True,'executables':['/usr/bin/cat']},
             'other':{'enabled':True,'executables':['/usr/bin/echo']}}):
            filt=ProcessFilter({'uid':os.getuid(),'mode':'messengers','messengers':messengers})
            with patch.dict(os.environ,{'DLP_TARGET_EXECUTABLE':'/usr/bin/cat',
                                        'DLP_SIGNAL_EXECUTABLE':'/usr/bin/echo'}):
                with self.assertRaisesRegex(ValueError,'signal target'):
                    run_filesystems(-1,None,None,filt,None,None,None)
