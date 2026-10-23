"""Native broker transport test without root, fanotify or real Telegram access."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('cc') and os.getuid() > 0, 'Native fixture expects compiler and non-root UID')
class NativeBrokerTests(unittest.TestCase):
    def test_identity_fd_passing_and_reply(self):
        with tempfile.TemporaryDirectory(prefix='dlp-native-test-') as tmp:
            binary = Path(tmp)/'broker-harness'
            data = Path(tmp)/'public.txt'
            data.write_text('public')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                            '-DDLP_PERMISSION_SECONDS=1', '-DTELEGRAM="'+str(binary)+'"', str(ROOT/'tests/native_broker_harness.c'),
                            '-o', str(binary)], check=True, capture_output=True)
            result = subprocess.run([str(binary),str(data)], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
