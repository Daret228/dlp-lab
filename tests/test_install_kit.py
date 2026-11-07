import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('kit',Path(__file__).resolve().parents[1]/'scripts/build-install-kit.py')
kit=importlib.util.module_from_spec(spec);spec.loader.exec_module(kit)


class InstallKitTests(unittest.TestCase):
    def test_private_kit_has_one_command_and_private_registration(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);package=root/'dlp-lab_test.deb';package.write_bytes(b'test')
            registration=root/'device.json';registration.write_text(json.dumps({'server':'https://192.0.2.1:8767','agent_id':'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa','token':'x'*43}));registration.chmod(0o600)
            ca=root/'ca.crt';ca.write_text('synthetic')
            output=root/'device.tar.gz'
            args=['kit','--package',str(package),'--registration',str(registration),'--ca',str(ca),'--output',str(output)]
            with patch('sys.argv',args),patch.object(ssl,'create_default_context'),contextlib.redirect_stdout(io.StringIO()):kit.main()
            self.assertEqual(output.stat().st_mode&0o777,0o600)
            with tarfile.open(output) as tar:
                self.assertEqual(tar.getmember('dlp-install/central-agent.json').mode,0o600)
                self.assertEqual(tar.getmember('dlp-install/install.sh').mode,0o755)
                self.assertIn(b'exec /usr/bin/python3 -I ./install-dlp.py',tar.extractfile('dlp-install/install.sh').read())
            with patch('sys.argv',args),patch.object(ssl,'create_default_context'),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):kit.main()

    def test_admin_token_is_not_accepted_as_device_registration(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);p=root/'admin.json';p.write_text('{"token":"private"}');p.chmod(0o600)
            with patch('sys.argv',['kit','--package',str(root/'dlp-lab_x.deb'),'--registration',str(p),'--ca',str(root/'ca'),'--output',str(root/'out')]):
                with self.assertRaises(ValueError):kit.main()
            self.assertFalse((root/'out').exists())
