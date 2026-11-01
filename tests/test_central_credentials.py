import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dlp.central import read_config, read_systemd_config, validate_credential_file, validate_credential_directory


class CredentialTests(unittest.TestCase):
    def test_only_root_readonly_regular_credentials(self):
        for mode in (0o400, 0o440):
            validate_credential_file(SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | mode))
        for uid, gid, mode in ((1000,0,stat.S_IFREG|0o440), (0,1000,stat.S_IFREG|0o440),
                              (0,0,stat.S_IFREG|0o444), (0,0,stat.S_IFREG|0o640),
                              (0,0,stat.S_IFLNK|0o440), (0,0,stat.S_IFIFO|0o440)):
            with self.assertRaises(ValueError):
                validate_credential_file(SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode))

    def test_ordinary_config_remains_private(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'agent.json'; p.write_text('{"synthetic":true}'); p.chmod(0o600)
            self.assertEqual(read_config(p), {'synthetic': True})
            p.chmod(0o440)
            with self.assertRaises(ValueError): read_config(p)

    def test_arbitrary_path_is_not_system_credential(self):
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY':'/tmp'}):
            with self.assertRaises(ValueError): read_systemd_config('/tmp/agent.json')
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                read_systemd_config('/run/credentials/dlp-lab-forwarder.service/agent.json')

    @patch('dlp.central.os.getuid', return_value=994)
    def test_service_owned_readonly_file(self, _):
        validate_credential_file(SimpleNamespace(st_uid=994, st_gid=0, st_mode=stat.S_IFREG|0o400))
        for uid, gid, mode in ((995,0,0o400),(994,0,0o440),(994,0,0o600),(994,994,0o400)):
            with self.assertRaises(ValueError):
                validate_credential_file(SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFREG|mode))

    @patch('dlp.central.os.getuid', return_value=994)
    def test_directory_variants_and_rejections(self, _):
        for uid,gid,mode in ((0,0,0o700),(0,0,0o500),(994,0,0o500)):
            validate_credential_directory(SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|mode))
        for uid,gid,mode in ((995,0,0o500),(994,0,0o700),(994,994,0o500),(0,0,0o777)):
            with self.assertRaises(ValueError):
                validate_credential_directory(SimpleNamespace(st_uid=uid,st_gid=gid,st_mode=stat.S_IFDIR|mode))
