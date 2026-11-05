import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

MODULE = runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/migrate-central-docker.py'))


class MigrationPreparationTests(unittest.TestCase):
    def test_two_listeners_share_state_and_keep_existing_endpoints(self):
        services = MODULE['configuration']()['services']
        local, tls = services['local'], services['https']
        self.assertEqual(local['command'], ['serve-local'])
        self.assertEqual(tls['environment'], {'DLP_TLS_HOST': '192.168.17.131', 'DLP_TLS_PORT': '8767'})
        for service in services.values():
            self.assertEqual(service['network_mode'], 'host')
            self.assertTrue(service['init'])
            self.assertTrue(service['read_only'])
            self.assertEqual(service['cap_drop'], ['ALL'])
            self.assertEqual(service['volumes'][0], '/var/lib/dlp-central:/var/lib/dlp-central')
        self.assertEqual(len(local['volumes']), 1)
        self.assertTrue(tls['volumes'][1].endswith(':/run/tls:ro'))

    def test_reject_link_before_changing_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'file').write_text('synthetic')
            (root/'link').symlink_to(root/'file')
            with patch('os.chown') as chown:
                with self.assertRaises(ValueError):
                    MODULE['private_tree'](root, 10001, 10001)
                chown.assert_not_called()

    def test_private_tree_permissions_and_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'file').write_text('synthetic')
            with patch('os.chown') as chown:
                MODULE['private_tree'](root, 10001, 10001)
                self.assertEqual(chown.call_count, 2)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root/'file').stat().st_mode & 0o777, 0o600)
