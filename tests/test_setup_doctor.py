import argparse
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dlp.doctor import collect, service_state

spec = importlib.util.spec_from_file_location('admin_setup_test', Path(__file__).resolve().parents[1]/'packaging/admin_configure.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupDoctorTests(unittest.TestCase):
    def args(self):
        return argparse.Namespace(user='nobody', telegram=Path('/usr/bin/telegram-desktop'), signal=None, enable=False)

    def test_wizard_cancellation_writes_nothing(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(setup, 'CONFIG', Path(folder)), \
                patch.object(setup.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', side_effect=['', '', '-', '', 'нет']):
            self.assertFalse(setup.wizard(self.args()))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_wizard_preserves_existing_setup(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(setup, 'CONFIG', Path(folder)), \
                patch.object(setup.sys.stdin, 'isatty', return_value=True), patch('builtins.input') as prompt:
            (Path(folder)/'system-gateway.conf').write_text('original')
            with self.assertRaises(ValueError):
                setup.wizard(self.args())
            prompt.assert_not_called()
            self.assertEqual((Path(folder)/'system-gateway.conf').read_text(), 'original')

    def test_wizard_no_terminal(self):
        with patch.object(setup.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(ValueError):
                setup.wizard(self.args())

    def test_wizard_manual_start_choice(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(setup, 'CONFIG', Path(folder)), \
                patch.object(setup.sys.stdin, 'isatty', return_value=True), \
                patch('builtins.input', side_effect=['', '', '/opt/Signal/signal-desktop', 'н', 'да']):
            args = self.args()
            self.assertTrue(setup.wizard(args))
            self.assertFalse(args.enable)
            self.assertEqual(args.signal, Path('/opt/Signal/signal-desktop'))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_missing_settings_not_healthy(self):
        with tempfile.TemporaryDirectory() as folder:
            checks = collect(Path(folder), lambda u: {'LoadState':'not-found'})
        self.assertEqual([c['status'] for c in checks[:3]], ['ERROR'] * 3)

    def test_running_not_delivery_proof_and_restart_count_not_failure(self):
        checks = collect(Path('/nonexistent'), lambda u: {
            'LoadState':'loaded', 'ActiveState':'active', 'SubState':'running', 'NRestarts':'15'})
        files = next(c for c in checks if c['name'] == 'Файловая защита')
        self.assertEqual(files['status'], 'OK')
        restarts = next(c for c in checks if c['name'] == 'Файловая защита: перезапуски')
        self.assertEqual(restarts['status'], 'INFO')
        self.assertEqual(checks[-1]['status'], 'UNKNOWN')

    def test_systemd_unavailable_is_unknown(self):
        checks = collect(Path('/nonexistent'), lambda u: None)
        self.assertEqual(next(c for c in checks if c['name'] == 'Файловая защита')['status'], 'UNKNOWN')
        with patch('dlp.doctor.subprocess.run', side_effect=OSError):
            self.assertIsNone(service_state('dlp-lab-files.service'))

    def test_failed_service_is_error(self):
        checks = collect(Path('/nonexistent'), lambda u: {'ActiveState':'failed'})
        self.assertEqual(next(c for c in checks if c['name'] == 'Отправщик событий')['status'], 'ERROR')


class InventoryIdentityTests(unittest.TestCase):
    def test_inventory_accepts_other_user_but_monitor_rejects(self):
        import json
        from dlp.processes import load_process_config, load_process_inventory
        from dlp.policy import PolicyError
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'processes.yaml'
            path.write_text(json.dumps({'version':1,'mode':'messengers','uid':1000,
                'messengers':{'telegram':{'enabled':True,'executables':['/usr/bin/telegram-desktop']}}}))
            with patch('dlp.processes.os.getuid',return_value=994):
                self.assertEqual(load_process_inventory(path)['uid'],1000)
                with self.assertRaises(PolicyError): load_process_config(path)
            with patch('dlp.processes.os.getuid',return_value=1000):
                self.assertEqual(load_process_config(path)['uid'],1000)
