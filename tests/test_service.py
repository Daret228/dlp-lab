import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from dlp import service


class ServiceTests(unittest.TestCase):
    def test_gateway_scope_and_no_extra_arguments(self):
        command = service.launch_command('files', service.ROOT / 'config/policy.yaml')
        worker = command[command.index('--') + 1:]
        self.assertEqual(worker, ['/usr/bin/sudo', '-n', service.GATEWAY])
        self.assertIn('--property=KillMode=control-group', command)
        self.assertIn('--property=Restart=no', command)
        self.assertIn('--property=SuccessExitStatus=130', command)
        with self.assertRaises(ValueError):
            service.launch_command('files', '/tmp/another-policy.yaml')

    def test_marker_and_path_are_literal_arguments(self):
        marker = '$HOME; $(touch /tmp/not-run)'
        command = service.launch_command('text', service.ROOT / 'config/policy.yaml', marker=marker)
        self.assertEqual(command[command.index('--marker') + 1], marker)
        self.assertIn('--expand-environment=no', command)
        self.assertIn('--property=StandardOutput=journal', command)
        command = service.launch_command('export', 'config/policy.yaml', file=Path('/tmp/a b.json'))
        self.assertEqual(command[-1], '/tmp/a b.json')
        self.assertIn('--wait', command)
        self.assertNotIn('--property=SuccessExitStatus=130', command)

    def test_text_requires_explicit_binding_and_bounded_duration(self):
        for marker, seconds in [(None, 120), ('', 120), ('test', 0), ('test', 3601)]:
            with self.assertRaises(ValueError):
                service.launch_command('text', 'config/policy.yaml', marker=marker, seconds=seconds)

    def test_duplicate_start_never_stops_existing_process(self):
        with patch.object(service, 'unit_status', return_value={'ActiveState': 'active'}), \
                patch.object(service, '_run') as run:
            with self.assertRaises(ValueError):
                service.start('files', service.ROOT / 'config/policy.yaml')
            run.assert_not_called()

    def test_failed_unit_reset_and_worker_error_propagated(self):
        with patch.object(service, 'unit_status', return_value={'ActiveState': 'failed'}), \
                patch.object(service, '_run', return_value=subprocess.CompletedProcess([], 2)) as run, \
                patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(service.start('files', service.ROOT / 'config/policy.yaml'), 2)
            self.assertEqual(run.call_args_list[0].args[0],
                             ['systemctl', '--user', 'reset-failed', service.UNITS['files']])

    def test_stop_uses_only_owned_units_and_is_idempotent(self):
        with patch.object(service, 'unit_status', return_value={'LoadState': 'not-found'}), \
                patch.object(service, '_run') as run, patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(service.stop('all'), 0)
            run.assert_not_called()
        with patch.object(service, 'unit_status', return_value={'LoadState': 'loaded', 'ActiveState': 'active'}), \
                patch.object(service, '_run') as run, patch('sys.stdout', new_callable=io.StringIO):
            service.stop('all')
            self.assertEqual([call.args[0][-1] for call in run.call_args_list], list(service.UNITS.values()))

    def test_unavailable_bus_is_error_not_stopped_status(self):
        failure = subprocess.CompletedProcess([], 1, '', 'Failed to connect to bus')
        with patch('subprocess.run', return_value=failure), patch('sys.stdout', new_callable=io.StringIO) as out:
            with self.assertRaises(ValueError):
                service.status()
            self.assertNotIn('ОСТАНОВЛЕН', out.getvalue())

    def test_status_explains_observation_and_manual_process_limit(self):
        with patch.object(service, 'unit_status', return_value={
                'ActiveState': 'active', 'SubState': 'running', 'MainPID': '12', 'Result': 'success'}), \
                patch('sys.stdout', new_callable=io.StringIO) as out:
            service.status()
            self.assertIn('Ручные процессы сюда не входят', out.getvalue())
            self.assertIn('Запрет отправки текста отсутствует', out.getvalue())

    def test_common_journal_selects_only_managed_units(self):
        with patch.object(service, '_run', return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(service.logs(20, True), 0)
            command = run.call_args.args[0]
            for unit in service.UNITS.values():
                self.assertIn(unit, command)
            self.assertIn('--follow', command)
        with self.assertRaises(ValueError):
            service.logs(0)


if __name__ == '__main__':
    unittest.main()
