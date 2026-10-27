from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dlp.dashboard_control import MonitorControl, ControlError
from dlp.policy_store import ROOT


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.control=MonitorControl(SimpleNamespace(path=ROOT/'config/policy.yaml',get=lambda:{'version':'revision'}))

    def test_start_text_has_fixed_marker_duration_and_no_shell(self):
        with patch('dlp.dashboard_control.service.unit_status',side_effect=[{'ActiveState':'inactive'},{'ActiveState':'active'}]), patch('dlp.dashboard_control.service._run') as run:
            result=self.control.execute({'component':'text','action':'start'})
        args=run.call_args.args[0]
        self.assertEqual(args[-5:],['text-monitor','--marker','DLP_TEST','--seconds','120'])
        self.assertEqual(result['policy_at_request'],'revision')
        self.assertFalse(result['applied_policy_confirmed'])

    def test_arbitrary_scope_and_commands_rejected(self):
        with patch('dlp.dashboard_control.service._run') as run:
            for request in [{'component':'all','action':'stop'},{'component':'local','action':'start'},
                            {'component':'files','action':'restart'},{'component':'text','action':'start','marker':'other'}]:
                with self.assertRaises(ValueError):self.control.execute(request)
            run.assert_not_called()

    def test_active_start_and_failed_command_are_errors(self):
        with patch('dlp.dashboard_control.service.unit_status',return_value={'ActiveState':'active'}),patch('dlp.dashboard_control.service._run') as run:
            with self.assertRaises(ControlError):self.control.execute({'component':'files','action':'start'})
            run.assert_not_called()
        with patch('dlp.dashboard_control.service.unit_status',side_effect=ValueError('secret stderr')):
            with self.assertRaises(ControlError) as error:self.control.execute({'component':'files','action':'stop'})
            self.assertNotIn('secret',str(error.exception))

    def test_stop_only_selected_unit(self):
        with patch('dlp.dashboard_control.service.unit_status',side_effect=[{'ActiveState':'active'},{'ActiveState':'inactive'}]),patch('dlp.dashboard_control.service._run') as run:
            self.control.execute({'component':'files','action':'stop'})
        run.assert_called_once_with(['systemctl','--user','stop','dlp-lab-files.service'])

    def test_signal_local_uses_fixed_profile_and_no_wait(self):
        with patch('dlp.dashboard_control.service.unit_status',side_effect=[{'ActiveState':'inactive'},{'ActiveState':'active'}]), patch('dlp.dashboard_control.service._run') as run:
            self.control.execute({'component':'signal-local','action':'start'})
        command=run.call_args.args[0]
        self.assertIn('signal-local-check',command)
        self.assertIn(str(Path.home()/'.config/Signal'),command)
        self.assertIn('--property=StateDirectory=dlp-lab',command)
        self.assertNotIn('--wait',command)
        for request in ({'component':'signal-local','action':'stop'},
                        {'component':'signal-local','action':'start','root':'/other'}):
            with self.assertRaises(ValueError):self.control.execute(request)
