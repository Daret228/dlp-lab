import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dlp.central import ServerStore, Forwarder, connect, make_server, project, now
from dlp import remote_control as control

VALID = Path(__file__).resolve().parents[1] / 'config/policy.yaml'


class PolicyChannelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ServerStore(self.root/'server')
        self.server = make_server(self.store, 'admin-test', '127.0.0.1', 0)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.configs = []
        for n in ('a','b'):
            self.store.add(n, self.url, self.root/(n+'.json'))
            self.configs.append(json.loads((self.root/(n+'.json')).read_text()))
        staging = patch.object(control, 'STAGED_POLICY', str(self.root/'queue'/'policy-incoming.yaml'))
        staging.start(); self.addCleanup(staging.stop)
        self.worker = Forwarder(self.root/'queue', self.configs[0])
        self.agent = self.configs[0]['agent_id']

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temp.cleanup()

    def request(self, path, token, data=None, method=None):
        headers = {'Authorization':'Bearer '+token}
        if data is not None:
            data = json.dumps(data).encode(); headers['Content-Type'] = 'application/json'
        with urlopen(Request(self.url+path, data=data, headers=headers, method=method), timeout=3) as response:
            return json.load(response)

    def save(self, content, expected=None, activate=False, agent=None):
        return self.request('/api/policy', 'admin-test',
                            {'agent': agent or self.agent, 'content': content,
                             'expected_version': expected, 'activate': activate})

    def health(self, ready=True, channel=True):
        payload = project({'event':'endpoint_health','timestamp':now(),'management_ready':ready,
                           'policy_channel':channel,'policy_version':'a'*64})
        self.store.ingest(self.agent, [{'id':'e'*64,'payload':payload}])

    def test_valid_policy_saved_without_command_and_report_shows_it(self):
        content = VALID.read_text()
        result = self.save(content, expected=None)
        self.assertEqual(result['command'], None)
        self.assertEqual(len(result['version']), 64)
        report = self.store.report()
        self.assertEqual(report['policies'][self.agent]['version'], result['version'])
        view = self.request('/api/policy?agent='+self.agent, 'admin-test')
        self.assertEqual(view['content'], content)
        self.assertEqual(view['version'], result['version'])

    def test_invalid_policy_rejected(self):
        for bad in ('', 'version: 2\n', 'thresholds: {warn: 0.9, block: 0.1}\n', 'a'*200000,
                    '{"broken": yaml', 'rules: []\n'):
            with self.assertRaises(HTTPError) as error:
                self.save(bad)
            self.assertEqual(error.exception.code, 400)
        self.assertEqual(self.store.report()['policies'], {})

    def test_expected_version_conflict_and_wrong_keys(self):
        content = VALID.read_text()
        first = self.save(content)
        with self.assertRaises(HTTPError) as error:
            self.save(content, expected=None)
        self.assertEqual(error.exception.code, 400)
        # Same content keeps the same content-addressed version.
        self.assertEqual(self.save(content, expected=first['version'])['version'], first['version'])
        changed = content.replace('warn: 0.3', 'warn: 0.35')
        second = self.save(changed, expected=first['version'])
        self.assertNotEqual(first['version'], second['version'])
        # The stale expected version is now rejected.
        with self.assertRaises(HTTPError) as error:
            self.save(changed, expected=first['version'])
        self.assertEqual(error.exception.code, 400)
        for payload in ({'agent':self.agent,'content':content},
                        {'agent':self.agent,'content':content,'expected_version':None,'activate':'yes'},
                        {'agent':'missing','content':content,'expected_version':second['version'],'activate':False}):
            with self.assertRaises(HTTPError) as error:
                self.request('/api/policy','admin-test',payload)
            self.assertEqual(error.exception.code, 400)

    def test_agent_fetches_only_own_policy_and_cannot_write(self):
        content = VALID.read_text()
        version = self.save(content)['version']
        fetched = self.request('/api/policy', self.configs[0]['token'])
        self.assertEqual(fetched, {'version':version,'content':content})
        self.assertEqual(self.request('/api/policy', self.configs[1]['token']),
                         {'version':None,'content':None})
        # A query parameter cannot redirect an agent to another device's policy.
        self.assertEqual(self.request('/api/policy?agent='+self.agent, self.configs[1]['token']),
                         {'version':None,'content':None})
        with self.assertRaises(HTTPError) as error:
            self.request('/api/policy', self.configs[0]['token'],
                         {'agent':self.agent,'content':content,'expected_version':version,'activate':True})
        self.assertEqual(error.exception.code, 401)

    def test_activation_requires_fresh_capable_agent_and_creates_command(self):
        content = VALID.read_text()
        with self.assertRaises(HTTPError) as error:
            self.save(content, activate=True)
        self.assertEqual(error.exception.code, 400)
        self.health(ready=False, channel=True)
        with self.assertRaises(HTTPError):
            self.save(content, activate=True)
        self.health(ready=True, channel=False)
        with self.assertRaises(HTTPError) as error:
            self.save(content, activate=True)
        self.assertEqual(error.exception.code, 400)
        self.health(ready=True, channel=True)
        result = self.save(content, activate=True)
        self.assertEqual(len(result['command']), 36)
        self.assertEqual(self.store.report()['commands'][0]['kind'], 'apply_policy')

    def test_end_to_end_apply_via_poll(self):
        content = VALID.read_text()
        self.health()
        identity = self.save(content, activate=True)['command']
        result = {'id':identity,'status':'completed',
                  'checks':[{'name':n,'status':'OK'} for n in control.CHECK_NAMES]}
        with patch('dlp.admin_control.request_restart', return_value=True) as install, \
             patch.object(control, 'diagnose', return_value=result) as run:
            self.assertEqual(control.poll(self.worker), 1)   # fetch job, install via broker
            self.assertEqual(control.poll(self.worker), 0)   # deliver the result
            install.assert_called_once()
            self.assertEqual(install.call_args.args[0]['kind'], 'install_policy')
            self.assertEqual(install.call_args.args[0]['id'], identity)
            run.assert_called_once()
        self.assertFalse((Path(self.worker.state)/control.STAGED_POLICY).exists())
        job = self.store.report()['commands'][0]
        self.assertEqual(job['status'], 'completed')

    def test_apply_reports_failure_when_nothing_is_assigned(self):
        self.health()
        identity = self.request('/api/commands', 'admin-test', {'agent': self.agent, 'kind': 'apply_policy'})['id']
        with patch.object(control, 'diagnose') as run:
            self.assertEqual(control.poll(self.worker), 1)   # executes: nothing assigned
            self.assertEqual(control.poll(self.worker), 0)   # delivers the failed result
            run.assert_not_called()
        job = self.store.report()['commands'][0]
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(job['result'], {'id':identity,'status':'failed','checks':[]})

    def test_apply_rejects_server_that_changed_policy_midway(self):
        content = VALID.read_text()
        self.health()
        self.save(content, activate=True)
        original = self.worker.request
        def switched(path, data=None):
            if path == '/api/policy':
                return {'version':'f'*64, 'content':content}
            return original(path, data)
        with patch.object(self.worker, 'request', side_effect=switched), \
             patch('dlp.admin_control.request_restart') as install:
            with self.assertRaises(ValueError):
                control.poll(self.worker)
            install.assert_not_called()
        self.assertEqual(self.store.report()['commands'][0]['status'], 'pending')
        self.assertFalse((Path(self.worker.state)/control.STAGED_POLICY).exists())

    def test_pending_apply_freezes_assigned_policy(self):
        self.health()
        original = VALID.read_text()
        first = self.save(original, activate=True)
        with self.assertRaises(HTTPError):
            self.save(original+'\n', expected=first['version'])
        self.assertEqual(self.worker.request('/api/policy')['version'],first['version'])

    def test_stage_permissions_allow_capabilityless_broker_group_read(self):
        import stat
        self.health()
        self.save(VALID.read_text(),activate=True)
        def check(job):
            staged=Path(self.worker.state)/control.STAGED_POLICY
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode),0o640)
            return False
        with patch('dlp.admin_control.request_restart',side_effect=check):
            control.poll(self.worker)
