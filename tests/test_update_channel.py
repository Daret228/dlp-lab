"""Update channel tests: name grammar, staged-pair validation, panel routes,
assignment gating and the end-to-end update_agent poll flow."""
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dlp.central import ServerStore, Forwarder, connect, make_server, project, now
from dlp import remote_control as control
from dlp import update_assist
from dlp import update_channel

PACKAGE = b'fake debian package body for the update channel tests'


class UpdateChannelTests(unittest.TestCase):
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
        for name, value in (('STAGED_UPDATE', str(self.root/'queue'/'update.deb')),
                            ('STAGED_UPDATE_META', str(self.root/'queue'/'update.meta.json'))):
            staged = patch.object(update_channel, name, value)
            staged.start(); self.addCleanup(staged.stop)
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

    def upload(self, token='admin-test', name='dlp-lab_0.2.37_amd64.deb', body=PACKAGE):
        request = Request(self.url+'/api/updates', data=body, method='POST',
                          headers={'Authorization':'Bearer '+token, 'X-Filename': name,
                                   'Content-Type':'application/octet-stream'})
        with urlopen(request, timeout=3) as response:
            return json.load(response)

    def assign(self, sha256, agent=None):
        return self.request('/api/updates/assign', 'admin-test',
                            {'agent': agent or self.agent, 'sha256': sha256})

    def health(self, ready=True, auto=True):
        payload = project({'event':'endpoint_health','timestamp':now(),'management_ready':ready,
                           'policy_channel':True,'auto_update':auto,'policy_version':'a'*64})
        self.store.ingest(self.agent, [{'id':'e'*64,'payload':payload}])

    def completed(self, identity):
        return {'id':identity,'status':'completed',
                'checks':[{'name':n,'status':'OK'} for n in control.CHECK_NAMES]}

    def test_name_grammar_is_shared_and_meta_from_validates(self):
        self.assertIs(update_assist.candidate_from_name, update_channel.candidate_from_name)
        self.assertEqual(update_channel.candidate_from_name('dlp-lab_0.2.37~deb12u1_amd64.deb'),
                         ('0.2.37~deb12u1','amd64'))
        self.assertEqual(update_channel.meta_from('dlp-lab_0.2.37_amd64.deb', 9),
                         {'filename':'dlp-lab_0.2.37_amd64.deb','version':'0.2.37','size':9})
        for name in ('evil.deb', '../dlp-lab_1.0_amd64.deb', 'x'*200):
            with self.assertRaises(ValueError):
                update_channel.meta_from(name, 9)
        for size in (0, -1, update_channel.MAX_UPDATE+1, '9', 1.5):
            with self.assertRaises(ValueError):
                update_channel.meta_from('dlp-lab_0.2.37_amd64.deb', size)

    def test_validate_staged_update_checks_hash_and_shape(self):
        import shutil
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, ignore_errors=True)
        digest = hashlib.sha256(PACKAGE).hexdigest()
        meta = json.dumps({'filename':'dlp-lab_0.2.37_amd64.deb','sha256':digest,'size':len(PACKAGE)})
        (folder/'update.deb').write_bytes(PACKAGE); (folder/'meta.json').write_text(meta)
        result = update_channel.validate_staged_update(folder/'update.deb', folder/'meta.json')
        self.assertEqual(result, {'filename':'dlp-lab_0.2.37_amd64.deb','version':'0.2.37',
                                  'size':len(PACKAGE),'sha256':digest})
        for broken in ({'filename':'evil.deb','sha256':digest,'size':len(PACKAGE)},
                       {'filename':'dlp-lab_0.2.37_amd64.deb','sha256':'f'*64,'size':len(PACKAGE)},
                       {'filename':'dlp-lab_0.2.37_amd64.deb','sha256':digest,'size':len(PACKAGE)+1},
                       {'filename':'dlp-lab_0.2.37_amd64.deb','sha256':digest}):
            (folder/'meta.json').write_text(json.dumps(broken))
            with self.assertRaises(ValueError):
                update_channel.validate_staged_update(folder/'update.deb', folder/'meta.json')
        (folder/'meta.json').write_text(meta); (folder/'update.deb').write_bytes(PACKAGE+b'x')
        with self.assertRaises(ValueError):
            update_channel.validate_staged_update(folder/'update.deb', folder/'meta.json')
        (folder/'update.deb').unlink(); (folder/'update.deb').symlink_to(folder/'meta.json')
        with self.assertRaises((OSError, ValueError)):
            update_channel.validate_staged_update(folder/'update.deb', folder/'meta.json')

    def test_upload_rejects_non_admin_bad_names_and_duplicates_collapse(self):
        with self.assertRaises(HTTPError) as error:
            self.upload(token=self.configs[0]['token'])
        self.assertEqual(error.exception.code, 401)
        for name in ('evil.deb', 'dlp-lab_1.0_amd64.deb.exe', '../dlp-lab_1.0_amd64.deb', ''):
            with self.assertRaises(HTTPError) as error:
                self.upload(name=name)
            self.assertEqual(error.exception.code, 400)
        first = self.upload()
        self.assertEqual(first, {'sha256':hashlib.sha256(PACKAGE).hexdigest(),'version':'0.2.37'})
        self.upload(body=PACKAGE+b'x', name='dlp-lab_0.2.38_amd64.deb')
        self.assertEqual(len(self.store.report()['updates']['uploads']), 2)

    def test_report_lists_uploads_and_assignments_without_payload(self):
        sha = self.upload()['sha256']
        self.health()
        self.assign(sha)
        state = self.store.report()['updates']
        self.assertEqual(state['uploads'][0]['sha256'], sha)
        self.assertEqual(state['uploads'][0]['size'], len(PACKAGE))
        self.assertNotIn('payload', state['uploads'][0])
        self.assertEqual(state['assignments'], {self.agent: {'sha256': sha}})

    def test_assign_gates_on_fresh_auto_update_agent(self):
        sha = self.upload()['sha256']
        with self.assertRaises(HTTPError) as error:
            self.request('/api/updates/assign', self.configs[0]['token'], {'agent': self.agent, 'sha256': sha})
        self.assertEqual(error.exception.code, 401)
        for staged in (None, 'stale', 'no-auto'):
            if staged == 'stale':
                payload = project({'event':'endpoint_health','timestamp':'2000-01-01T00:00:00+00:00',
                                   'management_ready':True,'auto_update':True})
                self.store.ingest(self.agent, [{'id':'e'*64,'payload':payload}])
            elif staged == 'no-auto':
                self.health(auto=False)
            for body in ({'agent': self.agent, 'sha256': sha},
                         {'agent': self.agent, 'sha256': 'f'*64},
                         {'agent': 'missing', 'sha256': sha},
                         {'agent': self.agent}):
                with self.assertRaises(HTTPError) as error:
                    self.request('/api/updates/assign', 'admin-test', body)
                self.assertEqual(error.exception.code, 400)
        self.health()
        result = self.assign(sha)
        self.assertEqual(len(result['command']), 36)
        self.assertEqual(self.store.report()['commands'][0]['kind'], 'update_agent')

    def test_agent_fetches_only_own_update_and_blob(self):
        sha = self.upload()['sha256']
        self.health()
        self.assign(sha)
        self.assertEqual(self.request('/api/update', self.configs[0]['token']),
                         {'filename':'dlp-lab_0.2.37_amd64.deb','sha256':sha,
                          'size':len(PACKAGE),'version':'0.2.37'})
        self.assertEqual(self.request('/api/update', self.configs[1]['token']), {})
        with urlopen(Request(self.url+'/api/update/blob',
                             headers={'Authorization':'Bearer '+self.configs[0]['token']}), timeout=3) as r:
            self.assertEqual(r.read(), PACKAGE)
            self.assertEqual(r.headers['Content-Type'], 'application/octet-stream; charset=utf-8')
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.url+'/api/update/blob',
                            headers={'Authorization':'Bearer '+self.configs[1]['token']}), timeout=3)
        self.assertEqual(error.exception.code, 400)
        with self.assertRaises(HTTPError) as error:  # the admin token is not an agent token
            self.request('/api/update', 'admin-test')
        self.assertEqual(error.exception.code, 401)

    def test_end_to_end_update_via_poll(self):
        sha = self.upload()['sha256']
        self.health()
        identity = self.assign(sha)['command']
        result = self.completed(identity)
        seen = {}
        def broker(job, timeout=120):
            seen['job'] = job; seen['timeout'] = timeout
            package = Path(update_channel.STAGED_UPDATE)
            sidecar = Path(update_channel.STAGED_UPDATE_META)
            seen['mode'] = stat.S_IMODE(package.stat().st_mode)
            seen['package'] = package.read_bytes()
            seen['sidecar'] = json.loads(sidecar.read_text())
            return True
        with patch('dlp.update_assist.installed_version', return_value='0.2.36'), \
             patch.object(self.worker, 'download', return_value=PACKAGE) as download, \
             patch('dlp.admin_control.request_restart', side_effect=broker) as install, \
             patch.object(control, 'diagnose', return_value=result) as run:
            self.assertEqual(control.poll(self.worker), 1)   # fetch job, download, install via broker
            self.assertEqual(control.poll(self.worker), 0)   # deliver the result
            download.assert_called_once_with('/api/update/blob', limit=update_channel.MAX_UPDATE)
            install.assert_called_once()
            run.assert_called_once()
        self.assertEqual(seen['job'], {'id':identity,'kind':'install_update','expires':seen['job']['expires']})
        self.assertGreaterEqual(seen['timeout'], 170)
        self.assertEqual(seen['mode'], 0o640)
        self.assertEqual(seen['package'], PACKAGE)
        self.assertEqual(seen['sidecar'], {'filename':'dlp-lab_0.2.37_amd64.deb','sha256':sha,
                                           'size':len(PACKAGE)})
        self.assertFalse(Path(update_channel.STAGED_UPDATE).exists())
        self.assertFalse(Path(update_channel.STAGED_UPDATE_META).exists())
        job = self.store.report()['commands'][0]
        self.assertEqual(job['status'], 'completed')

    def test_update_without_assignment_fails_once(self):
        self.health()
        identity = self.request('/api/commands', 'admin-test',
                                {'agent': self.agent, 'kind': 'update_agent'})['id']
        with patch.object(control, 'diagnose') as run:
            self.assertEqual(control.poll(self.worker), 1)   # executes: nothing assigned
            self.assertEqual(control.poll(self.worker), 0)   # delivers the failed result
            run.assert_not_called()
        job = self.store.report()['commands'][0]
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(job['result'], {'id':identity,'status':'failed','checks':[]})

    def test_update_rejects_tampered_download(self):
        sha = self.upload()['sha256']
        self.health()
        self.assign(sha)
        with patch('dlp.update_assist.installed_version', return_value='0.2.36'), \
             patch.object(self.worker, 'download', return_value=b'evil bytes'), \
             patch('dlp.admin_control.request_restart') as install:
            with self.assertRaises(ValueError):
                control.poll(self.worker)
            install.assert_not_called()
        self.assertEqual(self.store.report()['commands'][0]['status'], 'pending')
        self.assertFalse(Path(update_channel.STAGED_UPDATE).exists())

    def test_update_already_installed_reports_done_without_broker(self):
        sha = self.upload()['sha256']
        self.health()
        identity = self.assign(sha)['command']
        with patch('dlp.update_assist.installed_version', return_value='0.2.37'), \
             patch.object(self.worker, 'download') as download, \
             patch('dlp.admin_control.request_restart') as install, \
             patch.object(control, 'diagnose', return_value=self.completed(identity)) as run:
            self.assertEqual(control.poll(self.worker), 1)
            self.assertEqual(control.poll(self.worker), 0)
            download.assert_not_called(); install.assert_not_called(); run.assert_called_once()
        self.assertEqual(self.store.report()['commands'][0]['status'], 'completed')

    def test_uncertain_broker_death_never_fails_a_pending_update(self):
        sha = self.upload()['sha256']
        self.health()
        self.assign(sha)
        result = self.completed(self.store.report()['commands'][0]['id'])
        # The install finished while the connection died: report completion.
        with patch('dlp.update_assist.installed_version', side_effect=['0.2.36','0.2.37']), \
             patch.object(self.worker, 'download', return_value=PACKAGE), \
             patch('dlp.admin_control.request_restart', side_effect=OSError('connection reset')), \
             patch.object(control, 'diagnose', return_value=result):
            self.assertEqual(control.poll(self.worker), 1)
            self.assertEqual(control.poll(self.worker), 0)
        self.assertEqual(self.store.report()['commands'][0]['status'], 'completed')
        # Outcome genuinely unknown: leave a fresh command pending for a retry.
        self.assign(sha)
        with patch('dlp.update_assist.installed_version', return_value='0.2.36'), \
             patch.object(self.worker, 'download', return_value=PACKAGE), \
             patch('dlp.admin_control.request_restart', side_effect=OSError('connection reset')):
            with self.assertRaises(OSError):
                control.poll(self.worker)
        self.assertEqual(self.store.report()['commands'][0]['status'], 'pending')
