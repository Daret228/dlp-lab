import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from dlp.central import ServerStore, Forwarder, connect, make_server
from dlp import remote_control as control


class RemoteControlTests(unittest.TestCase):
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
        self.worker = Forwarder(self.root/'queue', self.configs[0])

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temp.cleanup()

    def post(self, path, token, data):
        with urlopen(Request(self.url+path, data=json.dumps(data).encode(),
                             headers={'Authorization':'Bearer '+token}), timeout=3) as response:
            return json.load(response)

    def create(self):
        return self.post('/api/commands','admin-test',{'agent':self.configs[0]['agent_id'],'kind':'diagnose'})['id']

    def result(self, identity):
        return {'id':identity,'status':'completed','checks':[{'name':name,'status':'OK'} for name in control.CHECK_NAMES]}

    def test_authenticated_roundtrip_and_result_survives_restart(self):
        identity=self.create()
        with patch.object(control,'diagnose',return_value=self.result(identity)) as run:
            self.assertEqual(control.poll(self.worker),1)
            self.assertEqual(run.call_count,1)
        restarted=Forwarder(self.root/'queue',self.configs[0])
        with patch.object(control,'diagnose') as run:
            self.assertEqual(control.poll(restarted),0)
            run.assert_not_called()
        job=self.store.report()['commands'][0]
        self.assertEqual(job['status'],'completed')
        self.assertEqual(job['result'],self.result(identity))

    def test_agent_cannot_issue_commands_or_complete_another_agent_job(self):
        identity=self.create()
        for path, token, data in (
            ('/api/commands',self.configs[0]['token'],{'agent':self.configs[1]['agent_id'],'kind':'diagnose'}),
            ('/api/control','admin-test',{'results':[]}),
            ('/api/control',self.configs[1]['token'],{'results':[self.result(identity)]})):
            with self.assertRaises(HTTPError):
                self.post(path,token,data)
        second=self.post('/api/control',self.configs[1]['token'],{'results':[]})
        self.assertEqual(second['commands'],[])
        self.assertEqual(self.store.report()['commands'][0]['status'],'pending')

    def test_unknown_actions_fields_and_duplicate_pending_rejected(self):
        self.create()
        for data in ({'agent':self.configs[0]['agent_id'],'kind':'diagnose'},
                     {'agent':self.configs[1]['agent_id'],'kind':'shell'},
                     {'agent':self.configs[1]['agent_id'],'kind':'diagnose','command':'id'}):
            with self.assertRaises(HTTPError) as e:
                self.post('/api/commands','admin-test',data)
            self.assertEqual(e.exception.code,400)

    def test_expired_job_not_executed(self):
        identity=self.create()
        with connect(self.store.directory) as db:
            db.execute('UPDATE commands SET expires=? WHERE id=?',(time.time()-1,identity))
        with patch.object(control,'diagnose') as run:
            self.assertEqual(control.poll(self.worker),0)
            run.assert_not_called()
        self.assertEqual(self.store.report()['commands'][0]['status'],'expired')

    def test_retry_after_lost_ack_is_idempotent(self):
        identity=self.create()
        with patch.object(control,'diagnose',return_value=self.result(identity)):
            control.poll(self.worker)
        original=self.worker.request
        def lost(path,data):
            original(path,data)
            raise OSError('lost reply')
        with patch.object(self.worker,'request',side_effect=lost):
            with self.assertRaises(OSError): control.poll(self.worker)
        with patch.object(control,'diagnose') as run:
            control.poll(self.worker)
            run.assert_not_called()
        self.assertEqual(len(self.store.report()['commands']),1)
        with connect(self.worker.state) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM command_results').fetchone()[0],0)

    def test_arbitrary_result_content_rejected(self):
        identity=self.create()
        result=self.result(identity)
        result['checks'][0]['detail']='private content'
        with self.assertRaises(HTTPError):
            self.post('/api/control',self.configs[0]['token'],{'results':[result]})
        self.assertEqual(self.store.report()['commands'][0]['status'],'pending')

    def test_unknown_server_job_does_not_execute(self):
        response={'acked':[],'commands':[{'id':'x'*36,'kind':'shell','expires':time.time()+60}]}
        with patch.object(self.worker,'request',return_value=response), patch.object(control,'diagnose') as run:
            with self.assertRaises(ValueError): control.poll(self.worker)
            run.assert_not_called()

    def test_restart_requires_capability_and_uses_fixed_broker(self):
        agent=self.configs[0]['agent_id']
        with self.assertRaises(HTTPError):
            self.post('/api/commands','admin-test',{'agent':agent,'kind':'restart_session'})
        from dlp.central import project, now
        self.store.ingest(agent,[{'id':'f'*64,'payload':project({'event':'endpoint_health','timestamp':now(),'management_ready':True})}])
        identity=self.post('/api/commands','admin-test',{'agent':agent,'kind':'restart_session'})['id']
        with patch('dlp.admin_control.request_restart',return_value=True) as restart, patch.object(control,'diagnose',return_value=self.result(identity)):
            control.poll(self.worker)
            self.assertEqual(restart.call_args.args[0]['kind'],'restart_session')
        with patch('dlp.admin_control.request_restart') as restart:
            control.poll(self.worker)
            restart.assert_not_called()
        self.assertEqual(self.store.report()['commands'][0]['status'],'completed')
