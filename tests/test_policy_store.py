import copy
import io
import json
from email.message import Message
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
from dlp.policy_store import PolicyStore, Conflict, ROOT
from dlp.policy import load_policy, PolicyError
from dlp.dashboard import Handler


class PolicyStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'policy.yaml'
        self.raw=(ROOT/'config/policy.yaml').read_bytes();self.path.write_bytes(self.raw)
        self.store=PolicyStore(self.path,Path(self.temp.name)/'backups')
        view=self.store.get();self.body=dict(view);self.body['expected_version']=self.body.pop('version')

    def test_preview_noop_and_save_preserve_other_settings_and_backup(self):
        self.assertFalse(self.store.update(self.body)['saved'])
        self.assertEqual(self.path.read_bytes(),self.raw)
        original=load_policy(self.path)
        self.body['thresholds']={'warn':0.2,'block':0.8}
        self.assertTrue(self.store.update(self.body,preview=True)['changes'])
        self.assertEqual(self.path.read_bytes(),self.raw)
        result=self.store.update(self.body)
        self.assertTrue(result['saved']);self.assertTrue(result['restart_required'])
        backup=self.store.backups/result['backup']
        self.assertEqual(backup.read_bytes(),self.raw);self.assertEqual(backup.stat().st_mode&0o777,0o600)
        changed=load_policy(self.path)
        for k in original:
            if k!='thresholds':self.assertEqual(changed[k],original[k])
        with self.assertRaises(Conflict):self.store.update(self.body)

    def test_invalid_values_cannot_write(self):
        for change in [{'thresholds':{'warn':0.8,'block':0.7}}, {'thresholds':{'warn':True,'block':1}},
                       {'thresholds':{'warn':0,'block':float('nan')}}, {'on_error':'other'}, {'sensitive_enabled':1}, {'rules':[]}]:
            body=copy.deepcopy(self.body);body.update(change)
            with self.assertRaises(PolicyError):self.store.update(body)
            self.assertEqual(self.path.read_bytes(),self.raw)

    def test_external_edit_and_backup_failure(self):
        self.path.write_bytes(self.raw+b'\n')
        with self.assertRaises(Conflict):self.store.update(self.body)
        self.path.write_bytes(self.raw);self.body['sensitive_enabled']=False
        with patch('dlp.policy_store.os.replace',side_effect=OSError('disk')):
            with self.assertRaises(OSError):self.store.update(self.body)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def post(self,body=None,origin='http://127.0.0.1:8765',auth='Bearer abc',raw=None,path='/api/policy/preview'):
        h=object.__new__(Handler);h.path=path
        h.server=SimpleNamespace(server_port=8765,token='abc',policy_store=self.store,
                                control=Mock(execute=lambda request: {'ok':True}),
                                source=SimpleNamespace(lock=__import__('threading').Lock(),cache={}))
        data=raw if raw is not None else json.dumps(body or self.body).encode()
        h.headers=Message()
        for k,v in {'Host':'127.0.0.1:8765','Authorization':auth,'Content-Type':'application/json','Content-Length':str(len(data))}.items():h.headers[k]=v
        if origin:h.headers['Origin']=origin
        h.rfile=io.BytesIO(data);h.connection=Mock();out=[];h.respond=lambda *args:out.append(args)
        h.do_POST();return out[0]

    def test_post_origin_auth_validation_and_preview(self):
        self.assertEqual(self.post()[0],200)
        self.assertEqual(self.post(origin=None)[0],403)
        self.assertEqual(self.post(origin='https://evil.example')[0],403)
        self.assertEqual(self.post(auth='')[0],401)
        self.assertEqual(self.post(raw=b'{"x":1,"x":2}')[0],400)
        self.assertEqual(self.post(raw=b'{"x":NaN}')[0],400)
        self.assertEqual(self.post(raw=b'x'*8193)[0],400)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_save_route_and_backup_directory_failure(self):
        self.body['thresholds']={'warn':0.2,'block':0.8}
        self.assertEqual(self.post(path='/api/policy')[0],200)
        self.assertEqual(load_policy(self.path)['thresholds'],self.body['thresholds'])
        self.assertEqual(self.post(path='/api/policy')[0],409)
        self.path.write_bytes(self.raw)
        with patch.object(Path,'mkdir',side_effect=OSError('read only')):
            self.assertEqual(self.post(path='/api/policy')[0],503)
        self.assertEqual(self.path.read_bytes(),self.raw)

    def test_control_route_requires_auth_and_origin(self):
        body={'component':'text','action':'start'}
        self.assertEqual(self.post(body=body,path='/api/control',origin=None)[0],403)
        self.assertEqual(self.post(body=body,path='/api/control',auth='')[0],401)
        self.assertEqual(self.post(body=body,path='/api/control'),(200,{'ok':True}))
