import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dlp.dashboard import project,Handler,JournalSource


def entry(event):
    return {'MESSAGE':json.dumps(event),'_SYSTEMD_USER_UNIT':'dlp-lab-text.service','__REALTIME_TIMESTAMP':'1791958500000000'}


class DashboardTests(unittest.TestCase):
    def test_projection_does_not_disclose_raw_text_paths_or_metadata(self):
        event={'event':'draft_analysis','text':'private body','path':'/home/secret/private.docx',
               'result':{'decision':'WARN','complete':True,'findings':[{'category':'credentials','metadata':{'secret':'private body'}}]},
               'metadata':{'password':'private body'}}
        result=project(entry(event));serialized=json.dumps(result)
        self.assertNotIn('private',serialized);self.assertNotIn('/home',serialized)
        self.assertEqual(result['categories'],['credentials']);self.assertEqual(result['decision'],'WARN')
        self.assertFalse(result['send_confirmed'])

    def test_unknown_malformed_and_oversized_records(self):
        for value in [{'MESSAGE':'not JSON'},entry({'event':'unexpected','text':'secret'}),
                      entry([]),{'MESSAGE':'x'*65537},[],{'MESSAGE':123}]:
            self.assertIsNone(project(value))

    def test_result_types_and_export(self):
        r=project(entry({'event':'export_message_analysis','result':{'decision':'other','complete':'yes','findings':'bad','metadata':[]}}))
        self.assertIsNone(r['decision']);self.assertIsNone(r['complete']);self.assertEqual(r['categories'],[])

    def request(self,path,auth='Bearer abc',host='127.0.0.1:8765',origin=None):
        h=object.__new__(Handler);h.path=path
        h.headers={'Host':host,'Authorization':auth}
        if origin:h.headers['Origin']=origin
        h.server=SimpleNamespace(server_port=8765,token='abc',source=SimpleNamespace(snapshot=lambda d:{'days':d}))
        captured=[];h.respond=lambda *a:captured.append(a)
        h.do_GET();return captured[0]

    def test_auth_host_and_origin_guards(self):
        self.assertEqual(self.request('/api/snapshot',auth='')[0],401)
        self.assertEqual(self.request('/api/snapshot',auth='Bearer é')[0],401)
        self.assertEqual(self.request('/api/snapshot',host='evil.example:8765')[0],403)
        self.assertEqual(self.request('/api/snapshot',origin='https://evil.example')[0],403)
        self.assertEqual(self.request('/api/snapshot?days=30'),(200,{'days':30}))

    def test_query_and_path_are_bounded(self):
        for path in ['/api/snapshot?days=0','/api/snapshot?unit=ssh','/api/snapshot?days=1&days=7']:
            self.assertEqual(self.request(path)[0],400)
        self.assertEqual(self.request('/../../config/policy.yaml')[0],404)
        self.assertEqual(self.request('/api/start')[0],404)

    def test_assets_and_unknown_mutation_route(self):
        self.assertEqual(self.request('/',auth='')[0],200)
        h=object.__new__(Handler);h.path='/api/start';out=[];h.respond=lambda *a:out.append(a)
        h.do_POST();self.assertEqual(out[0][0],404)

    def test_journal_source_cache_whitelist_and_status(self):
        log=json.dumps(entry({'event':'draft_analysis','result':{'decision':'WARN'}}))
        status='Id=dlp-lab-text.service\nActiveState=inactive\nSubState=dead\nResult=success\n'
        with patch('dlp.dashboard.command',side_effect=[log,status]) as command:
            source=JournalSource();first=source.snapshot(7);second=source.snapshot(7)
            self.assertIs(first,second);self.assertEqual(command.call_count,2)
            argv=command.call_args_list[0].args[0]
            self.assertIn('--user',argv);self.assertIn('1000',argv)
            self.assertNotIn('ssh.service',argv)
            self.assertEqual(first['modules'][0]['active'],'inactive')
            self.assertEqual(first['events'][0]['decision'],'WARN')

    def test_source_errors_are_not_reported_as_healthy(self):
        with patch('dlp.dashboard.command',side_effect=ValueError('session_unavailable')):
            result=JournalSource().snapshot(1)
        self.assertEqual(len(result['errors']),2);self.assertFalse(result['modules'])
