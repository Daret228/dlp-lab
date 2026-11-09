import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dlp.central import Forwarder, ServerStore, connect


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.config={'server':'http://127.0.0.1:8766','agent_id':'test','token':'x'*43}
        self.worker=Forwarder(self.root/'queue',self.config)

    def records(self,decisions):
        return [(str(i),{'event':'file_access_attempt','timestamp':'2026-11-08T12:00:00+00:00',
           'messenger':'telegram','correlation':{'group_id':'a'*32,'operation':True},
           'result':{'decision':d,'complete':True,'findings':[]},
           'enforcement':'DENY' if d=='BLOCK' else 'ALLOW'}) for i,d in enumerate(decisions)]

    def send(self,stamp):
        sent=[]
        def request(path,batch):sent.extend(batch);return {'acked':[r['id'] for r in batch]}
        with patch('dlp.central.time.time',return_value=stamp),patch.object(self.worker,'request',side_effect=request):
            self.worker.send()
        return sent

    def test_final_priority_restart_and_duplicate_input(self):
        records=self.records(['ALLOW','WARN','BLOCK','ALLOW'])
        with patch('dlp.central.time.time',return_value=100):
            self.worker.enqueue(records,'system');self.worker.enqueue(records,'system')
        self.assertEqual(self.send(105),[])
        self.worker=Forwarder(self.root/'queue',self.config)
        sent=self.send(107);self.assertEqual(len(sent),1)
        p=sent[0]['payload'];self.assertEqual((p['event'],p['decision'],p['enforcement'],p['operation_count']),('file_operation','BLOCK','DENY',4))
        self.assertEqual(self.send(120),[])

    def test_allowed_and_warn_operation(self):
        for decisions,result in [(['ALLOW','ALLOW'],'ALLOW'),(['ALLOW','WARN'],'WARN')]:
            with tempfile.TemporaryDirectory() as folder:
                self.worker=Forwarder(Path(folder)/'queue',self.config)
                with patch('dlp.central.time.time',return_value=100):self.worker.enqueue(self.records(decisions),'system')
                self.assertEqual(self.send(107)[0]['payload']['decision'],result)

    def test_backlog_holds_summary_and_failed_delivery_keeps_queue(self):
        with patch('dlp.central.time.time',return_value=100):self.worker.enqueue(self.records(['ALLOW']),'system')
        self.worker.collection_drained=False;self.assertEqual(self.send(110),[])
        self.worker.collection_drained=True
        with patch('dlp.central.time.time',return_value=110),patch.object(self.worker,'request',side_effect=OSError):
            with self.assertRaises(OSError):self.worker.send()
        self.assertEqual(len(self.send(111)),1)

    def test_late_continuation_updates_one_server_row(self):
        store=ServerStore(self.root/'server')
        # ingest accepts an already authenticated agent identifier.
        with patch('dlp.central.time.time',return_value=100):self.worker.enqueue(self.records(['ALLOW']),'system')
        first=self.send(107);store.ingest('test',first)
        with patch('dlp.central.time.time',return_value=110):self.worker.enqueue(self.records(['ALLOW','BLOCK']),'system')
        second=self.send(117);store.ingest('test',second);store.ingest('test',first)
        events=store.report()['events'];self.assertEqual(len(events),1)
        self.assertEqual(events[0]['decision'],'BLOCK');self.assertEqual(events[0]['operation_count'],2)

    def test_file_explanation_survives_summary_and_server_without_contents(self):
        records=self.records(['ALLOW','WARN','BLOCK'])
        for _,raw in records:
            raw['path']='/home/test/<example>.txt'
            raw['text']='PRIVATE CONTENT'
        records[1][1]['result'].update(reason='sensitive_alerts_incomplete', complete=False)
        records[2][1]['result']['findings']=[dict(analyzer='dictionary',rule_id='secret_keywords',category='confidential',metadata={'match':'PRIVATE CONTENT'})]
        with patch('dlp.central.time.time',return_value=100):self.worker.enqueue(records,'system')
        sent=self.send(107)
        store=ServerStore(self.root/'server');store.ingest('test',sent)
        e=store.report()['events'][0]
        self.assertEqual(e['file_path'],'/home/test/<example>.txt')
        self.assertEqual(e['reasons'],['sensitive_alerts_incomplete'])
        self.assertEqual(e['rules'],['secret_keywords'])
        self.assertFalse(e['complete'])
        self.assertNotIn('PRIVATE CONTENT',json.dumps(sent))
