import copy
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import yaml
from dlp.analysis import ContentAnalyzer, AnalysisTimeout
from dlp.audit import JsonAudit
from dlp.file_notifications import FileWarnings
from dlp.fanotify import process_event, OPEN_PERM, RESPONSE, ALLOW
from dlp.models import TextContent, FileContent
from dlp.policy import load_policy, PolicyError
from dlp.text_monitor import DraftMonitor
from test_documents import make_docx

ROOT=Path(__file__).resolve().parents[1]


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.policy=load_policy(ROOT/'config/policy.yaml')
        # Test the independent rules module, regardless of shipped ML defaults.
        self.policy['ml_alerts']['enabled']=False
        self.analyzer=ContentAnalyzer(self.policy)

    def test_categories_warn_not_score_block(self):
        r=self.analyzer.analyze(TextContent('Паспорт 0051 627384; мой оклад 95000 рублей; пароль: берёза'))
        self.assertEqual(r.decision,'WARN');self.assertEqual(r.score,0)
        self.assertEqual({f.category for f in r.findings},{'passport','financial','credentials'})
        self.assertTrue(r.complete)

    def test_legacy_block_and_warn_preserved(self):
        for text,decision,score in [('top secret; пароль: берёза','BLOCK',0.8),
                                    ('x@y.org; пароль: берёза','WARN',0.35)]:
            r=self.analyzer.analyze(TextContent(text))
            self.assertEqual(r.decision,decision);self.assertEqual(r.score,score)

    def test_missing_or_disabled_section(self):
        for cfg in (None,{'enabled':False,'mode':'rules','action':'WARN'}):
            p=copy.deepcopy(self.policy)
            if cfg is None:p.pop('sensitive_alerts')
            else:p['sensitive_alerts']=cfg
            r=ContentAnalyzer(p).analyze(TextContent('Пароль: берёза'))
            self.assertEqual(r.decision,'ALLOW');self.assertNotIn('sensitive_alerts',r.metadata)

    def test_limit_and_timeout_are_advisory_only(self):
        for text in ('x'*17000,'top secret '+'x'*17000):
            r=self.analyzer.analyze(TextContent(text))
            self.assertFalse(r.complete)
            self.assertEqual(r.decision,'BLOCK' if text.startswith('top') else 'WARN')
            self.assertEqual(r.reason,'sensitive_alerts_incomplete')
        with patch('dlp.sensitive_values_v4.rule_predict',side_effect=AnalysisTimeout):
            r=self.analyzer.analyze(TextContent('hello'))
            self.assertEqual(r.decision,'WARN');self.assertFalse(r.complete)

    def test_strict_config(self):
        for key,value in [('action','BLOCK'),('mode','hybrid'),('enabled',1)]:
            p=copy.deepcopy(self.policy);p['sensitive_alerts'][key]=value
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'policy.yaml';path.write_text(yaml.safe_dump(p))
                with self.assertRaises(PolicyError):load_policy(path)

    def test_docx_and_extraction_error_policy(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'sample.docx'
            for extras,expected in [(None,'WARN'),({'word/media/a.bin':b'fake'},'BLOCK')]:
                path.write_bytes(make_docx('<w:p><w:r><w:t>Пароль: берёза</w:t></w:r></w:p>',extras=extras))
                r=self.analyzer.analyze(FileContent(path))
                self.assertEqual(r.decision,expected)
                self.assertIn('credentials',{f.category for f in r.findings})

    def test_draft_warn_notification_and_no_secret_audit(self):
        out=io.StringIO();calls=[]
        monitor=DraftMonitor(self.analyzer,JsonAudit(out),lambda decision:calls.append(decision) or 'accepted')
        monitor.check('Пароль: берёза','telegram',123)
        self.assertEqual(calls,['WARN'])
        events=[json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(events[-1]['status'],'accepted');self.assertFalse(events[-1]['send_blocked'])
        self.assertNotIn('берёза',out.getvalue())

    def test_fanotify_response_precedes_warning(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'sample.txt';path.write_text('Пароль: берёза')
            fd=os.open(path,os.O_RDONLY);read,write=os.pipe()
            out=io.StringIO()
            class Check:
                def submit(inner,record):
                    self.assertEqual(RESPONSE.unpack(os.read(read,RESPONSE.size)),(fd,ALLOW))
                    self.assertEqual(record['result']['decision'],'WARN')
            try:process_event(write,OPEN_PERM,fd,os.getpid(),self.analyzer,JsonAudit(out),warnings=Check())
            finally:os.close(read);os.close(write)
            self.assertNotIn('берёза',out.getvalue())

    def test_queue_is_nonblocking_throttles_and_reports(self):
        out=io.StringIO();entered=threading.Event();release=threading.Event()
        def sender(_):entered.set();release.wait(2);return 'accepted'
        warnings=FileWarnings(JsonAudit(out),sender,clock=lambda:100)
        record={'result':asdict(self.analyzer.analyze(TextContent('Пароль: берёза')))}
        try:
            warnings.submit(record)
            self.assertTrue(entered.wait(1))
            warnings.submit(record)
        finally:release.set();warnings.close()
        statuses=[json.loads(line)['status'] for line in out.getvalue().splitlines()]
        self.assertEqual(statuses,['queued','suppressed_rate_limit','accepted'])

    def test_file_queue_does_not_notify_on_block(self):
        out=io.StringIO();calls=[]
        warnings=FileWarnings(JsonAudit(out),lambda d:calls.append(d))
        warnings.submit({'result':asdict(self.analyzer.analyze(TextContent('top secret; пароль: берёза')))})
        warnings.close();self.assertFalse(calls)
