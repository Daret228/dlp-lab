import copy
import hashlib
import io
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
from dlp.ml_classifier import (FEATURE_VERSION,LABELS,features,vector,probabilities,predict,
                               validate_model,load_model,MODEL_PATH)
from dlp.ml_training import fit,calibrate
from dlp.analysis import ContentAnalyzer,AnalysisTimeout
from dlp.models import TextContent,FileContent
from dlp.policy import load_policy,parse_policy,PolicyError
from dlp.audit import JsonAudit
from dlp.text_monitor import DraftMonitor
from dlp.dashboard import project
from test_documents import make_docx
ROOT=Path(__file__).resolve().parents[1]

class LinearTests(unittest.TestCase):
    def toy(self):
        return dict(version=1,algorithm='ovr_logistic_batch',features=FEATURE_VERSION,idf={'w:secret':2.0},
                    models={l:dict(bias=-1.0,weights={'w:secret':3.0},threshold=.8) for l in LABELS})

    def test_inference_matches_known_linear_equation_and_roundtrip(self):
        m=validate_model(self.toy())
        self.assertEqual(vector(m,'secret'),{'w:secret':1.0})
        self.assertAlmostEqual(probabilities(m,'secret')['financial'],1/(1+math.exp(-2)))
        self.assertEqual(predict(m,'secret'),list(LABELS))
        self.assertEqual(predict(m,'unknown'),[])
        self.assertEqual(predict(json.loads(json.dumps(m)),'secret'),list(LABELS))

    def test_model_integrity_shape_and_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'model.json';p.write_text(json.dumps(self.toy()))
            sha=hashlib.sha256(p.read_bytes()).hexdigest()
            self.assertEqual(load_model(sha,p),self.toy())
            p.write_text(p.read_text()+' ')
            with self.assertRaises(ValueError):load_model(sha,p)
        for value in (None,[],{},dict(self.toy(),idf={'w:secret':float('nan')})):
            with self.assertRaises(ValueError):validate_model(value)
        m=self.toy();m['models']['passport']['weights']={}
        with self.assertRaises(ValueError):validate_model(m)

    def test_limits_and_normalization(self):
        self.assertEqual(features('ПАРОЛЬ 123'),features('пароль 456'))
        with self.assertRaises(ValueError):features('я'*9000)

    def test_precision_calibration_preserves_recall_and_weights(self):
        model=self.toy()
        before=copy.deepcopy(model)
        rows=[dict(split='dev',text=str(i),labels=list(LABELS) if i<10 else []) for i in range(12)]
        scores=[.90]*9+[.45,.60,.30]
        with patch('dlp.ml_training.probabilities',side_effect=[dict.fromkeys(LABELS,s) for s in scores]):
            calibrate(model,rows,precision_with_recall=True)
        for label in LABELS:
            threshold=model['models'][label]['threshold']
            self.assertGreater(threshold,.60)
            self.assertLessEqual(threshold,.90)
            self.assertEqual(model['models'][label]['weights'],before['models'][label]['weights'])
        with self.assertRaises(ValueError):
            calibrate(model,rows,precision_first=True,precision_with_recall=True)

    def test_previous_feature_weights_remain_compatible(self):
        from dlp.ml_classifier import PREVIOUS_FEATURE_VERSION
        previous=features('alpha beta',PREVIOUS_FEATURE_VERSION)
        current=features('alpha beta')
        self.assertEqual(previous['w:alpha'],3.0)
        self.assertEqual(previous['b:alpha beta'],5.0)
        self.assertEqual(current['w:alpha'],2.0)
        self.assertEqual(current['b:alpha beta'],2.0)
        model=self.toy();model['features']=PREVIOUS_FEATURE_VERSION
        self.assertEqual(predict(validate_model(model),'secret'),list(LABELS))

    def test_training_learns_labels_and_honors_splits(self):
        rows=[dict(split='train',text=t,labels=l) for t,l in [
            ('money money',['financial']),('passport passport',['passport']),
            ('secret secret',['credentials']),('hello hello',[])]]*2
        model=fit(rows,epochs=100,regularization=.001)
        self.assertEqual(predict(model,'secret secret'),['credentials'])
        self.assertEqual(predict(model,'hello hello'),[])
        with self.assertRaises(ValueError):fit([dict(rows[0],split='test')])
        with self.assertRaises(ValueError):calibrate(model,rows)
        before=copy.deepcopy(model)
        calibrate(model,[dict(r,split='dev') for r in rows],precision_first=True)
        for l in LABELS:self.assertEqual(model['models'][l]['weights'],before['models'][l]['weights'])

class MLIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.policy=load_policy(ROOT/'config/policy.yaml')
        self.policy['sensitive_alerts']['enabled']=False
        self.policy['rules']=[]
        self.policy['ml_alerts']=dict(enabled=True,action='WARN',model_sha256=hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest())

    def test_ml_alone_triggers_without_rules(self):
        a=ContentAnalyzer(self.policy)
        for text,label in [('Мой оклад 95000 рублей','financial'),('Паспорт 0051 627384','passport'),
                           ('Пароль: Reka!6831','credentials')]:
            r=a.analyze(TextContent(text))
            self.assertTrue(r.complete);self.assertEqual(r.decision,'WARN');self.assertEqual(r.score,0)
            self.assertIn(label,{f.category for f in r.findings if f.analyzer=='ml'})
            self.assertTrue(r.metadata['ml']['complete'])
        self.assertEqual(a.analyze(TextContent('Привет, встречаемся завтра')).decision,'ALLOW')

    def test_missing_model_does_not_silently_allow_and_legacy_block_survives(self):
        self.policy['ml_alerts']['model_sha256']='0'*64
        r=ContentAnalyzer(self.policy).analyze(TextContent('ordinary'))
        self.assertFalse(r.complete);self.assertEqual(r.decision,'WARN')
        self.assertEqual(r.reason,'ml_analysis_incomplete')
        self.policy['rules']=load_policy(ROOT/'config/policy.yaml')['rules']
        r=ContentAnalyzer(self.policy).analyze(TextContent('top secret'))
        self.assertEqual(r.decision,'BLOCK');self.assertEqual(r.score,.8)

    def test_disabled_and_text_limit_timeout(self):
        a=ContentAnalyzer(self.policy)
        r=a.analyze(TextContent('x'*17000))
        self.assertFalse(r.complete);self.assertEqual(r.decision,'WARN')
        with patch('dlp.ml_classifier.probabilities',side_effect=AnalysisTimeout):
            self.assertFalse(a.analyze(TextContent('abc')).complete)
        self.policy['ml_alerts']['enabled']=False
        self.assertEqual(ContentAnalyzer(self.policy).analyze(TextContent('Пароль: Reka!6831')).decision,'ALLOW')

    def test_document_integration_and_no_secret_in_journal(self):
        a=ContentAnalyzer(self.policy)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'sample.docx'
            p.write_bytes(make_docx('<w:p><w:r><w:t>Пароль: Reka!6831</w:t></w:r></w:p>'))
            r=a.analyze(FileContent(p));self.assertEqual(r.decision,'WARN')
            self.assertIn('credentials',r.metadata['ml']['categories'])
        out=io.StringIO();calls=[]
        monitor=DraftMonitor(a,JsonAudit(out),lambda d:calls.append(d) or 'accepted')
        monitor.check('Пароль: Reka!6831','telegram',123)
        self.assertEqual(calls,['WARN']);self.assertNotIn('Reka!6831',out.getvalue())
        event=json.loads(out.getvalue().splitlines()[0]);self.assertFalse(event['send_blocked'])
        self.assertTrue(event['result']['metadata']['ml']['complete'])

    def test_policy_validation(self):
        for key,value in [('enabled',1),('action','BLOCK'),('model_sha256','bad')]:
            p=copy.deepcopy(self.policy);p['ml_alerts'][key]=value
            with self.assertRaises(PolicyError):parse_policy(yaml.safe_dump(p).encode())

    def test_dashboard_ml_projection_is_bounded_and_private(self):
        r=project({'MESSAGE':json.dumps({'timestamp':'2026-10-18T12:00:00Z','event':'draft_analysis',
            'result':{'metadata':{'ml':{'complete':True,'model_sha256':'a'*64,
                                     'categories':['credentials','private-secret'], 'text':'private-secret'}}}})})
        self.assertEqual(r['ml_categories'],['credentials'])
        self.assertTrue(r['ml_complete']);self.assertEqual(r['ml_model_sha256'],'a'*64)
        self.assertNotIn('private-secret',json.dumps(r))

    def test_ml_policy_toggle_preserves_other_analysis_settings(self):
        from dlp.policy_store import PolicyStore
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'policy.yaml'
            policy=load_policy(ROOT/'config/policy.yaml')
            policy['ml_alerts']['enabled']=False
            path.write_text(yaml.safe_dump(policy,allow_unicode=True))
            store=PolicyStore(path,Path(d)/'backups');view=store.get()
            body=dict(view);body['expected_version']=body.pop('version');body['ml_enabled']=True
            old=load_policy(path)
            self.assertEqual(store.update(body,preview=True)['changes']['ml_enabled']['after'],True)
            self.assertEqual(load_policy(path),old)
            store.update(body)
            updated=load_policy(path);self.assertTrue(updated['ml_alerts']['enabled'])
            for key in old:
                if key!='ml_alerts':self.assertEqual(old[key],updated[key])
            self.assertEqual(updated['ml_alerts']['model_sha256'],old['ml_alerts']['model_sha256'])
