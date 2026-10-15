import json
import math
import unittest
from dlp.ml_baseline import (LABELS, MAX_TEXT_BYTES, features, fit, scores, predict,
                             calibrate_thresholds, evaluate, binary_metrics, validate_model)


class BaselineTests(unittest.TestCase):
    def rows(self):
        return [dict(id=str(i), split='train', text=t, labels=labels)
                for i,(t,labels) in enumerate([
                    ('money bank bank',['financial']), ('passport identity',['passport']),
                    ('password secret',['credentials']), ('hello weather',[])])]

    def test_fit_matches_laplace_likelihood(self):
        rows=self.rows(); model=fit(rows)
        xs=[features(r['text']) for r in rows]
        vocab=set().union(*(set(x) for x in xs))
        pos=xs[0]; negatives=xs[1:]
        total_pos=sum(pos.values())+len(vocab)
        total_neg=sum(sum(x.values()) for x in negatives)+len(vocab)
        expected=math.log(1/3)
        for f,n in features('bank').items():
            expected += n*math.log(((pos[f]+1)/total_pos)/((sum(x[f] for x in negatives)+1)/total_neg))
        self.assertAlmostEqual(scores(model,'bank')['financial'],expected)

    def test_train_dev_separation(self):
        rows=self.rows(); rows[0]['split']='test'
        with self.assertRaises(ValueError): fit(rows)
        model=fit(self.rows())
        with self.assertRaises(ValueError): calibrate_thresholds(model,rows)
        before=json.dumps(model,sort_keys=True)
        evaluate(model,rows)
        self.assertEqual(before,json.dumps(model,sort_keys=True))

    def test_metrics_counts(self):
        result=binary_metrics([True,True,False,False],[True,False,True,False])
        self.assertEqual([result[k] for k in ('tp','fn','fp','tn')],[1,1,1,1])
        self.assertEqual(result['precision'],0.5)
        self.assertEqual(result['recall'],0.5)
        self.assertEqual(result['f1'],0.5)

    def test_roundtrip_unknown_and_multiple_labels(self):
        model=validate_model(json.loads(json.dumps(fit(self.rows()))))
        self.assertEqual(predict(model,''),[])
        for m in model['models'].values(): m['threshold']=-1e9
        self.assertEqual(predict(model,'hello'),list(LABELS))
        model['models']['financial']['threshold']=float('nan')
        with self.assertRaises(ValueError): validate_model(model)

    def test_normalization_and_limits(self):
        self.assertEqual(features('ПАСПОРТ 123'),features('паспорт 789'))
        with self.assertRaises(ValueError): features('я'*MAX_TEXT_BYTES)

    def test_development_changes_only_thresholds(self):
        model=fit(self.rows())
        before=json.loads(json.dumps(model))
        dev=[dict(r,split='dev') for r in self.rows()]
        calibrate_thresholds(model,dev)
        for label in LABELS:
            self.assertEqual(before['models'][label]['weights'],model['models'][label]['weights'])
            self.assertEqual(before['models'][label]['prior_log_odds'],model['models'][label]['prior_log_odds'])
            self.assertIn(model['models'][label]['threshold'],(-10,-5,0,5,10))
