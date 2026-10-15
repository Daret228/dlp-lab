#!/usr/bin/env python3
"""Fit on development data, then explicitly evaluate a held-out set once."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import time
from dlp.ml_baseline import LABELS, fit, calibrate_thresholds, predict, binary_metrics
from dlp.sensitive_values import rule_predict, hybrid_predict

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/ml/hybrid-v3'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(rows,predictor):
    predictions=[];durations=[]
    for r in rows:
        start=time.perf_counter(); predictions.append(predictor(r['text']));durations.append((time.perf_counter()-start)*1000)
    metrics={label:binary_metrics([label in r['labels'] for r in rows],[label in p for p in predictions]) for label in LABELS}
    normal=[i for i,r in enumerate(rows) if not r['labels']]
    return {'per_label':metrics,'any_sensitive':binary_metrics([bool(r['labels']) for r in rows],[bool(p) for p in predictions]),
            'normal_count':len(normal),'normal_false_alarms':sum(bool(predictions[i]) for i in normal),
            'exact_match_count':sum(set(r['labels'])==set(p) for r,p in zip(rows,predictions)),
            'count':len(rows),'median_ms':statistics.median(durations),'max_ms':max(durations),
            'errors':[{'id':r['id'],'expected':r['labels'],'predicted':p} for r,p in zip(rows,predictions) if set(r['labels'])!=set(p)]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('stage',choices=['fit','holdout'])
    args=parser.parse_args()
    model_path=OUT/'model.json'; manifest_path=OUT/'manifest.json'
    code_paths=['src/dlp/ml_baseline.py','src/dlp/sensitive_values.py','scripts/evaluate-ml-hybrid.py']
    if args.stage=='fit':
        if model_path.exists():
            raise SystemExit('Model already frozen; use a new experiment version for changes.')
        paths=['data/ml/synthetic-v2/train.json','data/ml/contrast-v3/train.json','data/ml/synthetic-v2/dev.json']
        rows=[json.loads((ROOT/p).read_text()) for p in paths]
        model=fit(rows[0]+rows[1]);calibrate_thresholds(model,rows[2])
        OUT.mkdir(parents=True,exist_ok=True)
        model_path.write_text(json.dumps(model,ensure_ascii=False,sort_keys=True)+'\n')
        manifest={'model_sha256':digest(model_path),'input_sha256':{p:digest(ROOT/p) for p in paths},
                  'code_sha256':{p:digest(ROOT/p) for p in code_paths},
                  'holdout_sha256':digest(ROOT/'data/ml/holdout-v3/test.json'),
                  'train_count':len(rows[0])+len(rows[1]),'dev_count':len(rows[2]),
                  'targets':{'per_label_precision_min':0.9,'per_label_recall_min':0.9,'normal_false_alarm_rate_max':0.05},
                  'dev':{name:measure(rows[2],fn) for name,fn in [('ml',lambda t:predict(model,t)),('rules',rule_predict),('hybrid',lambda t:hybrid_predict(model,t))]}}
        manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        print('Model and code hashes frozen; holdout has not been evaluated.')
    else:
        report_path=OUT/'holdout-metrics.json'
        if report_path.exists(): raise SystemExit('Holdout already evaluated; read the saved report.')
        manifest=json.loads(manifest_path.read_text())
        if digest(model_path)!=manifest['model_sha256'] or any(digest(ROOT/p)!=h for p,h in manifest['code_sha256'].items()):
            raise SystemExit('Frozen model/code changed; evaluation refused.')
        path=ROOT/'data/ml/holdout-v3/test.json'
        if digest(path)!=manifest['holdout_sha256']: raise SystemExit('Holdout changed.')
        rows=json.loads(path.read_text());model=json.loads(model_path.read_text())
        result={name:measure(rows,fn) for name,fn in [('ml',lambda t:predict(model,t)),('rules',rule_predict),('hybrid',lambda t:hybrid_predict(model,t))]}
        for m in result.values():
            m['target_met']=(all(v['precision']>=0.9 and v['recall']>=0.9 for v in m['per_label'].values())
                             and m['normal_count']>0 and m['normal_false_alarms']/m['normal_count']<=0.05)
        report_path.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        for name,m in result.items():
            print(name, 'target_met=',m['target_met'],'false alarms=',m['normal_false_alarms'],'/',m['normal_count'])
            print(json.dumps(m['per_label'],ensure_ascii=False));print('errors:',m['errors'])


if __name__=='__main__': main()
