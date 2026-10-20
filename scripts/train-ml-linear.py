#!/usr/bin/env python3
"""Train on train, select on dev, freeze artifact, then report test exactly once."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import time
import unicodedata
from dlp.ml_classifier import predict,validate_model
from dlp.ml_training import fit,calibrate,report
from dlp.sensitive_values_v4 import rule_predict

ROOT=Path(__file__).resolve().parents[1]
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--data',type=Path,default=ROOT/'data/ml/linear-v1')
    ap.add_argument('--output',type=Path,default=ROOT/'build/ml/linear-v1')
    strategy=ap.add_mutually_exclusive_group()
    strategy.add_argument('--precision-first',action='store_true')
    strategy.add_argument('--precision-with-recall',action='store_true')
    ap.add_argument('--disclosed-test',action='store_true')
    args=ap.parse_args()
    if args.output.exists():raise SystemExit('Output exists; choose a new version, do not overwrite an experiment.')
    data={s:json.loads((args.data/(s+'.json')).read_text()) for s in ('train','dev','test')}
    texts=set();groups={};ids=set()
    for split,rows in data.items():
        for r in rows:
            t=' '.join(unicodedata.normalize('NFKC',r['text']).casefold().split())
            if r['split']!=split or not t or t in texts or r['id'] in ids:raise ValueError('split_or_duplicate')
            if r['group_id'] in groups and groups[r['group_id']]!=split:raise ValueError('group_leakage')
            if not isinstance(r['labels'],list) or not set(r['labels']) <= {'financial','passport','credentials'}:raise ValueError('labels')
            texts.add(t);ids.add(r['id']);groups[r['group_id']]=split
    args.output.mkdir(parents=True)
    manifest={'data_sha256':{s:digest(args.data/(s+'.json')) for s in data},
              'code_sha256':{str(p.relative_to(ROOT)):digest(p) for p in [Path(__file__).resolve(),ROOT/'src/dlp/ml_training.py',ROOT/'src/dlp/ml_classifier.py']},
              'selection':'dev macro F1; fixed regularization grid; 250 epochs',
              'threshold_strategy':('dev F0.5 with recall >= 0.85; fallback maximum recall; grid 0.01..0.99' if args.precision_with_recall else 'zero dev FP first, then F1' if args.precision_first else 'dev F1'),
              'test_is_disclosed':args.disclosed_test,
              'limitations':'Handwritten synthetic test by same author; not an independent external evaluation. Earlier holdouts are now training data.'}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    candidates=[]
    started=time.perf_counter()
    for reg in (0.001,0.01,0.1):
        model=fit(data['train'],reg);calibrate(model,data['dev'],precision_first=args.precision_first,precision_with_recall=args.precision_with_recall)
        metrics=report(data['dev'],lambda text:predict(model,text))
        candidates.append((metrics['macro_f1'],-metrics['normal_false_alarms'],reg,model,metrics))
        print(json.dumps({'regularization':reg,'dev_macro_f1':metrics['macro_f1'],'dev_false_alarms':metrics['normal_false_alarms']}),flush=True)
    _,_,reg,model,dev=max(candidates,key=lambda c:c[:3])
    model['training']={'regularization':reg,'epochs':250,'train_count':len(data['train']),'dev_count':len(data['dev']),'data_sha256':{k:manifest['data_sha256'][k] for k in ('train','dev')}}
    validate_model(model)
    path=args.output/'model.json'
    path.write_text(json.dumps(model,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n')
    # All fitting and selection are complete before predicting test texts.
    outcome={'model_sha256':digest(path),'training_seconds':time.perf_counter()-started,'dev':dev,
             'ml':report(data['test'],lambda t:predict(model,t)),
             'rules':report(data['test'],rule_predict),
             'combined':report(data['test'],lambda t:sorted(set(predict(model,t))|set(rule_predict(t))))}
    durations=[]
    for r in data['test']:
        start=time.perf_counter();predict(model,r['text']);durations.append((time.perf_counter()-start)*1000)
    outcome['inference_ms']={'median':statistics.median(durations),'max':max(durations),'scope':'short synthetic texts, warm model, no extraction'}
    (args.output/'metrics.json').write_text(json.dumps(outcome,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:{f:v for f,v in outcome[k].items() if f!='errors'} for k in ('ml','rules','combined')},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
