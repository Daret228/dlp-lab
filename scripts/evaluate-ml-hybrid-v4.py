#!/usr/bin/env python3
"""Evaluate fixed v4 value binding with the already frozen v3 ML model."""
import hashlib
import json
from pathlib import Path
import runpy
from dlp.ml_baseline import predict
from dlp.sensitive_values_v4 import rule_predict, hybrid_predict

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/ml/hybrid-v4'
measure=runpy.run_path(str(ROOT/'scripts/evaluate-ml-hybrid.py'))['measure']

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    if (OUT/'holdout-metrics.json').exists():raise SystemExit('Already evaluated: read saved report; do not retune on this holdout.')
    OUT.mkdir(parents=True,exist_ok=True)
    model_path=ROOT/'build/ml/hybrid-v3/model.json'
    files=['src/dlp/ml_baseline.py','src/dlp/sensitive_values.py','src/dlp/sensitive_values_v4.py',
           'scripts/evaluate-ml-hybrid.py','scripts/evaluate-ml-hybrid-v4.py',
           'data/ml/holdout-v4/test.json']
    manifest={'model_sha256':sha(model_path),'sha256':{p:sha(ROOT/p) for p in files},
              'targets':{'per_label_precision_min':0.9,'per_label_recall_min':0.9,'normal_false_alarm_rate_max':0.05},
              'note':'ML weights and thresholds unchanged from v3; only rule binding improved using development/unit cases.'}
    # Persist exact inputs/criteria before scoring the new holdout.
    (OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    model=json.loads(model_path.read_text());rows=json.loads((ROOT/'data/ml/holdout-v4/test.json').read_text())
    result={name:measure(rows,fn) for name,fn in [('ml',lambda t:predict(model,t)),('rules',rule_predict),('hybrid',lambda t:hybrid_predict(model,t))]}
    for name,m in result.items():
        m['target_met']=(all(v['precision']>=0.9 and v['recall']>=0.9 for v in m['per_label'].values())
                         and m['normal_false_alarms']/m['normal_count']<=0.05)
        print(name,m['target_met'],m['exact_match_count'],'/',m['count'],'false alarms',m['normal_false_alarms'],'/',m['normal_count'])
        print(m['per_label']);print(m['errors'])
    (OUT/'holdout-metrics.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')

if __name__=='__main__':main()
