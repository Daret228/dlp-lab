#!/usr/bin/env python3
"""Reproducible offline experiment. Never reads Telegram or modifies agent policy."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

from dlp.ml_baseline import fit, calibrate_thresholds, evaluate, predict, binary_metrics
from dlp.analysis import ContentAnalyzer
from dlp.models import TextContent
from dlp.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', type=Path, default=ROOT/'data/ml/synthetic-v2')
    parser.add_argument('--output', type=Path, default=ROOT/'build/ml/baseline-v1')
    args = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT/'scripts/validate-ml-corpus.py'),
                    '--data', str(args.data)], check=True)
    data = {s: json.loads((args.data/f'{s}.json').read_text()) for s in ('train', 'dev', 'test')}
    started = time.perf_counter()
    model = fit(data['train'])
    calibrate_thresholds(model, data['dev'])
    train_seconds = time.perf_counter()-started
    model['training'] = {'data_sha256': {s: hashlib.sha256((args.data/f'{s}.json').read_bytes()).hexdigest()
                                        for s in ('train', 'dev')},
                         'train_rows': len(data['train']), 'dev_rows': len(data['dev'])}
    args.output.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(model, ensure_ascii=False, sort_keys=True, allow_nan=False)+'\n'
    (args.output/'model.json').write_text(encoded)
    # Frozen model has been persisted before any test evaluation.
    report = {'model_sha256': hashlib.sha256(encoded.encode()).hexdigest(),
              'python': platform.python_version(), 'training_seconds': train_seconds,
              'test_sha256': hashlib.sha256((args.data/'test.json').read_bytes()).hexdigest(),
              'thresholds': {label: m['threshold'] for label, m in model['models'].items()},
              'dev': evaluate(model, data['dev']), 'test': evaluate(model, data['test'])}
    durations=[]
    for row in data['test']:
        start=time.perf_counter(); predict(model, row['text']); durations.append((time.perf_counter()-start)*1000)
    report['prediction_ms'] = {'median': statistics.median(durations), 'max': max(durations),
                               'scope': 'short synthetic test texts, warm model, no extraction'}
    policy_path=ROOT/'config/policy.yaml'
    analyzer = ContentAnalyzer(load_policy(policy_path))
    results = [analyzer.analyze(TextContent(r['text'])) for r in data['test']]
    report['existing_rules_any_sensitive'] = binary_metrics(
        [bool(r['labels']) for r in data['test']], [bool(r.findings) for r in results])
    report['existing_rules_incomplete'] = sum(not r.complete for r in results)
    report['existing_policy_sha256'] = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    report['comparison_note'] = 'Existing rules target other categories; this is a coverage baseline, not a tuned rules-vs-ML comparison.'
    (args.output/'metrics.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__ == '__main__':
    main()
