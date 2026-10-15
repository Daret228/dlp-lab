#!/usr/bin/env python3
"""Read text from stdin; print labels only, no raw input or enforcement decision."""
import argparse
import json
from pathlib import Path
import sys
from dlp.ml_baseline import MAX_TEXT_BYTES, predict, validate_model

parser = argparse.ArgumentParser()
parser.add_argument('--model', type=Path, default=Path('build/ml/baseline-v1/model.json'))
args = parser.parse_args()
try:
    with args.model.open('rb') as f:
        raw=f.read(32*1024*1024+1)
    if len(raw)>32*1024*1024:
        raise ValueError('model_size_limit')
    model=validate_model(json.loads(raw))
    raw_text=sys.stdin.buffer.read(MAX_TEXT_BYTES+1)
    if len(raw_text)>MAX_TEXT_BYTES:
        raise ValueError('ml_text_limit')
    labels=predict(model, raw_text.decode('utf-8'))
    print(json.dumps({'labels':labels, 'experimental':True, 'enforcement':'none'},ensure_ascii=False))
except (OSError, ValueError, KeyError, TypeError, AttributeError):
    print('ML: input/model invalid, missing or exceeds limits; no prediction.',file=sys.stderr)
    sys.exit(2)
