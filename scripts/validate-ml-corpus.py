#!/usr/bin/env python3
"""Validate the synthetic corpus before a training experiment; stdlib only."""
import argparse
import json
from collections import Counter
from pathlib import Path
import re
import unicodedata

ROOT = Path(__file__).resolve().parents[1] / 'data/ml/synthetic-v1'
LABELS = {'financial', 'passport', 'credentials'}


def validate(root=ROOT):
    ids, texts, groups = set(), set(), {}
    for split in ('train', 'dev', 'test'):
        rows = json.loads((root / f'{split}.json').read_text())
        counts = Counter()
        if not rows:
            raise ValueError(f'{split}: empty split')
        for row in rows:
            if row['split'] != split or row['annotation_status'] != 'provisional':
                raise ValueError(f'{row["id"]}: unexpected split/status')
            if row['source'] != 'handwritten_synthetic' or not row['rationale'].strip():
                raise ValueError(f'{row["id"]}: missing provenance/rationale')
            if row['id'] in ids:
                raise ValueError(f'duplicate id: {row["id"]}')
            ids.add(row['id'])
            labels = row['labels']
            if not isinstance(labels, list) or not set(labels) <= LABELS or len(labels) != len(set(labels)):
                raise ValueError(f'{row["id"]}: invalid labels')
            text = re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', row['text'])).strip().casefold()
            if not text or text in texts:
                raise ValueError(f'{row["id"]}: empty/duplicate text')
            texts.add(text)
            group = row['group_id']
            if not group or (group in groups and groups[group] != split):
                raise ValueError(f'{row["id"]}: scenario crosses splits')
            groups[group] = split
            counts.update(labels or ['normal'])
        if set(counts) != LABELS | {'normal'}:
            raise ValueError(f'{split}: missing category')
        print(f'{split}: {len(rows)} rows; {dict(sorted(counts.items()))}')
    review = json.loads((root / 'review.json').read_text())
    for row in review:
        if row['id'] in ids or row['review_status'] != 'pending' or not row['question'].strip():
            raise ValueError('invalid review item')
        if not set(row['proposed_labels']) <= LABELS:
            raise ValueError('invalid proposed labels')
        ids.add(row['id'])
    print(f'review: {len(review)} pending items (excluded from training/evaluation)')
    print('OK: schema, labels, exact normalized duplicates, scenario split separation')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=ROOT)
    validate(parser.parse_args().data)
