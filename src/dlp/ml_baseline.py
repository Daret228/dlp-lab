"""Offline experimental multi-label Multinomial Naive Bayes; not an agent policy."""
from collections import Counter
import math
import re
import unicodedata

LABELS = ('financial', 'passport', 'credentials')
MAX_TEXT_BYTES = 16384


def features(text):
    if len(text.encode('utf-8')) > MAX_TEXT_BYTES:
        raise ValueError('ml_text_limit')
    text = unicodedata.normalize('NFKC', text).casefold()
    tokens = re.findall(r'\w+', re.sub(r'\d', '0', text))
    counts = Counter()
    for token in tokens:
        counts['word:' + token] += 1
        padded = '^' + token + '$'
        for n in (3, 4, 5):
            counts.update('char:' + padded[i:i+n] for i in range(len(padded)-n+1))
    return counts


def fit(rows):
    if not rows or any(r['split'] != 'train' for r in rows):
        raise ValueError('training_requires_train_only')
    xs = [features(r['text']) for r in rows]
    vocab = sorted(set().union(*(set(x) for x in xs)))
    if not vocab:
        raise ValueError('empty_vocabulary')
    models = {}
    for label in LABELS:
        positive, negative = Counter(), Counter()
        npos = 0
        for row, x in zip(rows, xs):
            if label in row['labels']:
                positive.update(x)
                npos += 1
            else:
                negative.update(x)
        if not 0 < npos < len(rows):
            raise ValueError('each_label_needs_positive_and_negative_examples')
        # Laplace smoothing alpha=1, empirical class priors.
        pos_total = sum(positive.values()) + len(vocab)
        neg_total = sum(negative.values()) + len(vocab)
        models[label] = {
            'prior_log_odds': math.log(npos / (len(rows)-npos)),
            'weights': {f: math.log((positive[f]+1)/pos_total)
                          - math.log((negative[f]+1)/neg_total) for f in vocab},
            'threshold': 0.0,
        }
    return {'version': 1, 'algorithm': 'binary_multinomial_nb_alpha1',
            'features': 'nfkc_casefold_digits0_word_char345_v1', 'models': models}


def scores(model, text):
    x = features(text)
    return {label: m['prior_log_odds'] + sum(count*m['weights'].get(f, 0.0)
                                          for f, count in x.items())
            for label, m in model['models'].items()}


def predict(model, text):
    values = scores(model, text)
    return [label for label in LABELS if values[label] >= model['models'][label]['threshold']]


def binary_metrics(expected, predicted):
    tp = sum(a and b for a, b in zip(expected, predicted))
    fp = sum(not a and b for a, b in zip(expected, predicted))
    fn = sum(a and not b for a, b in zip(expected, predicted))
    tn = sum(not a and not b for a, b in zip(expected, predicted))
    precision = tp/(tp+fp) if tp+fp else 0.0
    recall = tp/(tp+fn) if tp+fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=precision, recall=recall,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.0,
                f2=5*tp/(5*tp+fp+4*fn) if 5*tp+fp+4*fn else 0.0)


def calibrate_thresholds(model, rows):
    if not rows or any(r['split'] != 'dev' for r in rows):
        raise ValueError('threshold_selection_requires_dev_only')
    values = [scores(model, r['text']) for r in rows]
    # Fixed grid declared before test evaluation. Prefer F2, then fewer FP,
    # then stricter threshold. These are log-odds, not calibrated probabilities.
    for label in LABELS:
        candidates = []
        for threshold in (-10.0, -5.0, 0.0, 5.0, 10.0):
            m = binary_metrics([label in r['labels'] for r in rows],
                               [s[label] >= threshold for s in values])
            candidates.append((m['f2'], -m['fp'], threshold))
        model['models'][label]['threshold'] = max(candidates)[2]


def evaluate(model, rows):
    guesses = [predict(model, r['text']) for r in rows]
    normal = [i for i, r in enumerate(rows) if not r['labels']]
    return {
        'count': len(rows),
        'per_label': {label: binary_metrics([label in r['labels'] for r in rows],
                                            [label in p for p in guesses]) for label in LABELS},
        'any_sensitive': binary_metrics([bool(r['labels']) for r in rows], [bool(p) for p in guesses]),
        'normal_false_alarms': sum(bool(guesses[i]) for i in normal),
        'normal_count': len(normal),
        'exact_match_count': sum(set(r['labels']) == set(p) for r, p in zip(rows, guesses)),
        'errors': [{'id': r['id'], 'expected': r['labels'], 'predicted': p}
                   for r, p in zip(rows, guesses) if set(r['labels']) != set(p)],
    }


def validate_model(model):
    if (model.get('version') != 1 or model.get('algorithm') != 'binary_multinomial_nb_alpha1'
            or model.get('features') != 'nfkc_casefold_digits0_word_char345_v1'
            or set(model.get('models', {})) != set(LABELS)):
        raise ValueError('unsupported_model')
    for m in model['models'].values():
        if not isinstance(m['weights'], dict) or len(m['weights']) > 100000:
            raise ValueError('invalid_weights')
        values = [m['prior_log_odds'], m['threshold'], *m['weights'].values()]
        if any(type(v) not in (float, int) or not math.isfinite(v) for v in values):
            raise ValueError('invalid_model_numbers')
    return model
