"""Reproducible full-batch logistic training; never used in the daemon."""
from collections import Counter
import math
from .ml_classifier import LABELS, FEATURE_VERSION, features, vector, probabilities, predict
from .ml_baseline import binary_metrics


def fit(rows, regularization=0.01, epochs=250):
    if not rows or any(r['split']!='train' for r in rows):
        raise ValueError('training_requires_train_only')
    df=Counter()
    for r in rows: df.update(features(r['text']).keys())
    idf={f:math.log((1+len(rows))/(1+n))+1 for f,n in sorted(df.items()) if n>=2 and len(f)<=256}
    model=dict(version=1,algorithm='ovr_logistic_batch',features=FEATURE_VERSION,idf=idf,models={})
    xs=[vector(model,r['text']) for r in rows]
    for label in LABELS:
        ys=[int(label in r['labels']) for r in rows]
        pos=sum(ys);neg=len(ys)-pos
        if not pos or not neg:raise ValueError('missing_training_class')
        weights=dict.fromkeys(idf,0.0);bias=0.0
        for epoch in range(epochs):
            grad=dict.fromkeys(idf,0.0);gb=0.0
            for x,y in zip(xs,ys):
                z=bias+sum(weights[f]*v for f,v in x.items())
                p=1/(1+math.exp(-max(-60,min(60,z))))
                error=(p-y)*(len(ys)/(2*(pos if y else neg)))
                gb+=error
                for f,v in x.items():grad[f]+=error*v
            rate=2.0
            for f in weights:weights[f]-=rate*(grad[f]/len(ys)+regularization*weights[f])
            bias-=rate*gb/len(ys)
        model['models'][label]=dict(weights=weights,bias=bias,threshold=0.5)
    return model


def calibrate(model,rows,precision_first=False,precision_with_recall=False):
    if not rows or any(r['split']!='dev' for r in rows):raise ValueError('dev_only')
    if precision_first and precision_with_recall:raise ValueError('conflicting_threshold_strategies')
    values=[probabilities(model,r['text']) for r in rows]
    for label in LABELS:
        candidates=[]
        if precision_with_recall:
            for threshold in (i/100 for i in range(1,100)):
                m=binary_metrics([label in r['labels'] for r in rows],[v[label]>=threshold for v in values])
                p,r=m['precision'],m['recall']
                f05=1.25*p*r/(.25*p+r) if p+r else 0.0
                candidates.append((r>=.85, f05 if r>=.85 else r, -m['fp'], threshold))
            model['models'][label]['threshold']=max(candidates)[-1]
            continue
        for threshold in ((0.3,0.4,0.5,0.6,0.7,0.8,0.85,0.9,0.95,0.99) if precision_first else (0.3,0.4,0.5,0.6,0.7,0.8)):
            m=binary_metrics([label in r['labels'] for r in rows],[v[label]>=threshold for v in values])
            candidates.append(((m['fp']==0, m['f1'], threshold) if precision_first else (m['f1'],-m['fp'],threshold)))
        model['models'][label]['threshold']=max(candidates)[2]


def report(rows,predictor):
    guesses=[predictor(r['text']) for r in rows]
    per_label={l:binary_metrics([l in r['labels'] for r in rows],[l in g for g in guesses]) for l in LABELS}
    normal=[g for r,g in zip(rows,guesses) if not r['labels']]
    return dict(count=len(rows),per_label=per_label,macro_f1=sum(v['f1'] for v in per_label.values())/len(LABELS),
                normal_count=len(normal),normal_false_alarms=sum(bool(g) for g in normal),
                exact_match_count=sum(set(r['labels'])==set(g) for r,g in zip(rows,guesses)),
                errors=[dict(id=r['id'],expected=r['labels'],predicted=g) for r,g in zip(rows,guesses) if set(r['labels'])!=set(g)])
