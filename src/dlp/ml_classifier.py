"""Bounded, dependency-free inference for an offline trained linear classifier."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import unicodedata

LABELS = ('financial', 'passport', 'credentials')
LEGACY_FEATURE_VERSION = 'binary_word_bigram_char345_l2_v1'
PREVIOUS_FEATURE_VERSION = 'weighted_word_bigram_char345_l2_v2'
FEATURE_VERSION = 'weighted_word_bigram_char345_l2_v3'
MODEL_PATH = Path(__file__).with_name('ml_assets') / 'sensitive-linear-v1.json'
MAX_MODEL_BYTES = 4 * 1024 * 1024
MAX_TEXT_BYTES = 16384


def features(text, version=FEATURE_VERSION):
    if len(text.encode('utf-8')) > MAX_TEXT_BYTES:
        raise ValueError('ml_text_limit')
    text = unicodedata.normalize('NFKC', text).casefold().replace('ё', 'е')
    normalized = re.sub(r'\d', '0', text)
    words = re.findall(r'\w+', normalized)
    result = {'w:'+w: 1.0 for w in words}
    result.update({'b:'+a+' '+b: 1.0 for a,b in zip(words, words[1:])})
    for w in words:
        padded = '^'+w+'$'
        for n in (3,4,5):
            for i in range(len(padded)-n+1):
                result['c:'+padded[i:i+n]] = 1.0
    # Generic shape features, not category decisions or outputs of DLP rules.
    for pattern,name in [(r'\d','digit'), (r'\d{4}\s+\d{6}','number4_6'),
                         (r'[:=]','assignment'), (r'[*_]{3,}|\[[^]]+\]','mask'),
                         (r'\b\w*[a-zа-я]\w*\d\w*\b','mixed_token')]:
        if re.search(pattern,text): result['shape:'+name] = 3.0
    if version in (FEATURE_VERSION, PREVIOUS_FEATURE_VERSION):
        for key in result:
            word, bigram, char = (2.0, 2.0, 1.0) if version == FEATURE_VERSION else (3.0, 5.0, .35)
            result[key] *= word if key.startswith('w:') else bigram if key.startswith('b:') else char if key.startswith('c:') else 1.0
    return result


def vector(model, text):
    raw = features(text, model["features"])
    result = {f: value * model['idf'][f] for f,value in raw.items() if f in model['idf']}
    norm = math.sqrt(sum(v*v for v in result.values())) or 1
    return {f:v/norm for f,v in result.items()}


def probabilities(model, text):
    x = vector(model,text)
    result = {}
    for label in LABELS:
        m = model['models'][label]
        z = m['bias'] + sum(v*m['weights'].get(f,0) for f,v in x.items())
        result[label] = 1/(1+math.exp(-max(-60,min(60,z))))
    return result


def predict(model, text):
    values = probabilities(model,text)
    return [label for label in LABELS if values[label] >= model['models'][label]['threshold']]


def validate_model(model):
    try:
        if (model['version'] != 1 or model['algorithm'] != 'ovr_logistic_batch'
            or model['features'] not in (FEATURE_VERSION, PREVIOUS_FEATURE_VERSION, LEGACY_FEATURE_VERSION) or set(model['models']) != set(LABELS)):
            raise ValueError('unsupported_ml_model')
        idf = model['idf']
        if not isinstance(idf,dict) or not 1 <= len(idf) <= 40000:
            raise ValueError('invalid_ml_vocabulary')
        def finite(v): return type(v) in (int,float) and math.isfinite(v)
        if any(not isinstance(k,str) or len(k)>256 or not finite(v) or not 0<v<20 for k,v in idf.items()):
            raise ValueError('invalid_ml_idf')
        for m in model['models'].values():
            if not isinstance(m['weights'],dict) or set(m['weights']) != set(idf):
                raise ValueError('invalid_ml_weights')
            if any(not finite(v) or abs(v)>1000 for v in [m['bias'],*m['weights'].values()]):
                raise ValueError('invalid_ml_numbers')
            if not finite(m['threshold']) or not 0<m['threshold']<1:
                raise ValueError('invalid_ml_threshold')
        return model
    except (TypeError,KeyError,AttributeError,OverflowError) as e:
        raise ValueError('invalid_ml_model') from e


def load_model(expected_sha256, path=None):
    with Path(path or MODEL_PATH).open('rb') as stream:
        raw = stream.read(MAX_MODEL_BYTES+1)
    if len(raw)>MAX_MODEL_BYTES or hashlib.sha256(raw).hexdigest()!=expected_sha256:
        raise ValueError('ml_model_integrity')
    return validate_model(json.loads(raw))
