#!/usr/bin/env python3
"""Experimental offline text/PDF/DOCX classification. No automatic enforcement."""
import argparse
import json
from pathlib import Path
import sys
from dlp.analysis import ContentAnalyzer, deadline, AnalysisTimeout
from dlp.documents import extract_document, DocumentError
from dlp.file_types import detect_type
from dlp.ml_baseline import MAX_TEXT_BYTES, predict, validate_model
from dlp.models import FileContent
from dlp.policy import load_policy
from dlp.sensitive_values_v4 import hybrid_predict, rule_predict

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--stdin',action='store_true')
    source.add_argument('--file',type=Path)
    parser.add_argument('--mode',choices=['hybrid','rules','ml'],default='hybrid')
    parser.add_argument('--model',type=Path,default=ROOT/'build/ml/hybrid-v3/model.json')
    args=parser.parse_args()
    try:
        model=None
        if args.mode!='rules':
            with args.model.open('rb') as f: raw=f.read(32*1024*1024+1)
            if len(raw)>32*1024*1024:raise ValueError('model_limit')
            model=validate_model(json.loads(raw))
        policy=load_policy(ROOT/'config/policy.yaml')
        complete=True;reason=None;scope='input_text';kind='text'
        with deadline(policy['limits']['timeout_seconds']):
            if args.stdin:
                raw=sys.stdin.buffer.read(MAX_TEXT_BYTES+1)
                if len(raw)>MAX_TEXT_BYTES:raise ValueError('ml_text_limit')
                text=raw.decode('utf-8-sig')
            else:
                data=ContentAnalyzer(policy)._file_bytes(FileContent(args.file))
                kind=detect_type(data)
                types=policy.get('file_types')
                if types and (kind in types['deny'] or (types['allow'] and kind not in types['allow'])):
                    raise ValueError('file_type_denied')
                if kind=='text':text=data.decode('utf-8-sig')
                elif kind in ('pdf','docx'):
                    result=extract_document(data,kind,MAX_TEXT_BYTES,policy['limits']['timeout_seconds'])
                    text=result['text'];complete=result['complete'];reason=result['reason'];scope=result['scope']
                else:raise ValueError('unsupported_file_type')
            labels=(rule_predict(text) if args.mode=='rules' else predict(model,text)
                    if args.mode=='ml' else hybrid_predict(model,text))
        print(json.dumps({'labels':labels,'complete':complete,'reason':reason,'mode':args.mode,
                          'file_type':kind,'scope':scope,'ocr':False,'experimental':True,
                          'enforcement':'none'},ensure_ascii=False))
        return 0 if complete else 2
    except (OSError,ValueError,KeyError,TypeError,AttributeError,AnalysisTimeout) as exc:
        # Never echo parser/model/input data in diagnostics.
        known={'ml_text_limit','file_type_denied','unsupported_file_type','model_limit'}
        reason=str(exc) if isinstance(exc,DocumentError) or type(exc) is ValueError and str(exc) in known else type(exc).__name__
        print(json.dumps({'labels':None,'complete':False,'reason':reason,'experimental':True,'enforcement':'none'}))
        return 2


if __name__=='__main__':sys.exit(main())
