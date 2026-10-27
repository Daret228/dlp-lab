#!/usr/bin/env python3
"""Usage: PYTHONPATH=src:.deps python3 scripts/probe-signal-storage.py --root PATH"""
import argparse
import json
from pathlib import Path
from dlp.signal_storage import probe_signal_storage

parser = argparse.ArgumentParser(description='Probe Signal storage without reading messages or keys')
parser.add_argument('--root', required=True, type=Path)
args = parser.parse_args()
print(json.dumps(probe_signal_storage(args.root), ensure_ascii=False))
