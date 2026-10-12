"""Run: PYTHONPATH=src:.deps python3 scripts/probe-telegram-ui.py [--marker DLP_TEST]"""
import argparse
from pathlib import Path
import sys
from dlp.accessibility import probe
from dlp.policy import PolicyError
from dlp.processes import load_process_config
from dlp.audit import JsonAudit

parser = argparse.ArgumentParser(description='Read-only Telegram accessibility probe')
parser.add_argument('--marker', help='Explicit marker entered into your own test draft; text is never logged')
args = parser.parse_args()
try:
    config = load_process_config(Path(__file__).resolve().parents[1]/'config/processes.yaml')
    JsonAudit(sys.stdout).emit(probe(config, 'telegram', args.marker))
except (OSError, ValueError, ImportError, PolicyError) as exc:
    print(f'Probe failed: {exc}', file=sys.stderr)
    raise SystemExit(2)
