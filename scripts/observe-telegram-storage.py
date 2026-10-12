"""Bounded research observation of own-profile metadata; no file content reads.

Paths exist only in memory. Output contains aggregate changes, not messages,
account identifiers, paths, or ALLOW/WARN/BLOCK decisions.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location(
    'storage_inventory', Path(__file__).with_name('inspect-telegram-storage.py'))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def category(path):
    # Names are structural hints only, not verified content types.
    if len(path) == 1 and path[-1] == 'settingss':
        return 'settings_name'
    if len(path) == 2 and path[-1] in {'maps', 'configs'}:
        return path[-1] + '_name'
    if any(part in {'cache', 'media_cache', 'audio_cache'} for part in path[:-1]):
        return 'cache_directory_name'
    return 'other'


def compare(before, after):
    result = {}
    for path in before.keys() | after.keys():
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        counts = result.setdefault(category(path), Counter())
        if old is None:
            counts['appeared'] += 1
        elif new is None:
            counts['disappeared'] += 1
        else:
            counts['changed'] += 1
            if old[:2] != new[:2]:
                counts['identity_changed'] += 1
        counts['logical_bytes_delta'] += (new[2] if new else 0) - (old[2] if old else 0)
    return {key: dict(value) for key, value in sorted(result.items())}


def sample(root):
    records = {}
    report = inventory.inspect_storage(root, read_headers=False, records=records)
    return report, records


def observation(previous, report, records):
    usable = report['complete_within_limits']
    event = {
        'timestamp': report['observed_at'],
        'event': 'storage_metadata_observation',
        'source': 'telegram_local_filesystem_metadata',
        'complete_within_limits': usable,
        'comparison_available': usable and previous is not None,
        'changes_by_name_category': compare(previous, records) if usable and previous is not None else None,
        'regular_files': report['counts'].get('regular_files', 0),
        'logical_bytes': report['counts'].get('logical_bytes', 0),
        'errors': report['errors'],
        'consistent_profile_snapshot': False,
        'message_content_read': False,
        'key_content_read': False,
        'send_confirmed': False,
        'enforcement': 'none',
    }
    # A partial scan must not produce false deletions or bridge an unobserved gap.
    return event, records if usable else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.home()/'.local/share/TelegramDesktop/tdata')
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--interval', type=float, default=1.0)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 600 or not 0.5 <= args.interval <= 10:
        parser.error('seconds must be 1..600; interval must be 0.5..10')
    deadline = time.monotonic() + args.seconds
    previous = None
    failed = False
    try:
        while True:
            report, records = sample(args.root)
            event, previous = observation(previous, report, records)
            failed |= not event['complete_within_limits']
            print(json.dumps(event, ensure_ascii=False), flush=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(args.interval, remaining))
    except OSError as exc:
        print(json.dumps({'timestamp': datetime.now(timezone.utc).isoformat(),
                          'event': 'storage_observation_error', 'error': type(exc).__name__}), flush=True)
        return 2
    except KeyboardInterrupt:
        return 130
    return 2 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
