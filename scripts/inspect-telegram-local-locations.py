"""Inspect metadata for one synthetic test file in a copy of closed own tdata."""
import argparse
import getpass
import os
from pathlib import Path
import resource
import sys
import tempfile

from dlp.analysis import deadline, AnalysisTimeout
from dlp.audit import JsonAudit
from dlp.telegram_local import ProfileFiles, StorageError
from dlp.telegram_locations import collect_locations, inspect_locations, validate_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--profile-closed', action='store_true', required=True)
    parser.add_argument('--no-passcode', action='store_true')
    parser.add_argument('--expected-path', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    audit = JsonAudit(sys.stdout)
    try:
        validate_target(args.expected_path)
        if not args.no_passcode and not sys.stdin.isatty():
            raise StorageError('password_requires_local_terminal')
        password = b'' if args.no_passcode else getpass.getpass('Локальный код-пароль Telegram: ').encode('utf-8')
        with deadline(30):
            original = ProfileFiles(args.root)
            try:
                account, files = collect_locations(original,password)
            finally:
                original.close()
            with tempfile.TemporaryDirectory(prefix='dlp-local-locations-') as tmp:
                root = Path(tmp)
                for parts,data in files.items():
                    target = root.joinpath(*parts)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with target.open('xb') as output:
                        output.write(data)
                copy = ProfileFiles(root)
                try:
                    copied_account,copied = collect_locations(copy,password)
                finally:
                    copy.close()
                if account != copied_account or files != copied:
                    raise StorageError('snapshot_verification_failed')
                metadata = inspect_locations(account,copied,password,args.expected_path)
            audit.emit({'event':'local_locations_inspection', 'complete':True,
                        'source':'telegram_local_tdata_copy', 'scope':'file_location_metadata',
                        'profile_closed_user_confirmed':True, 'atomic_snapshot':False,
                        'copy_verified':True, 'temporary_copy_removed':True,
                        'enforcement':'none', 'send_confirmed':False,
                        'file_content_read':False, 'metadata':metadata})
            return 0
    except (StorageError, OSError, ImportError, UnicodeError, AnalysisTimeout) as exc:
        reason = str(exc) if isinstance(exc,StorageError) else type(exc).__name__
        audit.emit({'event':'local_locations_inspection_error', 'complete':False,
                    'reason':reason, 'enforcement':'none', 'send_confirmed':False})
        return 2
    except (KeyboardInterrupt, EOFError):
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
