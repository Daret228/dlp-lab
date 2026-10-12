"""Analyze one marked draft from an encrypted, temporary copy of own tdata.

Close Telegram first. No original file is written; no session/config file is read.
The temporary copy is removed on normal completion. Only aggregate findings print.
"""
import argparse
from dataclasses import asdict
import getpass
import os
from pathlib import Path
import resource
import sys
import tempfile

from dlp.analysis import ContentAnalyzer, deadline, AnalysisTimeout
from dlp.audit import JsonAudit
from dlp.models import TextContent
from dlp.policy import load_policy, PolicyError
from dlp.telegram_local import ProfileFiles, StorageError, collect, selected_draft


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--profile-closed', action='store_true', required=True,
                        help='Confirm Telegram has fully exited')
    parser.add_argument('--no-passcode', action='store_true', help='Explicitly confirm there is no local passcode')
    parser.add_argument('--marker', default='DLP_STORAGE_TEST')
    parser.add_argument('--expect-demo', action='store_true', help='Compare privately against the fixed artificial demo draft')
    parser.add_argument('--policy', type=Path, default=Path(__file__).resolve().parents[1]/'config/policy.yaml')
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    audit = JsonAudit(sys.stdout)
    try:
        analyzer = ContentAnalyzer(load_policy(args.policy))
        if not args.no_passcode and not sys.stdin.isatty():
            raise StorageError('password_requires_local_terminal')
        password = b'' if args.no_passcode else getpass.getpass('Локальный код-пароль Telegram (не пароль аккаунта): ').encode('utf-8')
        with deadline(30):
            original = ProfileFiles(args.root)
            try:
                account, files = collect(original, password)
            finally:
                original.close()
            # Only key_datas, maps and bounded draft records, never configs/auth files.
            with tempfile.TemporaryDirectory(prefix='dlp-local-draft-') as tmp:
                root = Path(tmp)
                for parts,data in files.items():
                    target = root.joinpath(*parts)
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with target.open('xb') as output:
                        output.write(data)
                copy = ProfileFiles(root)
                try:
                    copied_account, copied = collect(copy, password)
                finally:
                    copy.close()
                if account != copied_account or files != copied:
                    raise StorageError('snapshot_verification_failed')
                text, metadata = selected_draft(account, copied, password, args.marker)
                expected = text == 'DLP_STORAGE_TEST коммерческая тайна' if args.expect_demo else None
                if expected is False:
                    raise StorageError('demo_draft_mismatch')
                result = analyzer.analyze(TextContent(text, source='telegram_local_draft'))
            audit.emit({'event':'local_draft_analysis', 'source':'telegram_local_tdata_copy',
                        'scope':'one_marked_draft_text', 'retrospective':True,
                        'enforcement':'none', 'send_confirmed':False, 'send_blocked':False,
                        'profile_closed_user_confirmed':True, 'atomic_snapshot':False,
                        'copy_verified':True, 'temporary_copy_removed':True,
                        'expected_demo_match':expected, 'metadata':metadata,
                        'result':asdict(result)})
            return 0 if result.complete else 2
    except (StorageError, PolicyError, OSError, ImportError, UnicodeError, AnalysisTimeout) as exc:
        reason = str(exc) if isinstance(exc, StorageError) else type(exc).__name__
        audit.emit({'event':'local_draft_analysis_error', 'complete':False, 'reason':reason,
                    'enforcement':'none', 'send_confirmed':False})
        return 2
    except (KeyboardInterrupt, EOFError):
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
