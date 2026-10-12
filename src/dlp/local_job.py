"""One-shot local storage audit, closed own Telegram profile only."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from .notifications import report_warning
from .telegram_local import StorageError

ROOT = Path(__file__).resolve().parents[2]


def require_telegram_closed():
    # Check the current user's process names and executable names, without logging them.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            name = (entry/'comm').read_text().lower()
            if 'telegram' in name:
                raise StorageError('telegram_is_running_close_application')
            try:
                executable = os.readlink(entry/'exe').lower()
            except (FileNotFoundError, PermissionError):
                # Some unrelated same-UID sandboxed processes hide exe. Their
                # readable comm was checked above; this is not binary attestation.
                continue
            if 'telegram' in executable:
                raise StorageError('telegram_is_running_close_application')
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise StorageError('cannot_verify_telegram_closed') from None


def run_local(args, audit):
    run_id = uuid4().hex
    class RunAudit:
        def emit(self, event):
            audit.emit({**event, 'run_id':run_id})
    out = RunAudit()
    out.emit({'event':'local_check_started', 'enforcement':'none', 'send_blocked':False})
    failures = 0
    notification_status = 'not_needed'
    try:
        require_telegram_closed()
        jobs = [('draft', 'analyze-telegram-local-draft.py', ['--policy',args.policy,'--marker',args.marker])]
        if args.expected_path is not None:
            jobs.append(('locations','inspect-telegram-local-locations.py', ['--expected-path',str(args.expected_path)]))
        for component, script, extra in jobs:
            require_telegram_closed()
            command = [sys.executable,str(ROOT/'scripts'/script),'--root',str(args.root),
                       '--profile-closed','--no-passcode',*extra]
            result = subprocess.run(command,capture_output=True,text=True,timeout=40)
            # Never forward stderr or arbitrary child output to the journal.
            try:
                event = json.loads(result.stdout)
                expected = 'local_draft_analysis' if component == 'draft' else 'local_locations_inspection'
                if event.get('event') not in (expected,expected+'_error'):
                    raise ValueError()
            except (ValueError, AttributeError):
                raise StorageError('invalid_local_worker_output') from None
            if event.get('reason') == 'requires_exactly_one_marked_draft':
                event['message'] = 'Не найден единственный тестовый черновик с маркером. Сохраните его в Telegram и закройте клиент.'
            elif component == 'draft' and 'result' in event:
                event['message'] = 'Локальный черновик проверен; решение политики не запрещает отправку.'
            elif component == 'locations' and 'metadata' in event:
                event['message'] = 'Проверены локальные сведения о тестовом файле; это не подтверждение отправки.'
            out.emit(event)
            failures += result.returncode != 0
            if component == 'draft' and event.get('result',{}).get('decision') in ('WARN','BLOCK'):
                notification_status = report_warning(out,event['result']['decision'],'telegram_local_draft')
        require_telegram_closed()
    except (StorageError, OSError, subprocess.TimeoutExpired) as exc:
        failures += 1
        out.emit({'event':'local_check_error','complete':False,
                  'reason':str(exc) if isinstance(exc,StorageError) else type(exc).__name__})
    out.emit({'event':'local_check_finished','complete':failures == 0,
              'failed_checks':failures,'notification_status':notification_status,
              'message':'Проверка хранилища завершена.' if not failures else 'Проверка неполная; смотрите причины выше.',
              'enforcement':'none','send_confirmed':False,'send_blocked':False})
    return 2 if failures or notification_status not in ('not_needed','accepted') else 0
