"""Explicit offline Signal check in a bounded subprocess; never a background reader."""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager

from .audit import JsonAudit
from .signal_sqlcipher import ReadOnlySignalDatabase, analyze_recent_messages, unwrap_linux_v11


class LocalCheckError(ValueError):
    pass


def require_stopped(executable):
    target = str(Path(executable).resolve(strict=True))
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            if os.readlink(process/'exe').removesuffix(' (deleted)') == target:
                raise LocalCheckError('signal_running')
        except FileNotFoundError:
            continue
        except PermissionError:
            # Same-UID systemd/ssh-agent can hide /proc/exe. This is a liveness
            # guard, not process attestation: only known session helpers may pass.
            try:
                name = (process/'comm').read_text().strip()
            except OSError:
                raise LocalCheckError('process_visibility_unavailable') from None
            if name not in {'systemd','(sd-pam)','ssh-agent','vmtoolsd'}:
                raise LocalCheckError('process_visibility_unavailable') from None


def read_at(directory, name, limit, optional=False):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        if optional:
            return None
        raise LocalCheckError('required_file_missing') from None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_size > limit:
            raise LocalCheckError('unsupported_source_file')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(limit+1)
        after = os.fstat(fd)
        if len(data)>limit or (before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise LocalCheckError('source_changed')
        return data
    finally:
        os.close(fd)


@contextmanager
def snapshot(profile, scratch, executable):
    require_stopped(executable)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root = os.open(profile, flags)
    try:
        if os.fstat(root).st_uid != os.getuid():
            raise LocalCheckError('profile_owner_mismatch')
        sql = os.open('sql', flags, dir_fd=root)
        try:
            entries = [(root,'config.json',1024*1024,False)] + [
                (sql,name,256*1024*1024,name!='db.sqlite')
                for name in ('db.sqlite','db.sqlite-wal','db.sqlite-shm')]
            fingerprints = []
            config = None
            for directory,name,limit,optional in entries:
                data = read_at(directory,name,limit,optional)
                fingerprints.append(None if data is None else hashlib.sha256(data).digest())
                if data is None:
                    continue
                if name=='config.json':
                    config = json.loads(data)
                else:
                    fd = os.open(Path(scratch)/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                    with os.fdopen(fd,'wb') as stream:
                        stream.write(data)
            def verify():
                require_stopped(executable)
                for (directory,name,limit,optional),expected in zip(entries,fingerprints):
                    current = read_at(directory,name,limit,optional)
                    digest = None if current is None else hashlib.sha256(current).digest()
                    if digest != expected:
                        raise LocalCheckError('source_changed')
            verify()
            yield Path(scratch)/'db.sqlite',config
            verify()
        finally:
            os.close(sql)
    finally:
        os.close(root)


def key_from_keyring(config):
    if not isinstance(config,dict) or config.get('safeStorageBackend')!='gnome_libsecret':
        raise LocalCheckError('unsupported_key_backend')
    import gi
    gi.require_version('Secret','1')
    from gi.repository import Secret
    service = Secret.Service.get_sync(Secret.ServiceFlags.NONE,None)
    items = service.search_sync(None,{'application':'Signal'},
        Secret.SearchFlags.ALL|Secret.SearchFlags.UNLOCK|Secret.SearchFlags.LOAD_SECRETS,None)
    if len(items)!=1 or items[0].get_locked():
        raise LocalCheckError('keyring_unavailable_or_ambiguous')
    value = items[0].get_secret()
    if value is None:
        raise LocalCheckError('keyring_unavailable_or_ambiguous')
    return unwrap_linux_v11(bytes.fromhex(config['encryptedKey']),value.get_text().encode())


def worker(profile,scratch,executable,library,policy,limit):
    from .analysis import ContentAnalyzer
    from .policy import load_policy
    if os.geteuid()==0:
        raise LocalCheckError('run_as_desktop_user')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    analyzer = ContentAnalyzer(load_policy(policy))
    with snapshot(profile,scratch,executable) as (database,config):
        key = key_from_keyring(config)
        with ReadOnlySignalDatabase(database,key,library) as reader:
            summary = analyze_recent_messages(reader,analyzer,limit)
        del key,config
    summary['source_files_unchanged'] = True
    return summary


def save_event(audits,event):
    for audit in audits:
        audit.emit(event)


def notify_summary(summary,audits,notify=True):
    from .notifications import deliver_notification
    risk = summary['decisions']['BLOCK'] or summary['decisions']['WARN']
    unchecked = summary['incomplete'] or summary['skipped_oversize']
    if notify and (risk or unchecked):
        status = deliver_notification('DLP: проверка сохранённых сообщений Signal',
            'Обнаружен риск или часть текстов не проверена. Результат сохранён в журнале. '
            'Это проверка локальной базы; отправка не блокировалась.')
        save_event(audits,{'event':'notification_delivery','source':'signal_local_database',
                   'status':status,'display_confirmed':False,'send_blocked':False})


def worker_command(args, scratch):
    if Path(__file__).resolve().parents[2] == Path('/usr/lib/dlp-lab'):
        # Preserve isolated imports in the packaged subprocess as well.
        prefix = [sys.executable, '-I', '-c',
                  "import sys,runpy;sys.path.insert(0,'/usr/lib/dlp-lab/src');"
                  "runpy.run_module('dlp.signal_local',run_name='__main__')"]
    else:
        prefix = [sys.executable, '-m', 'dlp.signal_local']
    return prefix + [str(args.root),scratch,str(args.executable),
                     str(args.sqlcipher_library),str(args.policy),str(args.limit)]


def run_signal_local(args,audit):
    if not 1<=args.limit<=1000:
        raise ValueError('Лимит должен быть от 1 до 1000')
    if os.geteuid()==0:
        raise ValueError('Запускайте проверку от пользователя рабочего стола, без sudo')
    fd = os.open(args.journal,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    with os.fdopen(fd,'a',encoding='utf-8') as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode & 0o077:
            raise ValueError('Журнал должен быть обычным файлом владельца с правами 0600')
        audits = [JsonAudit(stream),audit]
        save_event(audits,{'event':'signal_local_started','messenger':'signal','sample_limit':args.limit})
        with tempfile.TemporaryDirectory(prefix='dlp-signal-offline-') as scratch:
            command = worker_command(args, scratch)
            try:
                result = subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                        timeout=45,check=False)
                if result.returncode or len(result.stdout)>16384:
                    # Worker emits only fixed diagnostics, never exception strings.
                    data = json.loads(result.stdout) if result.stdout else {}
                    reason = data.get('reason','worker_failed')
                    if reason not in ('signal_running','process_visibility_unavailable',
                        'required_file_missing','unsupported_source_file','source_changed',
                        'profile_owner_mismatch','unsupported_key_backend',
                        'keyring_unavailable_or_ambiguous','run_as_desktop_user'):
                        reason = 'worker_failed'
                    save_event(audits,{'event':'signal_local_failed','reason':reason})
                    return 2
                summary = json.loads(result.stdout)
            except subprocess.TimeoutExpired:
                save_event(audits,{'event':'signal_local_failed','reason':'timeout'})
                return 2
        save_event(audits,summary)
        notify_summary(summary,audits,not args.no_notify)
        return 0


if __name__=='__main__':
    try:
        print(json.dumps(worker(*sys.argv[1:6],int(sys.argv[6]))))
    except Exception as exc:
        reason = str(exc) if isinstance(exc,LocalCheckError) else 'worker_failed'
        print(json.dumps({'reason':reason}))
        raise SystemExit(2)
