"""Root broker: fixed DLP restarts and policy installation, from the forwarder service account."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import stat
import struct
import subprocess
import tempfile
import time
import uuid

SOCKET = '/run/dlp-admin-control/control.sock'
DATABASE = '/var/lib/dlp-admin-control/actions.sqlite'
UNITS = {'restart_files': 'dlp-lab-files.service', 'restart_session': 'dlp-lab-session.service'}
POLICY = '/etc/dlp-lab/system/policy.yaml'
INCOMING = '/run/dlp-admin-control/incoming/policy.yaml'
BACKUPS = '/var/lib/dlp-admin-control/policy-backups'
ACTIONS = (*UNITS, 'install_policy')


def validate_job(job):
    if (not isinstance(job, dict) or set(job) != {'id','kind','expires'}
            or not isinstance(job['id'],str) or str(uuid.UUID(job['id'])) != job['id']
            or job['kind'] not in ACTIONS or type(job['expires']) not in (int,float)
            or not time.time() < job['expires'] <= time.time()+901):
        raise ValueError('Invalid restart request')
    return job


def restart(runner, unit):
    runner(['/usr/bin/systemctl','restart',unit],check=True,timeout=20,
           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    runner(['/usr/bin/systemctl','is-active','--quiet',unit],check=True,timeout=5,
           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def install(runner):
    """Validate the staged policy, back up the current one, replace it atomically, restart protection."""
    from .policy import parse_policy
    descriptor = os.open(INCOMING, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Staged policy must be a regular file')
        raw = stream.read(262145)
    if not 0 < len(raw) <= 262144:
        raise ValueError('Staged policy exceeds the size limit')
    parse_policy(raw)
    source = Path(POLICY)
    if source.is_symlink() or not source.is_file():
        raise ValueError('Installed policy must be a regular file')
    previous = source.read_bytes()
    backups = Path(BACKUPS)
    backups.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(backups / (hashlib.sha256(previous).hexdigest()+'.yaml'),
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(previous)
        stream.flush()
        os.fsync(stream.fileno())
    handle, temporary = tempfile.mkstemp(dir=source.parent)
    try:
        with os.fdopen(handle,'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary,0o644)
        if source.is_symlink() or source.read_bytes() != previous:
            raise ValueError('Installed policy changed during installation')
        os.replace(temporary,source)
        temporary = None
    finally:
        if temporary:
            os.unlink(temporary)
    try:
        for unit in UNITS.values():
            restart(runner,unit)
    except (OSError, subprocess.SubprocessError):
        # Restore the last configuration before attempting to recover both services.
        handle, rollback = tempfile.mkstemp(dir=source.parent)
        try:
            with os.fdopen(handle,'wb') as stream:
                stream.write(previous)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(rollback,0o644)
            os.replace(rollback,source)
        finally:
            if os.path.exists(rollback):
                os.unlink(rollback)
        for unit in UNITS.values():
            try:
                restart(runner,unit)
            except (OSError, subprocess.SubprocessError):
                pass
        raise


def installed_version():
    try:
        with open(POLICY,'rb') as stream:
            raw = stream.read(262145)
    except OSError:
        return None
    return hashlib.sha256(raw).hexdigest() if len(raw) <= 262144 else None


def execute(job, database=DATABASE, runner=subprocess.run):
    validate_job(job)
    with closing(sqlite3.connect(database, timeout=5)) as db, db:
        db.execute('CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY,kind TEXT,status TEXT)')
        db.execute('BEGIN IMMEDIATE')
        old=db.execute('SELECT kind,status FROM actions WHERE id=?',(job['id'],)).fetchone()
        if old:
            if old[0] != job['kind']:
                raise ValueError('Action identity mismatch')
            # A crash after intent has an uncertain result. Never repeat a restart.
            return {'id':job['id'],'status':old[1] if old[1] in ('completed','failed') else 'failed'}
        db.execute('INSERT INTO actions VALUES(?,?,?)',(job['id'],job['kind'],'running'))
    status='failed'
    try:
        if job['kind'] == 'install_policy':
            install(runner)
        else:
            restart(runner,UNITS[job['kind']])
        status='completed'
    except (OSError,ValueError,subprocess.SubprocessError):
        pass
    with closing(sqlite3.connect(database,timeout=5)) as db, db:
        db.execute('UPDATE actions SET status=? WHERE id=?',(status,job['id']))
    return {'id':job['id'],'status':status}


def request_restart(job):
    validate_job(job)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(120)
        client.connect(SOCKET)
        client.sendall(json.dumps(job).encode()+b'\n')
        data=b''
        while b'\n' not in data and len(data)<=4096:
            chunk=client.recv(4096)
            if not chunk:break
            data+=chunk
        if len(data)>4096:raise ValueError('Oversized response')
        result=json.loads(data)
        if not isinstance(result,dict) or set(result)!={'id','status'} or result['id']!=job['id'] or result['status'] not in ('completed','failed'):
            raise ValueError('Invalid broker result')
        return result['status']=='completed'


def authorized_peer(client, forwarder_uid):
    _, uid, _ = struct.unpack('3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid in (0, forwarder_uid)


def serve():
    if os.geteuid()!=0:raise ValueError('Administrator required')
    uid=pwd.getpwnam('dlp-forwarder').pw_uid
    os.umask(0o077)
    incoming = Path(INCOMING).parent
    incoming.mkdir(mode=0o770, exist_ok=True)
    if incoming.is_symlink() or incoming.stat().st_uid != 0:
        raise ValueError('Invalid staging directory')
    incoming.chmod(0o770)
    path=Path(SOCKET)
    if path.exists():path.unlink()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(SOCKET)
        path.chmod(0o660)
        listener.listen(4)
        while True:
            client,_=listener.accept()
            with client:
                client.settimeout(2)
                try:
                    if not authorized_peer(client,uid):raise ValueError('Unauthorized peer')
                    raw=b''
                    while b'\n' not in raw and len(raw)<=4096:
                        chunk=client.recv(4096)
                        if not chunk:break
                        raw+=chunk
                    if len(raw)>4096:raise ValueError('Oversized request')
                    job=validate_job(json.loads(raw))
                    result=execute(job)
                    entry={'event':'admin_restart','kind':job['kind'],'status':result['status'],'command_id':job['id']}
                    if job['kind']=='install_policy':
                        entry['policy_version']=installed_version()
                    print(json.dumps(entry),flush=True)
                    client.sendall(json.dumps(result).encode()+b'\n')
                except (OSError,ValueError,TypeError,KeyError):
                    # Never echo untrusted requests or exception strings.
                    continue
