"""Root broker: only fixed DLP restarts, from the forwarder service account."""
from contextlib import closing
import json
import os
from pathlib import Path
import pwd
import socket
import sqlite3
import struct
import subprocess
import time
import uuid

SOCKET = '/run/dlp-admin-control/control.sock'
DATABASE = '/var/lib/dlp-admin-control/actions.sqlite'
UNITS = {'restart_files': 'dlp-lab-files.service', 'restart_session': 'dlp-lab-session.service'}


def validate_job(job):
    if (not isinstance(job, dict) or set(job) != {'id','kind','expires'}
            or not isinstance(job['id'],str) or str(uuid.UUID(job['id'])) != job['id']
            or job['kind'] not in UNITS or type(job['expires']) not in (int,float)
            or not time.time() < job['expires'] <= time.time()+901):
        raise ValueError('Invalid restart request')
    return job


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
        unit=UNITS[job['kind']]
        runner(['/usr/bin/systemctl','restart',unit],check=True,timeout=20,
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        runner(['/usr/bin/systemctl','is-active','--quiet',unit],check=True,timeout=5,
               stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        status='completed'
    except (OSError,subprocess.SubprocessError):
        pass
    with closing(sqlite3.connect(database,timeout=5)) as db, db:
        db.execute('UPDATE actions SET status=? WHERE id=?',(status,job['id']))
    return {'id':job['id'],'status':status}


def request_restart(job):
    validate_job(job)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(30)
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
                    print(json.dumps({'event':'admin_restart','kind':job['kind'],'status':result['status'],'command_id':job['id']}),flush=True)
                    client.sendall(json.dumps(result).encode()+b'\n')
                except (OSError,ValueError,TypeError,KeyError):
                    # Never echo untrusted requests or exception strings.
                    continue
