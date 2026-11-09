"""Bounded diagnostics, fixed service restarts and policy installation. No shell or executable payloads."""
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
import re
import time
import uuid

from .policy_channel import MAX_POLICY

KINDS = ('diagnose', 'restart_files', 'restart_session', 'apply_policy')
CHECK_NAMES = ('Политика', 'Мессенджеры', 'Сеансовая служба', 'Файловая защита', 'Отправщик событий',
               'Центральный сервер (необязательно)', 'HTTPS сервера (необязательно)',
               'Текст и локальные базы', 'Доставка и очередь')
STATUSES = ('OK', 'ERROR', 'UNKNOWN', 'INFO')


def schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS commands
        (id TEXT PRIMARY KEY, agent TEXT NOT NULL, kind TEXT NOT NULL,
         created REAL NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL,
         result TEXT, completed REAL)''')


def expire(db):
    db.execute("UPDATE commands SET status='expired' WHERE status='pending' AND expires<=?", (time.time(),))


def fresh_health(db, agent):
    row = db.execute('SELECT payload FROM endpoint_health WHERE agent=?', (agent,)).fetchone()
    health = json.loads(row[0]) if row else {}
    try:
        fresh = 0 <= time.time()-datetime.fromisoformat(health['timestamp']).timestamp() <= 120
    except (KeyError, ValueError, TypeError):
        fresh = False
    return health, fresh


def create(db, agent, kind):
    if not isinstance(agent, str) or kind not in KINDS:
        raise ValueError('Unsupported command')
    # Serialize enqueue and the pending limit across both server listeners.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    expire(db)
    if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent,)).fetchone():
        raise ValueError('Unknown agent')
    if kind != 'diagnose':
        health, fresh = fresh_health(db, agent)
        if health.get('management_ready') is not True or not fresh:
            raise ValueError('Management agent unavailable or outdated')
        if kind == 'apply_policy' and health.get('policy_channel') is not True:
            raise ValueError('Agent does not support policy management')
    if db.execute("SELECT 1 FROM commands WHERE agent=? AND status='pending'", (agent,)).fetchone():
        raise ValueError('A request is already pending')
    identity, stamp = str(uuid.uuid4()), time.time()
    db.execute('INSERT INTO commands VALUES(?,?,?,?,?,?,NULL,NULL)',
               (identity, agent, kind, stamp, stamp+900, 'pending'))
    return identity


def validate_result(value):
    if not isinstance(value, dict) or set(value) != {'id', 'status', 'checks'}:
        raise ValueError('Invalid result')
    if not isinstance(value['id'], str) or len(value['id']) != 36:
        raise ValueError('Invalid ID')
    if value['status'] not in ('completed', 'failed'):
        raise ValueError('Invalid status')
    checks = value['checks']
    if not isinstance(checks, list) or len(checks) > len(CHECK_NAMES):
        raise ValueError('Invalid checks')
    names = []
    for check in checks:
        if (not isinstance(check, dict) or set(check) != {'name', 'status'}
                or check['name'] not in CHECK_NAMES or check['status'] not in STATUSES):
            raise ValueError('Invalid check')
        names.append(check['name'])
    if len(set(names)) != len(names):
        raise ValueError('Duplicate check')
    if value['status'] == 'completed' and set(names) != set(CHECK_NAMES):
        raise ValueError('Incomplete report')
    if value['status'] == 'failed' and checks:
        raise ValueError('Failed result must not contain checks')
    return value


def exchange(db, agent, results):
    if not isinstance(results, list) or len(results) > 16:
        raise ValueError('Invalid result batch')
    # Validate the entire batch, including ownership, before modifying any row.
    for value in results:
        validate_result(value)
        if not db.execute('SELECT 1 FROM commands WHERE id=? AND agent=?', (value['id'], agent)).fetchone():
            raise ValueError('Unknown command')
    ack = []
    for value in results:
        db.execute("UPDATE commands SET status=?,result=?,completed=? WHERE id=? AND agent=? AND status='pending'",
                   (value['status'], json.dumps(value), time.time(), value['id'], agent))
        ack.append(value['id'])
    expire(db)
    jobs = [dict(zip(('id', 'kind', 'expires'), row)) for row in db.execute(
        "SELECT id,kind,expires FROM commands WHERE agent=? AND status='pending' ORDER BY created LIMIT 1", (agent,))]
    return {'acked': ack, 'commands': jobs}


def report(db):
    expire(db)
    return [dict(id=r[0], agent=r[1], kind=r[2], created=r[3], expires=r[4], status=r[5],
                 result=json.loads(r[6]) if r[6] else None, completed=r[7]) for r in db.execute(
        'SELECT * FROM commands ORDER BY created DESC LIMIT 100')]


def diagnose(identity):
    from .doctor import collect
    try:
        checks = [{'name': c['name'], 'status': c['status']} for c in collect() if c['name'] in CHECK_NAMES]
        return validate_result({'id': identity, 'status': 'completed', 'checks': checks})
    except Exception:
        return {'id': identity, 'status': 'failed', 'checks': []}


STAGED_POLICY = '/run/dlp-admin-control/incoming/policy.yaml'


def apply_policy(worker, job):
    """Fetch the assigned policy, verify it locally, stage it and ask the root broker to install."""
    from .policy import parse_policy
    fetched = worker.request('/api/policy')
    if not isinstance(fetched, dict) or set(fetched) != {'version', 'content'}:
        raise ValueError('Invalid policy payload')
    content = fetched['content']
    if fetched['version'] is None or content is None:
        # Nothing is assigned; report failure instead of retrying until expiry.
        return {'id': job['id'], 'status': 'failed', 'checks': []}
    if (not isinstance(fetched['version'], str) or not re.fullmatch('[0-9a-f]{64}', fetched['version'])
            or not isinstance(content, str) or not 0 < len(content.encode('utf-8')) <= MAX_POLICY
            or hashlib.sha256(content.encode('utf-8')).hexdigest() != fetched['version']):
        raise ValueError('Invalid policy payload')
    parse_policy(content.encode('utf-8'))
    staged = Path(worker.state) / STAGED_POLICY
    try:
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        # Root broker has no DAC override capability; read through its forwarder group.
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        from .admin_control import request_restart
        # The broker knows fixed local actions; translate the control command kind.
        installation = {'id': job['id'], 'kind': 'install_policy', 'expires': job['expires']}
        try:
            success = request_restart(installation)
        except (OSError, ValueError):
            success = False
    finally:
        staged.unlink(missing_ok=True)
    return diagnose(job['id']) if success else {'id': job['id'], 'status': 'failed', 'checks': []}


def poll(worker):
    from .central import connect
    with connect(worker.state) as db:
        db.execute('CREATE TABLE IF NOT EXISTS command_results(id TEXT PRIMARY KEY, result TEXT NOT NULL)')
        results = [json.loads(r[0]) for r in db.execute('SELECT result FROM command_results LIMIT 16')]
    response = worker.request('/api/control', {'results': results})
    expected = {r['id'] for r in results}
    if (not isinstance(response, dict) or set(response) != {'acked', 'commands'}
            or not isinstance(response['acked'], list)
            or any(not isinstance(i, str) for i in response['acked'])
            or set(response['acked']) != expected
            or not isinstance(response['commands'], list) or len(response['commands']) > 1):
        raise ValueError('Invalid control response')
    for job in response['commands']:
        if (not isinstance(job, dict) or set(job) != {'id', 'kind', 'expires'}
                or not isinstance(job['id'], str) or len(job['id']) != 36
                or job['kind'] not in KINDS or type(job['expires']) not in (int, float)
                or not time.time() < job['expires'] <= time.time()+901):
            raise ValueError('Invalid or expired command')
    with connect(worker.state) as db:
        db.executemany('DELETE FROM command_results WHERE id=?', [(i,) for i in expected])
    for job in response['commands']:
        with connect(worker.state) as db:
            existing = db.execute('SELECT 1 FROM command_results WHERE id=?', (job['id'],)).fetchone()
        if not existing:
            if job['kind'] == 'diagnose':
                result = diagnose(job['id'])
            elif job['kind'] == 'apply_policy':
                result = apply_policy(worker, job)
            else:
                from .admin_control import request_restart
                try:
                    success = request_restart(job)
                except (OSError, ValueError):
                    success = False
                result = diagnose(job['id']) if success else {'id':job['id'],'status':'failed','checks':[]}
            with connect(worker.state) as db:
                db.execute('INSERT OR IGNORE INTO command_results VALUES(?,?)', (job['id'], json.dumps(result)))
    return len(response['commands'])
