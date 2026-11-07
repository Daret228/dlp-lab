"""Bounded, read-only remote diagnostics. No shell, paths or executable payloads."""
import json
import time
import uuid

KINDS = ('diagnose',)
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


def create(db, agent, kind):
    if not isinstance(agent, str) or kind not in KINDS:
        raise ValueError('Unsupported command')
    # Serialize enqueue and the pending limit across both server listeners.
    db.execute('BEGIN IMMEDIATE')
    expire(db)
    if not db.execute('SELECT 1 FROM agents WHERE id=?', (agent,)).fetchone():
        raise ValueError('Unknown agent')
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
            result = diagnose(job['id'])
            with connect(worker.state) as db:
                db.execute('INSERT OR IGNORE INTO command_results VALUES(?,?)', (job['id'], json.dumps(result)))
    return len(response['commands'])
