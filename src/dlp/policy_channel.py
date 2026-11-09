"""Server-side per-device policy storage. Validates content; never logs it."""
import hashlib
import json
from datetime import datetime, timezone

from .policy import PolicyError, parse_policy

# A response carrying the content must stay inside the 256 KiB body cap.
MAX_POLICY = 128 * 1024


class Conflict(ValueError):
    pass


def schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS policies
        (agent TEXT PRIMARY KEY, version TEXT NOT NULL, content TEXT NOT NULL, updated TEXT NOT NULL)''')


def policy_version(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def validate(content):
    if not isinstance(content, str) or not content:
        raise PolicyError('Policy must be non-empty text')
    raw = content.encode('utf-8')
    if len(raw) > MAX_POLICY:
        raise PolicyError('Policy exceeds 128 KiB')
    if len(json.dumps({'version':'0'*64,'content':content}).encode()) > 240000:
        raise PolicyError('Encoded policy exceeds transport limit')
    parse_policy(raw)
    return policy_version(content)


def set_policy(db, agent, content, expected_version, activate):
    # create() opens BEGIN IMMEDIATE; call it before the first write of this transaction.
    from .remote_control import create
    if type(expected_version) not in (str, type(None)) or type(activate) is not bool:
        raise ValueError('Invalid policy request')
    version = validate(content)
    if not isinstance(agent, str) or not db.execute('SELECT 1 FROM agents WHERE id=?', (agent,)).fetchone():
        raise ValueError('Unknown agent')
    db.execute('BEGIN IMMEDIATE')
    from .remote_control import expire
    expire(db)
    if db.execute("SELECT 1 FROM commands WHERE agent=? AND kind='apply_policy' AND status='pending'", (agent,)).fetchone():
        raise Conflict('Policy application is pending')
    row = db.execute('SELECT version FROM policies WHERE agent=?', (agent,)).fetchone()
    if expected_version != (row[0] if row else None):
        raise Conflict('Assigned policy changed')
    command = create(db, agent, 'apply_policy') if activate else None
    db.execute('INSERT OR REPLACE INTO policies VALUES(?,?,?,?)',
               (agent, version, content, datetime.now(timezone.utc).isoformat()))
    return {'version': version, 'command': command}


def assigned(db):
    return {row[0]: {'version': row[1], 'updated': row[2]}
            for row in db.execute('SELECT agent,version,updated FROM policies')}


def view(db, agent):
    if not isinstance(agent, str) or not db.execute('SELECT 1 FROM agents WHERE id=?', (agent,)).fetchone():
        raise ValueError('Unknown agent')
    row = db.execute('SELECT version,content,updated FROM policies WHERE agent=?', (agent,)).fetchone()
    return {'version': row[0], 'content': row[1], 'updated': row[2]} if row else {
        'version': None, 'content': None, 'updated': None}


def fetch(db, agent):
    row = db.execute('SELECT version,content FROM policies WHERE agent=?', (agent,)).fetchone()
    return {'version': row[0], 'content': row[1]} if row else {'version': None, 'content': None}
