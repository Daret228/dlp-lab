"""Server-side update storage plus name/staging checks shared with the agent.

The panel accepts exactly one admin-uploaded dlp-lab DEB per content hash;
an agent ever receives only its own assignment. The file-name grammar and
the staged-pair layout live here so the server, the forwarder and the root
installer all reject the same things. No shell, no executable payloads.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
import re
import sqlite3
import stat

# Package bodies travel on their own routes with a dedicated cap; the JSON
# control transport keeps its smaller limit.
MAX_UPDATE = 4 * 1024 * 1024
NAME = re.compile(r'^dlp-lab_([0-9][0-9A-Za-z.~+-]*)_([a-z0-9]+)\.deb$')
STAGED_UPDATE = '/run/dlp-admin-control/incoming/update.deb'
STAGED_UPDATE_META = '/run/dlp-admin-control/incoming/update.meta.json'


def candidate_from_name(name):
    """Return (version, architecture) for a valid package file name."""
    match = NAME.fullmatch(name)
    return (match.group(1), match.group(2)) if match else None


def meta_from(filename, size):
    """Validate assignment metadata; returns the canonical filename/version."""
    parsed = candidate_from_name(filename) if isinstance(filename, str) and len(filename) <= 128 else None
    if parsed is None or type(size) is not int or not 0 < size <= MAX_UPDATE:
        raise ValueError('Invalid update metadata')
    return {'filename': filename, 'version': parsed[0], 'size': size}


def _read_regular(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Staged update file must be regular')
        return stream.read(limit + 1)


def validate_staged_update(package_path, meta_path):
    """Re-check the staged pair before anything privileged runs.

    Both files must be regular and non-symlinked, the sidecar must carry
    exactly the trusted filename grammar plus a sha256, and the package
    bytes must match that hash and size.
    """
    raw = _read_regular(meta_path, 65536)
    if not 0 < len(raw) <= 65536:
        raise ValueError('Staged metadata exceeds the size limit')
    meta = json.loads(raw)
    if not isinstance(meta, dict) or set(meta) != {'filename', 'sha256', 'size'}:
        raise ValueError('Invalid staged metadata')
    canonical = meta_from(meta['filename'], meta['size'])
    expected = meta['sha256']
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected):
        raise ValueError('Invalid staged checksum')
    data = _read_regular(package_path, MAX_UPDATE)
    if len(data) != canonical['size'] or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Staged update does not match its metadata')
    return {'filename': canonical['filename'], 'version': canonical['version'],
            'size': canonical['size'], 'sha256': expected}


def schema(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS updates
        (sha256 TEXT PRIMARY KEY, version TEXT NOT NULL, filename TEXT NOT NULL,
         size INTEGER NOT NULL, created TEXT NOT NULL, payload BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS update_assignments
        (agent TEXT PRIMARY KEY, sha256 TEXT NOT NULL, assigned TEXT NOT NULL)''')


def save(db, filename, data):
    """Store one uploaded package, content-addressed; duplicates are no-ops."""
    canonical = meta_from(filename, len(data))
    digest = hashlib.sha256(data).hexdigest()
    if not db.execute('SELECT 1 FROM updates WHERE sha256=?', (digest,)).fetchone():
        db.execute('INSERT INTO updates VALUES(?,?,?,?,?,?)',
                   (digest, canonical['version'], canonical['filename'], canonical['size'],
                    datetime.now(timezone.utc).isoformat(), sqlite3.Binary(data)))
    return {'sha256': digest, 'version': canonical['version']}


def assign(db, agent, sha256):
    # create() opens BEGIN IMMEDIATE; call it before the first write of this transaction.
    from .remote_control import create, expire
    if not isinstance(sha256, str) or not re.fullmatch('[0-9a-f]{64}', sha256 or ''):
        raise ValueError('Invalid update reference')
    if not isinstance(agent, str) or not db.execute('SELECT 1 FROM agents WHERE id=?', (agent,)).fetchone():
        raise ValueError('Unknown agent')
    db.execute('BEGIN IMMEDIATE')
    expire(db)
    row = db.execute('SELECT version FROM updates WHERE sha256=?', (sha256,)).fetchone()
    if not row:
        raise ValueError('Unknown update')
    command = create(db, agent, 'update_agent')
    db.execute('INSERT OR REPLACE INTO update_assignments VALUES(?,?,?)',
               (agent, sha256, datetime.now(timezone.utc).isoformat()))
    return {'version': row[0], 'command': command}


def uploads(db):
    return [dict(sha256=row[0], version=row[1], filename=row[2], size=row[3], created=row[4]) for row in
            db.execute('SELECT sha256,version,filename,size,created FROM updates ORDER BY created DESC')]


def assignments(db):
    return {row[0]: {'sha256': row[1]} for row in
            db.execute('SELECT agent,sha256 FROM update_assignments')}


def fetch(db, agent):
    row = db.execute('''SELECT u.filename,u.sha256,u.size,u.version
        FROM update_assignments a JOIN updates u ON u.sha256=a.sha256 WHERE a.agent=?''', (agent,)).fetchone()
    return {'filename': row[0], 'sha256': row[1], 'size': row[2], 'version': row[3]} if row else None


def blob(db, agent):
    row = db.execute('''SELECT u.payload,u.size
        FROM update_assignments a JOIN updates u ON u.sha256=a.sha256 WHERE a.agent=?''', (agent,)).fetchone()
    if not row:
        raise ValueError('No update assigned')
    payload = row[0]
    if not isinstance(payload, bytes) or not 0 < len(payload) == row[1] or len(payload) > MAX_UPDATE:
        raise ValueError('Stored update is invalid')
    return payload
