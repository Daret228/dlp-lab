"""Durable final summaries; input events stay in the endpoint system journal."""
import json

RANK = {'ALLOW': 0, 'WARN': 1, 'BLOCK': 2}


def schema(db):
    db.executescript('''CREATE TABLE IF NOT EXISTS file_operations
      (id TEXT PRIMARY KEY,payload TEXT NOT NULL,updated REAL NOT NULL,closed INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS file_operation_inputs
      (id TEXT PRIMARY KEY,operation TEXT NOT NULL);''')


def add(db, identity, operation, payload, stamp):
    if db.execute('SELECT 1 FROM file_operation_inputs WHERE id=?',(identity,)).fetchone():
        return
    db.execute('INSERT INTO file_operation_inputs VALUES(?,?)',(identity,operation))
    old=db.execute('SELECT payload FROM file_operations WHERE id=?',(operation,)).fetchone()
    if old:
        result=json.loads(old[0])
        result['decision']=max((result.get('decision','WARN'),payload.get('decision','WARN')),key=RANK.get)
        result['complete']=result.get('complete') is True and payload.get('complete') is True
        result['categories']=sorted(set(result.get('categories',[]))|set(payload.get('categories',[])))
        result['enforcement']='DENY' if 'DENY' in (result.get('enforcement'),payload.get('enforcement')) else 'ALLOW'
        result['operation_count']+=1
        if payload.get('timestamp','')>result.get('timestamp',''):result['timestamp']=payload['timestamp']
    else:
        result=dict(payload,event='file_operation',operation_count=1)
    db.execute('INSERT OR REPLACE INTO file_operations VALUES(?,?,?,0)',(operation,json.dumps(result),stamp))


def flush(db, stamp, quiet=6):
    for identity,payload in db.execute('SELECT id,payload FROM file_operations WHERE closed=0 AND updated<=?',(stamp-quiet,)).fetchall():
        db.execute('INSERT OR REPLACE INTO queue VALUES(?,?)',(identity,payload))
        db.execute('UPDATE file_operations SET closed=1 WHERE id=?',(identity,))
    # Keep replay identities for a week; journal cursors remain the primary boundary.
    db.execute('DELETE FROM file_operation_inputs WHERE operation IN (SELECT id FROM file_operations WHERE closed=1 AND updated<?)',(stamp-604800,))
    db.execute('DELETE FROM file_operations WHERE closed=1 AND updated<?',(stamp-604800,))
