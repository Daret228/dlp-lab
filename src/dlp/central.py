"""Central event collector and bounded read-only diagnostics. No shell commands."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import stat
import subprocess
import time
import uuid
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

EVENTS = {'analysis', 'draft_analysis', 'file_access_attempt', 'local_draft_analysis',
          'export_message_analysis', 'signal_local_analysis_summary', 'monitor_started',
          'text_monitor_started', 'text_monitor_stopped', 'signal_local_failed',
          'queue_overflow', 'notification_delivery'}
DECISIONS = ('ALLOW', 'WARN', 'BLOCK')
CATEGORIES = ('financial', 'passport', 'credentials', 'confidential', 'personal')
MAX_BODY = 256 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def private_dir(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('State directory must be owned by current user with mode 0700')
    return path


@contextmanager
def connect(directory):
    path = private_dir(directory) / 'state.sqlite'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    db = sqlite3.connect(path, timeout=5)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        with db:
            yield db
    finally:
        db.close()


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream)
        stream.write('\n')


def read_config(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError('Configuration must be owned by current user with mode 0600')
    return json.loads(path.read_text())


CREDENTIAL_DIRECTORY = Path('/run/credentials/dlp-lab-forwarder.service')


def validate_credential_file(info):
    # systemd versions use either root:root 0400/0440 plus ACL, or
    # service-UID:root 0400. Never accept a different user's credentials.
    mode = stat.S_IMODE(info.st_mode)
    root_owned = info.st_uid == 0 and mode in (0o400, 0o440)
    service_owned = info.st_uid == os.getuid() and mode == 0o400
    if not stat.S_ISREG(info.st_mode) or info.st_gid != 0 or not (root_owned or service_owned):
        raise ValueError('Invalid system credential metadata')


def validate_credential_directory(info):
    root_owned = info.st_uid == 0 and not info.st_mode & 0o022
    service_owned = (info.st_uid == os.getuid() and info.st_gid == 0
                     and stat.S_IMODE(info.st_mode) == 0o500)
    if not stat.S_ISDIR(info.st_mode) or not (root_owned or service_owned):
        raise ValueError('Invalid system credential directory')


def read_systemd_config(path):
    path = Path(path)
    if (path != CREDENTIAL_DIRECTORY / 'agent.json'
            or os.environ.get('CREDENTIALS_DIRECTORY') != str(CREDENTIAL_DIRECTORY)
            or CREDENTIAL_DIRECTORY.resolve() != CREDENTIAL_DIRECTORY):
        raise ValueError('Expected fixed systemd credential path')
    directory = CREDENTIAL_DIRECTORY.stat()
    validate_credential_directory(directory)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        validate_credential_file(os.fstat(stream.fileno()))
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('System credential exceeds size limit')
    return json.loads(data)


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def endpoint(url):
    parts = urlsplit(url)
    if (parts.username or parts.password or parts.query or parts.fragment or
            parts.path not in ('', '/') or not parts.hostname):
        raise ValueError('Expected server origin without path or credentials')
    if parts.scheme != 'https' and not (parts.scheme == 'http' and parts.hostname in ('127.0.0.1', '::1')):
        raise ValueError('HTTPS required except for literal loopback addresses')
    return url.rstrip('/')


def project(raw):
    """Fixed enums and bounded numbers only; never forward arbitrary strings."""
    if not isinstance(raw, dict) or not isinstance(raw.get('event'), str) or raw['event'] not in EVENTS:
        return None
    result = raw.get('result')
    if not isinstance(result, dict):
        result = {}
    value = {'event': raw['event']}
    stamp = raw.get('timestamp')
    if isinstance(stamp, str) and len(stamp) <= 40:
        try:
            parsed = datetime.fromisoformat(stamp)
            if parsed.tzinfo is not None:
                value['timestamp'] = parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    decision = result.get('decision', raw.get('decision'))
    if decision in DECISIONS:
        value['decision'] = decision
    complete = result.get('complete', raw.get('complete'))
    if type(complete) is bool:
        value['complete'] = complete
    findings = result.get('findings', [])
    if isinstance(findings, list):
        value['categories'] = sorted({f['category'] for f in findings[:100]
                                     if isinstance(f, dict) and f.get('category') in CATEGORIES})
    for key, allowed in (('messenger', ('telegram', 'signal')),
                         ('enforcement', ('observe_only', 'none', 'ALLOW', 'DENY')),
                         ('status', ('accepted', 'failed', 'unavailable'))):
        if raw.get(key) in allowed:
            value[key] = raw[key]
    # These flags are independent: a BLOCK classification never implies a veto.
    for key in ('send_blocked', 'send_confirmed', 'source_files_unchanged', 'more_text_rows'):
        if type(raw.get(key)) is bool:
            value[key] = raw[key]
    if raw['event'] == 'signal_local_analysis_summary':
        for key in ('analyzed', 'incomplete', 'skipped_oversize', 'sample_limit'):
            number = raw.get(key)
            if type(number) is int and 0 <= number <= 1000:
                value[key] = number
        counts = raw.get('decisions', {})
        if isinstance(counts, dict):
            value['decisions'] = {k: counts[k] for k in DECISIONS
                                  if type(counts.get(k)) is int and 0 <= counts[k] <= 1000}
    return value


class ServerStore:
    def __init__(self, directory):
        self.directory = directory
        with connect(directory) as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS agents
                (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL, last_seen TEXT);
                CREATE TABLE IF NOT EXISTS events
                (agent TEXT, id TEXT, received TEXT, payload TEXT, PRIMARY KEY(agent,id));''')
            from .remote_control import schema
            schema(db)

    def add(self, name, url, output):
        if not re.fullmatch(r'[\w .-]{1,64}', name):
            raise ValueError('Use a short device label without special characters')
        config = {'server': endpoint(url), 'agent_id': str(uuid.uuid4()), 'token': secrets.token_urlsafe(32)}
        # Refuse overwriting a credential file; never print the token.
        write_private(output, config)
        with connect(self.directory) as db:
            db.execute('INSERT INTO agents(id,name,token_hash) VALUES(?,?,?)',
                       (config['agent_id'], name, digest(config['token'])))
        return config['agent_id']

    def authenticate(self, token):
        with connect(self.directory) as db:
            row = db.execute('SELECT id FROM agents WHERE token_hash=?', (digest(token),)).fetchone()
        return row[0] if row else None

    def ingest(self, agent, batch):
        if not isinstance(batch, list) or len(batch) > 100:
            raise ValueError('Invalid batch')
        prepared = []
        for item in batch:
            if not isinstance(item, dict) or set(item) != {'id', 'payload'}:
                raise ValueError('Invalid event')
            if not isinstance(item['id'], str) or not re.fullmatch('[0-9a-f]{64}', item['id']):
                raise ValueError('Invalid event ID')
            payload = item['payload']
            # Rebuild as raw analysis to validate projected categories too.
            if not isinstance(payload, dict):
                raise ValueError('Invalid payload')
            categories = payload.get('categories', [])
            if not isinstance(categories, list) or len(categories) > len(CATEGORIES) or any(not isinstance(c, str) for c in categories):
                raise ValueError('Invalid categories')
            raw = dict(payload)
            raw['result'] = {'decision': payload.get('decision'), 'complete': payload.get('complete'),
                             'findings': [{'category': c} for c in payload.get('categories', [])]}
            if project(raw) != payload:
                raise ValueError('Noncanonical payload')
            prepared.append((agent, item['id'], now(), json.dumps(payload)))
        with connect(self.directory) as db:
            db.executemany('INSERT OR IGNORE INTO events VALUES(?,?,?,?)', prepared)
            db.execute('UPDATE agents SET last_seen=? WHERE id=?', (now(), agent))
        return [item['id'] for item in batch]

    def report(self):
        with connect(self.directory) as db:
            agents = [dict(zip(('id', 'name', 'last_seen'), row)) for row in
                      db.execute('SELECT id,name,last_seen FROM agents ORDER BY name')]
            events = [dict(agent=row[0], received=row[1], **json.loads(row[2])) for row in
                      db.execute('SELECT agent,received,payload FROM events ORDER BY rowid DESC LIMIT 200')]
            from .remote_control import report
            commands = report(db)
        return {'agents': agents, 'events': events, 'commands': commands}


PAGE = '''<!doctype html><html lang="ru"><meta charset="utf-8"><title>DLP · Сервер</title>
<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;background:#f5f7fa;color:#182536}input,button{padding:10px;margin:6px}table{border-collapse:collapse;width:100%;background:white}td,th{text-align:left;padding:12px;border-bottom:1px solid #ddd}pre{white-space:pre-wrap}small{color:#526070}</style>
<h1>DLP · Центральный журнал</h1><p>Устройства и последние 200 событий. Анализ выполняется на устройствах.</p>
<label>Токен администратора <input id="token" type="password" autocomplete="off"></label><button id="refresh">Обновить</button><p id="status"></p>
<h2>Устройства</h2><div id="agents"></div><h2>Задания агентам</h2><p>Удалённая диагностика требует системного отправщика версии 0.2.12+. Результат не подтверждает полную защиту. Настройки и службы не изменяются.</p><div id="commands"></div><h2>События</h2><div id="events"></div>
<small>BLOCK — результат анализа. Фактический запрет указан отдельно. Последняя связь не доказывает работу всех модулей.</small>
<script src="/app.js"></script></html>'''
JS = Path(__file__).with_name('central_ui.js').read_text()


def make_server(store, admin_token, host, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # No tokens, bodies or request paths in access logs.

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def reply(self, code, body, content='application/json'):
            data = json.dumps(body).encode() if content == 'application/json' else body.encode()
            self.send_response(code)
            self.send_header('Content-Type', content + '; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def token(self):
            auth = self.headers.get('Authorization', '')
            return auth[7:] if auth.startswith('Bearer ') and len(auth) < 256 else ''

        def do_GET(self):
            if self.path == '/':
                return self.reply(200, PAGE, 'text/html')
            if self.path == '/app.js':
                return self.reply(200, JS, 'text/javascript')
            if self.path != '/api/report':
                return self.reply(404, {})
            if not secrets.compare_digest(self.token(), admin_token):
                return self.reply(401, {})
            self.reply(200, store.report())

        def do_POST(self):
            if self.path not in ('/api/events', '/api/commands', '/api/control'):
                return self.reply(404, {})
            if self.path == '/api/commands':
                if not secrets.compare_digest(self.token(), admin_token):
                    return self.reply(401, {})
                agent = None
            else:
                agent = store.authenticate(self.token())
                if not agent:
                    return self.reply(401, {})
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= MAX_BODY or self.headers.get('Transfer-Encoding'):
                    raise ValueError('Invalid length')
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError('Incomplete body')
                data = json.loads(raw)
                if self.path == '/api/events':
                    result = {'acked': store.ingest(agent, data)}
                elif self.path == '/api/commands':
                    if not isinstance(data, dict) or set(data) != {'agent', 'kind'}:
                        raise ValueError('Invalid command')
                    from .remote_control import create
                    with connect(store.directory) as db:
                        result = {'id': create(db, data['agent'], data['kind'])}
                else:
                    if not isinstance(data, dict) or set(data) != {'results'}:
                        raise ValueError('Invalid exchange')
                    from .remote_control import exchange
                    with connect(store.directory) as db:
                        result = exchange(db, agent, data['results'])
            except (ValueError, TypeError, KeyError):
                return self.reply(400, {})
            self.reply(200, result)
    return ThreadingHTTPServer((host, port), Handler)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Forwarder:
    def __init__(self, state, config):
        self.state, self.config = state, config
        endpoint(config['server'])
        with connect(state) as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS queue(id TEXT PRIMARY KEY,payload TEXT);
                CREATE TABLE IF NOT EXISTS cursors(source TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE IF NOT EXISTS owner(id TEXT PRIMARY KEY);''')
            binding = digest(config['agent_id'] + ':' + endpoint(config['server']))
            row = db.execute('SELECT id FROM owner').fetchone()
            if row and row[0] != binding:
                raise ValueError('Queue belongs to another agent or server')
            db.execute('INSERT OR IGNORE INTO owner VALUES(?)', (binding,))

    def enqueue(self, records, source):
        # Cursor and events commit together. Full queue preserves previous cursor.
        with connect(self.state) as db:
            for cursor, raw in records:
                payload = project(raw)
                if payload is not None:
                    identity = digest(self.config['agent_id'] + ':' + source + ':' + cursor)
                    db.execute('INSERT OR IGNORE INTO queue VALUES(?,?)', (identity, json.dumps(payload)))
                db.execute('INSERT OR REPLACE INTO cursors VALUES(?,?)', (source, cursor))
            if db.execute('SELECT count(*) FROM queue').fetchone()[0] > 10000:
                raise ValueError('Queue full; collection paused, local protection continues')

    def collect(self, system=False):
        source = 'system' if system else 'user'
        with connect(self.state) as db:
            row = db.execute('SELECT value FROM cursors WHERE source=?', (source,)).fetchone()
        # A system unit's unprivileged worker may write to a split user journal.
        # Default journal scope includes both; --system would silently miss it.
        args = ['journalctl', *([] if system else ['--user']), '--output=json', '--no-pager',
                '--unit=dlp-lab-files.service']
        if not system:
            from .service import UNITS
            args += ['--unit=' + unit for unit in UNITS.values() if unit != 'dlp-lab-files.service']
        args += ['--after-cursor=' + row[0]] if row else ['--since=-5min']
        # Stream at most 500 records, never buffer an unlimited journal.
        import tempfile
        with tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=errors)
            records = []
            try:
                for _ in range(500):
                    line = process.stdout.readline(262145)
                    if not line:
                        break
                    if len(line) > 262144:
                        raise ValueError('Journal entry too large')
                    entry = json.loads(line)
                    cursor = entry.get('__CURSOR')
                    if not cursor:
                        raise ValueError('Missing journal cursor')
                    try:
                        raw = json.loads(entry.get('MESSAGE', ''))
                    except ValueError:
                        raw = {}
                    records.append((cursor, raw))
                if len(records) < 500 and process.wait(timeout=10) != 0:
                    raise ValueError('Journal unavailable; check permissions or expired cursor')
                errors.seek(0)
                if errors.read(1):
                    raise ValueError('Journal warning; check permissions or expired cursor')
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)
                process.stdout.close()
        self.enqueue(records, source)

    def request(self, path, data):
        request = Request(endpoint(self.config['server']) + path, data=json.dumps(data).encode(),
                          headers={'Authorization': 'Bearer ' + self.config['token'], 'Content-Type': 'application/json'})
        opener = build_opener(NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(request, timeout=10) as response:
            raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError('Response too large')
        return json.loads(raw)

    def send(self):
        with connect(self.state) as db:
            batch = [{'id': row[0], 'payload': json.loads(row[1])} for row in
                     db.execute('SELECT id,payload FROM queue ORDER BY rowid LIMIT 100')]
        result = self.request('/api/events', batch)
        expected = {item['id'] for item in batch}
        if (not isinstance(result, dict) or not isinstance(result.get('acked'), list) or
                any(not isinstance(item, str) for item in result['acked']) or set(result['acked']) != expected):
            raise ValueError('Invalid acknowledgement; queue retained')
        with connect(self.state) as db:
            db.executemany('DELETE FROM queue WHERE id=?', [(identity,) for identity in expected])
        return len(batch)


def main(argv=None, *, systemd_credential=False):
    parser = argparse.ArgumentParser(description='Opt-in DLP central server and journal forwarder')
    sub = parser.add_subparsers(dest='action', required=True)
    init = sub.add_parser('init'); init.add_argument('--state', type=Path, required=True)
    add = sub.add_parser('add-agent')
    add.add_argument('--state', type=Path, required=True); add.add_argument('--name', required=True)
    add.add_argument('--server', required=True); add.add_argument('--out', type=Path, required=True)
    revoke = sub.add_parser('revoke-agent')
    revoke.add_argument('--state', type=Path, required=True); revoke.add_argument('--id', required=True)
    serve = sub.add_parser('serve'); serve.add_argument('--state', type=Path, required=True)
    serve.add_argument('--host', default='127.0.0.1'); serve.add_argument('--port', type=int, default=8766)
    serve.add_argument('--cert', type=Path); serve.add_argument('--key', type=Path)
    forward = sub.add_parser('forward'); forward.add_argument('--state', type=Path, required=True)
    forward.add_argument('--config', type=Path, required=True); forward.add_argument('--system', action='store_true')
    forward.add_argument('--once', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'init':
            ServerStore(args.state)
            write_private(args.state / 'admin.json', {'token': secrets.token_urlsafe(32)})
            print('Server initialized; administrator token in private admin.json')
        elif args.action == 'add-agent':
            print('Registered agent:', ServerStore(args.state).add(args.name, args.server, args.out))
        elif args.action == 'revoke-agent':
            with connect(args.state) as db:
                changed = db.execute('UPDATE agents SET token_hash=? WHERE id=?', (digest(secrets.token_urlsafe(32)), args.id)).rowcount
            if not changed:
                raise ValueError('Unknown agent')
            print('Agent credential revoked; historical events retained')
        elif args.action == 'serve':
            if bool(args.cert) != bool(args.key) or (args.host != '127.0.0.1' and not args.cert):
                raise ValueError('Certificate and key required for non-loopback listener')
            server = make_server(ServerStore(args.state), read_config(args.state / 'admin.json')['token'], args.host, args.port)
            if args.cert:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(args.cert, args.key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
            print('Central server ready', flush=True)
            server.serve_forever()
        else:
            config = read_systemd_config(args.config) if systemd_credential else read_config(args.config)
            worker = Forwarder(args.state, config)
            while True:
                failed = False
                try:
                    worker.collect(args.system)
                except (OSError, ValueError, subprocess.SubprocessError):
                    print('Collection failed; local protection unchanged', flush=True)
                    failed = True
                try:
                    sent = worker.send()
                    print('Events acknowledged:', sent, flush=True)
                except (OSError, ValueError):
                    print('Delivery failed; queued events retained', flush=True)
                    failed = True
                if systemd_credential:
                    try:
                        from .remote_control import poll
                        if poll(worker):
                            print('Remote diagnostics processed', flush=True)
                    except (OSError, ValueError):
                        print('Control unavailable; event delivery remains independent', flush=True)
                if args.once:
                    return 2 if failed else 0
                time.sleep(15)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError) as error:
        print('Central operation failed:', type(error).__name__)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
