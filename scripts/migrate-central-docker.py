#!/usr/bin/python3 -I
"""Migrate this lab's two central listeners; keep the database and endpoints."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
STATE = Path('/var/lib/dlp-central')
DEST = Path('/etc/dlp-lab/docker')
UNITS = ['dlp-lab-central.service', 'dlp-lab-central-tls.service']
LAN = '192.168.17.131'
IMAGE = 'dlp-lab-central:0.2.15-migration1'


def run(*args, capture=False):
    result = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def private_tree(path, uid, gid):
    items = [path, *path.rglob('*')]
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in items):
        raise ValueError('Unexpected link or special file in central state')
    for p in items:
        os.chown(p, uid, gid)
        p.chmod(0o700 if p.is_dir() else 0o600)


def configuration():
    common = dict(image=IMAGE, network_mode='host', init=True, restart='unless-stopped',
                  read_only=True, cap_drop=['ALL'], security_opt=['no-new-privileges:true'],
                  tmpfs=['/tmp:size=16m,mode=1777'], stop_grace_period='15s')
    services = {}
    for name, action, health in [('local', 'serve-local', 'health-local'), ('https', 'serve', 'health')]:
        item = dict(common)
        item['command'] = [action]
        item['volumes'] = [str(STATE)+':/var/lib/dlp-central']
        item['healthcheck'] = dict(test=['CMD', 'python3', '/app/entrypoint.py', health],
                                  interval='5s', timeout='4s', retries=3, start_period='5s')
        if name == 'https':
            item['volumes'].append(str(DEST/'tls')+':/run/tls:ro')
            item['environment'] = {'DLP_TLS_HOST': LAN, 'DLP_TLS_PORT': '8767'}
        services[name] = item
    return {'services': services}


def report(url, token, context=None):
    with urlopen(Request(url+'/api/report', headers={'Authorization': 'Bearer '+token}),
                 context=context, timeout=4) as response:
        return json.load(response)


def main():
    if os.geteuid() != 0:
        raise ValueError('Запустите: sudo python3 scripts/migrate-central-docker.py')
    os.umask(0o077)
    with open('/run/lock/dlp-central-migrate.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if DEST.exists():
            raise ValueError('/etc/dlp-lab/docker уже существует; повторный перенос остановлен')
        if json.loads(Path('/etc/dlp-lab/central-server.json').read_text()) != {'host': '127.0.0.1', 'port': 8766}:
            raise ValueError('Настройки локального listener отличаются от проверенного стенда')
        unit = run('systemctl', 'cat', UNITS[1], capture=True)
        for expected in ('--host '+LAN, '--port 8767', '--cert /etc/dlp-lab/tls/server.crt',
                         '--key /etc/dlp-lab/tls/server.key', '--state /var/lib/dlp-central'):
            if expected not in unit:
                raise ValueError('HTTPS unit отличается от проверенного стенда')
        for unit_name in UNITS:
            run('systemctl', 'is-active', '--quiet', unit_name)
        enabled = {u: run('systemctl', 'is-enabled', u, capture=True) for u in UNITS}
        run('docker', 'info', '--format', '{{.ServerVersion}}')
        if run('docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=dlp-central-migrated', capture=True):
            raise ValueError('Migration Docker project already exists')
        token = json.loads((STATE/'admin.json').read_text())['token']
        token_hash = hashlib.sha256((STATE/'admin.json').read_bytes()).hexdigest()
        original = STATE.stat()
        tls_context = ssl.create_default_context(cafile='/etc/dlp-lab/tls/ca.crt')
        before = report('http://127.0.0.1:8766', token)
        report('https://'+LAN+':8767', token, tls_context)
        print('Предварительная проверка OK. Собираю образ до остановки сервера.', flush=True)
        run('docker', 'build', '-t', IMAGE, '-f', str(ROOT/'docker/Dockerfile'), str(ROOT))
        # Copy TLS and write root-owned deployment configuration before downtime.
        DEST.mkdir(mode=0o700)
        stopped = False
        compose = ['docker', 'compose', '-p', 'dlp-central-migrated', '-f', str(DEST/'compose.json')]
        backup = None
        try:
            tls = DEST/'tls'; tls.mkdir(mode=0o750)
            for name in ('server.crt', 'server.key', 'ca.crt'):
                shutil.copy2(Path('/etc/dlp-lab/tls')/name, tls/name)
            private_tree(tls, 0, 10001)
            tls.chmod(0o750)
            for p in tls.iterdir():
                p.chmod(0o640)
            (DEST/'compose.json').write_text(json.dumps(configuration(), indent=2)+'\n')
            run(*compose, 'config', '--quiet')
            # Reject unsafe state before stopping anything.
            for p in [STATE, *STATE.rglob('*')]:
                if p.is_symlink() or not (p.is_file() or p.is_dir()):
                    raise ValueError('Unexpected central state file')
            print('Останавливаю только два центральных listener-а; файловая защита продолжает работать.', flush=True)
            stopped = True
            run('systemctl', 'stop', *UNITS)
            backup = Path(tempfile.mkdtemp(prefix='dlp-central-before-docker-', dir='/var/backups'))
            shutil.copytree(STATE, backup/'state', copy_function=shutil.copy2)
            shutil.copytree('/etc/dlp-lab/tls', backup/'tls', copy_function=shutil.copy2)
            (backup/'services.json').write_text(json.dumps(enabled))
            with sqlite3.connect(STATE/'state.sqlite') as db:
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('SQLite integrity check failed')
            private_tree(STATE, 10001, 10001)
            run(*compose, 'up', '-d')
            for _ in range(40):
                ids = run(*compose, 'ps', '-q', capture=True).splitlines()
                statuses = [json.loads(run('docker', 'inspect', i, capture=True))[0] for i in ids]
                if len(statuses) == 2 and all(s['State'].get('Health', {}).get('Status') == 'healthy' for s in statuses):
                    break
                time.sleep(1)
            else:
                raise ValueError('Docker listeners did not become healthy')
            after = report('http://127.0.0.1:8766', token)
            secure = report('https://'+LAN+':8767', token, tls_context)
            expected = {a['id'] for a in before['agents']}
            if expected != {a['id'] for a in after['agents']} or expected != {a['id'] for a in secure['agents']}:
                raise ValueError('Registered agents mismatch')
            if len(after['events']) < len(before['events']):
                raise ValueError('Event history mismatch')
            if hashlib.sha256((STATE/'admin.json').read_bytes()).hexdigest() != token_hash:
                raise ValueError('Administrator token changed')
            run('systemctl', 'disable', *UNITS)
            print('PASS: сервер перенесён в Docker. Адреса, сертификат, токен, устройства и история сохранены.', flush=True)
            print('Резервная копия: '+str(backup), flush=True)
            print('Управление: sudo docker compose -p dlp-central-migrated -f /etc/dlp-lab/docker/compose.json ps', flush=True)
        except BaseException:
            if stopped:
                # Do not restore an old snapshot: keep events accepted during the attempted switch.
                if (DEST/'compose.json').exists():
                    run(*compose, 'down')
                private_tree(STATE, original.st_uid, original.st_gid)
                for unit, state in enabled.items():
                    if state == 'enabled':
                        run('systemctl', 'enable', unit)
                run('systemctl', 'start', *UNITS)
                print('Откат: systemd-серверы запущены на текущей базе; принятые события не заменялись старой копией.', flush=True)
            shutil.rmtree(DEST)
            if backup:
                print('Резервная копия: '+str(backup), flush=True)
            raise


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print('Перенос не завершён: '+str(error))
        raise SystemExit(1)
