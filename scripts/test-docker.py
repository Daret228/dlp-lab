#!/usr/bin/python3 -I
"""Check the real Compose deployment in a disposable project; never read live state."""
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Запустите: sudo python3 scripts/test-docker.py')
    os.umask(0o077)
    project = 'dlp-check-' + uuid.uuid4().hex[:12]
    print('Временный Docker-проект: ' + project, flush=True)
    with tempfile.TemporaryDirectory(prefix='dlp-docker-check-') as directory:
        temp = Path(directory)
        tls = temp / 'tls'
        tls.mkdir()
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-keyout', str(tls/'server.key'), '-out', str(tls/'server.crt')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chown(tls, 0, 10001); tls.chmod(0o750)
        os.chown(tls/'server.key', 0, 10001); (tls/'server.key').chmod(0o640)
        (tls/'server.crt').chmod(0o644)
        override = temp/'override.json'
        override.write_text(json.dumps({'services': {'central': {
            'volumes': [str(tls)+':/run/tls:ro'],
            'restart': 'no', 'healthcheck': {'interval': '2s', 'start_period': '2s'}}}}))
        env = dict(os.environ, DLP_BIND_ADDRESS='127.0.0.1', DLP_HTTPS_PORT='0')
        compose = ['docker', 'compose', '--project-directory', str(ROOT), '-p', project,
                   '-f', str(ROOT/'compose.yaml'), '-f', str(override)]
        def run(*args, capture=False):
            result = subprocess.run([*compose, *args], cwd=ROOT, env=env, check=True,
                                    stdout=subprocess.PIPE if capture else None, text=True)
            return result.stdout.strip() if capture else None
        def execute(*args):
            return run('exec', '-T', 'central', *args, capture=True)
        def wait():
            for _ in range(45):
                identity = run('ps', '-q', 'central', capture=True)
                if identity:
                    status = json.loads(subprocess.check_output(['docker', 'inspect', identity], text=True))[0]
                    if status['State'].get('Health', {}).get('Status') == 'healthy':
                        return status
                time.sleep(1)
            raise RuntimeError('Контейнер не стал healthy за 45 секунд')
        try:
            run('config', '--quiet')
            run('up', '-d', '--build')
            status = wait()
            check(status['Config']['User'] == '10001:10001', 'Неверный UID контейнера')
            check(status['HostConfig']['ReadonlyRootfs'], 'Rootfs не read-only')
            print('OK: образ собран, контейнер healthy, UID10001 и read-only rootfs', flush=True)
            address = run('port', 'central', '8766', capture=True)
            check(address.startswith('127.0.0.1:'), 'Тестовый порт доступен не только локально')
            url = 'https://' + address
            context = ssl.create_default_context(cafile=str(tls/'server.crt'))
            def request(path, token=None, payload=None):
                headers = {'Authorization': 'Bearer '+token} if token else {}
                if payload is not None:
                    headers['Content-Type'] = 'application/json'
                req = Request(url+path, headers=headers,
                              data=json.dumps(payload).encode() if payload is not None else None)
                with urlopen(req, context=context, timeout=5) as reply:
                    return reply.read()
            check(b'<html' in request('/').lower(), 'Нет HTML панели')
            check(len(request('/app.js')) > 100, 'Нет JS панели')
            try:
                request('/api/report')
            except HTTPError as error:
                check(error.code == 401, 'Ожидался401 без токена')
            else:
                raise RuntimeError('Отчёт доступен без токена')
            token = execute('python3', '/app/entrypoint.py', 'admin-token')
            execute('python3', '/app/entrypoint.py', 'add-agent', '--name', 'synthetic-docker-test',
                    '--server', url, '--out', '/var/lib/dlp-central/test-agent.json')
            agent = json.loads(execute('python3', '-c',
                'from pathlib import Path; print(Path("/var/lib/dlp-central/test-agent.json").read_text())'))
            identity = hashlib.sha256(project.encode()).hexdigest()
            batch = [{'id': identity, 'payload': {'event': 'analysis', 'decision': 'WARN',
                                               'complete': True, 'categories': ['financial']}}]
            check(json.loads(request('/api/events', agent['token'], batch))['acked'] == [identity],
                  'Нет подтверждения события')
            report = json.loads(request('/api/report', token))
            check(len(report['agents']) == 1 and len(report['events']) == 1, 'Нет устройства/события')
            print('OK: HTTPS с проверкой сертификата,401, регистрация и приём события', flush=True)
            run('restart', 'central')
            wait()
            # Docker may reallocate an ephemeral host port after restart.
            url = 'https://' + run('port', 'central', '8766', capture=True)
            check(execute('python3', '/app/entrypoint.py', 'admin-token') == token, 'Токен изменился')
            report = json.loads(request('/api/report', token))
            check(len(report['agents']) == 1 and len(report['events']) == 1, 'Данные потеряны')
            print('PASS: токен, устройство и событие сохранились после перезапуска', flush=True)
        finally:
            # Unique random project only: never remove the operational project's volume.
            run('down', '--volumes', '--remove-orphans')
            print('Временные контейнеры и том удалены; образ оставлен для установки.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, URLError) as error:
        print('FAIL: ' + str(error))
        raise SystemExit(1)
