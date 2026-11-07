#!/usr/bin/python3 -I
"""Update the migrated server first, then the local forwarder for administrator-managed session control."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CONFIG = Path('/etc/dlp-lab/docker/compose.json')
IMAGE = 'dlp-lab-central:0.2.21'
PACKAGE = ROOT/'build/dlp-lab_0.2.22_amd64.deb'


def run(*args, capture=False):
    result = subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def write_config(data):
    fd, name = tempfile.mkstemp(prefix='.compose-', dir=CONFIG.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
        os.replace(name, CONFIG)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    if os.geteuid() != 0:
        raise ValueError('Запустите через sudo python3 scripts/update-managed-agent.py')
    os.umask(0o077)
    if CONFIG.is_symlink() or CONFIG.stat().st_uid != 0 or CONFIG.stat().st_mode & 0o022:
        raise ValueError('Нужна защищённая root-owned конфигурация миграции')
    original = CONFIG.read_text()
    updated = json.loads(original)
    if set(updated['services']) != {'local', 'https'}:
        raise ValueError('Неизвестная конфигурация контейнеров')
    if run('dpkg-deb', '-f', str(PACKAGE), 'Version', capture=True) != '0.2.22':
        raise ValueError('Нужен пакет0.2.22')
    installed = run('dpkg-query', '-W', '-f=${Version}', 'dlp-lab', capture=True)
    if subprocess.run(['dpkg', '--compare-versions', installed, 'gt', '0.2.22']).returncode == 0:
        raise ValueError('Установлена более новая версия; понижение отменено')
    run('apt-get', '--simulate', '--no-remove', 'install', str(PACKAGE))
    token = json.loads(Path('/var/lib/dlp-central/admin.json').read_text())['token']
    compose = ['docker', 'compose', '-p', 'dlp-central-migrated', '-f', str(CONFIG)]
    run('docker', 'build', '-t', IMAGE, '-f', str(ROOT/'docker/Dockerfile'), str(ROOT))
    backup = CONFIG.with_name('compose-before-managed-'+str(time.time_ns())+'.json')
    backup.write_text(original)
    for service in updated['services'].values():
        service['image'] = IMAGE
    try:
        write_config(json.dumps(updated, indent=2)+'\n')
        run(*compose, 'up', '-d', '--force-recreate')
        for _ in range(40):
            ids = run(*compose, 'ps', '-q', capture=True).splitlines()
            states = [json.loads(run('docker', 'inspect', i, capture=True))[0] for i in ids]
            if len(states) == 2 and all(s['State'].get('Health', {}).get('Status') == 'healthy' for s in states):
                break
            time.sleep(1)
        else:
            raise ValueError('Сервер не стал healthy')
        with urlopen(Request('http://127.0.0.1:8766/api/report', headers={'Authorization': 'Bearer '+token}), timeout=5) as reply:
            report = json.load(reply)
        if not isinstance(report.get('agents'), list) or any('health' not in a for a in report['agents']):
            raise ValueError('Сервер не поддерживает состояние защиты')
    except BaseException:
        write_config(original)
        run(*compose, 'up', '-d', '--force-recreate')
        print('Возвращена предыдущая конфигурация сервера. Агент ещё не обновлялся.', flush=True)
        raise
    # Server-first order is mandatory: the older server rejects new projection fields.
    run('apt-get', '-y', '--no-remove', '-o', 'Dpkg::Options::=--force-confold', 'install', str(PACKAGE))
    run('systemctl', 'enable', '--now', 'dlp-lab-session.service')
    run('systemctl', 'restart', 'dlp-lab-session.service', 'dlp-lab-forwarder.service')
    run('systemctl', 'is-active', '--quiet', 'dlp-lab-forwarder.service', 'dlp-lab-session.service', 'dlp-lab-admin-control.service')
    print('PASS: сервер и системный отправщик обновлены. Обновите страницу и повторите тестовое прикрепление.')
    print('Проверьте состояние текстового контроля в карточке устройства. Второй агент обновляется после сервера.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print('Обновление не завершено: '+str(error))
        raise SystemExit(1)
