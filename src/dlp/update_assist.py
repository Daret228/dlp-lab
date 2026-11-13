"""Passwordless, narrowly scoped agent update helper.

SUID is ignored for interpreted scripts on Linux, so the passwordless path
is a sudoers rule that permits exactly `/usr/sbin/dlp-lab-update ""` for the
system group dlp-updaters (created empty; the administrator adds members).
Membership is a trust decision: it equals permission to install a dlp-lab
package, because maintainer scripts run as root.

The helper itself never takes arguments: the package comes from the invoking
user's ~/dlp-build-input, must be named dlp-lab_<version>_<arch>.deb, must
declare Package=dlp-lab with the host architecture, and must be strictly
newer than the installed version. Install preserves local configuration
(--force-confold) exactly like the documented manual command.
"""
import fcntl
import os
import pwd
import re
import subprocess
import sys
from pathlib import Path

NAME = re.compile(r'^dlp-lab_([0-9][0-9A-Za-z.~+-]*)_([a-z0-9]+)\.deb$')
LOCK = '/run/lock/dlp-lab-update.lock'
INPUT_DIR = 'dlp-build-input'


def candidate_from_name(name):
    """Return (version, architecture) for a valid package file name."""
    match = NAME.fullmatch(name)
    return (match.group(1), match.group(2)) if match else None


def dpkg_newer(candidate, installed):
    return subprocess.run(['dpkg', '--compare-versions', candidate, 'gt', installed],
                          capture_output=True).returncode == 0


def read_fields(path, fields):
    result = subprocess.run(['dpkg-deb', '-f', str(path), *fields],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return None
    values = result.stdout.strip().splitlines()
    return dict(zip(fields, values)) if len(values) == len(fields) else None


def select_candidate(directory, *, installed, architecture,
                     field_reader=read_fields, compare=dpkg_newer):
    """Pick the newest valid strictly-newer dlp-lab package in directory."""
    best = None
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return None
    for name in names:
        parsed = candidate_from_name(name)
        if parsed is None:
            continue
        version, _ = parsed
        path = directory / name
        fields = field_reader(path, ['Package', 'Architecture', 'Version'])
        if not fields or fields['Package'] != 'dlp-lab':
            continue
        if fields['Architecture'] != architecture:
            continue
        if fields['Version'] != version:
            continue
        if installed and not compare(version, installed):
            continue
        if best is None or compare(version, best[1]):
            best = (path, version)
    return best


def installed_version(runner=subprocess.run):
    result = runner(['dpkg-query', '-W', '-f=${Version}\n', 'dlp-lab'], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else ''


def build_install_command(path):
    return ['apt-get', 'install', '-y', '-o', 'Dpkg::Options::=--force-confold', str(path)]


def invoking_home():
    user = os.environ.get('SUDO_USER') if os.geteuid() != 0 else None
    if not user:
        return Path.home()
    try:
        return Path(pwd.getpwnam(user).pw_dir)
    except KeyError:
        return None


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) != 1:
        print('Команда не принимает аргументы.', file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print('Запустите: sudo dlp-lab-update', file=sys.stderr)
        return 2
    home = invoking_home()
    if home is None:
        print('Не удалось определить домашний каталог вызывающего пользователя.', file=sys.stderr)
        return 1
    directory = home / INPUT_DIR
    current = installed_version()
    if not current:
        print('Пакет dlp-lab не установлен; обновление не выполняется.', file=sys.stderr)
        return 1
    architecture = subprocess.run(['dpkg', '--print-architecture'],
                                  capture_output=True, text=True).stdout.strip()
    chosen = select_candidate(directory, installed=current, architecture=architecture)
    if chosen is None:
        print(f'Новый пакет dlp-lab в {directory} не найден '
              f'(нужен строго новее установленной версии {current}).')
        return 0
    path, version = chosen
    print(f'Устанавливается {path.name} (новее {current})…')
    lock = open(LOCK, 'w')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print('Обновление уже выполняется другим процессом.', file=sys.stderr)
        return 1
    environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    result = subprocess.run(build_install_command(path), env=environment)
    if result.returncode != 0:
        print('Установка не завершена; конфигурация не изменена.', file=sys.stderr)
        return 1
    for unit in ('dlp-lab-files.service', 'dlp-lab-session.service',
                 'dlp-lab-forwarder.service', 'dlp-lab-admin-control.service'):
        state = subprocess.run(['systemctl', 'show', unit, '-p', 'ActiveState', '--value'],
                               capture_output=True, text=True).stdout.strip()
        print(f'{unit}: {state or "неизвестно"}')
    print(f'Готово: версия {version}. Проверьте устройство в центральной панели.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
