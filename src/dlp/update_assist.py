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
import subprocess
import sys
from pathlib import Path

# The name grammar is shared with the server-side update channel so both
# sides accept exactly the same package file names.
from .update_channel import NAME, candidate_from_name

LOCK = '/run/lock/dlp-lab-update.lock'
INPUT_DIR = 'dlp-build-input'


def dpkg_newer(candidate, installed):
    return subprocess.run(['dpkg', '--compare-versions', candidate, 'gt', installed],
                          capture_output=True).returncode == 0


def read_fields(path, fields):
    """Read control fields with dpkg-deb.

    With several fields dpkg-deb prints `Field: value` lines; with one
    field it prints the bare value. Strip the expected prefix so both
    real formats yield bare values.
    """
    result = subprocess.run(['dpkg-deb', '-f', str(path), *fields],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return None
    values = {}
    for name, line in zip(fields, result.stdout.strip().splitlines()):
        prefix = name + ': '
        values[name] = line[len(prefix):] if line.startswith(prefix) else line
    return values if len(values) == len(fields) else None


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
    # The dpkg lock timeout keeps unattended runs from waiting behind an
    # unrelated system transaction (for example packagekitd) forever.
    return ['apt-get', 'install', '-y', '-o', 'Dpkg::Options::=--force-confold',
            '-o', 'DPkg::Lock::Timeout=60', str(path)]


def invoking_home():
    """Home directory of the invoking user.

    The helper runs as root via sudo, and sudo keeps the invoking user in
    SUDO_USER — while HOME already points at /root. Resolve SUDO_USER
    whenever it is set; without it (direct root run) fall back to HOME.
    """
    user = os.environ.get('SUDO_USER')
    if not user:
        return Path.home()
    try:
        return Path(pwd.getpwnam(user).pw_dir)
    except KeyError:
        return None


def perform_install(path, *, expected_version, capture=True):
    """Validate one package file and install it as root.

    Shared by the sudo helper and the broker-triggered oneshot installer:
    the declared fields must match the trusted file name, the version must
    be strictly newer than the installed one, and only one install may run
    at a time (the lock is shared with dlp-lab-update). Returns the version.
    """
    if os.geteuid() != 0:
        raise ValueError('Требуются права администратора.')
    architecture = subprocess.run(['dpkg', '--print-architecture'],
                                  capture_output=True, text=True).stdout.strip()
    if not architecture:
        raise ValueError('Не удалось определить архитектуру системы.')
    fields = read_fields(path, ['Package', 'Architecture', 'Version'])
    if (not fields or fields['Package'] != 'dlp-lab' or fields['Architecture'] != architecture
            or fields['Version'] != expected_version):
        raise ValueError('Пакет не соответствует доверенному имени файла.')
    current = installed_version()
    if not current:
        raise ValueError('Пакет dlp-lab не установлен.')
    if not dpkg_newer(expected_version, current):
        raise ValueError('Пакет не новее установленной версии.')
    lock = open(LOCK, 'w')
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ValueError('Другое обновление уже выполняется.')
        environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
        result = subprocess.run(build_install_command(path), env=environment, capture_output=capture)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, build_install_command(path))
    finally:
        lock.close()
    return expected_version


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
    try:
        perform_install(path, expected_version=version, capture=False)
    except subprocess.CalledProcessError:
        print('Установка не завершена; конфигурация не изменена.', file=sys.stderr)
        return 1
    except (ValueError, OSError) as error:
        print(str(error) or 'Установка не выполнена.', file=sys.stderr)
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
