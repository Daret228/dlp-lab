"""Root-only host setup. Standard library only, invoked with Python isolated mode.

Never load project code, YAML constructors, plugins, or shell configuration as root.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import subprocess
import tempfile

CONFIG = Path('/etc/dlp-lab')
STATE = Path('/var/lib/dlp-lab-package')


def protected(path, directory=False):
    st = path.lstat()
    kind = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1
    if st.st_uid != 0 or st.st_mode & 0o022 or not kind:
        raise ValueError(f'Not a protected root-owned path: {path}')


def directory(path, mode=0o755):
    for parent in reversed(path.parents):
        protected(parent, True)
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
    protected(path, True)


def valid_path(value):
    if (not value.startswith('/') or len(value.encode()) >= 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(c in value for c in (':', '\\'))
            or '//' in value or '/./' in value or '/../' in value
            or value.endswith(('/.', '/..')) or (value != '/' and value.endswith('/'))):
        raise ValueError('Invalid absolute configuration path')
    return value


def replace_file(path, data, mode):
    if path.exists() or path.is_symlink():
        protected(path)
    fd, temporary = tempfile.mkstemp(prefix='.configure-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def configuration(account, telegram, signal=None):
    if not 0 < account.pw_uid < 2**32-1 or not 0 < account.pw_gid < 2**32-1:
        raise ValueError('Choose a non-root user and primary group')
    home = valid_path(account.pw_dir)
    telegram = valid_path(str(telegram))
    excludes = ['/usr', '/opt', '/etc', '/bin', '/sbin', '/lib', '/lib64']
    excludes += [home + p for p in ('/.cache', '/.config', '/.local/share/TelegramDesktop',
                                   '/.local/share/fonts', '/.fonts')]
    gateway = (f'uid={account.pw_uid}\ngid={account.pw_gid}\nhome={home}\n'
               f'project=/usr/lib/dlp-lab\ntelegram={telegram}\n'
               + ''.join(f'exclude={p}\n' for p in excludes))
    if signal is not None:
        signal = valid_path(str(signal))
        if signal == telegram:
            raise ValueError('Messenger executables must be distinct')
        gateway += f'signal={signal}\n'
    processes = {'version': 1, 'mode': 'messengers', 'uid': account.pw_uid,
                 'messengers': {'telegram': {'enabled': True, 'executables': [telegram]},
                                'express': {'enabled': False, 'executables': []}}}
    if signal is not None:
        processes['messengers']['signal'] = {'enabled': True, 'executables': [signal]}
    return gateway.encode(), (json.dumps(processes, indent=2) + '\n').encode()


def wizard(args):
    """Collect choices only; all writes still use the hardened setup below."""
    if not sys.stdin.isatty():
        raise ValueError('Мастер требует терминал. Используйте --user и --telegram для скриптов.')
    if (CONFIG/'system-gateway.conf').exists():
        raise ValueError('Уже настроено. Проверьте dlp-agent doctor; мастер не заменяет настройки.')
    print('Настройка файлового контроля DLP (Telegram, дополнительно Signal).')
    print('Текстовые поля и локальные базы этим мастером не включаются.')
    default_user = args.user or os.environ.get('SUDO_USER', '')
    if default_user == 'root':
        default_user = ''
    args.user = input(f'Пользователь рабочего стола [{default_user}]: ').strip() or default_user
    account = pwd.getpwnam(args.user)
    if account.pw_uid == 0:
        raise ValueError('Укажите обычного пользователя, не root')
    candidates = ('/usr/bin/telegram-desktop', '/opt/Telegram/Telegram')
    detected = next((p for p in candidates if Path(p).is_file()), '')
    default = str(args.telegram) if args.telegram else detected
    value = input(f'Исполняемый файл Telegram [{default}]: ').strip() or default
    if not value:
        raise ValueError('Telegram не найден. Установите клиент и повторите настройку.')
    args.telegram = Path(value)
    detected_signal = '/opt/Signal/signal-desktop'
    signal_default = str(args.signal) if args.signal else (
        detected_signal if Path(detected_signal).is_file() else '')
    value = input(f'Signal: путь или «-» для пропуска [{signal_default or "-"}]: ').strip()
    value = value or signal_default
    args.signal = Path(value) if value and value != '-' else None
    args.enable = input('Включить автозапуск и запустить сейчас? [Д/н]: ').strip().lower() in ('', 'д', 'да', 'y', 'yes')
    print(f'Пользователь: {args.user}; Telegram: {args.telegram}; Signal: {args.signal or "не включён"}')
    print('Контроль локальных файловых систем с исключениями для системных каталогов и профилей.')
    print('Запуск службы: ' + ('да' if args.enable else 'нет'))
    if input('Применить? [д/Н]: ').strip().lower() not in ('д', 'да', 'y', 'yes'):
        print('Отменено. Настройки не изменены.')
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description='Configure the packaged DLP filesystem service')
    parser.add_argument('--wizard', action='store_true', help='Пошаговая первоначальная настройка')
    parser.add_argument('--user')
    parser.add_argument('--telegram', type=Path)
    parser.add_argument('--signal', type=Path, help='Optional protected Signal Desktop executable')
    parser.add_argument('--replace', action='store_true', help='Back up and replace existing host settings; resets exclusions')
    parser.add_argument('--enable', action='store_true', help='Enable and start the system service after configuration')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo; this modifies administrator-owned settings')
    os.umask(0o077)
    try:
        if args.wizard:
            if args.replace:
                raise ValueError('Мастер не поддерживает --replace')
            if not wizard(args):
                return
        if not args.user or not args.telegram:
            parser.error('Укажите --wizard либо --user USER --telegram /path/to/Telegram')
        account = pwd.getpwnam(args.user)
        telegram = args.telegram.resolve(strict=True)
        for parent in reversed(telegram.parents):
            protected(parent, True)
        protected(telegram)
        if not os.access(telegram, os.X_OK):
            raise ValueError('Telegram is not executable')
        signal = args.signal.resolve(strict=True) if args.signal else None
        if signal:
            for parent in reversed(signal.parents):
                protected(parent, True)
            protected(signal)
            if not os.access(signal, os.X_OK):
                raise ValueError('Signal is not executable')
        gateway, processes = configuration(account, telegram, signal)
        directory(CONFIG)
        directory(CONFIG/'system')
        directory(STATE, 0o700)
        # Same lock as the laboratory gateway: migration cannot run both brokers.
        fd = os.open(CONFIG/'gateway.lock', os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW, 0o600)
        try:
            protected(CONFIG/'gateway.lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            targets = [(CONFIG/'system/processes.yaml', processes, 0o644),
                       (CONFIG/'system-gateway.conf', gateway, 0o600)]
            for path, _, _ in targets:
                if path.exists() or path.is_symlink():
                    protected(path)
                    if not args.replace:
                        raise ValueError('Already configured. Stop the service and use --replace to reset host settings')
            for path, _, _ in targets:
                if path.exists():
                    if path.stat().st_size > 65536:
                        raise ValueError('Existing configuration is too large')
                    replace_file(STATE/(path.name+'.previous'), path.read_bytes(), 0o600)
            # The broker lock excludes service startup until both files are ready.
            # Per-file atomic writes, not a power-loss transaction.
            for path, data, mode in targets:
                replace_file(path, data, mode)
        finally:
            os.close(fd)
        if args.enable:
            subprocess.run(['/usr/bin/systemctl', 'enable', '--now', 'dlp-lab-files.service', 'dlp-lab-session.service'], check=True)
        print('Configured. Readiness is confirmed by monitor_started in the system journal.')
        if not args.enable:
            print('Start: sudo systemctl enable --now dlp-lab-files.service')
    except BlockingIOError:
        parser.exit(2, 'Gateway is running. Stop the laboratory or system files service first.\n')
    except (KeyError, OSError, ValueError, EOFError, KeyboardInterrupt, subprocess.CalledProcessError) as exc:
        parser.exit(2, f'Configuration failed: {exc}\n')


if __name__ == '__main__':
    main()
