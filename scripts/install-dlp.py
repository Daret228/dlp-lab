#!/usr/bin/python3 -I
"""Standalone administrator bootstrap. Uses stdlib and fixed system tools only."""
import argparse
import json
import os
from pathlib import Path
import pwd
import ssl
import stat
import subprocess
import sys
import tempfile
import uuid
from urllib.parse import urlsplit

CONFIG = Path('/etc/dlp-lab')
DROPIN = Path('/etc/systemd/system/dlp-lab-forwarder.service.d')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
       'DEBIAN_FRONTEND': 'noninteractive'}


def run(args, capture=False):
    result = subprocess.run(args, env=ENV, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ''


def read_file(path, limit=65536, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Ожидался обычный файл')
        if private and info.st_mode & 0o077:
            raise ValueError('Файл регистрации должен быть закрыт от других пользователей: chmod 600 FILE')
        data = stream.read(limit+1)
    if len(data) > limit:
        raise ValueError('Входной файл слишком большой')
    return data


def protected(path, directory=False):
    info = path.lstat()
    if (info.st_uid != 0 or info.st_mode & 0o022 or
            not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError('Нужен защищённый root-owned путь: ' + str(path))


def executable(path):
    path = Path(path).resolve(strict=True)
    protected(path)
    for parent in path.parents:
        protected(parent, True)
    if not os.access(path, os.X_OK) or any(c in str(path) for c in ('\n','\r',':','\\')):
        raise ValueError('Недопустимый исполняемый файл')
    return path


def registration(data):
    value = json.loads(data)
    if not isinstance(value, dict) or set(value) != {'server','agent_id','token'}:
        raise ValueError('Некорректная структура файла регистрации')
    if not all(isinstance(v, str) for v in value.values()):
        raise ValueError('Некорректные поля регистрации')
    url = urlsplit(value['server'])
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ('','/') or not url.port
            or any(ord(c) <= 32 for c in value['server'])):
        raise ValueError('Нужен HTTPS адрес сервера с явным портом, без пути/пароля')
    uuid.UUID(value['agent_id'])
    if not 32 <= len(value['token']) <= 128 or not all(c.isascii() and (c.isalnum() or c in '_-') for c in value['token']):
        raise ValueError('Некорректный токен регистрации')
    return value


def package_info(path, expected, architecture, release):
    path = path.resolve(strict=True)
    if not path.is_file() or path.suffix != '.deb':
        raise ValueError('Нужен локальный DEB пакет')
    values = [run(['/usr/bin/dpkg-deb','-f',str(path),key], True)
              for key in ('Package','Architecture','Version','Depends')]
    if values[0] != expected or values[1] not in (architecture, 'all'):
        raise ValueError('Имя/архитектура пакета не соответствует установке')
    if release == '12' and expected == 'dlp-lab' and 'deb12' not in values[2]:
        raise ValueError('Для Debian12 требуется нативная сборка с меткой deb12 в версии')
    if release == '13' and expected == 'dlp-lab' and 'deb12' in values[2]:
        raise ValueError('Выбран пакет Debian12 вместо Debian13')
    return path, values[2]


def choose_user(requested):
    if requested:
        account = pwd.getpwnam(requested)
    else:
        name = os.environ.get('SUDO_USER')
        if name and name != 'root':
            account = pwd.getpwnam(name)
        else:
            candidates = [p for p in pwd.getpwall() if 1000 <= p.pw_uid < 60000
                          and Path(p.pw_dir).is_dir() and not p.pw_shell.endswith(('nologin','false'))]
            if len(candidates) != 1:
                raise ValueError('Укажите --user: нельзя однозначно выбрать пользователя рабочего стола')
            account = candidates[0]
    if not account.pw_uid or not account.pw_gid:
        raise ValueError('Пользователь рабочего стола не должен быть root')
    return account


def ensure_directory(path):
    for parent in reversed(path.parents):
        protected(parent, True)
    if not path.exists():
        path.mkdir(mode=0o755)
    protected(path, True)


def atomic_write(path, data, mode):
    ensure_directory(path.parent)
    if path.exists() or path.is_symlink():
        protected(path)
    fd, name = tempfile.mkstemp(prefix='.install-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def check_existing(path, desired, mode):
    if path.exists() or path.is_symlink():
        protected(path)
        if stat.S_IMODE(path.stat().st_mode) != mode or read_file(path) != desired:
            raise ValueError('Существующая настройка отличается; автоматическая замена запрещена: '+str(path))
        return True
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description='Установка файлового DLP-агента и HTTPS отправщика (Debian12/13)')
    parser.add_argument('--package', type=Path, help='DEB агента; по умолчанию единственный dlp-lab_*.deb рядом со скриптом')
    parser.add_argument('--sqlcipher-package', type=Path, help='Локальный libsqlcipher1 DEB для Debian12')
    parser.add_argument('--user', help='Пользователь рабочего стола')
    parser.add_argument('--telegram', type=Path)
    parser.add_argument('--signal', type=Path)
    parser.add_argument('--no-signal', action='store_true')
    parser.add_argument('--central-config', type=Path, help='Индивидуальный JSON устройства, права0600')
    parser.add_argument('--ca', type=Path, help='Публичный CA сервера')
    parser.add_argument('--local-only', action='store_true', help='Явно установить только локальную защиту')
    parser.add_argument('--check', action='store_true', help='Проверка и apt simulation без изменений')
    parser.add_argument('--yes', action='store_true', help='Применить без итогового вопроса')
    args = parser.parse_args(argv)
    try:
        if not args.check and os.geteuid() != 0:
            raise ValueError('Запустите установку через sudo; --check допускается без sudo')
        if args.signal and args.no_signal:
            raise ValueError('--signal несовместим с --no-signal')
        release = {}
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                k,v = line.split('=',1); release[k] = v.strip('"')
        if release.get('ID') != 'debian' or release.get('VERSION_ID') not in ('12','13'):
            raise ValueError('Этот установщик поддерживает только Debian12/13')
        if not Path('/run/systemd/system').is_dir():
            raise ValueError('Нужна система с работающим systemd')
        base = Path(__file__).resolve().parent
        if not args.package:
            candidates = list(base.glob('dlp-lab_*.deb'))
            if len(candidates) != 1:
                raise ValueError('Укажите --package или положите единственный DEB агента рядом со скриптом')
            args.package = candidates[0]
        arch = run(['/usr/bin/dpkg','--print-architecture'], True)
        package, version = package_info(args.package, 'dlp-lab', arch, release['VERSION_ID'])
        try:
            run(['/usr/bin/dpkg','--compare-versions',version,'ge','0.2.13~'])
        except subprocess.CalledProcessError:
            raise ValueError('Нужен агент0.2.13 или новее')
        packages = []
        if args.sqlcipher_package:
            packages.append(str(package_info(args.sqlcipher_package,'libsqlcipher1',arch,release['VERSION_ID'])[0]))
        elif release['VERSION_ID'] == '12':
            candidates = list(base.glob('libsqlcipher1_*.deb'))
            if len(candidates) == 1:
                packages.append(str(package_info(candidates[0],'libsqlcipher1',arch,'12')[0]))
        packages.append(str(package))
        gateway = CONFIG/'system-gateway.conf'
        existing = gateway.exists() or gateway.is_symlink()
        setup = []
        if existing:
            protected(gateway)
            if args.user:
                host = dict(line.split('=',1) for line in read_file(gateway).decode().splitlines() if '=' in line)
                if str(pwd.getpwnam(args.user).pw_uid) != host.get('uid'):
                    raise ValueError('Пользователь отличается от существующей настройки')
            if args.telegram or args.signal or args.no_signal:
                raise ValueError('Пути уже настроены; заменяйте отдельно через dlp-lab-configure --replace')
        else:
            if (CONFIG/'system/processes.yaml').exists():
                raise ValueError('Обнаружена неполная существующая конфигурация; требуется диагностика')
            account = choose_user(args.user)
            tg = args.telegram or next((Path(p) for p in ('/usr/bin/telegram-desktop','/opt/Telegram/Telegram') if Path(p).is_file()), None)
            if not tg:
                raise ValueError('Telegram не найден: установите клиент или укажите --telegram')
            setup = ['/usr/sbin/dlp-lab-configure','--user',account.pw_name,'--telegram',str(executable(tg))]
            signal = args.signal or (Path('/opt/Signal/signal-desktop') if not args.no_signal and Path('/opt/Signal/signal-desktop').is_file() else None)
            if signal:
                setup += ['--signal',str(executable(signal))]
        writes = []
        central = CONFIG/'central-agent.json'
        if args.local_only and (args.central_config or args.ca):
            raise ValueError('--local-only несовместим с настройкой сервера')
        if not args.local_only:
            if not args.central_config and (base/'central-agent.json').is_file():
                args.central_config = base/'central-agent.json'
            if not args.ca and (base/'central-ca.crt').is_file():
                args.ca = base/'central-ca.crt'
            if not args.central_config:
                if not central.exists():
                    raise ValueError('Нужны --central-config и --ca либо явный --local-only')
                protected(central)
                registration(read_file(central, private=True))
                print('Существующее подключение сохраняется; параметры TLS не меняются.')
                if args.ca:
                    raise ValueError('Для изменения CA существующей регистрации используйте отдельную процедуру')
            else:
                data = read_file(args.central_config, private=True)
                registration(data)
                if not args.ca:
                    raise ValueError('Укажите публичный --ca')
                ca = read_file(args.ca)
                ssl.create_default_context(cadata=ca.decode('ascii'))
                writes = [(central,data,0o600),(CONFIG/'central-ca.crt',ca,0o644),
                          (DROPIN/'tls.conf',b'[Service]\nEnvironment=SSL_CERT_FILE=/etc/dlp-lab/central-ca.crt\n',0o644)]
                for path,data,mode in writes:
                    check_existing(path,data,mode)
        print('ОС: Debian '+release['VERSION_ID']+'; архитектура: '+arch+'; DLP: '+version)
        print('Файловая защита: '+('сохранить настройки' if existing else ' '.join(setup[1:])))
        print('Сервер: '+('не настраивать, существующий отправщик не отключается' if args.local_only else 'включить системный отправщик'))
        print('Текст/локальные базы требуют отдельной настройки пользовательского сеанса.')
        print('Проверка зависимостей apt (без установки):', flush=True)
        run(['/usr/bin/apt-get','--simulate','--no-remove','install',*packages])
        if args.check:
            print('Проверка завершена. Изменения не внесены; связь и реальная защита ещё не проверены.')
            return 0
        if not args.yes:
            if not sys.stdin.isatty():
                raise ValueError('Для неинтерактивной установки добавьте --yes')
            if input('Установить и включить службы? [д/Н]: ').strip().lower() not in ('д','да','y','yes'):
                print('Отменено. Изменения не внесены.'); return 0
        os.umask(0o077)
        # Apt/debconf must not guess desktop settings during bootstrap.
        subprocess.run(['/usr/bin/debconf-set-selections'], input='dlp-lab dlp-lab/configure boolean false\n',
                       text=True, check=True, env=ENV)
        run(['/usr/bin/apt-get','-y','--no-remove','-o','Dpkg::Options::=--force-confold','install',*packages])
        if setup:
            run(setup)
        for path,data,mode in writes:
            if not check_existing(path,data,mode):
                atomic_write(path,data,mode)
        run(['/usr/bin/systemctl','daemon-reload'])
        run(['/usr/bin/systemctl','enable','--now','dlp-lab-files.service'])
        if not args.local_only:
            run(['/usr/bin/systemctl','enable','--now','dlp-lab-forwarder.service'])
        run(['/usr/bin/dlp-agent','doctor'])
        for unit in (['dlp-lab-files.service'] + ([] if args.local_only else ['dlp-lab-forwarder.service'])):
            run(['/usr/bin/systemctl','is-active','--quiet',unit])
        print('Установка выполнена. Проверьте monitor_started и тестовое прикрепление; затем событие в центральной панели.')
        print('sudo journalctl -u dlp-lab-files.service -n 20 --no-pager')
        print('sudo journalctl -u dlp-lab-forwarder.service -n 20 --no-pager')
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, EOFError) as error:
        # Never echo credentials, arbitrary server replies or subprocess command payloads.
        if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError):
            print('Установка остановлена: '+str(error), file=sys.stderr)
        else:
            print('Установка остановлена: '+type(error).__name__+'. Проверьте файлы, права и вывод системной команды.',file=sys.stderr)
        print('Уже выполненные шаги не откатываются автоматически. Настройки не удаляются.',file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Прервано; уже выполненные шаги могли сохраниться.',file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
