#!/usr/bin/python3 -I
"""Move the migrated lab server to a stable DNS name without replacing its CA.

Run once on the server, then --agent-only on each other existing endpoint.
Default is preflight only; --apply performs backed-up changes. No tokens printed.
"""
import argparse
import copy
from contextlib import closing
import fcntl
import http.client
import hashlib
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sqlite3
import stat
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler, HTTPSHandler

CONFIG = Path('/etc/dlp-lab/docker/compose.json')
AGENT = Path('/etc/dlp-lab/central-agent.json')
CONNECTION = Path('/etc/dlp-lab/connection.json')
AGENT_CA = Path('/etc/dlp-lab/central-ca.crt')
TLS = Path('/etc/dlp-lab/docker/tls')
PUBLIC_TLS = Path('/etc/dlp-lab/tls')
COMPOSE = ['docker', 'compose', '-p', 'dlp-central-migrated', '-f', str(CONFIG)]
NSS = Path('/etc/nsswitch.conf')
MDNS_ALLOW = Path('/etc/mdns.allow')
AVAHI = Path('/etc/avahi/avahi-daemon.conf')


def queue_binding(registration):
    return hashlib.sha256((registration['agent_id']+':'+
                           registration['server'].rstrip('/')).encode()).hexdigest()


def rebind_queue_file(path, old, new):
    """Called as the service user, with the forwarder stopped; preserve all events."""
    if not path.exists():
        return False
    if path.is_symlink():
        raise ValueError('Очередь не должна быть символической ссылкой')
    with closing(sqlite3.connect(str(path), timeout=10)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        rows = db.execute('SELECT id FROM owner').fetchall()
        if rows == [(new,)]:
            return False
        if rows != [(old,)]:
            raise ValueError('Очередь принадлежит другой регистрации; перенос отменён')
        db.execute('UPDATE owner SET id=? WHERE id=?', (new, old))
    return True


def rebind_queue(old, new):
    output = run('runuser', '-u', 'dlp-forwarder', '--', '/usr/bin/python3', '-I', '-c',
                 'import sqlite3,sys\nfrom pathlib import Path\nfrom contextlib import closing\n'+inspect.getsource(rebind_queue_file)+
                 '\nprint(int(rebind_queue_file(Path("/var/lib/dlp-forwarder/state.sqlite"),'
                 'sys.argv[1],sys.argv[2])))', old, new)
    return output == '1'


def previous_registration(backup, current):
    info = backup.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Нужна приватная root-owned резервная копия')
    protected(backup/'manifest.json')
    entries = json.loads((backup/'manifest.json').read_text())
    names = [e['file'] for e in entries if e['path'] == str(AGENT)]
    if len(names) != 1 or not isinstance(names[0], str) or not names[0].isdigit():
        raise ValueError('В копии нет исходной регистрации')
    path = backup/names[0]
    protected(path)
    old = json.loads(path.read_text())
    if changed_registration(old, current['server']) != current:
        raise ValueError('Копия принадлежит другой регистрации')
    return old


def mdns_changes(name, server=False):
    """Make .local authoritative in Avahi even when unicast DNS misanswers."""
    if not re.fullmatch(r'[a-z0-9-]+\.local', name):
        raise ValueError('--configure-mdns требует имя вида dlp-server.local')
    run('systemctl', 'is-active', 'avahi-daemon.service')
    run('dpkg-query', '-W', '-f=${Status}', 'libnss-mdns')
    protected(NSS)
    source = NSS.read_text()
    lines = re.findall(r'^hosts:.*$', source, re.M)
    if len(lines) != 1 or not re.search(r'\bmdns4(?:_minimal)?\s+\[NOTFOUND=return\]', lines[0]):
        raise ValueError('Неизвестная hosts-строка nsswitch.conf; автоматическая замена отменена')
    line = re.sub(r'\bmdns4_minimal\b', 'mdns4', lines[0])
    if any(line.find(token) < line.find('mdns4') for token in (' dns', ' resolve') if token in line):
        raise ValueError('DNS стоит раньше mDNS; требуется отдельная проверка nsswitch.conf')
    # Refuse to overwrite an administrator's unrelated mDNS domain policy.
    if MDNS_ALLOW.exists() or MDNS_ALLOW.is_symlink():
        protected(MDNS_ALLOW)
        domains = {x.split('#')[0].strip() for x in MDNS_ALLOW.read_text().splitlines()} - {''}
        if domains != {'.local', '.local.'}:
            raise ValueError('Нестандартный /etc/mdns.allow; автоматическая замена отменена')
    changes = [(NSS, source.replace(lines[0], line).encode(), 0o644, 0, 0),
               (MDNS_ALLOW, b'# DLP Lab: resolve .local through Avahi\n.local.\n.local\n', 0o644, 0, 0)]
    if server:
        protected(AVAHI)
        text = AVAHI.read_text()
        match = re.search(r'(?ms)^\[server\]\s*\n(.*?)(?=^\[|\Z)', text)
        if not match:
            raise ValueError('Нет секции server в avahi-daemon.conf')
        section = re.sub(r'(?m)^\s*#?\s*host-name=.*\n?', '', match[1])
        section = 'host-name='+name[:-6]+'\n'+section
        text = text[:match.start(1)]+section+text[match.end(1):]
        changes.append((AVAHI, text.encode(), 0o644, 0, 0))
    return changes


def check_mdns(name, server=False):
    if server:
        published = json.loads(run('busctl', 'call', 'org.freedesktop.Avahi', '/',
                                   'org.freedesktop.Avahi.Server', 'GetHostNameFqdn')[2:])
        if published != name:
            raise ValueError('Avahi объявляет другое имя (возможен конфликт): '+published)
    # A fresh process observes nsswitch changes without libc's in-process cache.
    output = run('getent', 'ahostsv4', name)
    addresses = {line.split()[0] for line in output.splitlines()}
    if not addresses or any(ipaddress.ip_address(ip).is_loopback or
                            ipaddress.ip_address(ip).is_unspecified for ip in addresses):
        raise ValueError('Имя сервера разрешается в loopback или пустой адрес')


def fresh_probe(name, port, ca):
    run('/usr/bin/python3', '-I', '-c',
        'import runpy,sys; m=runpy.run_path(sys.argv[1]); '
        'm["probe"](sys.argv[2],int(sys.argv[3]),sys.argv[4])',
        str(Path(__file__).resolve()), name, str(port), str(ca))


def run(*argv):
    # OpenSSL diagnostics never include key material, but keep stdout private.
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True).stdout.strip()


def hostname(value):
    value = value.lower().rstrip('.')
    if len(value) > 253 or '.' not in value or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
            for p in value.split('.')):
        raise ValueError('Нужно полное DNS-имя, например debian.local')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Используйте постоянное DNS-имя вместо IP')


def protected(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Нужен обычный root-owned файл без записи для других: '+str(path))
    return info


def atomic(path, data, mode, uid=0, gid=0):
    fd, name = tempfile.mkstemp(prefix='.portable-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


def encoded(value):
    return (json.dumps(value, indent=2)+'\n').encode()


def portable_compose(original):
    updated = copy.deepcopy(original)
    if set(updated.get('services', {})) != {'local', 'https'}:
        raise ValueError('Ожидался мигрированный сервер local + https')
    service = updated['services']['https']
    if service.get('network_mode') != 'host' or str(TLS)+':/run/tls:ro' not in service.get('volumes', []):
        raise ValueError('Неизвестная сеть или расположение TLS')
    env = service.setdefault('environment', {})
    port = int(env.get('DLP_TLS_PORT', 8766))
    if not 1 <= port <= 65535:
        raise ValueError('Некорректный HTTPS-порт')
    env['DLP_TLS_HOST'] = '0.0.0.0'
    return updated, port


def changed_registration(data, url):
    updated = copy.deepcopy(data)
    if not isinstance(updated, dict) or not isinstance(updated.get('server'), str):
        raise ValueError('Неизвестный формат регистрации')
    updated['server'] = url
    return updated


def agent_changes(url):
    protected(AGENT)
    changes = [(AGENT, encoded(changed_registration(json.loads(AGENT.read_text()), url)), 0o600, 0, 0)]
    if CONNECTION.exists():
        protected(CONNECTION)
        value = json.loads(CONNECTION.read_text())
        value['registration'] = changed_registration(value['registration'], url)
        changes.append((CONNECTION, encoded(value), 0o600, 0, 0))
    return changes


def fingerprint(path):
    return run('openssl', 'x509', '-in', str(path), '-noout', '-fingerprint', '-sha256')


def issue_certificate(directory, name, ca_cert, ca_key):
    # No CA serial file is modified, and the CA private key is never copied.
    key, csr, cert = (directory / n for n in ('server.key', 'server.csr', 'server.crt'))
    ext = directory/'extensions.cnf'
    ext.write_text('basicConstraints=critical,CA:FALSE\n'
                   'keyUsage=critical,digitalSignature,keyEncipherment\n'
                   'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+name+'\n')
    run('openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
        '-subj', '/CN='+name, '-keyout', str(key), '-out', str(csr))
    key.chmod(0o600)
    run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca_cert),
        '-CAkey', str(ca_key), '-set_serial', '0x'+secrets.token_hex(16),
        '-days', '365', '-sha256', '-extfile', str(ext), '-out', str(cert))
    run('openssl', 'verify', '-CAfile', str(ca_cert), '-purpose', 'sslserver',
        '-verify_hostname', name, str(cert))
    return cert, key


def probe(name, port, ca, address=None):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if address:
        # Connect locally while still checking the certificate against its DNS name.
        with socket.create_connection((address, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=name) as stream:
                stream.sendall(('GET / HTTP/1.1\r\nHost: '+name+'\r\nConnection: close\r\n\r\n').encode())
                reply = http.client.HTTPResponse(stream)
                reply.begin()
                if reply.status != 200:
                    raise ValueError('HTTPS вернул статус '+str(reply.status))
    else:
        # Local management traffic must not be sent to an inherited HTTP proxy.
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
        with opener.open(f'https://{name}:{port}/', timeout=5) as reply:
            if reply.status != 200:
                raise ValueError('HTTPS не готов')


def apply_changes(changes, activate, verify, recover):
    originals = []
    for path, *_ in changes:
        if not path.exists() and not path.is_symlink():
            if path != MDNS_ALLOW:
                raise ValueError('Неожиданный отсутствующий файл: '+str(path))
            originals.append((path, None, 0o644, 0, 0))
            continue
        info = protected(path)
        originals.append((path, path.read_bytes(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
    backup = Path(tempfile.mkdtemp(prefix='dlp-portable-', dir='/var/backups'))
    backup.chmod(0o700)
    manifest = []
    for index, (path, data, mode, uid, gid) in enumerate(originals):
        target = backup/str(index)
        if data is not None:
            target.write_bytes(data)
            target.chmod(0o600)
        manifest.append(dict(path=str(path), file=str(index) if data is not None else None,
                             mode=mode, uid=uid, gid=gid))
    (backup/'manifest.json').write_bytes(encoded(manifest))
    print('Резервная копия:', backup, flush=True)
    try:
        for args in changes:
            atomic(*args)
        activate()
        verify()
    except BaseException:
        for args in originals:
            if args[1] is None:
                args[0].unlink(missing_ok=True)
            else:
                atomic(*args)
        recover()
        print('Исходные файлы восстановлены; проверьте службы. Копия:', backup, flush=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', required=True, type=hostname)
    parser.add_argument('--ca-cert', type=Path)
    parser.add_argument('--ca-key', type=Path)
    parser.add_argument('--agent-only', action='store_true')
    parser.add_argument('--port', type=int, default=8767, help='Порт для --agent-only')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--configure-mdns', action='store_true',
                        help='Настроить .local через Avahi; на сервере также задать объявляемое имя')
    parser.add_argument('--previous-backup', type=Path,
                        help='Для восстановления привязки очереди после уже выполненной смены URL')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise ValueError('Запустите через sudo; без --apply выполняется только проверка')
    os.umask(0o077)
    if args.previous_backup and not args.agent_only:
        raise ValueError('--previous-backup применяется только с --agent-only')
    with open('/run/lock/dlp-portable-server.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        network_changes = mdns_changes(args.hostname, not args.agent_only) if args.configure_mdns else []
        if args.agent_only:
            if not 1 <= args.port <= 65535:
                raise ValueError('Некорректный порт')
            url = f'https://{args.hostname}:{args.port}'
            changes = network_changes + agent_changes(url)
            current = json.loads(AGENT.read_text())
            old = previous_registration(args.previous_backup, current) if args.previous_backup else current
            old_binding = queue_binding(old)
            new_binding = queue_binding(changed_registration(current, url))
            if not args.configure_mdns:
                probe(args.hostname, args.port, AGENT_CA)
            if args.apply:
                restart = lambda: run('systemctl', 'restart', 'dlp-lab-forwarder.service')
                rebound = False
                def activate_agent():
                    nonlocal rebound
                    if args.configure_mdns:
                        check_mdns(args.hostname)
                    fresh_probe(args.hostname, args.port, AGENT_CA)
                    run('systemctl', 'stop', 'dlp-lab-forwarder.service')
                    rebound = rebind_queue(old_binding, new_binding)
                    restart()
                def verify_agent():
                    fresh_probe(args.hostname, args.port, AGENT_CA)
                    for _ in range(3):
                        time.sleep(1)
                        run('systemctl', 'is-active', 'dlp-lab-forwarder.service')
                def recover_agent():
                    run('systemctl', 'stop', 'dlp-lab-forwarder.service')
                    if rebound:
                        rebind_queue(new_binding, old_binding)
                    restart()
                apply_changes(changes, activate_agent,
                              verify_agent, recover_agent)
            elif args.configure_mdns:
                print('План mDNS готов; HTTPS по новому имени будет проверен при --apply.')
                return
            print('HTTPS проверен. '+('Адрес агента обновлён: ' if args.apply else 'План адреса: ')+url)
            return
        protected(CONFIG)
        config, port = portable_compose(json.loads(CONFIG.read_text()))
        if not args.ca_cert or not args.ca_key:
            raise ValueError('Нужны --ca-cert и --ca-key существующего CA')
        for path in (TLS/'server.crt', TLS/'server.key', TLS/'ca.crt',
                     PUBLIC_TLS/'server.crt', PUBLIC_TLS/'server.key', PUBLIC_TLS/'ca.crt'):
            protected(path)
        expected = fingerprint(TLS/'ca.crt')
        if any(fingerprint(p) != expected for p in (args.ca_cert, PUBLIC_TLS/'ca.crt')):
            raise ValueError('CA не совпадает с действующим; замена доверия запрещена')
        if args.hostname.endswith('.local') and not args.configure_mdns:
            published = json.loads(run('busctl', 'call', 'org.freedesktop.Avahi', '/',
                                       'org.freedesktop.Avahi.Server', 'GetHostNameFqdn')[2:])
            if published != args.hostname:
                raise ValueError('Avahi объявляет другое имя: '+published)
        # Name must resolve before changing the installed service.
        if not args.configure_mdns:
            socket.getaddrinfo(args.hostname, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        url = f'https://{args.hostname}:{port}'
        changes = network_changes + [(CONFIG, encoded(config), 0o600, 0, 0)]
        print('HTTPS будет слушать все IPv4-интерфейсы; адрес агентов:', url)
        print('HTTP и локальный отправщик остаются прежними; CA, токены и база сохраняются.')
        with tempfile.TemporaryDirectory(prefix='dlp-portable-cert-') as tmp:
            cert, key = issue_certificate(Path(tmp), args.hostname, args.ca_cert, args.ca_key)
            for directory in (TLS, PUBLIC_TLS):
                for source in (cert, key):
                    target = directory/source.name
                    info = protected(target)
                    changes.append((target, source.read_bytes(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
            if not args.apply:
                print('Проверка завершена, сертификат проверен. Для установки добавьте --apply.')
                return
            def activate():
                if args.configure_mdns:
                    run('systemctl', 'restart', 'avahi-daemon.service')
                run(*COMPOSE, 'config', '--quiet')
                run(*COMPOSE, 'up', '-d', '--no-deps', '--force-recreate', 'https')
            def verify():
                for attempt in range(20):
                    try:
                        probe(args.hostname, port, TLS/'ca.crt', '127.0.0.1')
                        break
                    except (OSError, ValueError):
                        if attempt == 19:
                            raise
                        time.sleep(1)
                if args.configure_mdns:
                    for attempt in range(15):
                        try:
                            check_mdns(args.hostname, server=True)
                            fresh_probe(args.hostname, port, TLS/'ca.crt')
                            break
                        except (OSError, ValueError, subprocess.CalledProcessError):
                            if attempt == 14:
                                raise
                            time.sleep(1)
                else:
                    probe(args.hostname, port, TLS/'ca.crt')
            def recover():
                activate()
            apply_changes(changes, activate, verify, recover)
        print('Готово: '+url+' — HTTPS и имя сертификата проверены.')
        print('Другие агенты: выполните этот скрипт с --agent-only '+
              ('--configure-mdns ' if args.configure_mdns else '')+'--hostname '+args.hostname+
              ' --port '+str(port)+' --apply на каждом из них.')
        print('Доставка событий и доступ из другой машины проверяются отдельно.')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print('Команда завершилась с ошибкой:', error.cmd[0], 'код', error.returncode)
        # Do not print command arguments or captured outputs containing configuration.
        raise SystemExit(1)
    except (OSError, ValueError, KeyError) as error:
        print('Настройка не завершена:', str(error))
        raise SystemExit(1)
