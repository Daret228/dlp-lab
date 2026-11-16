#!/usr/bin/python3 -I
"""Move the migrated lab server to a stable DNS name without replacing its CA.

Run once on the server, then --agent-only on each other existing endpoint.
Default is preflight only; --apply performs backed-up changes. No tokens printed.
"""
import argparse
import copy
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
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
        info = protected(path)
        originals.append((path, path.read_bytes(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
    backup = Path(tempfile.mkdtemp(prefix='dlp-portable-', dir='/var/backups'))
    backup.chmod(0o700)
    manifest = []
    for index, (path, data, mode, uid, gid) in enumerate(originals):
        target = backup/str(index)
        target.write_bytes(data)
        target.chmod(0o600)
        manifest.append(dict(path=str(path), file=str(index), mode=mode, uid=uid, gid=gid))
    (backup/'manifest.json').write_bytes(encoded(manifest))
    print('Резервная копия:', backup, flush=True)
    try:
        for args in changes:
            atomic(*args)
        activate()
        verify()
    except BaseException:
        for args in originals:
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
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise ValueError('Запустите через sudo; без --apply выполняется только проверка')
    os.umask(0o077)
    with open('/run/lock/dlp-portable-server.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.agent_only:
            if not 1 <= args.port <= 65535:
                raise ValueError('Некорректный порт')
            url = f'https://{args.hostname}:{args.port}'
            changes = agent_changes(url)
            probe(args.hostname, args.port, AGENT_CA)
            if args.apply:
                restart = lambda: run('systemctl', 'restart', 'dlp-lab-forwarder.service')
                apply_changes(changes, restart,
                              lambda: probe(args.hostname, args.port, AGENT_CA), restart)
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
        if args.hostname.endswith('.local'):
            published = json.loads(run('busctl', 'call', 'org.freedesktop.Avahi', '/',
                                       'org.freedesktop.Avahi.Server', 'GetHostNameFqdn')[2:])
            if published != args.hostname:
                raise ValueError('Avahi объявляет другое имя: '+published)
        # Name must resolve before changing the installed service.
        socket.getaddrinfo(args.hostname, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        url = f'https://{args.hostname}:{port}'
        changes = [(CONFIG, encoded(config), 0o600, 0, 0)]
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
                probe(args.hostname, port, TLS/'ca.crt')
            def recover():
                activate()
            apply_changes(changes, activate, verify, recover)
        print('Готово: '+url+' — HTTPS и имя сертификата проверены.')
        print('Другие агенты: выполните этот скрипт с --agent-only --hostname '+args.hostname+
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
