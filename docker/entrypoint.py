"""Unprivileged central-only entry point. State persists in a private volume."""
import os
from pathlib import Path
import ssl
import sys
from urllib.request import urlopen
from dlp.central import main, private_dir, read_config

STATE = Path('/var/lib/dlp-central')
TLS_DIR = Path('/run/tls')
PORT = 8766
TLS_HOST = os.environ.get('DLP_TLS_HOST', '0.0.0.0')
TLS_PORT = int(os.environ.get('DLP_TLS_PORT', '8766'))


def run(argv):
    os.umask(0o077)
    action = argv[0] if argv else 'serve'
    if action == 'serve-local':
        # Migration companion: never expose the unencrypted endpoint on the LAN.
        if len(argv) != 1:
            raise ValueError('serve-local takes no arguments')
        return main(['serve', '--state', str(STATE), '--host', '127.0.0.1', '--port', str(PORT)])
    if action == 'health-local':
        with urlopen(f'http://127.0.0.1:{PORT}/', timeout=3) as reply:
            return 0 if reply.status == 200 else 1
    if action == 'health':
        # Liveness only: certificate identity is checked by external clients.
        host = '127.0.0.1' if TLS_HOST == '0.0.0.0' else TLS_HOST
        with urlopen(f'https://{host}:{TLS_PORT}/', context=ssl._create_unverified_context(), timeout=3) as reply:
            return 0 if reply.status == 200 else 1
    if action == 'admin-token':
        print(read_config(STATE / 'admin.json')['token'])
        return 0
    if action == 'serve':
        if len(argv) > 1:
            raise ValueError('serve takes no arguments')
        for name in ('server.crt', 'server.key'):
            if not (TLS_DIR / name).is_file():
                raise ValueError('Mount readable server.crt and server.key in /run/tls')
        private_dir(STATE)
        if not (STATE / 'admin.json').exists():
            if (STATE / 'state.sqlite').exists():
                raise ValueError('Existing database has no admin token; restore its admin.json')
            if main(['init', '--state', str(STATE)]):
                return 2
        return main(['serve', '--state', str(STATE), '--host', TLS_HOST,
                     '--port', str(TLS_PORT), '--cert', str(TLS_DIR / 'server.crt'), '--key', str(TLS_DIR / 'server.key')])
    if action in ('add-agent', 'revoke-agent'):
        if any(arg == '--state' or arg.startswith('--state=') for arg in argv):
            raise ValueError('State path is fixed in this container')
        return main([action, '--state', str(STATE), *argv[1:]])
    raise ValueError('Use serve, admin-token, add-agent, revoke-agent or health')


if __name__ == '__main__':
    try:
        sys.exit(run(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print('Central container: ' + str(error), file=sys.stderr)
        sys.exit(2)
