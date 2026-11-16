"""Portable addressing: real TLS over changing addresses, plus transactional rollback."""
import contextlib
import copy
import errno
import io
import json
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from dlp.central import ServerStore, make_server, main as central_main

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/configure-portable-server.py'


class PortablePlanTests(unittest.TestCase):
    def setUp(self):
        self.m = runpy.run_path(str(SCRIPT))

    def test_binding_changes_without_touching_local_server_or_state(self):
        original = {'services': {
            'local': {'network_mode': 'host', 'command': ['serve-local'], 'volumes': ['state']},
            'https': {'network_mode': 'host', 'volumes': [str(self.m['TLS'])+':/run/tls:ro'],
                      'environment': {'DLP_TLS_HOST': '192.0.2.45', 'DLP_TLS_PORT': '8767'}}}}
        before = copy.deepcopy(original)
        changed, port = self.m['portable_compose'](original)
        self.assertEqual(original, before)
        self.assertEqual(changed['services']['local'], original['services']['local'])
        self.assertEqual(changed['services']['https']['environment']['DLP_TLS_HOST'], '0.0.0.0')
        self.assertEqual(port, 8767)
        original['services']['https']['network_mode'] = 'bridge'
        with self.assertRaises(ValueError):
            self.m['portable_compose'](original)

    def test_only_dns_names_and_valid_labels(self):
        self.assertEqual(self.m['hostname']('Debian.LOCAL.'), 'debian.local')
        for invalid in ('192.0.2.45', 'localhost', '*.local', 'bad/name.local',
                        'foo.local\nsubjectAltName=DNS:evil', '-x.local', 'a..local'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.m['hostname'](invalid)

    def test_registration_changes_only_server(self):
        data = dict(server='https://192.0.2.45:8767', token='synthetic', agent_id='test', version=1)
        updated = self.m['changed_registration'](data, 'https://lab.test:8767')
        self.assertEqual({k:v for k,v in data.items() if k!='server'},
                         {k:v for k,v in updated.items() if k!='server'})
        self.assertEqual(data['server'], 'https://192.0.2.45:8767')

    def test_transaction_restores_files_and_permissions_on_failed_health(self):
        function = self.m['apply_changes']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root/'config.json'; config.write_text('before'); config.chmod(0o640)
            original_info = config.stat()
            real_mkdtemp = tempfile.mkdtemp
            def backup(**kwargs):
                return real_mkdtemp(prefix='backup-', dir=root)
            # Production enforces root ownership; tests keep files under the test UID.
            with patch.dict(function.__globals__, protected=lambda p:p.stat()), \
                 patch('tempfile.mkdtemp', side_effect=backup), patch('os.fchown'), \
                 contextlib.redirect_stdout(io.StringIO()):
                actions = []
                def fail():
                    self.assertEqual(config.read_bytes(), b'after')
                    raise ValueError('synthetic health failure')
                with self.assertRaisesRegex(ValueError, 'synthetic health'):
                    function([(config, b'after', 0o600, 0, 0)],
                             lambda:actions.append('activate'), fail,
                             lambda:actions.append('recover'))
            self.assertEqual(actions, ['activate', 'recover'])
            self.assertEqual(config.read_text(), 'before')
            self.assertEqual(config.stat().st_mode, original_info.st_mode)
            saved = next(root.glob('backup-*'))
            self.assertEqual((saved/'0').read_text(), 'before')
            self.assertEqual(saved.stat().st_mode & 0o777, 0o700)

    def test_agent_connection_copy_preserves_ca_and_identity(self):
        function = self.m['agent_changes']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = root/'agent'; connection = root/'connection'
            value = dict(server='https://192.0.2.1:8767', agent_id='test', token='synthetic')
            agent.write_text(json.dumps(value))
            connection.write_text(json.dumps({'registration':value, 'ca':'synthetic CA'}))
            with patch.dict(function.__globals__, AGENT=agent, CONNECTION=connection,
                            protected=lambda p:p.stat()):
                changes = function('https://lab.test:8767')
            result = json.loads(changes[1][1])
            self.assertEqual(result['ca'], 'synthetic CA')
            self.assertEqual(result['registration']['token'], 'synthetic')
            self.assertEqual(result['registration']['server'], 'https://lab.test:8767')
            self.assertEqual(json.loads(agent.read_text()), value)

    def test_os_diagnostic_has_errno_without_sensitive_exception_text(self):
        with patch('dlp.central.ServerStore', side_effect=OSError(errno.EADDRNOTAVAIL, 'private-data')), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(central_main(['serve', '--state', '/unused']), 2)
        self.assertIn(str(errno.EADDRNOTAVAIL), output.getvalue())
        self.assertNotIn('private-data', output.getvalue())


class PortableTLSTests(unittest.TestCase):
    def test_same_dns_certificate_survives_address_change_and_rejects_wrong_name(self):
        m = runpy.run_path(str(SCRIPT))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca, ca_key = root/'ca.crt', root/'ca.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-days', '2', '-subj', '/CN=Synthetic CA',
                            '-addext', 'basicConstraints=critical,CA:TRUE',
                            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                            '-keyout', str(ca_key), '-out', str(ca)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ca_before = ca.read_bytes()
            cert, key = m['issue_certificate'](root, 'lab.test', ca, ca_key)
            self.assertEqual(ca.read_bytes(), ca_before)
            store = ServerStore(root/'state')
            server = make_server(store, 'synthetic-admin', '0.0.0.0', 0)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            resolve = socket.getaddrinfo
            try:
                # Simulate DNS moving between two addresses; the listener/cert stay unchanged.
                for address in ('127.0.0.1', '127.0.0.2'):
                    def resolved(host, port, *args, **kwargs):
                        return resolve(address if host == 'lab.test' else host, port, *args, **kwargs)
                    with patch('socket.getaddrinfo', side_effect=resolved):
                        m['probe']('lab.test', server.server_port, ca)
                with self.assertRaises(ssl.SSLCertVerificationError):
                    m['probe']('wrong.test', server.server_port, ca, '127.0.0.1')
                with self.assertRaises(ssl.SSLCertVerificationError):
                    m['probe']('127.0.0.1', server.server_port, ca, '127.0.0.1')
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
