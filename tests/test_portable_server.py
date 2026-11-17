"""Portable addressing: real TLS over changing addresses, plus transactional rollback."""
import contextlib
import copy
import errno
import io
import json
from pathlib import Path
import runpy
import socket
import sqlite3
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

    def test_queue_rebind_preserves_pending_events_and_cursors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'queue.sqlite'
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                db.executescript("CREATE TABLE owner(id TEXT PRIMARY KEY); INSERT INTO owner VALUES('old');"
                                 "CREATE TABLE queue(id TEXT PRIMARY KEY,payload TEXT);"
                                 "INSERT INTO queue VALUES('event-1','synthetic');"
                                 "CREATE TABLE cursors(source TEXT PRIMARY KEY,value TEXT);"
                                 "INSERT INTO cursors VALUES('test','cursor-1');")
            rebind = self.m['rebind_queue_file']
            self.assertTrue(rebind(path, 'old', 'new'))
            self.assertFalse(rebind(path, 'old', 'new'))
            with self.assertRaisesRegex(ValueError, 'другой регистрации'):
                rebind(path, 'foreign', 'other')
            self.assertTrue(rebind(path, 'new', 'old'))
            with contextlib.closing(sqlite3.connect(path)) as db, db:
                self.assertEqual(db.execute('SELECT * FROM owner').fetchall(), [('old',)])
                self.assertEqual(db.execute('SELECT * FROM queue').fetchall(), [('event-1', 'synthetic')])
                self.assertEqual(db.execute('SELECT * FROM cursors').fetchall(), [('test', 'cursor-1')])

    def test_previous_backup_requires_same_agent_and_token(self):
        function = self.m['previous_registration']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            current = dict(agent_id='test', token='synthetic', server='https://new.local:8767')
            old = dict(current, server='https://old.local:8767')
            (root/'0').write_text(json.dumps(old))
            (root/'manifest.json').write_text(json.dumps([dict(path=str(self.m['AGENT']),file='0')]))
            with patch('pathlib.Path.lstat') as metadata, \
                 patch.dict(function.__globals__, protected=lambda p:None):
                import stat
                metadata.return_value.st_mode = stat.S_IFDIR | 0o700
                metadata.return_value.st_uid = 0
                self.assertEqual(function(root, current), old)
                with self.assertRaisesRegex(ValueError, 'другой регистрации'):
                    function(root, dict(current, token='different'))

    def test_mdns_plan_preserves_other_settings_and_is_idempotent(self):
        function = self.m['mdns_changes']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nss, allow, avahi = (root/n for n in ('nss', 'allow', 'avahi'))
            nss.write_text('passwd: files\nhosts: files myhostname mdns4_minimal [NOTFOUND=return] dns\n')
            avahi.write_text('[server]\n#host-name=foo\nuse-ipv4=yes\n[wide-area]\nenable-wide-area=yes\n')
            with patch.dict(function.__globals__, NSS=nss, MDNS_ALLOW=allow, AVAHI=avahi,
                            protected=lambda p:p.stat(), run=lambda *a:'active'):
                changes = function('dlp-server.local', server=True)
                self.assertIn(b'hosts: files myhostname mdns4 [NOTFOUND=return] dns', changes[0][1])
                self.assertIn(b'host-name=dlp-server\nuse-ipv4=yes\n[wide-area]', changes[2][1])
                for path, data, *_ in changes:
                    path.write_bytes(data)
                self.assertEqual(function('dlp-server.local', server=True), changes)
                allow.write_text('*\n')
                with self.assertRaisesRegex(ValueError, 'Нестандартный'):
                    function('dlp-server.local')
                allow.unlink()
                nss.write_text('hosts: files dns mdns4_minimal [NOTFOUND=return]\n')
                with self.assertRaisesRegex(ValueError, 'DNS стоит раньше'):
                    function('dlp-server.local')

    def test_mdns_verification_rejects_loopback_and_name_collision(self):
        function = self.m['check_mdns']
        with patch.dict(function.__globals__, run=lambda *a:'127.0.0.200 STREAM'):
            with self.assertRaisesRegex(ValueError, 'loopback'):
                function('dlp-server.local')
        with patch.dict(function.__globals__, run=lambda *a:'s "dlp-server-2.local"'):
            with self.assertRaisesRegex(ValueError, 'конфликт'):
                function('dlp-server.local', server=True)
        with patch.dict(function.__globals__, run=lambda *a:'192.0.2.10 STREAM'):
            function('dlp-server.local')

    def test_rollback_removes_new_mdns_file(self):
        function = self.m['apply_changes']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allow = root/'allow'
            real_mkdtemp = tempfile.mkdtemp
            with patch.dict(function.__globals__, MDNS_ALLOW=allow), \
                 patch('tempfile.mkdtemp', side_effect=lambda **kw:real_mkdtemp(dir=root)), \
                 patch('os.fchown'), contextlib.redirect_stdout(io.StringIO()):
                def fail():
                    self.assertTrue(allow.exists())
                    raise ValueError('failed TLS')
                with self.assertRaisesRegex(ValueError, 'failed TLS'):
                    function([(allow, b'.local\n.local.\n', 0o644, 0, 0)],
                             lambda:None, fail, lambda:None)
            self.assertFalse(allow.exists())
            manifest = json.loads(next(root.glob('*/manifest.json')).read_text())
            self.assertIsNone(manifest[0]['file'])

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
