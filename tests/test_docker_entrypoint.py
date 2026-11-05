"""Exercise container entrypoint with temporary state, TLS and a real collector."""
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from dlp.central import Forwarder

ENTRY = Path(__file__).resolve().parents[1] / 'docker/entrypoint.py'


class DockerEntryTests(unittest.TestCase):
    def test_https_delivery_restart_and_admin_token(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(root/'server.key'), '-out', str(root/'server.crt'),
                            '-days', '1', '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=IP:127.0.0.1'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            runner = """import runpy,sys
from pathlib import Path
f=runpy.run_path(sys.argv[1])['run']
f.__globals__.update(STATE=Path(sys.argv[2]), TLS_DIR=Path(sys.argv[3]), PORT=int(sys.argv[4]))
sys.exit(f(['serve']))
"""
            args = [sys.executable, '-c', runner, str(ENTRY), str(root/'state'), str(root), str(port)]
            context = ssl.create_default_context(cafile=str(root/'server.crt'))
            url = f'https://127.0.0.1:{port}'
            def start():
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        if process.poll() is not None:
                            self.fail('Entrypoint exited before readiness')
                        try:
                            with urlopen(url, context=context, timeout=.2) as reply:
                                self.assertIn(b'<html', reply.read().lower())
                            return process
                        except (OSError, URLError):
                            time.sleep(.05)
                    self.fail('Entrypoint did not become ready')
                except BaseException:
                    process.terminate(); process.wait(timeout=5)
                    raise
            process = start()
            try:
                token = json.loads((root/'state/admin.json').read_text())['token']
                with self.assertRaises(HTTPError) as failure:
                    urlopen(url+'/api/report', context=context)
                self.assertEqual(failure.exception.code, 401)
                run = runpy.run_path(str(ENTRY))['run']
                run.__globals__.update(STATE=root/'state', PORT=port)
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(run(['admin-token']), 0)
                self.assertEqual(output.getvalue().strip(), token)
                self.assertEqual(run(['health']), 0)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(run(['add-agent', '--name', 'synthetic-device', '--server', url,
                                          '--out', str(root/'agent.json')]), 0)
                config = json.loads((root/'agent.json').read_text())
                worker = Forwarder(root/'queue', config)
                worker.enqueue([('synthetic-cursor', {'event': 'analysis', 'result': {'decision': 'WARN', 'score': .5, 'complete': True}})], 'system')
                with patch.dict(os.environ, {'SSL_CERT_FILE': str(root/'server.crt')}):
                    self.assertEqual(worker.send(), 1)
                process.terminate(); process.wait(timeout=5)
                process = start()
                self.assertEqual(json.loads((root/'state/admin.json').read_text())['token'], token)
                request = Request(url+'/api/report', headers={'Authorization': 'Bearer '+token})
                with urlopen(request, context=context) as reply:
                    report = json.load(reply)
                self.assertEqual(len(report['agents']), 1)
                self.assertEqual(len(report['events']), 1)
            finally:
                process.terminate(); process.wait(timeout=5)

    def test_reject_unknown_commands_and_missing_certificates(self):
        run = runpy.run_path(str(ENTRY))['run']
        with self.assertRaises(ValueError):
            run(['shell'])
        with self.assertRaises(ValueError):
            run(['add-agent', '--state=/tmp/other'])
        with tempfile.TemporaryDirectory() as directory:
            run.__globals__['TLS_DIR'] = Path(directory)
            with self.assertRaises(ValueError):
                run(['serve'])
