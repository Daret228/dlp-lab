"""Real loopback TLS: system trust remains enabled, no insecure client mode."""
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import URLError
from dlp.central import Forwarder, ServerStore, make_server


@unittest.skipUnless(shutil.which('openssl'), 'openssl required for TLS integration')
class CentralTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certdir = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.certdir.name)/'cert.pem'
        cls.key = Path(cls.certdir.name)/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                        '-keyout',str(cls.key),'-out',str(cls.cert)],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)

    @classmethod
    def tearDownClass(cls):
        cls.certdir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ServerStore(self.root/'server')
        self.server = make_server(self.store, 'synthetic-admin', '127.0.0.1', 0)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert,self.key)
        self.server.socket = context.wrap_socket(self.server.socket,server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        path = self.root/'agent.json'
        self.store.add('synthetic', f'https://localhost:{self.server.server_port}',path)
        self.worker = Forwarder(self.root/'queue',json.loads(path.read_text()))
        self.worker.enqueue([('tls-cursor',{'event':'file_access_attempt','result':{'decision':'BLOCK'},'enforcement':'DENY'})],'system')

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.temp.cleanup()

    def test_unknown_certificate_rejected_then_trusted_delivery(self):
        with patch.dict(os.environ, {'SSL_CERT_FILE':'/nonexistent/dlp-test-ca', 'SSL_CERT_DIR':str(self.root)}):
            with self.assertRaises(URLError):
                self.worker.send()
        self.assertEqual(len(self.store.report()['events']),0)
        with patch.dict(os.environ, {'SSL_CERT_FILE':str(self.cert)}):
            self.assertEqual(self.worker.send(),1)
        event = self.store.report()['events'][0]
        self.assertEqual((event['decision'],event['enforcement']),('BLOCK','DENY'))

    def test_trusted_certificate_wrong_hostname_rejected(self):
        self.worker.config['server'] = f'https://127.0.0.1:{self.server.server_port}'
        with patch.dict(os.environ, {'SSL_CERT_FILE':str(self.cert)}):
            with self.assertRaises(URLError):
                self.worker.send()
        self.assertEqual(len(self.store.report()['events']),0)
