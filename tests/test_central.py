import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from dlp.central import ServerStore, Forwarder, connect, make_server, project, endpoint


class CentralTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ServerStore(self.root / 'server')
        self.server = make_server(self.store, 'test-admin', '127.0.0.1', 0)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.configs = []
        for name in ('one', 'two'):
            path = self.root / (name + '.json')
            self.store.add(name, self.url, path)
            self.configs.append(json.loads(path.read_text()))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def worker(self, index=0):
        return Forwarder(self.root / ('queue' + str(index)), self.configs[index])

    def event(self):
        return {'event': 'analysis', 'timestamp': '2026-10-27T10:00:00+00:00',
                'text': 'do not transmit', 'path': '/private/example',
                'result': {'decision': 'BLOCK', 'complete': True,
                           'findings': [{'category': 'credentials', 'metadata': {'password': 'hidden'}}]}}

    def test_two_agents_deduplication_and_privacy(self):
        for index in (0, 1):
            worker = self.worker(index)
            worker.enqueue([('cursor-one', self.event())], 'user')
            self.assertEqual(worker.send(), 1)
            # Replay after lost acknowledgement / local queue replay.
            worker.enqueue([('cursor-one', self.event())], 'user')
            self.assertEqual(worker.send(), 1)
        report = self.store.report()
        self.assertEqual(len(report['events']), 2)
        self.assertEqual(len({r['agent'] for r in report['events']}), 2)
        self.assertTrue(all(r['last_seen'] for r in report['agents']))
        output = json.dumps(report)
        for secret in ('do not transmit', '/private/example', 'hidden', 'password', 'token'):
            self.assertNotIn(secret, output)
        self.assertNotIn('send_blocked', report['events'][0])

    def test_offline_queue_survives_restart(self):
        worker = self.worker()
        worker.enqueue([('cursor-one', self.event())], 'user')
        worker.config = {**worker.config, 'token': 'invalid'}
        with self.assertRaises(HTTPError):
            worker.send()
        restarted = self.worker()
        self.assertEqual(restarted.send(), 1)
        self.assertEqual(restarted.send(), 0)
        self.assertEqual(len(self.store.report()['events']), 1)

    def test_auth_separation_and_malformed_payload(self):
        for token in ('', self.configs[0]['token']):
            with self.assertRaises(HTTPError) as error:
                urlopen(Request(self.url + '/api/report', headers={'Authorization': 'Bearer ' + token}))
            self.assertEqual(error.exception.code, 401)
        with urlopen(Request(self.url + '/api/report', headers={'Authorization': 'Bearer test-admin'})) as response:
            self.assertEqual(len(json.load(response)['agents']), 2)
        for payload in ({'event': 'analysis', 'text': 'private'}, {'event': []},
                        {'event': 'analysis', 'categories': None}):
            request = Request(self.url + '/api/events', data=json.dumps([{'id': 'a'*64, 'payload': payload}]).encode(),
                              headers={'Authorization': 'Bearer ' + self.configs[0]['token']})
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, 400)
        self.assertEqual(self.store.report()['events'], [])

    def test_queue_limit_rolls_back_cursor(self):
        worker = self.worker()
        with connect(worker.state) as db:
            db.executemany('INSERT INTO queue VALUES(?,?)', [(str(i), '{}') for i in range(10000)])
        with self.assertRaises(ValueError):
            worker.enqueue([('new-cursor', self.event())], 'user')
        with connect(worker.state) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM cursors').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0], 10000)

    def test_transport_and_signal_aggregate(self):
        for url in ('http://example.com', 'https://user:pass@example.com', 'https://example.com/path'):
            with self.assertRaises(ValueError):
                endpoint(url)
        worker = self.worker()
        worker.enqueue([('s', {'event': 'signal_local_analysis_summary', 'analyzed': 2,
                              'decisions': {'ALLOW': 1, 'BLOCK': 1}, 'key': 'private'})], 'user')
        self.assertEqual(worker.send(), 1)
        event = self.store.report()['events'][0]
        self.assertEqual(event['decisions'], {'ALLOW': 1, 'BLOCK': 1})
        self.assertNotIn('decision', event)
        self.assertIsNone(project({'event': []}))

    def test_connection_failure_and_queue_binding(self):
        worker = self.worker()
        worker.enqueue([('cursor-offline', self.event())], 'user')
        with patch('dlp.central.build_opener') as opener:
            opener.return_value.open.side_effect = OSError('offline')
            with self.assertRaises(OSError):
                worker.send()
        with self.assertRaises(ValueError):
            Forwarder(worker.state, self.configs[1])
        self.assertEqual(self.worker().send(), 1)

    def test_revocation_retains_history(self):
        from dlp.central import main
        worker = self.worker()
        worker.enqueue([('cursor-revoke', self.event())], 'user')
        worker.send()
        self.assertEqual(main(['revoke-agent', '--state', str(self.root/'server'),
                               '--id', self.configs[0]['agent_id']]), 0)
        with self.assertRaises(HTTPError):
            worker.send()
        self.assertEqual(len(self.store.report()['events']), 1)
