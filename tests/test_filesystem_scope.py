import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from dlp.fanotify import METADATA, OPEN_PERM, RESPONSE, events, process_event
from dlp.filesystem_scope import PermissionPump, excluded
from dlp.processes import ProcessFilter, ProcessIdentity
from dlp.analysis import ContentAnalyzer
from dlp.policy import load_policy
from dlp.audit import JsonAudit
from dlp.dashboard import project

ROOT = Path(__file__).resolve().parents[1]


class FilesystemScopeTests(unittest.TestCase):
    def setUp(self):
        self.reader, self.kernel = socket.socketpair()
        self.kernel.settimeout(2)
        st = Path('/usr/bin/cat').stat()
        self.identity = ProcessIdentity(123456, os.getuid(), '/usr/bin/cat', 1, st.st_dev, st.st_ino)
        self.filter = ProcessFilter({'mode':'messengers', 'uid':os.getuid(),
                                    'messengers':{'test':{'enabled':True,'executables':['/usr/bin/cat']}}})
        self.pump = PermissionPump(self.reader.fileno(), self.filter, events, RESPONSE, capacity=1)
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'nested'/'outside-watch.txt'
        self.path.parent.mkdir()
        self.path.write_text('top secret')

    def tearDown(self):
        self.pump.stop.set()
        if self.pump.thread.is_alive():
            self.pump.thread.join(2)
        while not self.pump.jobs.empty():
            os.close(self.pump.jobs.get_nowait()[1])
        self.reader.close()
        self.kernel.close()
        self.tmp.cleanup()

    def send(self, pid):
        fd = os.open(self.path, os.O_RDONLY)
        os.write(self.kernel.fileno(), METADATA.pack(METADATA.size, 3, 0, METADATA.size, OPEN_PERM, fd, pid))
        return fd

    def test_no_global_all_mode(self):
        self.filter.mode = 'all'
        with self.assertRaises(ValueError):
            PermissionPump(self.reader.fileno(), self.filter, events, RESPONSE)

    def test_unrelated_open_progresses_while_target_waits(self):
        with patch('dlp.filesystem_scope.identify', return_value=self.identity):
            self.pump.thread.start()
            target = self.send(123456)
            event = self.pump.jobs.get(timeout=2)
            # The analyzer may be waiting for a parser/library open. Pump must
            # answer it without waiting for analysis or its audit output.
            own = self.send(os.getpid())
            self.assertEqual(RESPONSE.unpack(self.kernel.recv(8)), (own, 1))
            audit = io.StringIO()
            analyzer = ContentAnalyzer(load_policy(ROOT/'config/policy.yaml'))
            with patch('dlp.fanotify.identify', return_value=self.identity):
                process_event(self.reader.fileno(), *event, analyzer, JsonAudit(audit), self.filter)
            self.assertEqual(RESPONSE.unpack(self.kernel.recv(8)), (target, 2))
            self.assertFalse(json.loads(audit.getvalue())['send_confirmed'])

    def test_queue_overload_denies_target_without_stalling_pump(self):
        with patch('dlp.filesystem_scope.identify', return_value=self.identity):
            fd1 = os.open(self.path, os.O_RDONLY)
            fd2 = os.open(self.path, os.O_RDONLY)
            self.pump.dispatch(OPEN_PERM, fd1, 123456)
            self.pump.dispatch(OPEN_PERM, fd2, 123456)
            self.assertEqual(RESPONSE.unpack(self.kernel.recv(8)), (fd2, 2))
            self.assertEqual(self.pump.counts['analysis_queue_denied'], 1)
            with self.assertRaises(OSError):
                os.fstat(fd2)

    def test_unknown_identity_is_unchecked_not_system_denial(self):
        with patch('dlp.filesystem_scope.identify', return_value=None):
            fd = os.open(self.path, os.O_RDONLY)
            self.pump.dispatch(OPEN_PERM, fd, 123456)
            self.assertEqual(RESPONSE.unpack(self.kernel.recv(8)), (fd, 1))
            self.assertEqual(self.pump.counts['identity_unknown_allowed'], 1)

    def test_other_process_is_not_analyzed(self):
        self.filter.uid += 1
        with patch('dlp.filesystem_scope.identify', return_value=self.identity):
            fd = os.open(self.path, os.O_RDONLY)
            self.pump.dispatch(OPEN_PERM, fd, 123456)
            self.assertEqual(RESPONSE.unpack(self.kernel.recv(8)), (fd, 1))
            self.assertTrue(self.pump.jobs.empty())

    def test_runtime_exclusion_and_path_boundaries(self):
        self.assertTrue(excluded('/usr/lib/test'))
        self.assertTrue(excluded('/home/roman/.local/share/TelegramDesktop/tdata/map (deleted)'))
        self.assertFalse(excluded('/usr-other/file'))
        self.assertFalse(excluded('/home/roman/Documents/sub/file.docx'))
        self.assertFalse(excluded('/var/lib/dlp-lab/watch/test'))
        with patch('dlp.filesystem_scope.identify', return_value=self.identity), \
             patch('dlp.filesystem_scope.os.readlink', return_value='/usr/lib/library'):
            fd = os.open(self.path, os.O_RDONLY)
            self.pump.dispatch(OPEN_PERM, fd, 123456)
            self.assertEqual(RESPONSE.unpack(self.kernel.recv(8)), (fd, 1))
            self.assertEqual(self.pump.counts['runtime_excluded'], 1)

    def test_overflow_marks_coverage_loss(self):
        self.pump.dispatch(0x4000, -1, 0)
        self.assertEqual(self.pump.counts['kernel_overflow'], 1)

    def test_dashboard_scope_exposes_only_configured_paths(self):
        event = project({'MESSAGE':json.dumps({'event':'monitor_started', 'timestamp':'2026-10-18',
                         'scope':'local_filesystems', 'filesystem_roots':['/data'], 'path':'/private/accessed.txt'})})
        self.assertEqual(event['scope'], 'local_filesystems')
        self.assertEqual(event['filesystem_roots'], ['/data'])
        self.assertNotIn('/private/accessed.txt', json.dumps(event))

class BrokerProtocolTests(unittest.TestCase):
    def test_descriptor_token_is_translated_and_closed_on_reject(self):
        import array
        from dlp.filesystem_scope import BrokerTransport
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        transport = BrokerTransport(left.detach())
        fd = os.open(ROOT/'examples/public.txt', os.O_RDONLY)
        packet = transport.PACKET.pack(OPEN_PERM, 871, 123)
        rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]).tobytes())]
        try:
            with patch.object(BrokerTransport, 'PACKET', transport.PACKET), \
                 patch('dlp.filesystem_scope.socket.socket.recvmsg', return_value=(packet, rights, 0, None)):
                self.assertEqual(transport.receive(), (OPEN_PERM, fd, 123))
            transport.respond(fd, 2, wait=False)
            self.assertEqual(RESPONSE.unpack(os.read(right.fileno(), 8)), (871, 2))
            self.assertFalse(transport.tokens)
        finally:
            os.close(fd)
            transport.socket.close()
            right.close()

    def test_truncated_packet_closes_received_descriptor(self):
        import array
        from dlp.filesystem_scope import BrokerTransport
        left, right = socket.socketpair()
        transport = BrokerTransport(left.detach())
        fd = os.open(ROOT/'examples/public.txt', os.O_RDONLY)
        rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]).tobytes())]
        try:
            with patch('dlp.filesystem_scope.socket.socket.recvmsg', return_value=(b'x', rights, socket.MSG_TRUNC, None)):
                with self.assertRaises(OSError):
                    transport.receive()
            with self.assertRaises(OSError):
                os.fstat(fd)
        finally:
            transport.socket.close()
            right.close()

    def test_confirmed_denial_overrides_analyzer_allow(self):
        analyzer = ContentAnalyzer(load_policy(ROOT/'config/policy.yaml'))
        fd = os.open(ROOT/'examples/public.txt', os.O_RDONLY)
        stream = io.StringIO()
        process_event(-1, OPEN_PERM, fd, os.getpid(), analyzer, JsonAudit(stream),
                      responder=lambda fd, decision: 2)
        record = json.loads(stream.getvalue())
        self.assertEqual(record['result']['decision'], 'ALLOW')
        self.assertEqual(record['enforcement'], 'DENY')
        self.assertEqual(record['enforcement_reason'], 'broker_deadline_or_overload')

    def test_missing_enforcement_ack_is_not_logged_as_success(self):
        analyzer = ContentAnalyzer(load_policy(ROOT/'config/policy.yaml'))
        fd = os.open(ROOT/'examples/public.txt', os.O_RDONLY)
        stream = io.StringIO()
        def fail(fd, decision):
            raise OSError('no acknowledgment')
        with self.assertRaises(OSError):
            process_event(-1, OPEN_PERM, fd, os.getpid(), analyzer, JsonAudit(stream), responder=fail)
        self.assertEqual(stream.getvalue(), '')
        with self.assertRaises(OSError):
            os.fstat(fd)
