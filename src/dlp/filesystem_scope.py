"""Scope and event pump for filesystem marks; content analysis stays on main thread.

The pump only opens /proc metadata, never watched files. In particular it must
not log to disk or import modules while answering permission requests.
"""
import os
import array
import socket
import struct
import time
import queue
import select
import threading
from .processes import identify

# Explicit operational exceptions, not a claim that these locations cannot leak.
# Match the path supplied by the event FD, never the caller's symlink spelling.
EXCLUDED_ROOTS = (
    '/usr', '/opt', '/etc', '/bin', '/sbin', '/lib', '/lib64',
    '/home/roman/.cache',
    '/home/roman/.local/share/TelegramDesktop',
    '/home/roman/.config', '/home/roman/.local/share/fonts', '/home/roman/.fonts',
)


def excluded(path):
    if path.endswith(' (deleted)'):
        path = path[:-10]
    return any(path == root or path.startswith(root + '/') for root in EXCLUDED_ROOTS)


class PermissionPump:
    def __init__(self, group_fd, process_filter, events, response, capacity=128, transport=None):
        if process_filter is None or process_filter.mode != 'messengers':
            raise ValueError('Filesystem scope requires mode=messengers; all is unsafe here')
        self.fd, self.process_filter = group_fd, process_filter
        self.events, self.response = events, response
        self.transport = transport
        self.jobs = queue.Queue(maxsize=capacity)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True, name='fanotify-pump')
        self.error = None
        self.counts = {'unrelated_allowed': 0, 'identity_unknown_allowed': 0,
                       'runtime_excluded': 0, 'analysis_queue_denied': 0, 'kernel_overflow': 0}

    def answer(self, mask, fd, decision):
        try:
            if mask & 0x10000:
                if self.transport is not None:
                    self.transport.respond(fd, decision, wait=False)
                else:
                    data = self.response.pack(fd, decision)
                    if os.write(self.fd, data) != len(data):
                        raise OSError('Short permission response')
        finally:
            os.close(fd)

    def dispatch(self, mask, fd, pid):
        if fd < 0:
            if mask & 0x4000:
                self.counts['kernel_overflow'] += 1
            if mask & 0x20000000:
                self.counts['identity_unknown_allowed'] += 1
            if mask & 0x10000000:
                self.counts['analysis_queue_denied'] += 1
            return
        owned = True
        try:
            if not mask & 0x10000:
                return
            if pid == os.getpid():
                self.counts['unrelated_allowed'] += 1
                return
            identity = identify(pid)
            if identity is None:
                # Never deny arbitrary system activity when /proc is inaccessible.
                # This is an explicit coverage gap, not successful inspection.
                self.counts['identity_unknown_allowed'] += 1
                return
            if self.process_filter.match(identity) is None:
                self.counts['unrelated_allowed'] += 1
                return
            try:
                path = os.readlink(f'/proc/self/fd/{fd}')
            except OSError:
                path = ''  # Selected target: let analyzer's on_error decide.
            if excluded(path):
                self.counts['runtime_excluded'] += 1
                return
            try:
                self.jobs.put_nowait((mask, fd, pid))
                owned = False
            except queue.Full:
                owned = False
                self.answer(mask, fd, 2)
                self.counts['analysis_queue_denied'] += 1
        finally:
            if owned:
                self.answer(mask, fd, 1)

    def run(self):
        try:
            while not self.stop.is_set():
                ready, _, _ = select.select([self.fd], [], [], .2)
                if not ready:
                    continue
                try:
                    data = None if self.transport else os.read(self.fd, 65536)
                except BlockingIOError:
                    continue
                if self.transport:
                    batch = [self.transport.receive()]
                else:
                    if not data:
                        raise OSError('fanotify stream closed')
                    batch = self.events(data)
                for event in batch:
                    self.dispatch(*event)
        except BaseException as exc:
            self.error = exc


class BrokerTransport:
    PACKET = struct.Struct('=Qii')
    ANSWER = struct.Struct('=iI')

    def __init__(self, fd):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET, 0, fileno=fd)
        self.tokens = {}
        self.condition = threading.Condition()
        self.acks = {}

    def receive(self):
        raw, ancillary, flags, _ = self.socket.recvmsg(self.PACKET.size, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        fds = []
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array('i')
                values.frombytes(data[:len(data) - len(data) % values.itemsize])
                fds.extend(values)
        try:
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(raw) != self.PACKET.size:
                raise OSError('Invalid broker packet')
            mask, token, pid = self.PACKET.unpack(raw)
            if mask == 0x40000000 and token > 0 and not fds and pid in (1, 2):
                with self.condition:
                    if token in self.acks:
                        self.acks[token] = pid
                        self.condition.notify_all()
                return 0, -1, 0
            if token < 0 and not fds:
                return mask, -1, pid
            if token <= 0 or len(fds) != 1:
                raise OSError('Invalid broker descriptor')
            fd = fds[0]
            self.tokens[fd] = token
            return mask, fd, pid
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise

    def respond(self, fd, decision, wait=True):
        token = self.tokens.pop(fd)
        with self.condition:
            if wait:
                self.acks[token] = None
        try:
            data = self.ANSWER.pack(token, decision)
            if os.write(self.socket.fileno(), data) != len(data):
                raise OSError('Short broker response')
            if wait:
                with self.condition:
                    if not self.condition.wait_for(lambda: self.acks[token] is not None, timeout=5):
                        raise OSError('Broker enforcement not confirmed')
                    return self.acks[token]
            return decision
        finally:
            with self.condition:
                self.acks.pop(token, None)


def run_filesystems(group_fd, analyzer, audit, process_filter, events, response, process_event):
    from .file_notifications import FileWarnings
    from .correlation import AccessCorrelator
    transport = BrokerTransport(group_fd)
    pump = PermissionPump(group_fd, process_filter, events, response, transport=transport)
    warnings = FileWarnings(audit)
    correlator = AccessCorrelator()
    os.set_inheritable(group_fd, False)
    try:
        os.write(group_fd, b'R')
        if not select.select([group_fd], [], [], 15)[0] or os.read(group_fd, 1) != b'A':
            raise OSError('Filesystem marks were not confirmed')
        pump.thread.start()
        audit.emit({'event': 'monitor_started', 'pid': os.getpid(), 'uid': os.geteuid(),
                    'filter_mode': 'messengers', 'scope': 'local_filesystems',
                    'broker': 'fixed_telegram_uid_1000',
                    'filesystem_roots': os.environ['DLP_FS_ROOTS'].splitlines(),
                    'excluded_roots': list(EXCLUDED_ROOTS), 'new_mounts': 'restart_required',
                    'broker_deadline_seconds': 30,
                    'identity_unknown': 'ALLOW_unchecked', 'warn_enforcement': 'ALLOW'})
        previous = dict(pump.counts)
        last_report = time.monotonic()
        while True:
            if pump.error is not None:
                raise OSError('Permission pump failed') from pump.error
            warnings.drain()
            try:
                event = pump.jobs.get(timeout=.5)
            except queue.Empty:
                event = None
            if event:
                process_event(group_fd, *event, analyzer, audit, process_filter, correlator, warnings,
                              responder=transport.respond)
            counts = dict(pump.counts)
            significant = ('identity_unknown_allowed', 'analysis_queue_denied', 'kernel_overflow')
            if time.monotonic() - last_report >= 5 and any(counts[k] != previous[k] for k in significant):
                audit.emit({'event': 'filesystem_coverage', 'counts': counts, 'coverage': 'degraded'})
                previous, last_report = counts, time.monotonic()
    finally:
        pump.stop.set()
        if pump.thread.is_alive():
            pump.thread.join(timeout=2)
        while True:
            try:
                _, fd, _ = pump.jobs.get_nowait()
                os.close(fd)
            except queue.Empty:
                break
        transport.socket.close()  # Broker denies pending accesses and releases marks.
        warnings.close()
