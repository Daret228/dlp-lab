"""Bounded background delivery; all journal writes remain on the main thread."""
import queue
import threading
import time
import uuid
from .notifications import desktop_warning


class FileWarnings:
    def __init__(self, audit, sender=desktop_warning, clock=time.monotonic):
        self.audit, self.sender, self.clock = audit, sender, clock
        self.jobs, self.results = queue.Queue(maxsize=1), queue.Queue(maxsize=4)
        self.last = None
        self.worker = threading.Thread(target=self._work, daemon=True)
        self.worker.start()

    def _work(self):
        while True:
            job = self.jobs.get()
            if job is None:
                return
            try:
                status = self.sender('WARN')
            except Exception:
                status = 'failed'
            self.results.put(dict(job, status=status))

    def drain(self):
        while True:
            try:
                self.audit.emit(self.results.get_nowait())
            except queue.Empty:
                return

    def submit(self, record):
        self.drain()
        result = record.get('result', {})
        advisory = result.get('metadata', {}).get('sensitive_alerts', {})
        if result.get('decision') != 'WARN' or not (advisory.get('categories') or advisory.get('complete') is False):
            return
        event = {'event':'notification_delivery', 'source':'file_sensitive_advisory',
                 'decision':'WARN', 'display_confirmed':False, 'send_blocked':False,
                 'notification_id':uuid.uuid4().hex,
                 'access_group_id':record.get('correlation', {}).get('group_id')}
        now = self.clock()
        if self.last is not None and now-self.last < 10:
            self.audit.emit(dict(event, status='suppressed_rate_limit'))
            return
        try:
            self.jobs.put_nowait(event)
        except queue.Full:
            self.audit.emit(dict(event, status='queue_full'))
            return
        self.last = now
        self.audit.emit(dict(event, status='queued'))

    def close(self):
        # Delivery has a 5s subprocess limit. Never hold fanotify open while waiting.
        self.drain()
        try:
            self.jobs.put(None, timeout=6)
        except queue.Full:
            self.audit.emit({'event':'notification_shutdown', 'status':'unfinished'})
            return
        self.worker.join(timeout=6)
        self.drain()
