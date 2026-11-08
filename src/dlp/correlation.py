"""Bounded grouping of repeat access attempts, never evidence of sending."""
from collections import OrderedDict
import time
import uuid


class AccessCorrelator:
    def __init__(self, window=5, capacity=1024, max_duration=30):
        self.window, self.capacity, self.max_duration = window, capacity, max_duration
        self.groups = OrderedDict()

    def observe(self, identity, st):
        if identity is None:
            return {'status': 'access_only', 'group_id': None, 'repeat_count': 1}
        now = time.monotonic()
        # Process IDs are deliberately excluded: one messenger may use multiple
        # processes to open the same file. File version prevents merging edits.
        key = (identity.uid, identity.executable, identity.device, identity.inode,
               st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        previous = self.groups.pop(key, None)
        group, count = (previous[0], previous[1]+1) if previous and 0 <= now-previous[3] < self.window and now-previous[2] < self.max_duration else (uuid.uuid4().hex, 1)
        self.groups[key] = (group, count, previous[2] if count > 1 else now, now)
        while len(self.groups) > self.capacity:
            self.groups.popitem(last=False)
        return {'status': 'access_only', 'group_id': group, 'repeat_count': count, 'operation': True}
