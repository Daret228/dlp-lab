"""Bounded grouping of repeat access attempts, never evidence of sending."""
from collections import OrderedDict
import time
import uuid


class AccessCorrelator:
    def __init__(self, window=5, capacity=1024):
        self.window, self.capacity = window, capacity
        self.groups = OrderedDict()

    def observe(self, identity, st):
        if identity is None:
            return {'status': 'access_only', 'group_id': None, 'repeat_count': 1}
        now = time.monotonic()
        key = (identity.uid, identity.pid, identity.start_ticks, st.st_dev, st.st_ino)
        previous = self.groups.pop(key, None)
        group, count = (previous[0], previous[1]+1) if previous and now-previous[2] <= self.window else (uuid.uuid4().hex, 1)
        self.groups[key] = (group, count, now)
        while len(self.groups) > self.capacity:
            self.groups.popitem(last=False)
        return {'status': 'access_only', 'group_id': group, 'repeat_count': count}
