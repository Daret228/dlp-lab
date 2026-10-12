import json
from datetime import datetime, timezone


class JsonAudit:
    def __init__(self, stream):
        self.stream = stream

    def emit(self, event):
        self.stream.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), **event}, ensure_ascii=False) + "\n")
        self.stream.flush()
