"""Linux fanotify consumer; launched after privilege drop by native helper."""
import os
import select
import struct
import time
from dataclasses import asdict
from pathlib import Path
from .models import Decision, FileContent
from .processes import identify
from .correlation import AccessCorrelator

METADATA = struct.Struct("=IBBHQii")
RESPONSE = struct.Struct("=iI")
OPEN_PERM, OVERFLOW = 0x10000, 0x4000
ALLOW, DENY = 1, 2


def events(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < METADATA.size:
            raise ValueError("Truncated fanotify event")
        length, version, _, metadata_len, mask, fd, pid = METADATA.unpack_from(data, offset)
        if version != 3 or not METADATA.size <= metadata_len <= length or length > len(data)-offset:
            raise ValueError("Unsupported fanotify metadata")
        yield mask, fd, pid
        offset += length


def process_event(group_fd, mask, fd, pid, analyzer, audit, process_filter=None, correlator=None, warnings=None, responder=None):
    if fd < 0:
        if mask & OVERFLOW:
            audit.emit({"event": "queue_overflow", "coverage": "lost"})
        return
    began = time.monotonic()
    response = DENY
    record = {"event": "file_access_attempt", "pid": pid, "send_confirmed": False}
    try:
        if mask & OPEN_PERM:
            identity = identify(pid)
            messenger = process_filter.match(identity) if process_filter else None
            record.update(executable=identity.executable if identity else None,
                          process=asdict(identity) if identity else None, messenger=messenger,
                          filter_mode=process_filter.mode if process_filter else "all")
            bypass = process_filter and process_filter.mode == "messengers" and identity is not None and messenger is None
            try:
                record["path"] = os.readlink(f"/proc/self/fd/{fd}")
                st = os.fstat(fd)
                record.update(device=st.st_dev, inode=st.st_ino, size=st.st_size, mtime_ns=st.st_mtime_ns)
                if correlator:
                    record['correlation'] = correlator.observe(identity, st)
                if bypass:
                    from .models import AnalysisResult
                    result = AnalysisResult([], 0, Decision.ALLOW, False, "process_out_of_scope")
                elif process_filter and process_filter.mode == "messengers" and identity is None:
                    result = analyzer.failure("process_identity_unknown")
                else:
                    analysis_start = time.monotonic()
                    result = analyzer.analyze(FileContent(Path(record["path"]), fd))
                    record["analysis_ms"] = round((time.monotonic() - analysis_start) * 1000, 3)
            except OSError:
                result = analyzer.failure("event_metadata_unavailable")
            response = DENY if result.decision == Decision.BLOCK else ALLOW
            record.update(result=asdict(result), enforcement="DENY" if response == DENY else "ALLOW")
    finally:
        try:
            if mask & OPEN_PERM:
                if responder is not None:
                    actual = responder(fd, response)
                    if actual != response:
                        record['enforcement_reason'] = 'broker_deadline_or_overload'
                    record['enforcement'] = 'DENY' if actual == DENY else 'ALLOW'
                elif os.write(group_fd, RESPONSE.pack(fd, response)) != RESPONSE.size:
                    raise OSError("Short fanotify response")
        finally:
            os.close(fd)
    # Respond before potentially blocking audit IO. Audit failure terminates daemon.
    if mask & OPEN_PERM:
        record["worker_elapsed_ms"] = round((time.monotonic() - began) * 1000, 3)
        audit.emit(record)
        if warnings is not None:
            warnings.submit(record)


def run(group_fd, analyzer, audit, process_filter=None):
    if os.environ.get("DLP_FAN_SCOPE") == "local_filesystems":
        from .filesystem_scope import run_filesystems
        return run_filesystems(group_fd, analyzer, audit, process_filter, events, RESPONSE, process_event)
    from .file_notifications import FileWarnings
    warnings = FileWarnings(audit)
    correlator = AccessCorrelator()
    audit.emit({"event": "monitor_started", "pid": os.getpid(), "uid": os.geteuid(), "filter_mode": process_filter.mode if process_filter else "all", "scope": "direct_children", "warn_enforcement": "ALLOW"})
    try:
        while True:
            warnings.drain()
            ready, _, _ = select.select([group_fd], [], [], 1)
            if ready:
                try:
                    data = os.read(group_fd, 65536)
                except BlockingIOError:
                    continue
                if not data:
                    raise OSError("fanotify stream closed")
                for mask, fd, pid in events(data):
                    process_event(group_fd, mask, fd, pid, analyzer, audit, process_filter, correlator, warnings)
    finally:
        # Closing the group releases outstanding operations (kernel fail-open).
        os.close(group_fd)
        warnings.close()
