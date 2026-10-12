"""Explicit single-chat exports only; never opens tdata or attachment paths."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat

from .models import NormalizedMessage, TextContent


MAX_EXPORT_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10_000


class ExportError(ValueError):
    """Messages must contain fixed diagnostics, never input values."""


@dataclass(frozen=True)
class TelegramExport:
    messages: tuple[NormalizedMessage, ...]
    records: int
    service_records: int


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExportError("Duplicate JSON key in export")
        result[key] = value
    return result


def _invalid_constant(_):
    raise ExportError("Nonstandard JSON number in export")


def _text(value):
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        raise ExportError("Expected text string or entity array")
    parts = []
    for part in value:
        if isinstance(part, str):
            parts.append(part)
        elif (isinstance(part, dict) and isinstance(part.get("type"), str)
              and isinstance(part.get("text"), str)):
            parts.append(part["text"])
        else:
            raise ExportError("Invalid text entity in export")
    # Formatting may split a sensitive phrase in the middle of a word.
    return "".join(parts)


def _timestamp(record):
    raw = record.get("date_unixtime")
    if raw is not None:
        if not isinstance(raw, str) or not raw.isascii() or not raw.isdecimal():
            raise ExportError("Invalid date_unixtime in export")
        try:
            return datetime.fromtimestamp(int(raw), timezone.utc).isoformat(), "utc"
        except (ValueError, OverflowError, OSError):
            raise ExportError("Out-of-range date_unixtime in export") from None
    raw = record.get("date")
    if not isinstance(raw, str) or "T" not in raw:
        raise ExportError("Missing or invalid message date")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        raise ExportError("Invalid message date") from None
    if parsed.tzinfo is None:
        return parsed.isoformat(), "unspecified"
    return parsed.astimezone(timezone.utc).isoformat(), "utc"


def normalize_export(data):
    if (not isinstance(data, dict) or "chats" in data or "left_chats" in data
            or type(data.get("id")) is not int
            or not isinstance(data.get("type"), str)
            or not isinstance(data.get("messages"), list)):
        raise ExportError("Expected JSON export of one chat, not an account export")
    records = data["messages"]
    if len(records) > MAX_RECORDS:
        raise ExportError("Export exceeds message count limit")
    messages = []
    service_records = 0
    ids = set()
    for ordinal, record in enumerate(records, 1):
        if not isinstance(record, dict) or type(record.get("id")) is not int:
            raise ExportError("Invalid message record")
        if record["id"] in ids:
            raise ExportError("Duplicate message ID in export")
        ids.add(record["id"])
        kind = record.get("type")
        if kind == "service":
            service_records += 1
            continue
        if kind != "message":
            raise ExportError("Unsupported message record type")
        text = _text(record.get("text"))
        timestamp, time_basis = _timestamp(record)
        sender = record.get("from_id")
        if sender is not None and not isinstance(sender, str):
            raise ExportError("Invalid sender ID in export")
        attachments = []
        for key in ("file", "photo"):
            if key in record:
                if not isinstance(record[key], str):
                    raise ExportError("Invalid attachment reference in export")
                attachments.append(record[key])
        messages.append(NormalizedMessage(
            messenger="telegram", account=None, chat=str(data["id"]),
            sender=sender, recipient=None, timestamp=timestamp, text=text,
            attachments=tuple(attachments), source="telegram_json_export",
            metadata={"message_id": record["id"], "record_index": ordinal,
                      "timestamp_basis": time_basis},
        ))
    return TelegramExport(tuple(messages), len(records), service_records)


def read_export(path: Path):
    """Read one bounded, stable regular file. Validate all records before auditing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_EXPORT_BYTES:
                raise ExportError("Export must be a regular file of at most 16 MiB")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_EXPORT_BYTES + 1)
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if (identity(before) != identity(after) or len(raw) != before.st_size
                    or len(raw) > MAX_EXPORT_BYTES):
                raise ExportError("Export changed during read")
        finally:
            os.close(fd)
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_object,
                          parse_constant=_invalid_constant)
        return normalize_export(data)
    except ExportError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise ExportError("Invalid UTF-8 JSON export") from None
    except OSError:
        raise ExportError("Cannot read export file") from None


def analyze_export(path, analyzer, audit):
    export = read_export(path)
    counts = {"ALLOW": 0, "WARN": 0, "BLOCK": 0}
    failures = empty = 0
    common = {"source": "telegram_json_export", "scope": "message_text_only",
              "enforcement": "none", "retrospective": True,
              "attachments_analyzed": False}
    for message in export.messages:
        if not message.text:
            empty += 1
            continue
        result = analyzer.analyze(TextContent(message.text, source=message.source))
        counts[result.decision] += 1
        failures += not result.complete
        audit.emit({"event": "export_message_analysis", **common,
                    "record_index": message.metadata["record_index"],
                    "result": asdict(result)})
    audit.emit({"event": "export_analysis_summary", **common,
                "records": export.records, "message_records": len(export.messages),
                "service_records_skipped": export.service_records,
                "empty_text_records_skipped": empty,
                "messages_with_attachment_references": sum(
                    bool(m.attachments) for m in export.messages),
                "analyzed_texts": sum(counts.values()), "decisions": counts,
                "analysis_failures": failures, "text_analysis_complete": failures == 0})
    return 2 if failures else 0
