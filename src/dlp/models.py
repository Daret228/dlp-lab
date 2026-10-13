from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Decision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class TextContent:
    text: str
    source: str = "cli"


@dataclass(frozen=True)
class FileContent:
    path: Path
    fd: int | None = None  # Borrowed event FD; never reopen a fanotify path.


@dataclass(frozen=True)
class Finding:
    analyzer: str
    rule_id: str
    category: str
    confidence: float
    severity: float
    location: tuple[int, int]
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AnalysisResult:
    findings: list[Finding]
    score: float
    decision: Decision
    complete: bool = True
    reason: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedMessage:
    messenger: str
    account: str | None
    chat: str | None
    sender: str | None
    recipient: str | None
    timestamp: str | None
    text: str
    attachments: tuple[str, ...] = ()
    source: str = "unknown"
    metadata: dict = field(default_factory=dict)
