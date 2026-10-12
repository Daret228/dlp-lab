"""Contracts for stages which must not depend on a GUI framework."""
from typing import Protocol, Iterable
from .models import Finding, NormalizedMessage, Decision
from .processes import ProcessIdentity


class Analyzer(Protocol):
    def analyze(self, text: str) -> list[Finding]: ...


class MLAnalyzer(Analyzer, Protocol):
    """Optional plugin; no mandatory model or dependency."""


class MessengerAdapter(Protocol):
    name: str
    def matches(self, identity: "ProcessIdentity") -> bool: ...
    def capabilities(self) -> dict[str, bool]: ...


class Collector(Protocol):
    def collect(self) -> Iterable[object]: ...


class Normalizer(Protocol):
    def normalize(self, event: object) -> NormalizedMessage: ...


class Enforcer(Protocol):
    def enforce(self, event: object, decision: Decision) -> None: ...


class AuditSink(Protocol):
    def emit(self, event: dict) -> None: ...
