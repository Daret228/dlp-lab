import os
import re
import signal
import stat
from contextlib import contextmanager
from .models import AnalysisResult, Decision, Finding, TextContent
from .policy import PolicyEngine
from .file_types import detect_type
from .documents import extract_document, DocumentError


class AnalysisTimeout(Exception):
    pass


@contextmanager
def deadline(seconds):
    # Linux CLI / daemon main thread only. No regex executes without a deadline.
    def expire(*_):
        raise AnalysisTimeout("analysis_timeout")
    old_handler = signal.signal(signal.SIGALRM, expire)
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)
        signal.setitimer(signal.ITIMER_REAL, *old_timer)


class DictionaryAnalyzer:
    def __init__(self, rule):
        self.rule = rule
        self.pattern = re.compile("|".join(re.escape(t) for t in rule["terms"]), re.IGNORECASE)

    def analyze(self, text):
        for m in self.pattern.finditer(text):
            if self.accept(text, m):
                r = self.rule
                return [Finding(r["type"], r["id"], r["category"], 1.0, r["severity"], m.span())]
        return []

    def accept(self, text, match):
        return True


class RegexAnalyzer(DictionaryAnalyzer):
    def __init__(self, rule):
        self.rule = rule
        self.pattern = re.compile(rule["pattern"])


class ContextAnalyzer(DictionaryAnalyzer):
    def __init__(self, rule):
        super().__init__(rule)
        self.context = re.compile("|".join(re.escape(t) for t in rule["context"]), re.IGNORECASE)

    def accept(self, text, match):
        w = self.rule["window"]
        return self.context.search(text[max(0, match.start()-w):match.end()+w]) is not None


class ContentAnalyzer:
    def __init__(self, policy):
        self.policy = policy
        self.engine = PolicyEngine(policy)
        kinds = {"dictionary": DictionaryAnalyzer, "regex": RegexAnalyzer, "context": ContextAnalyzer}
        self.analyzers = [kinds[r["type"]](r) for r in policy["rules"]]

    def failure(self, reason):
        return AnalysisResult([], 0, Decision(self.policy["on_error"]), False, reason)

    def analyze(self, content):
        metadata = {}
        extraction_complete, extraction_reason = True, None
        try:
            with deadline(self.policy["limits"]["timeout_seconds"]):
                if isinstance(content, TextContent):
                    text = self._text(content)
                else:
                    data = self._file_bytes(content)
                    kind = detect_type(data)
                    metadata = {"file_type": kind, "type_detection": "signature_or_utf8",
                                "content_checked": False}
                    types = self.policy.get("file_types")
                    if kind == "unknown":
                        return AnalysisResult([], 0, Decision(self.policy["on_error"]), False,
                                              "unknown_file_type", metadata)
                    if types is not None:
                        if kind in types["deny"] or (types["allow"] and kind not in types["allow"]):
                            metadata["decision_basis"] = "file_type_policy"
                            return AnalysisResult([], 0, Decision.BLOCK, True,
                                                  "file_type_denied", metadata)
                    if kind in ("pdf", "docx"):
                        extracted = extract_document(data, kind, self.policy["limits"]["max_bytes"],
                                                     self.policy["limits"]["timeout_seconds"])
                        text = extracted.pop("text")
                        extraction_complete = extracted.pop("complete")
                        extraction_reason = extracted.pop("reason")
                        metadata.update(extracted)
                    elif kind == "text":
                        text = data.decode("utf-8-sig", errors="strict")
                    else:
                        return AnalysisResult([], 0, Decision(self.policy["on_error"]), False,
                                              "unsupported_content_type", metadata)
                findings = [f for analyzer in self.analyzers for f in analyzer.analyze(text)]
                score, decision = self.engine.decide(findings)
                if metadata:
                    metadata["content_checked"] = extraction_complete
                    metadata["extracted_text_checked"] = True
                if not extraction_complete:
                    rank = {Decision.ALLOW: 0, Decision.WARN: 1, Decision.BLOCK: 2}
                    decision = max(decision, Decision(self.policy["on_error"]), key=rank.get)
                return AnalysisResult(findings, score, decision, extraction_complete,
                                      extraction_reason, metadata)
        except (OSError, UnicodeError, ValueError, AnalysisTimeout) as exc:
            reason = str(exc) if isinstance(exc, DocumentError) else type(exc).__name__
            return AnalysisResult([], 0, Decision(self.policy["on_error"]), False, reason, metadata)

    def _text(self, content):
        limit = self.policy["limits"]["max_bytes"]
        if isinstance(content, TextContent):
            if len(content.text.encode("utf-8")) > limit:
                raise ValueError("oversize")
            return content.text
        return self._file_bytes(content).decode("utf-8", errors="strict")

    def _file_bytes(self, content):
        limit = self.policy["limits"]["max_bytes"]
        owned = content.fd is None
        fd = os.open(content.path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC) if owned else content.fd
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("unsupported_or_oversize")
            data = os.pread(fd, limit + 1, 0)
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or len(data) != before.st_size or len(data) > limit:
                raise ValueError("changed_during_analysis")
            return data
        finally:
            if owned:
                os.close(fd)
