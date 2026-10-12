import copy
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from dlp.analysis import ContentAnalyzer
from dlp.audit import JsonAudit
from dlp.models import TextContent, FileContent, Decision, Finding
from dlp.policy import load_policy, PolicyError, PolicyEngine
from dlp.fanotify import events, process_event, METADATA, RESPONSE, OPEN_PERM, OVERFLOW

ROOT = Path(__file__).resolve().parents[1]


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / "config/policy.yaml")
        self.analyzer = ContentAnalyzer(self.policy)

    def result(self, text):
        return self.analyzer.analyze(TextContent(text))

    def test_allow(self):
        self.assertEqual(self.result("общедоступный текст").decision, Decision.ALLOW)

    def test_dictionary_unicode_case(self):
        r = self.result("КОММЕРЧЕСКАЯ ТАЙНА")
        self.assertEqual(r.decision, Decision.BLOCK)
        self.assertEqual(r.findings[0].location, (0, 18))

    def test_email_warn(self):
        self.assertEqual(self.result("test@example.org").decision, Decision.WARN)

    def test_context_required(self):
        self.assertEqual(self.result("проект открыт").decision, Decision.ALLOW)
        self.assertEqual(self.result("закрытый проект").decision, Decision.BLOCK)
        self.assertEqual(self.result("закрытый " + "x" * 100 + " проект").decision, Decision.ALLOW)

    def test_repetitions_do_not_inflate(self):
        self.assertEqual(self.result("a@b.org " * 50).score, 0.35)

    def test_combined_score(self):
        self.assertAlmostEqual(self.result("top secret a@b.org").score, 1.15)

    def test_boundaries_and_weights(self):
        engine = PolicyEngine(self.policy)
        for score, expected in [(0.299, Decision.ALLOW), (0.3, Decision.WARN), (0.7, Decision.BLOCK)]:
            f = Finding("regex", "test", "test", 1, score, (0, 1))
            self.assertEqual(engine.decide([f])[1], expected)
        self.policy["weights"]["regex"] = 0
        self.assertEqual(engine.decide([f])[1], Decision.ALLOW)

    def test_file_and_borrowed_fd(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "text"
            p.write_text("top secret")
            fd = os.open(p, os.O_RDONLY)
            try:
                p.unlink()
                r = self.analyzer.analyze(FileContent(p, fd))
                self.assertEqual(r.decision, Decision.BLOCK)
                os.fstat(fd)  # Analyzer must not close the event's FD.
            finally:
                os.close(fd)

    def test_unsupported_missing_oversize(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "data"
            for data in (b'\xff', b'a\x00b', b'x' * (self.policy["limits"]["max_bytes"]+1)):
                p.write_bytes(data)
                r = self.analyzer.analyze(FileContent(p))
                self.assertFalse(r.complete)
                self.assertEqual(r.decision, Decision.BLOCK)
            self.assertFalse(self.analyzer.analyze(FileContent(Path(d))).complete)
            self.assertFalse(self.analyzer.analyze(FileContent(Path(d)/"missing")).complete)

    def test_error_policy(self):
        self.policy["on_error"] = "WARN"
        self.assertEqual(self.analyzer.analyze(FileContent(Path('/does-not-exist'))).decision, Decision.WARN)

    def test_regex_deadline(self):
        self.policy["limits"]["timeout_seconds"] = 0.02
        self.policy["rules"] = [dict(id="slow", type="regex", pattern="(a+)+$", severity=1, category="test")]
        r = ContentAnalyzer(self.policy).analyze(TextContent("a" * 30 + "!"))
        self.assertFalse(r.complete)
        self.assertEqual(r.reason, "AnalysisTimeout")

    def test_invalid_policies(self):
        import yaml
        variants = []
        for mutate in [lambda p: p["rules"].append(p["rules"][0]),
                       lambda p: p["thresholds"].update(block=-1),
                       lambda p: p["weights"].update(regex=float('nan')),
                       lambda p: p["rules"][1].update(pattern="["),
                       lambda p: p["rules"][0].update(terms=[]),
                       lambda p: p.update(on_error="ignore")]:
            p = copy.deepcopy(self.policy)
            mutate(p)
            variants.append(yaml.safe_dump(p))
        variants += ['!!python/object/apply:os.system ["false"]', 'null']
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/"policy.yaml"
            for text in variants:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(PolicyError):
                    load_policy(path)

    def test_audit_does_not_include_content(self):
        from dataclasses import asdict
        stream = io.StringIO()
        JsonAudit(stream).emit({"result": asdict(self.result("top secret"))})
        self.assertNotIn("top secret", stream.getvalue())
        self.assertIn("timestamp", json.loads(stream.getvalue()))


class FanotifyTests(unittest.TestCase):
    def test_event_batch(self):
        event = METADATA.pack(24, 3, 0, 24, OPEN_PERM, 10, 25)
        self.assertEqual(list(events(event*2)), [(OPEN_PERM, 10, 25)]*2)
        for broken in (event[:10], METADATA.pack(0, 3, 0, 24, OPEN_PERM, 10, 25), METADATA.pack(24, 4, 0, 24, OPEN_PERM, 10, 25)):
            with self.assertRaises(ValueError):
                list(events(broken))

    def test_real_fd_response_and_close(self):
        analyzer = ContentAnalyzer(load_policy(ROOT/'config/policy.yaml'))
        for name, decision in [('public.txt', 1), ('secret.txt', 2)]:
            fd = os.open(ROOT/'examples'/name, os.O_RDONLY)
            read_fd, write_fd = os.pipe()
            try:
                stream = io.StringIO()
                process_event(write_fd, OPEN_PERM, fd, os.getpid(), analyzer, JsonAudit(stream))
                self.assertEqual(RESPONSE.unpack(os.read(read_fd, 8)), (fd, decision))
                with self.assertRaises(OSError):
                    os.fstat(fd)
                self.assertFalse(json.loads(stream.getvalue())["send_confirmed"])
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_overflow(self):
        stream = io.StringIO()
        process_event(-1, OVERFLOW, -1, 0, None, JsonAudit(stream))
        self.assertEqual(json.loads(stream.getvalue())["coverage"], "lost")

    def test_unexpected_exception_denies_and_closes(self):
        analyzer = ContentAnalyzer(load_policy(ROOT/'config/policy.yaml'))
        fd = os.open(ROOT/'examples/public.txt', os.O_RDONLY)
        r, w = os.pipe()
        try:
            with patch.object(analyzer, 'analyze', side_effect=RuntimeError('failure')):
                with self.assertRaises(RuntimeError):
                    process_event(w, OPEN_PERM, fd, os.getpid(), analyzer, JsonAudit(io.StringIO()))
            self.assertEqual(RESPONSE.unpack(os.read(r, 8)), (fd, 2))
            with self.assertRaises(OSError):
                os.fstat(fd)
        finally:
            os.close(r)
            os.close(w)
