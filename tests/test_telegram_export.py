import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dlp.analysis import ContentAnalyzer
from dlp.audit import JsonAudit
from dlp.cli import main
from dlp.models import TextContent
from dlp.policy import load_policy
from dlp.telegram_export import ExportError, normalize_export, read_export, analyze_export


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/telegram-export-synthetic.json"


class TelegramExportTest(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(EXAMPLE.read_text())
        self.analyzer = ContentAnalyzer(load_policy(ROOT / "config/policy.yaml"))
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "result.json"

    def write(self, data=None):
        self.path.write_text(json.dumps(self.data if data is None else data), encoding="utf-8")
        return self.path

    def test_model_mapping_and_markup_split_phrase(self):
        export = normalize_export(self.data)
        message = export.messages[2]
        self.assertEqual(message.text, "Это коммерческая тайна")
        self.assertEqual(self.analyzer.analyze(TextContent(message.text)).decision, "BLOCK")
        self.assertEqual(message.chat, "100")
        self.assertEqual(message.sender, "user100")
        self.assertIsNone(message.account)
        self.assertIsNone(message.recipient)
        self.assertEqual(message.timestamp, "2026-10-06T12:00:02+00:00")
        self.assertEqual(message.metadata["record_index"], 3)
        self.assertEqual(export.service_records, 1)

    def test_dates_do_not_invent_timezone(self):
        record = self.data["messages"][0]
        del record["date_unixtime"]
        result = normalize_export(self.data).messages[0]
        self.assertEqual(result.metadata["timestamp_basis"], "unspecified")
        self.assertEqual(result.timestamp, record["date"])
        record["date"] = "2026-10-06T15:00:00+03:00"
        self.assertEqual(normalize_export(self.data).messages[0].timestamp,
                         "2026-10-06T12:00:00+00:00")

    def test_schema_errors(self):
        for replacement in ({"text": None}, {"text": [42]},
                            {"text": [{"type": "bold"}]}, {"type": "unknown"},
                            {"id": True}, {"date_unixtime": "secret"},
                            {"date_unixtime": "9" * 50}, {"from_id": []}, {"file": []}):
            with self.subTest(replacement=replacement):
                data = copy.deepcopy(self.data)
                data["messages"][0].update(replacement)
                with self.assertRaises(ExportError):
                    normalize_export(data)
        for data in ([], {}, {"chats": {"list": [self.data]}}):
            with self.assertRaises(ExportError):
                normalize_export(data)

    def test_duplicate_ids_and_record_limit(self):
        self.data["messages"].append(self.data["messages"][0])
        with self.assertRaises(ExportError):
            normalize_export(self.data)
        with patch("dlp.telegram_export.MAX_RECORDS", 1):
            with self.assertRaises(ExportError):
                normalize_export(self.data)

    def test_invalid_json_reports_no_content(self):
        for raw in (b'{"private-sentinel": 1, "private-sentinel": 2}',
                    b'{"private-sentinel": NaN}', b'private-sentinel',
                    b'\xffprivate-sentinel', b'[' * 2000):
            self.path.write_bytes(raw)
            with self.assertRaises(ExportError) as error:
                read_export(self.path)
            self.assertNotIn("private-sentinel", str(error.exception))

    def test_file_limits_symlink_and_fifo(self):
        self.write()
        with patch("dlp.telegram_export.MAX_EXPORT_BYTES", 10):
            with self.assertRaises(ExportError):
                read_export(self.path)
        link = self.path.with_name("link.json")
        link.symlink_to(self.path)
        with self.assertRaises(ExportError):
            read_export(link)
        fifo = self.path.with_name("fifo")
        os.mkfifo(fifo)
        with self.assertRaises(ExportError):
            read_export(fifo)

    def test_detects_changed_file(self):
        self.write()
        before = self.path.stat()
        values = list(before)
        values[6] += 1
        after = os.stat_result(values)
        with patch("dlp.telegram_export.os.fstat", side_effect=[before, after]):
            with self.assertRaisesRegex(ExportError, "changed"):
                read_export(self.path)

    def test_only_export_opened_and_audit_contains_no_private_fields(self):
        self.data["name"] = "private-chat-sentinel"
        self.data["messages"][0]["text"] += " private-text-sentinel"
        self.data["messages"][0]["from_id"] = "private-sender-sentinel"
        self.data["messages"][-1]["file"] = "../../private-attachment-sentinel"
        self.write()
        out = io.StringIO()
        with patch("dlp.telegram_export.os.open", wraps=os.open) as opened:
            self.assertEqual(analyze_export(self.path, self.analyzer, JsonAudit(out)), 0)
        self.assertEqual(opened.call_count, 1)
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertNotIn("sentinel", out.getvalue())
        self.assertEqual([e["result"]["decision"] for e in events[:-1]],
                         ["ALLOW", "WARN", "BLOCK"])
        summary = events[-1]
        self.assertEqual(summary["records"], 5)
        self.assertEqual(summary["empty_text_records_skipped"], 1)
        self.assertEqual(summary["service_records_skipped"], 1)
        self.assertEqual(summary["messages_with_attachment_references"], 1)
        self.assertFalse(summary["attachments_analyzed"])
        self.assertEqual(summary["enforcement"], "none")

    def test_failure_is_not_reported_as_success(self):
        out = io.StringIO()
        self.analyzer.policy["limits"]["max_bytes"] = 1
        self.assertEqual(analyze_export(self.write(), self.analyzer, JsonAudit(out)), 2)
        summary = json.loads(out.getvalue().splitlines()[-1])
        self.assertFalse(summary["text_analysis_complete"])
        self.assertEqual(summary["analysis_failures"], 3)

    def test_no_partial_success_if_late_record_invalid(self):
        self.data["messages"][-1]["text"] = {}
        out = io.StringIO()
        with self.assertRaises(ExportError):
            analyze_export(self.write(), self.analyzer, JsonAudit(out))
        self.assertEqual(out.getvalue(), "")

    def test_empty_chat_and_empty_text_not_classified_as_allow(self):
        for records in ([], [self.data["messages"][-1]]):
            self.data["messages"] = records
            out = io.StringIO()
            self.assertEqual(analyze_export(self.write(), self.analyzer, JsonAudit(out)), 0)
            summary = json.loads(out.getvalue())
            self.assertEqual(summary["analyzed_texts"], 0)
            self.assertEqual(summary["decisions"], {"ALLOW": 0, "WARN": 0, "BLOCK": 0})

    def test_cli_and_invalid_file_exit(self):
        argv = ["dlp", "--policy", str(ROOT / "config/policy.yaml"),
                "analyze-export", "--file", str(self.write())]
        with patch("sys.argv", argv), patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(main(), 0)
        self.assertIn('"export_analysis_summary"', out.getvalue())
        self.path.write_text("not json")
        with patch("sys.argv", argv), patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(main(), 2)


if __name__ == "__main__":
    unittest.main()
