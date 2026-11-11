import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import yaml

from dlp.analysis import ContentAnalyzer
from dlp.models import FileContent, Decision
from dlp.policy import load_policy, PolicyError
from dlp.fanotify import process_event, OPEN_PERM, RESPONSE
from dlp.audit import JsonAudit

ROOT = Path(__file__).resolve().parents[1]


class FileTypeTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / 'config/policy.yaml')

    def analyze(self, data, name='renamed.txt'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / name
            path.write_bytes(data)
            return ContentAnalyzer(self.policy).analyze(FileContent(path))

    def test_renamed_signatures_denied(self):
        for data, kind in [(b'\x7fELF\x02\x01', 'elf'), (b'MZ\0\0', 'dos_pe'),
                           (b'#!/bin/sh\necho hello', 'script'),
                           (b'PK\x03\x04\0', 'zip'), (b'\x1f\x8b\0', 'gzip'),
                           (b'7z\xbc\xaf\x27\x1c', '7z'), (b'Rar!\x1a\x07\0', 'rar')]:
            with self.subTest(kind=kind):
                r = self.analyze(data)
                self.assertEqual((r.decision, r.reason, r.complete),
                                 (Decision.BLOCK, 'file_type_denied', True))
                self.assertEqual(r.metadata['file_type'], kind)
                self.assertFalse(r.metadata['content_checked'])

    def test_extension_does_not_override_content(self):
        r = self.analyze(b'hello', 'file.exe')
        self.assertEqual(r.decision, Decision.ALLOW)
        self.assertEqual(r.metadata['file_type'], 'text')
        r = self.analyze('коммерческая тайна'.encode(), 'file.pdf')
        self.assertEqual(r.decision, Decision.BLOCK)
        self.assertTrue(r.metadata['content_checked'])
        self.assertEqual(r.findings[0].analyzer, 'dictionary')

    def test_unknown_uses_error_policy(self):
        self.policy['on_error'] = 'WARN'
        r = self.analyze(b'\xff\x00')
        self.assertEqual((r.decision, r.complete, r.reason),
                         (Decision.WARN, False, 'unknown_file_type'))

    def test_permitted_image_allows_without_extractor(self):
        # Explicit type permission is a final policy verdict: ALLOW with the
        # content honestly marked unchecked (no OCR in this build).
        self.policy['file_types']['allow'] = ['text', 'png']
        r = self.analyze(b'\x89PNG\r\n\x1a\n')
        self.assertEqual((r.decision, r.reason, r.complete),
                         (Decision.ALLOW, 'file_type_allowed', True))
        self.assertFalse(r.metadata['content_checked'])
        self.assertEqual(r.metadata['decision_basis'], 'file_type_policy')

    def test_allowlist_and_denylist(self):
        self.policy['file_types']['allow'] = ['text']
        self.assertEqual(self.analyze(b'\x89PNG\r\n\x1a\n').reason, 'file_type_denied')
        self.policy['file_types']['allow'] = []
        self.assertEqual(self.analyze(b'\x89PNG\r\n\x1a\n').reason, 'unsupported_content_type')
        self.assertEqual(self.analyze(b'PK\x03\x04').reason, 'file_type_denied')

    def test_images_blocked_by_type_and_allowed_explicitly(self):
        # Supervisor scenario: block images per device policy, allow them for another role.
        for sample in (b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff\xe0' + b'\x00' * 32):
            self.policy['file_types']['allow'] = ['text', 'pdf', 'docx']
            r = self.analyze(sample)
            self.assertEqual(r.decision, Decision.BLOCK)
            self.assertEqual(r.reason, 'file_type_denied')
            self.assertTrue(r.complete)
            self.assertFalse(r.metadata['content_checked'])
        # A role that explicitly permits images gets an honest ALLOW, content unchecked.
        self.policy['file_types']['allow'] = ['text', 'pdf', 'docx', 'png', 'jpeg']
        for sample in (b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff\xe0' + b'\x00' * 32):
            r = self.analyze(sample)
            self.assertEqual(r.decision, Decision.ALLOW)
            self.assertEqual(r.reason, 'file_type_allowed')
            self.assertTrue(r.complete)
            self.assertFalse(r.metadata['content_checked'])
            self.assertEqual(r.metadata['decision_basis'], 'file_type_policy')

    def test_old_policy_no_format_allow(self):
        del self.policy['file_types']
        self.assertEqual(self.analyze(b'hello').decision, Decision.ALLOW)
        self.assertEqual(self.analyze(b'\x7fELF').reason, 'unsupported_content_type')

    def test_policy_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.yaml'
            for setting in [{'allow': ['unknown'], 'deny': []},
                            {'allow': ['text', 'text'], 'deny': []},
                            {'allow': ['text'], 'deny': ['text']},
                            {'allow': 'text', 'deny': []},
                            {'allow': [], 'deny': [{}]}, {'allow': []}]:
                p = copy.deepcopy(self.policy)
                p['file_types'] = setting
                path.write_text(yaml.safe_dump(p))
                with self.subTest(setting=setting), self.assertRaises(PolicyError):
                    load_policy(path)
            del p['file_types']
            path.write_text(yaml.safe_dump(p))
            load_policy(path)

    def test_borrowed_event_fd_denied_and_journaled(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public.txt'
            path.write_bytes(b'\x7fELF\x02\x01')
            fd = os.open(path, os.O_RDONLY)
            path.unlink()  # Must use event FD, never reopen the path.
            read_fd, write_fd = os.pipe()
            try:
                stream = io.StringIO()
                process_event(write_fd, OPEN_PERM, fd, os.getpid(),
                              ContentAnalyzer(self.policy), JsonAudit(stream))
                self.assertEqual(RESPONSE.unpack(os.read(read_fd, 8)), (fd, 2))
                record = json.loads(stream.getvalue())
                self.assertEqual(record['result']['reason'], 'file_type_denied')
                self.assertEqual(record['enforcement'], 'DENY')
                self.assertFalse(record['send_confirmed'])
            finally:
                os.close(read_fd)
                os.close(write_fd)
