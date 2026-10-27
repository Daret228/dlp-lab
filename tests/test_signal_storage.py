import tempfile
import unittest
from pathlib import Path
from dlp.signal_storage import probe_signal_storage


class SignalStorageProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'sql').mkdir()

    def test_plaintext_is_not_message_analysis_and_does_not_modify_files(self):
        db = self.root / 'sql/db.sqlite'
        content = b'SQLite format 3\x00' + b'synthetic private content'
        db.write_bytes(content)
        # Invalid JSON is deliberately not read or parsed by this probe.
        (self.root / 'config.json').write_bytes(b'invalid secret config')
        before = db.stat().st_mtime_ns
        result = probe_signal_storage(self.root)
        self.assertEqual(result['database_header'], 'sqlite_plaintext')
        self.assertEqual(result['messages_read'], 0)
        self.assertFalse(result['content_analysis'])
        self.assertNotIn('secret', str(result))
        self.assertEqual(db.read_bytes(), content)
        self.assertEqual(db.stat().st_mtime_ns, before)

    def test_unknown_header_does_not_claim_encryption(self):
        (self.root / 'sql/db.sqlite').write_bytes(b'x' * 32)
        self.assertEqual(probe_signal_storage(self.root)['database_header'], 'not_plaintext_sqlite')
        (self.root / 'sql/db.sqlite').write_bytes(b'x')
        self.assertEqual(probe_signal_storage(self.root)['database_header'], 'short_or_empty')

    def test_symlink_database_and_sql_directory_are_not_followed(self):
        (self.root / 'sql/db.sqlite').symlink_to('/dev/zero')
        self.assertEqual(probe_signal_storage(self.root)['status'], 'database_unavailable')
        (self.root / 'sql/db.sqlite').unlink()
        (self.root / 'sql').rmdir()
        (self.root / 'sql').symlink_to('/tmp')
        self.assertEqual(probe_signal_storage(self.root)['status'], 'database_directory_unavailable')

    def test_missing_profile_and_database(self):
        self.assertEqual(probe_signal_storage(self.root / 'missing')['status'], 'profile_unavailable')
        self.assertEqual(probe_signal_storage(self.root)['status'], 'database_unavailable')
