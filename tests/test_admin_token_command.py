import json
from pathlib import Path
import runpy
import tempfile
import unittest


read_token = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'packaging/dlp-admin-token'))['read_token']


class AdminTokenCommandTest(unittest.TestCase):
    def test_private_token_read_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admin.json'
            original = json.dumps({'token': 'synthetic_' + 'a' * 34})
            path.write_text(original)
            path.chmod(0o600)
            self.assertEqual(read_token(path), 'synthetic_' + 'a' * 34)
            self.assertEqual(path.read_text(), original)

    def test_reject_public_file_symlink_and_invalid_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'admin.json'
            path.write_text(json.dumps({'token': 'a' * 43}))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_token(path)
            path.chmod(0o600)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                read_token(link)
            for content in ('{}', '[]', 'invalid json', '{"token":"bad\\nvalue"}', 'x' * 4097):
                path.write_text(content)
                with self.assertRaises(ValueError):
                    read_token(path)
