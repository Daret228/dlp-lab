import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dlp.signal_sqlcipher import library_name

spec=importlib.util.spec_from_file_location('bundle',Path(__file__).resolve().parents[1]/'packaging/sqlcipher_bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)


class PrivateSQLCipherTests(unittest.TestCase):
    def test_default_prefers_private_and_explicit_override_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            private=Path(folder)/'private.so';override=Path(folder)/'override.so'
            with patch('dlp.signal_sqlcipher.PRIVATE_LIBRARY',private):
                self.assertEqual(library_name('libsqlcipher.so.1'),'libsqlcipher.so.1')
                private.touch();override.touch()
                self.assertEqual(library_name('libsqlcipher.so.1'),str(private))
                self.assertEqual(library_name(override),str(override.resolve()))

    def test_missing_or_unreviewed_bundle_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'staged';deb=Path(folder)/'invalid.deb'
            with patch.dict('os.environ',{'DLP_SQLCIPHER_DEB':str(deb)}):
                with self.assertRaises(ValueError):bundle.stage(root)
                deb.write_bytes(b'unreviewed')
                with self.assertRaises(ValueError):bundle.stage(root)
                self.assertFalse(root.exists())
