import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('storage_inventory', ROOT/'scripts/inspect-telegram-storage.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class StorageInventoryTests(unittest.TestCase):
    def test_only_allowlisted_headers_and_no_content_in_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'settingss').write_bytes(b'TDF$'+struct.pack('<I', 7002008)+b'SECRET_PAYLOAD')
            (root/'key_datas').write_bytes(b'KEY_SECRET')
            (root/'messages.sqlite').write_bytes(b'SQLite format 3\0PRIVATE_MESSAGE')
            (root/'opaque_file').write_bytes(b'PRIVATE_MESSAGE')
            before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir()}
            real_pread = os.pread
            reads = []
            def pread(fd, length, offset):
                reads.append((Path(os.readlink(f'/proc/self/fd/{fd}')).name, length, offset))
                return real_pread(fd, length, offset)
            with patch.object(inventory.os, 'pread', side_effect=pread):
                report = inventory.inspect_storage(root)
            self.assertEqual(reads, [('settingss', 8, 0)])
            self.assertEqual(report['headers'][0]['writer_version_le'], 7002008)
            self.assertEqual(report['extensions_by_name_only']['.sqlite'], 1)
            self.assertFalse(report['sqlite_content_scan_performed'])
            for secret in ['SECRET_PAYLOAD', 'KEY_SECRET', 'PRIVATE_MESSAGE', 'opaque_file']:
                self.assertNotIn(secret, json.dumps(report))
            for p in root.iterdir():
                self.assertEqual((p.read_bytes(), p.stat().st_mtime_ns), before[p.name])

    def test_no_symlink_traversal_or_special_file_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'; root.mkdir()
            outside = Path(tmp)/'outside'; outside.mkdir()
            (outside/'settingss').write_bytes(b'TDF$'+b'\x00'*4)
            (root/'linked').symlink_to(outside, target_is_directory=True)
            (root/'settingss').symlink_to(outside/'settingss')
            os.mkfifo(root/'maps')
            report = inventory.inspect_storage(root)
            self.assertEqual(report['counts']['symlinks_skipped'], 2)
            self.assertEqual(report['counts']['special_files_skipped'], 1)
            self.assertEqual(report['headers'], [])
            with self.assertRaises(OSError):
                inventory.inspect_storage(root/'linked')

    def test_limits_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'sub').mkdir()
            (root/'sub'/'maps').write_bytes(b'TDF$'+b'\x00'*4)
            self.assertFalse(inventory.inspect_storage(root,max_depth=0)['complete_within_limits'])
            (root/'a').write_bytes(b'a')
            report = inventory.inspect_storage(root,max_entries=1)
            self.assertFalse(report['complete_within_limits'])
            self.assertEqual(report['counts']['entries'],1)

    def test_unknown_header_not_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'settingss').write_bytes(b'PRIVATE_TEXT')
            report=inventory.inspect_storage(root)
            self.assertEqual(report['headers'][0]['format'],'unknown_or_changed')
            self.assertIsNone(report['headers'][0]['writer_version_le'])
            self.assertNotIn('PRIVATE',json.dumps(report))

    def test_atime_preserved_on_header_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); p=root/'settingss'
            p.write_bytes(b'TDF$'+b'\x00'*4)
            os.utime(p, ns=(1_000_000_000,2_000_000_000))
            inventory.inspect_storage(root)
            self.assertEqual(p.stat().st_atime_ns,1_000_000_000)
