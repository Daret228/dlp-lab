import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'storage_observation', Path(__file__).resolve().parents[1]/'scripts/observe-telegram-storage.py')
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class StorageObservationTests(unittest.TestCase):
    def test_no_content_reads_or_private_names_in_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'settingss').write_text('PRIVATE_MESSAGE')
            (root/'private_account_id').mkdir()
            (root/'private_account_id'/'key_datas').write_text('PRIVATE_KEY')
            with patch.object(observer.inventory.os, 'pread', side_effect=AssertionError('content read')):
                report, records = observer.sample(root)
            event, _ = observer.observation(None, report, records)
            self.assertEqual(len(records), 2)
            self.assertEqual(report['counts'].get('header_bytes_read', 0), 0)
            output = json.dumps(event)
            for private in ('PRIVATE_MESSAGE', 'PRIVATE_KEY', 'private_account_id', 'key_datas', tmp):
                self.assertNotIn(private, output)
            self.assertFalse(event['comparison_available'])

    def test_changes_and_replacement_not_treated_as_send(self):
        before = {('maps',): (1, 2, 10, 1, 1), ('gone',): (1, 3, 20, 1, 1)}
        after = {('maps',): (1, 4, 10, 2, 2), ('new',): (1, 5, 30, 1, 1)}
        self.assertEqual(observer.compare(before, after), {'other': {
            'changed': 1, 'identity_changed': 1, 'appeared': 1,
            'disappeared': 1, 'logical_bytes_delta': 10}})
        self.assertEqual(observer.compare(after, after), {})

    def test_incomplete_scan_breaks_comparison(self):
        report = {'complete_within_limits': False, 'observed_at': 'test',
                  'counts': {}, 'errors': ['PermissionError']}
        event, previous = observer.observation({('private',): (1, 1, 5, 1, 1)}, report, {})
        self.assertIsNone(previous)
        self.assertIsNone(event['changes_by_name_category'])
        report['complete_within_limits'] = True
        event, previous = observer.observation(previous, report, {})
        self.assertFalse(event['comparison_available'])

    def test_symlink_target_not_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root'; root.mkdir()
            outside = Path(tmp)/'outside'; outside.mkdir()
            (outside/'secret').write_text('private')
            (root/'linked').symlink_to(outside, target_is_directory=True)
            report, records = observer.sample(root)
            self.assertEqual(records, {})
            self.assertEqual(report['counts']['symlinks_skipped'], 1)

    def test_real_files_appear_change_disappear(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, before = observer.sample(root)
            file = root/'sample'; file.write_text('a')
            _, after = observer.sample(root)
            self.assertEqual(observer.compare(before, after)['other']['appeared'], 1)
            before = after
            file.write_text('abcd')
            _, after = observer.sample(root)
            self.assertEqual(observer.compare(before, after)['other']['logical_bytes_delta'], 3)
            before = after
            file.unlink()
            _, after = observer.sample(root)
            self.assertEqual(observer.compare(before, after)['other']['disappeared'], 1)
