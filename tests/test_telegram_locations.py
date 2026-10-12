import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from dlp import telegram_local as local
from dlp import telegram_locations as locations
from test_telegram_local import blob, encrypt, tdf, fixture

KEY = bytes(range(256))
TARGET = '/synthetic/DLP_STORAGE_ATTACHMENT_TEST.txt'


def row(name='', first=0, size=0, spec=0):
    return (struct.pack('>QQI',first,0,0)+blob(name.encode('utf-16-be'))+blob(b'')
            +struct.pack('>qIbI',2440588,3600000,spec,size))


def encoded(body):
    return tdf(blob(encrypt(body,KEY)))


def setup_locations(root):
    account = fixture(root)
    reference = 42
    mapping = struct.pack('>IQ',4,reference)
    (root/account/'maps').write_bytes(tdf(blob(b'')+blob(b'')+blob(encrypt(mapping,KEY))))
    (root/account/(local.file_part(reference)+'s')).write_bytes(
        encoded(row(TARGET,1,123)+row()+struct.pack('>II',0,0)+blob(b'')))
    return account


class LocationsTests(unittest.TestCase):
    def test_selected_metadata_and_redaction(self):
        body = row('/private/unrelated.txt',2,321)+row(TARGET,1,123)+row('*media_cache*',3)+row()
        result = locations.parse_locations(encoded(body+struct.pack('>II',0,0)+blob(b'opaque')),KEY,TARGET)
        self.assertEqual(result['location_records'],3)
        self.assertEqual(result['media_cache_records'],1)
        self.assertEqual(result['target_matches'],1)
        self.assertEqual(result['target_records'][0]['size_bytes'],123)
        self.assertEqual(result['target_records'][0]['modified']['value'],'1970-01-01T01:00:00.000')
        self.assertEqual(result['unparsed_downloads_bytes'],6)
        self.assertNotIn('/private',json.dumps(result))
        self.assertNotIn(TARGET,json.dumps(result))

    def test_time_basis_not_invented(self):
        for spec,basis in ((2,'utc'),(3,'offset_not_serialized'),(4,'timezone_not_serialized')):
            data = encoded(row(TARGET,1,spec=spec)+row()+struct.pack('>I',0))
            modified = locations.parse_locations(data,KEY,TARGET)['target_records'][0]['modified']
            self.assertEqual(modified['time_basis'],basis)
            self.assertEqual(modified['value'].endswith('Z'),spec==2)
        invalid = local.Reader(struct.pack('>qIb',-2**63,0xffffffff,-1))
        self.assertIsNone(locations.modified_time(invalid)['value'])

    def test_absent_and_duplicate_matches(self):
        for rows,count in ((b'',0),(row(TARGET,1)+row(TARGET,2),2)):
            result=locations.parse_locations(encoded(rows+row()+struct.pack('>I',0)),KEY,TARGET)
            self.assertEqual(result['target_matches'],count)

    def test_invalid_records_fail_closed(self):
        valid = row(TARGET,1)+row()+struct.pack('>II',0,0)+blob(b'')
        for body in (valid[:-1],valid+b'x',row(TARGET,1),row()+struct.pack('>I',10001),
                     row(TARGET,1,spec=9)+row()+struct.pack('>I',0)):
            with self.assertRaises(local.StorageError):
                locations.parse_locations(encoded(body),KEY,TARGET)
        for target in ('relative/DLP_STORAGE_ATTACHMENT_TEST.txt','/private/other.txt','/a/../DLP_STORAGE_ATTACHMENT_TEST.txt'):
            with self.assertRaises(local.StorageError):locations.validate_target(target)

    def test_collection_never_opens_drafts_auth_or_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); account=setup_locations(root)
            profile=local.ProfileFiles(root)
            read=profile.read; opened=[]
            def tracked(parts):
                opened.append(parts)
                return read(parts)
            profile.read=tracked
            try: actual,files=locations.collect_locations(profile,b'')
            finally:profile.close()
            self.assertEqual(actual,account)
            self.assertEqual(set(opened),{('key_datas',),(account,'maps'),(account,local.file_part(42)+'s')})
            self.assertEqual(locations.inspect_locations(account,files,b'',TARGET)['target_matches'],1)

    def test_no_locations_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);account=fixture(root)
            profile=local.ProfileFiles(root)
            try:_,files=locations.collect_locations(profile,b'')
            finally:profile.close()
            self.assertEqual(len(files),2)
            self.assertFalse(locations.inspect_locations(account,files,b'',TARGET)['locations_reference_present'])

    def test_cli_copy_and_error_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);setup_locations(root)
            cmd=[sys.executable,'scripts/inspect-telegram-local-locations.py','--root',str(root),
                 '--profile-closed','--no-passcode','--expected-path',TARGET]
            proc=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stderr)
            event=json.loads(proc.stdout)
            self.assertTrue(event['copy_verified'])
            self.assertFalse(event['send_confirmed'])
            self.assertFalse(event['file_content_read'])
            cmd[-1]='/private/should-not-print'
            proc=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(proc.returncode,2)
            self.assertNotIn('/private',proc.stdout+proc.stderr)
