import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from dlp import telegram_local as local


def blob(data):
    return struct.pack('>I',len(data))+data


def tdf(data, version=local.VERSION):
    v=struct.pack('<I',version)
    return b'TDF$'+v+data+hashlib.md5(data+struct.pack('<I',len(data))+v+b'TDF$').digest()


def encrypt(data, key):
    # Independent AES-IGE implementation from system OpenSSL, not reader's loop.
    body=struct.pack('<I',len(data)+4)+data
    body+=b'\xa5'*(-len(body)%16)
    msg=hashlib.sha1(body).digest()[:16]
    aeskey,iv=local.aes_parameters(key,msg)
    lib=ctypes.CDLL(ctypes.util.find_library('crypto'))
    lib.AES_set_encrypt_key.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p]
    lib.AES_set_encrypt_key.restype=ctypes.c_int
    lib.AES_ige_encrypt.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_int]
    lib.AES_ige_encrypt.restype=None
    schedule=ctypes.create_string_buffer(4096)
    ivbuf=ctypes.create_string_buffer(iv)
    out=ctypes.create_string_buffer(len(body))
    assert lib.AES_set_encrypt_key(aeskey,256,schedule)==0
    lib.AES_ige_encrypt(body,out,len(body),schedule,ivbuf,1)
    return msg+out.raw


def fixture(root, password=b'', text='DLP_STORAGE_TEST коммерческая тайна'):
    key=bytes(range(256)); salt=bytes(range(32))
    account='0123456789ABCDEF'; folder=root/account; folder.mkdir()
    (root/'key_datas').write_bytes(tdf(blob(salt)+blob(encrypt(key,local.password_key(password,salt)))+blob(b'unused encrypted info')))
    peer=1234; file_key=0x123456789abcdef
    mapping=struct.pack('>IIQQ',1,1,file_key,peer)
    (folder/'maps').write_bytes(tdf(blob(b'')+blob(b'')+blob(encrypt(mapping,key))))
    draft=struct.pack('>QQIQ',0xffffffffffffff06,peer,1,0)
    draft+=blob(text.encode('utf-16-be'))+blob(b'')+struct.pack('>QQQQ',0,0,0,0)+blob(b'')+struct.pack('>IIIII',0,0,0,0,0)
    (folder/(local.file_part(file_key)+'s')).write_bytes(tdf(blob(encrypt(draft,key))))
    (folder/'configs').write_bytes(b'SESSION_MUST_NOT_BE_READ')
    return account


class LocalStorageTests(unittest.TestCase):
    def test_crypto_against_openssl_ige(self):
        key=bytes(range(256))
        for size in (0,1,12,15,16,17,255):
            data=bytes(range(256))[:size]
            self.assertEqual(local.decrypt(encrypt(data,key),key),data)
        bad=bytearray(encrypt(b'test',key)); bad[-1]^=1
        with self.assertRaises(local.StorageError):local.decrypt(bytes(bad),key)
        with self.assertRaises(local.StorageError):local.decrypt(encrypt(b'test',key),bytes(256))

    def test_container_and_bounds(self):
        data=tdf(blob(b'hello'))
        self.assertEqual(local.container(data).blob(),b'hello')
        for bad in (data[:-1],data[:10]+b'!' + data[11:],tdf(b'',1)):
            with self.assertRaises(local.StorageError):local.container(bad)
        with self.assertRaises(local.StorageError):local.Reader(struct.pack('>I',0xfffffffe)).blob()
        with self.assertRaises(local.StorageError):local.Reader(blob(b'\xff')).text()

    def test_supported_mixed_versions_and_reject_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); account=fixture(root)
            for path in (root/account).iterdir():
                if path.name != 'configs':
                    path.write_bytes(tdf(path.read_bytes()[8:-16],7002009))
            profile=local.ProfileFiles(root)
            try: _,files=local.collect(profile,b'')
            finally:profile.close()
            text,meta=local.selected_draft(account,files,b'','DLP_STORAGE_TEST')
            self.assertEqual(meta['writer_versions'],[7002008,7002009])
            self.assertEqual(text,'DLP_STORAGE_TEST коммерческая тайна')
        with self.assertRaisesRegex(local.StorageError,'unsupported_writer_version'):
            local.container(tdf(blob(b'test'),7002010))

    def test_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); fixture(root,b'known')
            data=(root/'key_datas').read_bytes()
            self.assertEqual(local.unlock_key(data,b'known'),bytes(range(256)))
            with self.assertRaises(local.StorageError):local.unlock_key(data,b'wrong')

    def test_full_read_only_and_no_auth_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); account=fixture(root)
            before={p: (p.read_bytes(),p.stat().st_mtime_ns) for p in root.rglob('*') if p.is_file()}
            profile=local.ProfileFiles(root)
            try: found,files=local.collect(profile,b'')
            finally:profile.close()
            self.assertEqual(found,account)
            self.assertEqual(len(files),3)
            self.assertFalse(any('configs' in p for p in files))
            text,meta=local.selected_draft(account,files,b'','DLP_STORAGE_TEST')
            self.assertEqual(text,'DLP_STORAGE_TEST коммерческая тайна')
            self.assertEqual(meta['draft_records_scanned'],1)
            for p,old in before.items():self.assertEqual((p.read_bytes(),p.stat().st_mtime_ns),old)

    def test_missing_marker_and_unknown_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); account=fixture(root,text='different')
            profile=local.ProfileFiles(root)
            try: _,files=local.collect(profile,b'')
            finally:profile.close()
            with self.assertRaises(local.StorageError):local.selected_draft(account,files,b'','DLP_STORAGE_TEST')
        data=tdf(blob(b'')+blob(b'')+blob(encrypt(struct.pack('>I',99),bytes(range(256)))))
        with self.assertRaises(local.StorageError):local.draft_map(data,bytes(range(256)))

    def test_duplicate_marker_and_reference_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); account=fixture(root)
            profile=local.ProfileFiles(root)
            try: _,files=local.collect(profile,b'')
            finally:profile.close()
            key=bytes(range(256)); peer=1234
            parts=next(p for p in files if p[-1] not in ('maps','key_datas'))
            record=local.Reader(local.decrypt(local.container(files[parts]).blob(),key))
            header=record.take(16); record.take(4)
            item=record.take(len(record.data)-record.pos)
            payload=header+struct.pack('>I',2)+item+struct.pack('>Q',1)+item[8:]
            files[parts]=tdf(blob(encrypt(payload,key)))
            with self.assertRaisesRegex(local.StorageError,'requires_exactly_one_marked_draft'):
                local.selected_draft(account,files,b'','DLP_STORAGE_TEST')
            with self.assertRaisesRegex(local.StorageError,'draft_reference_mismatch'):
                local.parse_drafts(files[parts],key,peer+1)

    def test_unknown_schema_and_trailing_data(self):
        key=bytes(range(256))
        for payload in (struct.pack('>QQI',123,5,1),
                        struct.pack('>QQI',0xffffffffffffff06,5,0)):
            with self.assertRaises(local.StorageError):
                local.parse_drafts(tdf(blob(encrypt(payload,key))),key,5)
        with self.assertRaisesRegex(local.StorageError,'unexpected_trailing_data'):
            r=local.Reader(b'x'); r.end()

    def test_symlink_fifo_and_duplicate_accounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); fixture(root)
            profile=local.ProfileFiles(root)
            try:
                (root/'link').symlink_to(root/'key_datas')
                os.mkfifo(root/'fifo')
                for name in ('link','fifo'):
                    with self.assertRaises((OSError,local.StorageError)):profile.read((name,))
                (root/'FFFFFFFFFFFFFFFF').mkdir()
                with self.assertRaises(local.StorageError):profile.account()
            finally:profile.close()

    def test_cli_redacted_and_no_false_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); account=fixture(root)
            command=[sys.executable,'scripts/analyze-telegram-local-draft.py','--root',tmp,'--profile-closed','--no-passcode','--expect-demo']
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            event=json.loads(result.stdout)
            self.assertEqual(event['result']['decision'],'BLOCK')
            self.assertTrue(event['expected_demo_match'])
            for secret in (account,'коммерческая тайна','SESSION_MUST_NOT_BE_READ',tmp):self.assertNotIn(secret,result.stdout+result.stderr)
            (root/account/'maps').write_bytes(b'broken')
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads(result.stdout)['event'],'local_draft_analysis_error')
