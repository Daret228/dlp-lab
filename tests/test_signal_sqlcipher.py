import hashlib
import unittest
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ImportError:
    AES = None
from dlp.signal_sqlcipher import unwrap_linux_v11, SignalDatabaseError

@unittest.skipIf(AES is None, "Optional PyCryptodome required")
class ProtectedKeyTests(unittest.TestCase):
    def test_synthetic_roundtrip_and_wrong_password(self):
        password=b'synthetic password'; key=b'01'*32
        derived=hashlib.pbkdf2_hmac('sha1',password,b'saltysalt',1,16)
        blob=b'v11'+AES.new(derived,AES.MODE_CBC,b' '*16).encrypt(pad(key,16))
        self.assertEqual(unwrap_linux_v11(blob,password),key)
        with self.assertRaises(SignalDatabaseError):unwrap_linux_v11(blob,b'wrong')

    def test_no_legacy_or_empty_password_fallback(self):
        for blob,password in ((b'v10'+b'x'*16,b'password'),(b'v11'+b'x'*16,b''),(b'v11',b'password')):
            with self.assertRaises(SignalDatabaseError):unwrap_linux_v11(blob,password)

import ctypes as C
import os
from pathlib import Path
import secrets
import tempfile
from dlp.signal_sqlcipher import load_library, ReadOnlySignalDatabase


@unittest.skipUnless(os.environ.get('DLP_SQLCIPHER_LIBRARY'), 'Explicit SQLCipher library required')
class ReadOnlyDatabaseTests(unittest.TestCase):
    def test_encrypted_read_write_denial_and_wrong_key(self):
        library=os.environ['DLP_SQLCIPHER_LIBRARY'];lib=load_library(library)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'synthetic.sqlite';key=secrets.token_hex(32).encode()
            db=C.c_void_p()
            self.assertEqual(lib.sqlite3_open_v2(str(path).encode(),C.byref(db),2|4,None),0)
            try:
                sql=b'PRAGMA key="x\''+key+b'\'"; CREATE TABLE messages(body TEXT); INSERT INTO messages VALUES (\'synthetic\');'
                self.assertEqual(lib.sqlite3_exec(db,sql,None,None,None),0)
            finally:lib.sqlite3_close(db)
            before=path.read_bytes()
            self.assertNotEqual(before[:16],b'SQLite format 3\0')
            with ReadOnlySignalDatabase(path,key,library) as reader:
                self.assertEqual(reader.rows('SELECT body FROM messages'),[['synthetic']])
                with self.assertRaises(SignalDatabaseError):
                    reader._exec(b"INSERT INTO messages VALUES ('unexpected')")
            self.assertEqual(before,path.read_bytes())
            with self.assertRaises(SignalDatabaseError):
                ReadOnlySignalDatabase(path,b'ff'*32,library)

import sqlite3
from dlp.signal_sqlcipher import analyze_recent_messages
from dlp.models import AnalysisResult, Decision


class MessageSampleTests(unittest.TestCase):
    def test_sample_limit_oversize_and_no_message_disclosure(self):
        connection=sqlite3.connect(':memory:')
        self.addCleanup(connection.close)
        connection.execute('CREATE TABLE messages(id INTEGER, received_at INTEGER, body TEXT)')
        connection.executemany('INSERT INTO messages VALUES (?,?,?)',
                               [(1,1,'old'),(2,2,'private sample'),(3,3,'x'*50),(4,4,None)])
        class Reader:
            def rows(self,query,max_rows):
                return connection.execute(query).fetchall()
        class Analyzer:
            def analyze(self,content):
                return AnalysisResult([],0.8,Decision.BLOCK)
        summary=analyze_recent_messages(Reader(),Analyzer(),limit=2,max_text_bytes=20)
        self.assertTrue(summary['more_text_rows'])
        self.assertEqual(summary['analyzed'],1)
        self.assertEqual(summary['skipped_oversize'],1)
        self.assertEqual(summary['decisions']['BLOCK'],1)
        self.assertNotIn('private sample',str(summary))
        self.assertFalse(summary['send_blocked'])

    def test_invalid_limit_rejected_before_read(self):
        for limit in (0,True,1001,'1'):
            with self.assertRaises(SignalDatabaseError):
                analyze_recent_messages(None,None,limit=limit)
