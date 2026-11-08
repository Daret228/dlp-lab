"""Experimental SQLCipher reader. Requires an explicit offline copy and library.

No client initialization, migration, keyring access or logging is performed here.
"""
import ctypes as C
import hashlib
import re
from pathlib import Path


class SignalDatabaseError(ValueError):
    pass


def unwrap_linux_v11(blob: bytes, password: bytes) -> bytes:
    """Chromium Linux v11 only. No basic_text or empty-password fallback."""
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad
    except ImportError:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    if not password or blob[:3] != b'v11' or len(blob) < 19 or (len(blob)-3) % 16:
        raise SignalDatabaseError('Unsupported protected key format')
    derived = hashlib.pbkdf2_hmac('sha1', password, b'saltysalt', 1, 16)
    try:
        key = unpad(AES.new(derived, AES.MODE_CBC, b' '*16).decrypt(blob[3:]), 16)
    except ValueError:
        raise SignalDatabaseError('Protected key could not be decoded') from None
    if re.fullmatch(b'[0-9a-fA-F]{64}', key) is None:
        raise SignalDatabaseError('Invalid database key format')
    return key


PRIVATE_LIBRARY = Path("/usr/lib/dlp-lab/lib/libsqlcipher.so.1")


def library_name(path):
    if str(path) == "libsqlcipher.so.1":
        return str(PRIVATE_LIBRARY) if PRIVATE_LIBRARY.is_file() else str(path)
    return str(Path(path).resolve(strict=True))


def load_library(path):
    lib = C.CDLL(library_name(path))
    signatures = {
        'sqlite3_open_v2': ([C.c_char_p, C.POINTER(C.c_void_p), C.c_int, C.c_char_p], C.c_int),
        'sqlite3_close': ([C.c_void_p], C.c_int),
        'sqlite3_exec': ([C.c_void_p, C.c_char_p, C.c_void_p, C.c_void_p, C.c_void_p], C.c_int),
        'sqlite3_prepare_v2': ([C.c_void_p, C.c_char_p, C.c_int, C.POINTER(C.c_void_p), C.c_void_p], C.c_int),
        'sqlite3_step': ([C.c_void_p], C.c_int),
        'sqlite3_finalize': ([C.c_void_p], C.c_int),
        'sqlite3_column_count': ([C.c_void_p], C.c_int),
        'sqlite3_column_bytes': ([C.c_void_p, C.c_int], C.c_int),
        'sqlite3_column_text': ([C.c_void_p, C.c_int], C.c_void_p),
        'sqlite3_db_readonly': ([C.c_void_p, C.c_char_p], C.c_int),
        'sqlite3_limit': ([C.c_void_p, C.c_int, C.c_int], C.c_int),
    }
    for name,(args,result) in signatures.items():
        fn=getattr(lib,name); fn.argtypes=args; fn.restype=result
    return lib


class ReadOnlySignalDatabase:
    def __init__(self, copy_path, key_hex: bytes, library):
        if not isinstance(key_hex, bytes) or re.fullmatch(b'[0-9a-fA-F]{64}', key_hex) is None:
            raise SignalDatabaseError('Invalid database key format')
        self.lib=load_library(library); self.db=C.c_void_p()
        # mode=ro is enforced by sqlite3_open_v2 itself. No CREATE or READWRITE.
        uri=Path(copy_path).resolve(strict=True).as_uri()+'?mode=ro'
        rc=self.lib.sqlite3_open_v2(uri.encode(),C.byref(self.db),1|64,None)
        try:
            if rc or self.lib.sqlite3_db_readonly(self.db,b'main') != 1:
                raise SignalDatabaseError('Read-only database open failed')
            self.lib.sqlite3_limit(self.db,0,4*1024*1024)  # bounded row/string size
            self._exec(b'PRAGMA key="x\''+key_hex+b'\'"')
            self._exec(b'PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;')
            self.rows('SELECT count(*) FROM sqlite_master',1)
        except BaseException:
            self.close(); raise

    def _exec(self, sql):
        if self.lib.sqlite3_exec(self.db,sql,None,None,None):
            raise SignalDatabaseError('Database operation rejected')

    def rows(self, sql, max_rows=100):
        stmt=C.c_void_p()
        if self.lib.sqlite3_prepare_v2(self.db,sql.encode(),-1,C.byref(stmt),None):
            raise SignalDatabaseError('Database query rejected')
        try:
            output=[]
            while True:
                rc=self.lib.sqlite3_step(stmt)
                if rc==101:return output
                if rc!=100:raise SignalDatabaseError('Database read failed')
                if len(output)>=max_rows:raise SignalDatabaseError('Database result exceeds limit')
                row=[]
                for i in range(self.lib.sqlite3_column_count(stmt)):
                    size=self.lib.sqlite3_column_bytes(stmt,i)
                    if size>4*1024*1024:raise SignalDatabaseError('Database field exceeds limit')
                    ptr=self.lib.sqlite3_column_text(stmt,i)
                    row.append(C.string_at(ptr,size).decode('utf-8') if ptr else None)
                output.append(row)
        finally:self.lib.sqlite3_finalize(stmt)

    def close(self):
        if self.db and self.db.value:
            self.lib.sqlite3_close(self.db); self.db=C.c_void_p()

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def analyze_recent_messages(reader, analyzer, limit=100, max_text_bytes=16384):
    """Analyze a bounded recent text sample; return aggregates, never message data.

    Attachment-only/service rows and oversized text are not classified. This is
    retrospective analysis of stored bodies, not a sending control.
    """
    from .models import TextContent
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise SignalDatabaseError('Invalid message limit')
    if type(max_text_bytes) is not int or not 1 <= max_text_bytes <= 65536:
        raise SignalDatabaseError('Invalid text limit')
    # Parameters above are validated integers, all identifiers are fixed.
    rows = reader.rows(f'''SELECT
        CASE WHEN length(CAST(body AS BLOB)) <= {max_text_bytes} THEN body ELSE NULL END,
        length(CAST(body AS BLOB))
        FROM messages WHERE typeof(body)='text' AND length(body)>0
        ORDER BY received_at DESC, id DESC LIMIT {limit+1}''', limit+1)
    summary = {'event': 'signal_local_analysis_summary', 'source': 'offline_database_copy',
               'messenger': 'signal', 'scope': 'recent_nonempty_message_bodies',
               'sample_limit': limit, 'more_text_rows': len(rows)>limit,
               'analyzed': 0, 'skipped_oversize': 0, 'incomplete': 0,
               'decisions': {'ALLOW': 0, 'WARN': 0, 'BLOCK': 0},
               'enforcement': 'observe_only', 'send_blocked': False}
    for body, size in rows[:limit]:
        if body is None or int(size)>max_text_bytes:
            summary['skipped_oversize']+=1
            continue
        result=analyzer.analyze(TextContent(body,source='signal_local_database'))
        summary['analyzed']+=1
        summary['incomplete']+=int(not result.complete)
        summary['decisions'][str(result.decision)]+=1
    return summary
