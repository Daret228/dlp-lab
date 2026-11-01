"""Experimental offline Telegram Desktop 7.2.8/7.2.9 draft reader.

Own test profiles only. No network, login/session extraction or source writes.
See ADR-007. Private values must never be logged or used in exception messages.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import struct

VERSION = 7002008
SUPPORTED_VERSIONS = {7002008, 7002009}
MAX_FILE = 4 * 1024 * 1024
MAX_DRAFTS = 32
MAX_TEXT = 1024 * 1024


class StorageError(ValueError):
    """Messages are fixed codes, never derived from profile content."""


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise StorageError('truncated_record')
        result = self.data[self.pos:self.pos+n]
        self.pos += n
        return result

    def number(self, fmt):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))[0]

    def u32(self):
        return self.number('>I')

    def u64(self):
        return self.number('>Q')

    def blob(self, limit=MAX_FILE):
        n = self.u32()
        if n == 0xffffffff:
            return b''
        if n > limit:
            raise StorageError('field_size_limit')
        return self.take(n)

    def text(self):
        try:
            return self.blob(MAX_TEXT).decode('utf-16-be', errors='strict')
        except UnicodeError:
            raise StorageError('invalid_text_encoding') from None

    def count(self, limit):
        n = self.u32()
        if n > limit:
            raise StorageError('record_count_limit')
        return n

    def end(self):
        if self.pos != len(self.data):
            raise StorageError('unexpected_trailing_data')


def container(data):
    if not 24 <= len(data) <= MAX_FILE or data[:4] != b'TDF$':
        raise StorageError('invalid_container')
    version = struct.unpack('<I', data[4:8])[0]
    if version not in SUPPORTED_VERSIONS:
        raise StorageError('unsupported_writer_version')
    body = data[8:-16]
    digest = hashlib.md5(body + struct.pack('<I', len(body)) + data[4:8] + b'TDF$').digest()
    if not hmac.compare_digest(digest, data[-16:]):
        raise StorageError('container_checksum_mismatch')
    return Reader(body)


def password_key(password, salt):
    if len(salt) != 32 or len(password) > 1024:
        raise StorageError('invalid_password_parameters')
    initial = hashlib.sha512(salt + password + salt).digest()
    return hashlib.pbkdf2_hmac('sha512', initial, salt, 100000 if password else 1, 256)


def aes_parameters(local_key, msg_key):
    if len(local_key) != 256 or len(msg_key) != 16:
        raise StorageError('invalid_key_length')
    # Telegram aesDecryptLocal uses prepareAES_oldmtp(send=false), hence x=8.
    a = hashlib.sha1(msg_key + local_key[8:40]).digest()
    b = hashlib.sha1(local_key[40:56] + msg_key + local_key[56:72]).digest()
    c = hashlib.sha1(local_key[72:104] + msg_key).digest()
    d = hashlib.sha1(msg_key + local_key[104:136]).digest()
    return a[:8]+b[8:20]+c[4:16], a[8:20]+b[:8]+c[16:20]+d[:8]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def decrypt(encrypted, local_key):
    if not 32 <= len(encrypted) <= MAX_FILE or len(encrypted) % 16:
        raise StorageError('invalid_encrypted_length')
    try:
        from Cryptodome.Cipher import AES  # Debian package namespace.
    except ImportError:
        from Crypto.Cipher import AES  # Optional pip dependency.
    msg_key = encrypted[:16]
    key, iv = aes_parameters(local_key, msg_key)
    cipher = AES.new(key, AES.MODE_ECB)
    prev_cipher, prev_plain = iv[:16], iv[16:]
    plain = bytearray()
    for offset in range(16, len(encrypted), 16):
        block = encrypted[offset:offset+16]
        decoded = xor(cipher.decrypt(xor(block, prev_plain)), prev_cipher)
        plain.extend(decoded)
        prev_cipher, prev_plain = block, decoded
    if not hmac.compare_digest(hashlib.sha1(plain).digest()[:16], msg_key):
        raise StorageError('wrong_password_or_invalid_encrypted_data')
    size = struct.unpack('<I', plain[:4])[0]
    if size < 4 or size > len(plain) or len(plain)-size >= 16:
        raise StorageError('invalid_plaintext_length')
    return bytes(plain[4:size])


def unlock_key(data, password):
    stream = container(data)
    salt, protected = stream.blob(), stream.blob()
    stream.blob()  # Encrypted account-index metadata, not needed by this reader.
    stream.end()
    key = decrypt(protected, password_key(password, salt))
    if len(key) != 256:
        raise StorageError('invalid_local_key')
    return key


def map_references(data, key):
    outer = container(data)
    outer.blob(); outer.blob()  # Legacy fields, not used for a modern profile.
    encrypted = outer.blob()
    outer.end()
    stream = Reader(decrypt(encrypted, key))
    drafts, seen = {}, set()
    locations = 0
    single = {4,7,8,9,10,11,12,13,14,15,17,18,19,24,26,27,28,30}
    while stream.pos < len(stream.data):
        kind = stream.u32()
        if kind in seen:
            raise StorageError('duplicate_map_section')
        seen.add(kind)
        if kind in (1,2,29):
            for _ in range(stream.count(MAX_DRAFTS if kind == 1 else 10000)):
                file_key, peer = stream.u64(), stream.u64()
                if kind == 1:
                    if not file_key or peer in drafts or file_key in drafts.values():
                        raise StorageError('invalid_draft_reference')
                    drafts[peer] = file_key
        elif kind in (3,5,6):
            stream.take(stream.count(10000) * 28)
        elif kind == 4:
            locations = stream.u64()
        elif kind in single:
            stream.take(8)
        elif kind in (16,20,22,23):
            stream.take({16:32,20:16,22:24,23:24}[kind])
        elif kind == 21:
            stream.blob()  # Serialized self: not decoded or reported.
        elif kind == 25:
            stream.blob(); stream.blob()  # Not interpreted or exported.
        else:
            raise StorageError('unsupported_map_section')
    return drafts, locations


def draft_map(data, key):
    return map_references(data, key)[0]


def file_part(number):
    return f'{number:016X}'[::-1]


def parse_drafts(data, key, expected_peer):
    outer = container(data)
    encrypted = outer.blob(); outer.end()
    stream = Reader(decrypt(encrypted, key))
    tag, peer = stream.u64(), stream.u64()
    tags = {0xffffffffffffff01,0xffffffffffffff03,0xffffffffffffff05,0xffffffffffffff06}
    if tag not in tags:
        raise StorageError('unsupported_draft_schema')
    if peer != expected_peer:
        raise StorageError('draft_reference_mismatch')
    count = stream.count(1000)
    if not count:
        raise StorageError('empty_draft_record')
    result, seen = [], set()
    for _ in range(count):
        draft_id = stream.take(4 if tag == 0xffffffffffffff01 else 8)
        if draft_id in seen:
            raise StorageError('duplicate_draft_record')
        seen.add(draft_id)
        text = stream.text()
        formatting = stream.blob(MAX_TEXT)
        if tag in (0xffffffffffffff05,0xffffffffffffff06):
            reply_peer, reply_message = stream.u64(), stream.u64()
            if tag == 0xffffffffffffff06:
                stream.take(16)  # SuggestOptions, not a timestamp.
            url = stream.text()
            for _ in range(5):
                if stream.u32() not in (0,1):
                    raise StorageError('invalid_draft_flag')
            reply_present = bool(reply_peer or reply_message)
            preview_present = bool(url)
        else:
            reply_present = bool(stream.u64())
            if stream.u32() not in (0,1,2):
                raise StorageError('invalid_preview_state')
            preview_present = None
        result.append((text, {'formatting_present': bool(formatting),
                              'reply_present': reply_present,
                              'preview_present': preview_present,
                              'draft_schema': f'{tag:016X}'}))
    stream.end()
    return result


class ProfileFiles:
    """Dirfd-relative reads of current-user-owned regular files; no symlinks."""
    def __init__(self, root):
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME)
        if os.fstat(self.fd).st_uid != os.getuid():
            self.close()
            raise StorageError('foreign_profile_owner')

    def close(self):
        os.close(self.fd)

    def read(self, parts):
        if not parts or any(not p or '/' in p or p in ('.','..') for p in parts):
            raise StorageError('invalid_relative_path')
        fd = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME, dir_fd=fd)
                os.close(fd); fd = child
                if os.fstat(fd).st_uid != os.getuid():
                    raise StorageError('foreign_directory_owner')
            handle = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME, dir_fd=fd)
            try:
                before = os.fstat(handle)
                if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_size > MAX_FILE:
                    raise StorageError('unsupported_file')
                data = os.pread(handle, MAX_FILE+1, 0)
                after = os.fstat(handle)
                identity = lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                if identity(before) != identity(after) or len(data) != before.st_size:
                    raise StorageError('file_changed_during_read')
                return data
            finally:
                os.close(handle)
        finally:
            os.close(fd)

    def account(self):
        candidates = []
        with os.scandir(self.fd) as entries:
            for entry in entries:
                if re.fullmatch('[A-F0-9]{16}', entry.name) and entry.is_dir(follow_symlinks=False):
                    candidates.append(entry.name)
        if len(candidates) != 1:
            raise StorageError('requires_exactly_one_account_directory')
        return candidates[0]


def collect(profile, password):
    """Return a bounded encrypted subset in memory; never touch configs/session files."""
    account = profile.account()
    files = {('key_datas',): profile.read(('key_datas',)),
             (account,'maps'): profile.read((account,'maps'))}
    key = unlock_key(files[('key_datas',)], password)
    refs = draft_map(files[(account,'maps')], key)
    for file_key in refs.values():
        parts = (account, file_part(file_key)+'s')
        files[parts] = profile.read(parts)
    # Detect source changes over collection; this is not a filesystem transaction.
    if any(profile.read(parts) != data for parts,data in files.items()):
        raise StorageError('profile_changed_during_collection')
    return account, files


def selected_draft(account, files, password, marker):
    if not marker.startswith('DLP_STORAGE_TEST') or not 16 <= len(marker) <= 128:
        raise StorageError('invalid_test_marker')
    key = unlock_key(files[('key_datas',)], password)
    refs = draft_map(files[(account,'maps')], key)
    matches = []
    scanned = 0
    for peer, file_key in refs.items():
        parts = (account,file_part(file_key)+'s')
        if parts not in files:
            raise StorageError('missing_draft_file')
        for text, metadata in parse_drafts(files[parts], key, peer):
            scanned += 1
            if marker in text:
                matches.append((text,metadata))
    if len(matches) != 1:
        raise StorageError('requires_exactly_one_marked_draft')
    text, metadata = matches[0]
    return text, {**metadata, 'draft_files_scanned': len(refs), 'draft_records_scanned': scanned,
                  'writer_versions': sorted({struct.unpack('<I', data[4:8])[0] for data in files.values()})}
