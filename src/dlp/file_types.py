"""Bounded signature classification, not full format validation or malware scanning.

ZIP candidates are refined by package entries; extraction validates the DOCX.
Filesystem names are ignored.
"""

import io
import zipfile


SUPPORTED_TYPES = frozenset({
    'text', 'elf', 'dos_pe', 'script', 'zip', 'gzip', '7z', 'rar',
    'pdf', 'docx', 'png', 'jpeg', 'ole',
})


def detect_type(data: bytes) -> str:
    signatures = (
        (b'\x7fELF', 'elf'), (b'MZ', 'dos_pe'), (b'#!', 'script'),
        (b'PK\x03\x04', 'zip'), (b'PK\x05\x06', 'zip'), (b'PK\x07\x08', 'zip'),
        (b'\x1f\x8b', 'gzip'), (b'7z\xbc\xaf\x27\x1c', '7z'),
        (b'Rar!\x1a\x07', 'rar'), (b'%PDF-', 'pdf'),
        (b'\x89PNG\r\n\x1a\n', 'png'), (b'\xff\xd8\xff', 'jpeg'),
        (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole'),
    )
    for signature, kind in signatures:
        if data.startswith(signature):
            if kind == 'zip':
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as archive:
                        names = archive.namelist()
                        if len(names) <= 256 and {'[Content_Types].xml', '_rels/.rels',
                                                'word/document.xml'}.issubset(names):
                            return 'docx'
                except (zipfile.BadZipFile, ValueError):
                    pass
            return kind
    try:
        text = data.decode('utf-8-sig', errors='strict')
    except UnicodeError:
        return 'unknown'
    # Do not treat arbitrary UTF-8-decodable binary bytes as ordinary text.
    if any(ord(c) < 32 and c not in '\t\r\n\f' or 127 <= ord(c) < 160 for c in text):
        return 'unknown'
    return 'text'
