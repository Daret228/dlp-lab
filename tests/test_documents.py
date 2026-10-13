import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from dataclasses import asdict

from dlp.analysis import ContentAnalyzer
from dlp.documents import extract_document, DocumentError
from dlp.document_worker import docx, ExtractionError, MAIN_TYPE
from dlp.models import FileContent, Decision
from dlp.policy import load_policy
from dlp.audit import JsonAudit
from dlp.fanotify import process_event, OPEN_PERM, RESPONSE

ROOT = Path(__file__).resolve().parents[1]
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'


def make_docx(body='<w:p><w:r><w:t>hello</w:t></w:r></w:p>', extras=None, main_type=MAIN_TYPE):
    parts = {
        '[Content_Types].xml': '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        f'<Override PartName="/word/document.xml" ContentType="{main_type}"/></Types>',
        '_rels/.rels': '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/></Relationships>',
        'word/document.xml': f'<w:document xmlns:w="{W}"><w:body>{body}</w:body></w:document>',
    }
    parts.update(extras or {})
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return output.getvalue()


def make_pdf(pages=('hello',)):
    # Small standards-shaped ASCII PDF fixture with accurate xref offsets.
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    kids = []
    for text in pages:
        page_id = len(objects) + 1
        kids.append(f'{page_id} 0 R')
        objects.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] '
                       f'/Resources << /Font << /F1 3 0 R >> >> /Contents {page_id+1} 0 R >>'.encode())
        content = f'BT /F1 12 Tf 72 700 Td ({text}) Tj ET'.encode() if text else b''
        objects.append(f'<< /Length {len(content)} >>\nstream\n'.encode() + content + b'\nendstream')
    objects[1] = f'<< /Type /Pages /Count {len(pages)} /Kids [{" ".join(kids)}] >>'.encode()
    result = bytearray(b'%PDF-1.4\n')
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n')
    xref = len(result)
    result.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        result.extend(f'{offset:010} 00000 n \n'.encode())
    result.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return bytes(result)


class DocumentTests(unittest.TestCase):
    def setUp(self):
        self.policy = load_policy(ROOT / 'config/policy.yaml')

    def analyze(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'renamed.bin'
            path.write_bytes(data)
            return ContentAnalyzer(self.policy).analyze(FileContent(path))

    def test_docx_split_runs_table_header_unicode(self):
        data = make_docx('<w:tbl><w:tr><w:tc><w:p><w:r><w:t>коммерческая </w:t></w:r>'
                         '<w:r><w:t>тайна</w:t></w:r></w:p></w:tc></w:tr></w:tbl>',
                         {'word/header1.xml': f'<w:hdr xmlns:w="{W}"><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:hdr>'})
        r = self.analyze(data)
        self.assertEqual((r.decision, r.complete), (Decision.BLOCK, True))
        self.assertEqual(r.metadata['parts'], 2)
        self.assertEqual(r.metadata['file_type'], 'docx')
        self.assertEqual(r.findings[0].location, (0, 18))
        stream = io.StringIO()
        JsonAudit(stream).emit({'result': asdict(r)})
        self.assertNotIn('коммерческая', stream.getvalue())

    def test_docx_public_and_warn(self):
        self.assertEqual(self.analyze(make_docx()).decision, Decision.ALLOW)
        r = self.analyze(make_docx('<w:p><w:r><w:t>test@example.org</w:t></w:r></w:p>'))
        self.assertEqual(r.decision, Decision.WARN)

    def test_archive_is_not_docx_by_extension(self):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            z.writestr('public.txt', 'hello')
        self.assertEqual(self.analyze(out.getvalue()).reason, 'file_type_denied')

    def test_macro_and_forged_docx_rejected(self):
        r = self.analyze(make_docx(main_type='application/vnd.ms-word.document.macroEnabled.main+xml'))
        self.assertEqual(r.reason, 'unsupported_docx_type')
        r = self.analyze(make_docx(extras={'_rels/.rels': '<Relationships/>'}))
        self.assertFalse(r.complete)
        self.assertEqual(r.decision, Decision.BLOCK)

    def test_xml_entities_and_utf16_rejected(self):
        for raw in ['<!DOCTYPE x [<!ENTITY a "secret">]><x>&a;</x>',
                    '<x/>'.encode('utf-16'), '<broken>']:
            r = self.analyze(make_docx(extras={'word/document.xml': raw}))
            self.assertFalse(r.complete)
            self.assertEqual(r.decision, Decision.BLOCK)

    def test_archive_bomb_and_traversal_rejected(self):
        for extras in [{'word/media/a': 'A' * 100000}, {'../outside': 'no'}]:
            r = self.analyze(make_docx(extras=extras))
            self.assertFalse(r.complete)
            self.assertEqual(r.decision, Decision.BLOCK)

    def test_partial_docx_keeps_findings_and_error_policy(self):
        self.policy['on_error'] = 'WARN'
        data = make_docx('<w:p><w:r><w:t>top secret</w:t></w:r></w:p>', {'word/media/image.png': b'fake'})
        r = self.analyze(data)
        self.assertFalse(r.complete)
        self.assertFalse(r.metadata['content_checked'])
        self.assertTrue(r.metadata['extracted_text_checked'])
        self.assertEqual(r.decision, Decision.BLOCK)
        self.assertTrue(r.findings)
        self.assertEqual(self.analyze(make_docx(extras={'word/media/image.png': b'fake'})).decision, Decision.WARN)

    def test_docx_text_limit_and_empty(self):
        with self.assertRaises(ExtractionError):
            docx(make_docx(), 2)
        r = self.analyze(make_docx(''))
        self.assertEqual(r.reason, 'no_extractable_text')

    @unittest.skipUnless(Path('/usr/bin/pdftotext').exists() and Path('/usr/bin/pdfinfo').exists(), 'Poppler needed')
    def test_real_pdf_allow_warn_block_and_empty_pages(self):
        for text, expected in [('hello', Decision.ALLOW), ('test@example.org', Decision.WARN), ('top secret', Decision.BLOCK)]:
            r = self.analyze(make_pdf((text,)))
            self.assertEqual((r.decision, r.complete), (expected, True), r)
            self.assertEqual(r.metadata['scope'], 'pdf_extracted_text_only')
        r = self.analyze(make_pdf(('',)))
        self.assertEqual(r.reason, 'no_extractable_text')
        r = self.analyze(make_pdf(('top secret', '')))
        self.assertEqual(r.reason, 'pdf_pages_without_text')
        self.assertFalse(r.complete)
        self.assertTrue(r.findings)

    def test_pdf_failure_and_dependency_absence(self):
        from dlp.document_worker import pdf
        with tempfile.TemporaryDirectory() as directory:
            with patch('dlp.document_worker.subprocess.run', side_effect=FileNotFoundError):
                with self.assertRaisesRegex(ExtractionError, 'pdf_dependency_missing'):
                    pdf(make_pdf(), 1000, Path(directory))

    def test_timeout_cleanup(self):
        # Real subprocess is started and must be reaped before returning.
        with self.assertRaisesRegex(DocumentError, 'document_timeout'):
            extract_document(make_docx(), 'docx', 1000, 0.000001)

    def test_docx_fanotify_borrowed_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'public.txt'
            path.write_bytes(make_docx('<w:p><w:r><w:t>top secret</w:t></w:r></w:p>'))
            fd = os.open(path, os.O_RDONLY)
            path.unlink()
            rfd, wfd = os.pipe()
            try:
                audit = io.StringIO()
                process_event(wfd, OPEN_PERM, fd, os.getpid(), ContentAnalyzer(self.policy), JsonAudit(audit))
                self.assertEqual(RESPONSE.unpack(os.read(rfd, 8)), (fd, 2))
                event = json.loads(audit.getvalue())
                self.assertEqual(event['result']['metadata']['file_type'], 'docx')
                self.assertFalse(event['send_confirmed'])
            finally:
                os.close(rfd)
                os.close(wfd)

    @unittest.skipUnless(Path('/usr/bin/pdfinfo').exists(), 'Poppler needed')
    def test_encrypted_pdf_fixture(self):
        r = self.analyze((ROOT / 'tests/fixtures/encrypted.pdf').read_bytes())
        self.assertEqual((r.decision, r.complete), (Decision.BLOCK, False))
        self.assertIn(r.reason, ('encrypted_document', 'pdf_encrypted_or_invalid'))

    def test_docx_encryption_flag_and_duplicates(self):
        import struct
        import warnings
        data = bytearray(make_docx())
        start = 0
        while True:
            index = data.find(b'PK\x01\x02', start)
            if index < 0:
                break
            flags = struct.unpack_from('<H', data, index + 8)[0]
            struct.pack_into('<H', data, index + 8, flags | 1)
            start = index + 4
        self.assertEqual(self.analyze(bytes(data)).reason, 'encrypted_document')
        output = io.BytesIO(make_docx())
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(output, 'a') as archive:
                archive.writestr('word/document.xml', '<x/>')
        self.assertEqual(self.analyze(output.getvalue()).reason, 'docx_archive_limits')

    def test_denied_docx_never_calls_extractor(self):
        self.policy['file_types']['allow'] = ['text']
        with patch('dlp.analysis.extract_document', side_effect=AssertionError('must not run')):
            self.assertEqual(self.analyze(make_docx()).reason, 'file_type_denied')
