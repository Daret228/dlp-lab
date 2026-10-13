"""Linux document extraction worker. No archive extraction, macros or network calls.

Resource limits contain resource use; they are not a security sandbox against
native parser vulnerabilities. Input and temporary output stay local.
"""
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile

MAX_EXPANDED = 8 * 1024 * 1024
MAX_ENTRIES = 256
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
CT = '{http://schemas.openxmlformats.org/package/2006/content-types}'
REL = '{http://schemas.openxmlformats.org/package/2006/relationships}'
OFFICE = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument'
MAIN_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'


class ExtractionError(Exception):
    pass


def xml(raw):
    # This reader supports UTF-8 XML only; rejecting other encodings also makes
    # the DTD/entity check unambiguous (no UTF-16 NUL-byte bypass).
    text = raw.decode('utf-8-sig')
    declaration = re.match(r'<\?xml[^?]*encoding=["\x27]([^"\x27]+)', text)
    if ('\x00' in text or '<!DOCTYPE' in text or '<!ENTITY' in text
            or declaration and declaration[1].lower() not in ('utf-8', 'utf8')):
        raise ExtractionError('unsupported_xml')
    return ET.fromstring(text)


def docx(data, limit):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > MAX_ENTRIES or len(names) != len(set(names)):
            raise ExtractionError('docx_archive_limits')
        if sum(entry.file_size for entry in entries) > MAX_EXPANDED:
            raise ExtractionError('docx_archive_limits')
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename
                    or '\x00' in entry.filename or len(entry.filename) > 256):
                raise ExtractionError('invalid_docx_path')
            if entry.flag_bits & 1:
                raise ExtractionError('encrypted_document')
            if (entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    or entry.file_size > max(1, entry.compress_size) * 200):
                raise ExtractionError('docx_archive_limits')
        def read(name):
            with archive.open(name) as stream:
                raw = stream.read(MAX_EXPANDED + 1)
                if len(raw) > MAX_EXPANDED:
                    raise ExtractionError('docx_archive_limits')
                return raw
        types = xml(read('[Content_Types].xml'))
        if types.tag != CT + 'Types':
            raise ExtractionError('invalid_docx')
        main = [e for e in types if e.get('PartName') == '/word/document.xml']
        if len(main) != 1 or main[0].get('ContentType') != MAIN_TYPE:
            raise ExtractionError('unsupported_docx_type')
        if any('macroEnabled' in e.get('ContentType', '') or 'vba' in e.get('ContentType', '').lower() for e in types):
            raise ExtractionError('unsupported_docx_type')
        relations = xml(read('_rels/.rels'))
        targets = [e for e in relations if e.get('Type') == OFFICE]
        if (relations.tag != REL + 'Relationships' or len(targets) != 1
                or targets[0].get('Target') not in ('word/document.xml', '/word/document.xml')
                or targets[0].get('TargetMode', 'Internal') != 'Internal'):
            raise ExtractionError('invalid_docx')
        stories = ['word/document.xml'] + sorted(n for n in names if re.fullmatch(
            r'word/(header\d+|footer\d+|footnotes|endnotes|comments)\.xml', n))
        chunks, size = [], 0
        partial = any(n.startswith(('word/media/', 'word/embeddings/', 'word/charts/',
                                    'word/diagrams/')) or 'vbaproject' in n.lower() for n in names)
        for name in stories:
            root = xml(read(name))
            if name == 'word/document.xml' and root.tag != W + 'document':
                raise ExtractionError('invalid_docx')
            for event, node in walk(root):
                part = ''
                if event == 'start':
                    if node.tag in (W + 't', W + 'delText', W + 'instrText'):
                        part = node.text or ''
                    elif node.tag == W + 'tab':
                        part = '\t'
                    elif node.tag in (W + 'br', W + 'cr'):
                        part = '\n'
                    elif node.tag in (W + 'altChunk', W + 'object', W + 'drawing', W + 'pict'):
                        partial = True
                elif node.tag in (W + 'p', W + 'tr'):
                    part = '\n'
                elif node.tag == W + 'tc':
                    part = '\t'
                size += len(part.encode('utf-8'))
                if size > limit:
                    raise ExtractionError('extracted_text_limit')
                chunks.append(part)
            chunks.append('\n')
            size += 1
        text = ''.join(chunks)
        if not text.strip():
            raise ExtractionError('no_extractable_text')
        return {'text': text, 'complete': not partial,
                'reason': 'unsupported_document_parts' if partial else None,
                'scope': 'docx_word_text_parts', 'parts': len(stories), 'ocr': False}


def walk(root):
    # Iterative traversal avoids Python recursion on nested untrusted XML.
    stack = [('start', root)]
    while stack:
        event, node = stack.pop()
        yield event, node
        if event == 'start':
            stack.append(('end', node))
            stack.extend(('start', child) for child in reversed(node))


def pdf(data, limit, directory):
    source = directory / 'input.pdf'
    source.write_bytes(data)
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(directory)}
    def run(args, output):
        with output.open('wb') as out, (directory / 'errors').open('wb') as err:
            try:
                p = subprocess.run(args, stdout=out, stderr=err, env=env, timeout=25)
            except FileNotFoundError as exc:
                raise ExtractionError('pdf_dependency_missing') from exc
        # Do not accept recovered/damaged PDFs as fully checked, and never log
        # diagnostics (they can contain document data).
        if p.returncode or (directory / 'errors').stat().st_size:
            raise ExtractionError('pdf_encrypted_or_invalid')
    info = directory / 'info'
    run(['/usr/bin/pdfinfo', str(source)], info)
    raw_info = info.read_bytes()
    if len(raw_info) > 65536:
        raise ExtractionError('pdf_metadata_limit')
    if re.search(rb'^Encrypted:\s+yes', raw_info, re.M):
        raise ExtractionError('encrypted_document')
    pages = re.search(rb'^Pages:\s+(\d+)', raw_info, re.M)
    if not pages or not 1 <= int(pages[1]) <= 200:
        raise ExtractionError('pdf_page_limit')
    output = directory / 'text'
    run(['/usr/bin/pdftotext', '-enc', 'UTF-8', str(source), '-'], output)
    if output.stat().st_size > limit:
        raise ExtractionError('extracted_text_limit')
    text = output.read_text(encoding='utf-8')
    if not text.strip():
        raise ExtractionError('no_extractable_text')
    parts = text.split('\f')
    if parts and not parts[-1].strip():
        parts.pop()
    partial = len(parts) != int(pages[1]) or any(not p.strip() for p in parts)
    return {'text': text, 'complete': not partial,
            'reason': 'pdf_pages_without_text' if partial else None,
            'scope': 'pdf_extracted_text_only', 'pages': int(pages[1]), 'ocr': False}


def main():
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (20 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    os.umask(0o077)
    kind, limit, directory = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])
    try:
        data = sys.stdin.buffer.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ExtractionError('document_input_limit')
        result = docx(data, limit) if kind == 'docx' else pdf(data, limit, directory)
        if len(result['text'].encode()) > limit:
            raise ExtractionError('extracted_text_limit')
    except ExtractionError as exc:
        result = {'error': str(exc)}
    except Exception:
        result = {'error': 'invalid_document'}
    sys.stdout.write(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
