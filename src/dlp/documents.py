"""Run document parsers in a bounded, disposable unprivileged process group."""
import json
import os
import signal
import subprocess
import sys
import tempfile


class DocumentError(ValueError):
    pass


def extract_document(data, kind, max_text_bytes, timeout):
    # Parent owns the directory so it is removed even when the worker is killed.
    with tempfile.TemporaryDirectory(prefix='dlp-document-') as directory:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                [sys.executable, '-m', 'dlp.document_worker', kind,
                 str(min(max_text_bytes, 4 * 1024 * 1024)), directory],
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                start_new_session=True, close_fds=True)
            try:
                process.communicate(input=data, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                raise DocumentError('document_timeout') from exc
            finally:
                # Includes pdfinfo/pdftotext descendants, also on outer SIGALRM.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            if process.returncode != 0:
                raise DocumentError('document_worker_failed')
            output.seek(0)
            raw = output.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise DocumentError('extracted_text_limit')
            try:
                result = json.loads(raw)
                if result.get('error'):
                    raise DocumentError(result['error'])
                if not isinstance(result['text'], str) or len(result['text'].encode()) > max_text_bytes:
                    raise DocumentError('invalid_extraction_result')
                return result
            except (KeyError, json.JSONDecodeError, UnicodeError, TypeError) as exc:
                raise DocumentError('invalid_extraction_result') from exc
