import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_documents import make_docx,make_pdf

ROOT=Path(__file__).resolve().parents[1]


class SensitiveCLITests(unittest.TestCase):
    def run_cli(self,args,input_text=None):
        env=dict(os.environ,PYTHONPATH=str(ROOT/'src')+':'+str(ROOT/'.deps'))
        r=subprocess.run([sys.executable,str(ROOT/'scripts/predict-sensitive.py'),'--mode','rules',*args],
                         input=input_text,text=True,capture_output=True,env=env,timeout=8)
        return r,json.loads(r.stdout)

    def test_plain_text_and_no_echo(self):
        secret='Пароль: сиреневыйлес'
        r,out=self.run_cli(['--stdin'],secret)
        self.assertEqual(r.returncode,0)
        self.assertEqual(out['labels'],['credentials'])
        self.assertNotIn(secret,r.stdout+r.stderr)
        self.assertEqual(out['enforcement'],'none')

    def test_docx_and_partial_docx(self):
        for extras,complete in [(None,True),({'word/media/x.bin':b'fake'},False)]:
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'sample.docx'
                path.write_bytes(make_docx('<w:p><w:r><w:t>Пароль: сиреневыйлес</w:t></w:r></w:p>',extras=extras))
                r,out=self.run_cli(['--file',str(path)])
                self.assertEqual(out['labels'],['credentials'])
                self.assertEqual(out['complete'],complete)
                self.assertEqual(r.returncode,0 if complete else 2)

    @unittest.skipUnless(Path('/usr/bin/pdftotext').exists() and Path('/usr/bin/pdfinfo').exists(),'Poppler missing')
    def test_pdf(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sample.pdf';path.write_bytes(make_pdf(('Password: y7Q!3nR5mV',)))
            r,out=self.run_cli(['--file',str(path)])
            self.assertEqual(r.returncode,0);self.assertEqual(out['labels'],['credentials'])
            self.assertEqual(out['scope'],'pdf_extracted_text_only')

    def test_overlimit_is_not_negative_classification(self):
        r,out=self.run_cli(['--stdin'],'x'*17000)
        self.assertEqual(r.returncode,2);self.assertFalse(out['complete'])
        self.assertIsNone(out['labels'])

    def test_denied_file_format(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'looks.txt';path.write_bytes(b'\x7fELFfake')
            r,out=self.run_cli(['--file',str(path)])
            self.assertEqual(r.returncode,2);self.assertEqual(out['reason'],'file_type_denied')
