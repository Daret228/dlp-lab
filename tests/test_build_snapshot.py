"""Exercise snapshot cleanup without actually building or installing packages."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/build-deb.sh'


class BuildSnapshotTests(unittest.TestCase):
    def execute_build(self, *, failure=False, keep=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('debian', 'packaging', 'src', 'native', 'config', 'tests',
                         'scripts', 'examples', 'data', 'docker', '.deps', 'bin'):
                (root/name).mkdir()
            for name in ('Makefile', 'pyproject.toml', 'LICENSE'):
                (root/name).write_text('fixture')
            (root/'.deps/sentinel').write_text('preserve dependency')
            shutil.copyfile(SCRIPT, root/'scripts/build-deb.sh')
            builder = root/'bin/dpkg-buildpackage'
            builder.write_text('#!/bin/sh\nprintf "package" > ../fixture.deb\nexit '+('7' if failure else '0')+'\n')
            builder.chmod(0o755)
            env = dict(os.environ, PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],
                       DLP_KEEP_BUILD='1' if keep else '0')
            env.pop('DLP_SQLCIPHER_DEB', None)
            result = subprocess.run(['bash', str(root/'scripts/build-deb.sh'), '--local-deps'],
                                    env=env, capture_output=True, text=True)
            snapshots = list((root/'build').glob('deb-source.*'))
            self.assertEqual(result.returncode, 7 if failure else 0, result.stderr)
            self.assertEqual(len(snapshots), 1 if failure or keep else 0)
            self.assertEqual((root/'build/fixture.deb').read_text(), 'package')
            self.assertEqual((root/'.deps/sentinel').read_text(), 'preserve dependency')
            if failure or keep:
                self.assertIn(str(snapshots[0]), result.stderr)

    def test_success_removes_only_snapshot_and_keeps_output(self):
        self.execute_build()

    def test_failure_retains_snapshot_and_exit_code(self):
        self.execute_build(failure=True)

    def test_explicit_keep_retains_successful_snapshot(self):
        self.execute_build(keep=True)
