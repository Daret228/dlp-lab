import os
from pathlib import Path
import tempfile
import unittest
from dlp.filesystem_scope import session_authority


class SessionAuthorityTests(unittest.TestCase):
    def test_exact_private_file_only(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            path = home / '.Xauthority'
            path.write_bytes(b'synthetic')
            path.chmod(0o600)
            with path.open('rb') as stream:
                fd = stream.fileno()
                self.assertTrue(session_authority(str(path), fd, root, os.getuid()))
                self.assertFalse(session_authority(str(path), fd, root, os.getuid()+1))
                self.assertFalse(session_authority(str(path)+' (deleted)', fd, root, os.getuid()))
                self.assertFalse(session_authority(str(home/'secret.txt'), fd, root, os.getuid()))
                path.chmod(0o644)
                self.assertFalse(session_authority(str(path), fd, root, os.getuid()))
                path.chmod(0o600)
                os.link(path, home/'alias')
                self.assertFalse(session_authority(str(path), fd, root, os.getuid()))
                (home/'alias').unlink()
                path.rename(home/'old')
                path.write_bytes(b'replacement')
                path.chmod(0o600)
                self.assertFalse(session_authority(str(path), fd, root, os.getuid()))
                path.unlink()
                path.symlink_to(home/'old')
                self.assertFalse(session_authority(str(path), fd, root, os.getuid()))
