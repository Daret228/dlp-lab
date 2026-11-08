"""Stage the reviewed Debian12 SQLCipher backport as a private agent library."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile

SHA256 = '1be243f9b4e36186990e93e951aec966ff67ed436ee0a05032349826a255670b'
VERSION = '4.6.1-2~dlplab12.1'
LIBRARY = './usr/lib/x86_64-linux-gnu/libsqlcipher.so.1.8.0'
COPYRIGHT = './usr/share/doc/libsqlcipher1/copyright'


def stage(root):
    path = Path(os.environ.get('DLP_SQLCIPHER_DEB', ''))
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != SHA256:
        raise ValueError('Debian12 build requires the reviewed SQLCipher DEB via DLP_SQLCIPHER_DEB (see docs/DEVELOPMENT.md)')
    metadata = subprocess.check_output(['dpkg-deb','-f',str(path),'Package','Version','Architecture'],text=True)
    if metadata != f'Package: libsqlcipher1\nVersion: {VERSION}\nArchitecture: amd64\n':
        raise ValueError('Unexpected SQLCipher package metadata')
    if subprocess.check_output(['dpkg-architecture','-qDEB_HOST_ARCH'],text=True).strip() != 'amd64':
        raise ValueError('Reviewed SQLCipher bundle is amd64 only')
    with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(path)]))) as archive:
        for member, destination, mode in (
            (LIBRARY,'usr/lib/dlp-lab/lib/libsqlcipher.so.1',0o644),
            (COPYRIGHT,'usr/share/doc/dlp-lab/copyright.sqlcipher',0o644),
        ):
            info=archive.getmember(member)
            if not info.isfile() or info.size > 8*1024*1024:
                raise ValueError('Unexpected bundled member')
            target=root/destination
            target.parent.mkdir(parents=True,exist_ok=True)
            target.parent.chmod(0o755)
            target.write_bytes(archive.extractfile(info).read())
            target.chmod(mode)
    return root/'usr/lib/dlp-lab/lib/libsqlcipher.so.1'
