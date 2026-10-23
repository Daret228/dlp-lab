#!/usr/bin/python3
"""Copy a small host runtime into an ephemeral root; never copy user profiles."""
import glob
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1])
(root/"usr/lib64").mkdir(parents=True, exist_ok=True)
binaries = '''sh dash bash perl python3 python3.13 dpkg dpkg-deb dpkg-query
 dpkg-maintscript-helper deb-systemd-helper deb-systemd-invoke debconf-set-selections
 debconf-communicate debconf-show py3compile py3clean
 find dirname basename ln mkdir chmod chown stat sha256sum rm rmdir tar gzip xz
 diff cmp cat readlink realpath sort touch sed grep head tail cut tr id env printf test
 systemctl dpkg-divert update-alternatives'''.split()
binaries += [p.name for p in Path('/usr/bin').glob('dpkg*') if p.is_file()]
for name in binaries:
    source = Path('/usr/bin')/name
    if source.exists():
        target = root/'usr/bin'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=True)
for name in ('ldconfig', 'start-stop-daemon'):
    target = root/'usr/sbin'/name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path('/usr/sbin')/name, target)
for pattern in ('/usr/lib/python3.13', '/usr/share/python3', '/usr/share/debconf',
                '/usr/share/perl', '/usr/share/perl5',
                '/usr/lib/x86_64-linux-gnu/perl', '/usr/lib/x86_64-linux-gnu/perl-base'):
    for source in glob.glob(pattern):
        shutil.copytree(source, root/source.lstrip('/'), symlinks=True, dirs_exist_ok=True)
# Resolve each executable/module's shared libraries on the host, not in the new root.
libs = set()
for path in list(root.rglob('*')):
    if not path.is_file() or path.is_symlink():
        continue
    with path.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            continue
    output = subprocess.run(['ldd', str(path)], text=True, capture_output=True, check=False).stdout
    for line in output.splitlines():
        for part in line.split():
            if part.startswith('/'):
                libs.add(part)
# PyYAML's extension needs this even before it is unpacked into the root.
libs.add('/usr/lib/x86_64-linux-gnu/libyaml-0.so.2')
for lib in libs:
    canonical = str(Path(lib).resolve())
    target = root/lib.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(canonical, target)
