#!/usr/bin/python3
"""Stage only allowlisted package inputs; no profiles, .deps, or project history."""
from pathlib import Path
import shutil
import subprocess
import os

root = Path('build/debian/dlp-lab')
if root.exists():
    shutil.rmtree(root)


def install(source, destination, mode=0o644):
    target = root / destination.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


for path in Path('src/dlp').rglob('*'):
    if path.is_file() and path.suffix in ('.py', '.json', '.html', '.js', '.css') and '__pycache__' not in path.parts:
        install(path, '/usr/lib/dlp-lab/src/dlp/' + str(path.relative_to('src/dlp')))
install('build/debian/fanotify-gateway', '/usr/libexec/dlp-lab/fanotify-gateway', 0o755)
install('packaging/admin_configure.py', '/usr/lib/dlp-lab/admin_configure.py')
install('packaging/dlp-agent', '/usr/bin/dlp-agent', 0o755)
install('packaging/dlp-lab-run-files', '/usr/sbin/dlp-lab-run-files', 0o755)
install('packaging/dlp-lab-configure', '/usr/sbin/dlp-lab-configure', 0o755)
install('packaging/dlp-lab-files.service', '/usr/lib/systemd/system/dlp-lab-files.service')
install('config/policy.yaml', '/etc/dlp-lab/system/policy.yaml')
install('debian/copyright', '/usr/share/doc/dlp-lab/copyright')
install('packaging/README.Debian', '/usr/share/doc/dlp-lab/README.Debian')
install('debian/changelog', '/usr/share/doc/dlp-lab/changelog')
subprocess.run(['gzip', '-n', '-9', str(root/'usr/share/doc/dlp-lab/changelog')], check=True)
for name in ('postinst', 'prerm', 'postrm', 'config', 'templates', 'conffiles'):
    install('debian/'+name, 'DEBIAN/'+name, 0o644 if name in ('conffiles', 'templates') else 0o755)
for path in root.rglob('*'):
    if path.is_dir():
        path.chmod(0o755)
subprocess.run(['strip', '--strip-unneeded', str(root/'usr/libexec/dlp-lab/fanotify-gateway')], check=True)
subprocess.run(['dpkg-shlibdeps', '-O', str(root/'usr/libexec/dlp-lab/fanotify-gateway')],
               stdout=open('debian/substvars', 'w'), check=True)
subprocess.run(['dpkg-gencontrol', '-pdlp-lab', '-P'+str(root)], check=True)
# dpkg verifies installed payload against these hashes; conffiles have own handling.
import hashlib
with (root/'DEBIAN/md5sums').open('w') as output:
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if path.is_file() and relative.parts[0] != 'DEBIAN':
            output.write(hashlib.md5(path.read_bytes()).hexdigest()+'  '+str(relative)+'\n')
# Stable archive timestamps for reproducible builds, while preserving permissions.
epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '1792483200'))
for path in root.rglob('*'):
    os.utime(path, (epoch, epoch), follow_symlinks=False)
root.chmod(0o755)
os.utime(root, (epoch, epoch))
