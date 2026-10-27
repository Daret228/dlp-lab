#!/bin/bash
# Rootless installation test, no host package/service mutations.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
umask 022
if [[ ${1:-} != --inside ]]; then
    [[ $# == 2 || $# == 3 ]] || { echo 'Usage: test-deb-lifecycle.sh PACKAGE.deb PYTHON3-YAML.deb [PREVIOUS.deb]' >&2; exit 2; }
    scratch=$(mktemp -d "$PWD/build/deb-lifecycle.XXXXXX")
    echo "Isolated test root: $scratch"
    exec unshare --user --map-root-user --mount --pid --fork /bin/bash "$0" --inside "$scratch" "$(realpath "$1")" "$(realpath "$2")" "$(realpath "${3:-$1}")"
fi
scratch=$2
package=$3
yaml=$4
previous=$5
root=$scratch/root
mkdir -p "$root"/{usr,etc,var/lib,run,tmp,proc,dev,opt,home/testuser} "$scratch"/{upper,work}
mount --make-rprivate /
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
ln -s usr/lib64 "$root/lib64"
python3 "$(dirname "$0")/prepare-deb-test-root.py" "$root"
mkdir -p "$root/var/lib/dpkg"
(cd /var/lib/dpkg && tar --exclude=lock --exclude=lock-frontend --exclude=Lock -cf - .) | tar --no-same-owner -xf - -C "$root/var/lib/dpkg"
# Host statoverrides name unrelated service accounts; do not apply them here.
rm -f "$root/var/lib/dpkg/statoverride" "$root/var/lib/dpkg/statoverride-old"
mkdir -p "$root/var/cache/debconf"
cp /etc/debconf.conf "$root/etc/debconf.conf"
cp /etc/ld.so.cache "$root/etc/ld.so.cache"
printf 'root:x:0:0:root:/root:/bin/sh\ntestuser:x:1000:1000:Test:/home/testuser:/bin/sh\n' > "$root/etc/passwd"
printf 'root:x:0:\ntestuser:x:1000:\n' > "$root/etc/group"
cp /etc/os-release "$root/etc/os-release"
chmod 1777 "$root/tmp"
for device in null zero random urandom; do
    touch "$root/dev/$device"
    mount --bind "/dev/$device" "$root/dev/$device"
done
mount -t proc proc "$root/proc"
cp "$package" "$root/tmp/dlp.deb"
cp "$yaml" "$root/tmp/yaml.deb"
cp "$previous" "$root/tmp/previous.deb"
# Optional explicit runtime packages for new Depends absent from the host.
if [[ -n ${DLP_TEST_DEP_DIR:-} ]]; then
    mkdir -p "$root/tmp/extra-deps"
    cp "$DLP_TEST_DEP_DIR"/*.deb "$root/tmp/extra-deps/"
fi
printf '#!/bin/sh\nexit 0\n' > "$root/opt/test-telegram"
chmod 755 "$root/opt/test-telegram"
cp "$root/opt/test-telegram" "$root/opt/test-signal"
/usr/sbin/chroot "$root" /bin/sh -eu <<'CHECKS'
export DEBIAN_FRONTEND=noninteractive
printf 'dlp-lab dlp-lab/configure boolean false\n' | debconf-set-selections
if [ -d /tmp/extra-deps ]; then
    dpkg --no-triggers -i /tmp/extra-deps/*.deb
fi
# Host dpkg metadata may already list DLP; restore conffiles absent from this test root.
dpkg --force-confmiss --no-triggers -i /tmp/yaml.deb /tmp/previous.deb
# The first install must not invent a host target.
test ! -e /etc/dlp-lab/system-gateway.conf
/usr/sbin/dlp-lab-configure --user testuser --telegram /opt/test-telegram
/usr/bin/dlp-agent analyze --text 'public release' > /tmp/analysis.json
/usr/bin/python3 -c 'import json; assert json.load(open("/tmp/analysis.json"))["result"]["decision"] == "ALLOW"'
# Caller-controlled import paths must not execute in the packaged entry point.
printf 'raise RuntimeError("untrusted yaml imported")\n' > /tmp/yaml.py
(cd /tmp && PYTHONPATH=/tmp /usr/bin/dlp-agent analyze --text 'public release' > /tmp/isolated.json)
printf '\n# administrator edit retained across upgrade\n' >> /etc/dlp-lab/system/policy.yaml
sha256sum /etc/dlp-lab/system/policy.yaml /etc/dlp-lab/system/processes.yaml /etc/dlp-lab/system-gateway.conf > /tmp/before.sha256
dpkg --no-triggers -i /tmp/dlp.deb
sha256sum -c /tmp/before.sha256
test "$(stat -c %u /usr/libexec/dlp-lab/fanotify-gateway)" = 0
# Exercise the optional second messenger using protected synthetic executables.
/usr/sbin/dlp-lab-configure --user testuser --telegram /opt/test-telegram --signal /opt/test-signal --replace
/usr/bin/python3 - <<'PYVERIFY'
from pathlib import Path
import yaml
assert 'signal=/opt/test-signal' in Path('/etc/dlp-lab/system-gateway.conf').read_text()
s = Path('/etc/dlp-lab/system/processes.yaml').read_text()
assert '/opt/test-telegram' in s and '/opt/test-signal' in s
yaml.safe_load(s)
assert Path('/usr/sbin/dlp-lab-run-files').is_file()
assert Path('/usr/lib/systemd/system/dlp-lab-files.service').is_file()
PYVERIFY
# Packaged Signal CLI imports and dependency wiring (no real profile or keyring).
/usr/bin/dlp-agent signal-local-check --help > /tmp/signal-help.txt
/usr/bin/python3 -I - <<'PYSIGNAL'
import sys, ctypes, tempfile
from pathlib import Path
sys.path.insert(0, '/usr/lib/dlp-lab/src')
from dlp.signal_sqlcipher import load_library, ReadOnlySignalDatabase, unwrap_linux_v11
from dlp.signal_local import worker_command
from types import SimpleNamespace
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import hashlib
password=b'synthetic'; key=b'12'*32
derived=hashlib.pbkdf2_hmac('sha1',password,b'saltysalt',1,16)
blob=b'v11'+AES.new(derived,AES.MODE_CBC,b' '*16).encrypt(pad(key,16))
assert unwrap_linux_v11(blob,password)==key
lib=load_library('libsqlcipher.so.1')
with tempfile.TemporaryDirectory() as folder:
    path=Path(folder)/'synthetic.sqlite'; db=ctypes.c_void_p()
    assert lib.sqlite3_open_v2(str(path).encode(),ctypes.byref(db),6,None)==0
    sql=b"PRAGMA key=\"x'"+key+b"'\"; CREATE TABLE sample(body TEXT);"
    assert lib.sqlite3_exec(db,sql,None,None,None)==0
    lib.sqlite3_close(db)
    with ReadOnlySignalDatabase(path,key,'libsqlcipher.so.1') as reader:
        assert reader.rows('SELECT count(*) FROM sample')==[['0']]
args=SimpleNamespace(root='/tmp/no-profile',executable='/opt/test-signal',
                     sqlcipher_library='libsqlcipher.so.1',policy='/etc/dlp-lab/system/policy.yaml',limit=100)
command=worker_command(args,'/tmp/no-copy')
assert '-I' in command
import subprocess,json,os
result=subprocess.run(command,env={**os.environ,'PYTHONPATH':'/tmp'},capture_output=True)
assert result.returncode==2
assert json.loads(result.stdout)=={'reason':'run_as_desktop_user'}
PYSIGNAL
# Removal preserves settings, purge removes managed configuration only.
printf 'legacy sentinel\n' > /etc/dlp-lab/gateway.conf
dpkg --no-triggers --remove dlp-lab
test -f /etc/dlp-lab/system/policy.yaml
test -f /etc/dlp-lab/system-gateway.conf
test ! -e /usr/libexec/dlp-lab/fanotify-gateway
dpkg --no-triggers --purge dlp-lab
test ! -e /etc/dlp-lab/system/policy.yaml
test ! -e /etc/dlp-lab/system/processes.yaml
test ! -e /etc/dlp-lab/system-gateway.conf
test ! -e /usr/lib/dlp-lab
if debconf-show dlp-lab | grep -q 'dlp-lab/'; then
    echo 'debconf answers remained after purge' >&2
    exit 1
fi
test -f /etc/dlp-lab/gateway.conf
printf 'PASS: install, configure, isolated imports, upgrade preservation, remove, purge\n'
CHECKS
