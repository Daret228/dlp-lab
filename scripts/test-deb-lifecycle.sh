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
printf '#!/bin/sh\nexit 0\n' > "$root/opt/test-telegram"
chmod 755 "$root/opt/test-telegram"
cp "$root/opt/test-telegram" "$root/opt/test-signal"
/usr/sbin/chroot "$root" /bin/sh -eu <<'CHECKS'
export DEBIAN_FRONTEND=noninteractive
printf 'dlp-lab dlp-lab/configure boolean false\n' | debconf-set-selections
dpkg --no-triggers -i /tmp/yaml.deb /tmp/previous.deb
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
