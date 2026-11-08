#!/bin/bash
# Build in an allowlisted snapshot so dpkg output stays in build/.
set -euo pipefail
project=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$project"
mode=${1:-}
[[ $# -le 1 && ( -z $mode || $mode == --local-deps ) ]] || { echo 'Usage: build-deb.sh [--local-deps]' >&2; exit 2; }
if [[ -z $mode ]]; then
    dpkg-checkbuilddeps
else
    echo 'Local dependency mode: build dependency check skipped; tests use project .deps. Project Python dependencies are not bundled.' >&2
fi
# Debian12 builds require a reviewed private SQLCipher input; keep it outside snapshots.
if [[ -n ${DLP_SQLCIPHER_DEB:-} ]]; then
    export DLP_SQLCIPHER_DEB=$(realpath "$DLP_SQLCIPHER_DEB")
fi
snapshot=$(mktemp -d "$project/build/deb-source.XXXXXX")
python3 - "$snapshot" "$mode" <<'PY'
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
for name in ('debian', 'packaging', 'src', 'native', 'config', 'tests', 'scripts', 'examples', 'data', 'docker'):
    shutil.copytree(name, root/name, ignore=shutil.ignore_patterns('__pycache__', 'files', 'substvars'))
for name in ('Makefile', 'pyproject.toml', 'LICENSE'):
    shutil.copyfile(name, root/name)
if sys.argv[2] == '--local-deps':
    (root/'.deps').symlink_to(Path('.deps').resolve(), target_is_directory=True)
PY
cd "$snapshot"
if [[ $mode == --local-deps ]]; then
    exec dpkg-buildpackage -b -us -uc -d
else
    exec dpkg-buildpackage -b -us -uc
fi
