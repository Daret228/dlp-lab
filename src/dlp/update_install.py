"""Oneshot root installer for the staged agent package.

Started on demand by dlp-lab-admin-control via `systemctl start --wait`.
Runs as its own unit without the broker's sandbox because package
installation needs the full dpkg/apt filesystem surface; the fixed staged
pair is the only input and is re-validated here before anything runs.
"""
import subprocess
import sys

from .update_assist import installed_version, perform_install
from .update_channel import STAGED_UPDATE, STAGED_UPDATE_META, validate_staged_update


def apply_staged():
    meta = validate_staged_update(STAGED_UPDATE, STAGED_UPDATE_META)
    if installed_version() == meta['version']:
        # A previous attempt finished after its caller was restarted.
        return 0
    perform_install(STAGED_UPDATE, expected_version=meta['version'])
    return 0


def main():
    try:
        return apply_staged()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Exception text may carry paths; the type is enough for the journal.
        print('Staged update failed:', type(error).__name__, file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
