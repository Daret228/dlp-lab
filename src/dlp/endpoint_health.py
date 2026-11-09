"""Read administrator-owned service state; never inspect user messages."""
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import subprocess
import time
from .managed_session import trusted_json, STATES

POLICY = '/etc/dlp-lab/system/policy.yaml'


def service_state(unit):
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit, '-p', 'ActiveState', '--value'],
                                capture_output=True, text=True, timeout=5, check=True)
        value = result.stdout.strip()
        return value if value in ('active', 'inactive', 'failed', 'activating', 'deactivating') else 'unknown'
    except (OSError, subprocess.SubprocessError):
        return 'unknown'


def policy_version():
    try:
        with Path(POLICY).open('rb') as stream:
            raw = stream.read(262145)
    except OSError:
        return None
    return hashlib.sha256(raw).hexdigest() if 0 < len(raw) <= 262144 else None


def snapshot():
    files = service_state('dlp-lab-files.service')
    session = service_state('dlp-lab-session.service')
    status = 'stopped' if session in ('inactive', 'failed') else 'unavailable'
    if session == 'active':
        try:
            value = trusted_json(Path('/run/dlp-lab-session/state.json'))
            if (value.get('state') in STATES and type(value.get('updated')) in (int, float)
                    and 0 <= time.time()-value['updated'] <= 35):
                status = value['state']
        except (OSError, ValueError, TypeError, AttributeError):
            pass
    result = {'event': 'endpoint_health', 'timestamp': datetime.now(timezone.utc).isoformat(),
              'files_state': files, 'session_state': status,
              'management_ready': service_state('dlp-lab-admin-control.service') == 'active'}
    installed = policy_version()
    if installed:
        result['policy_version'] = installed
    # This agent build understands the policy command; older agents simply omit the flag.
    result['policy_channel'] = True
    return result
