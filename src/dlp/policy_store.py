"""Restricted policy editing with validation, revision checks and private backups."""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import threading
import yaml
from .policy import load_policy, PolicyError, keys, number

ROOT = Path(__file__).resolve().parents[2]


class Conflict(ValueError):
    pass


class PolicyStore:
    def __init__(self, path=None, backups=None):
        self.path = Path(path) if path else ROOT / 'config/policy.yaml'
        self.backups = Path(backups) if backups else ROOT / 'build/policy-backups'
        self.lock = threading.Lock()

    def read(self):
        if self.path.is_symlink() or not self.path.is_file():
            raise PolicyError('Policy must be a regular file')
        with self.path.open('rb') as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise PolicyError('Policy too large')
        policy = load_policy(self.path)
        if self.path.read_bytes() != raw:
            raise Conflict('Policy changed')
        return raw, policy

    @staticmethod
    def view(raw, policy):
        return dict(version=hashlib.sha256(raw).hexdigest(), thresholds=policy['thresholds'],
                    on_error=policy['on_error'], sensitive_enabled=policy.get('sensitive_alerts', {}).get('enabled', False),
                    ml_enabled=policy.get('ml_alerts', {}).get('enabled', False))

    def get(self):
        with self.lock:
            return self.view(*self.read())

    def update(self, request, preview=False):
        with self.lock:
            keys(request, ('expected_version', 'thresholds', 'on_error', 'sensitive_enabled', 'ml_enabled'))
            keys(request['thresholds'], ('warn', 'block'))
            warn = number(request['thresholds']['warn'])
            block = number(request['thresholds']['block'])
            if warn >= block or request['on_error'] not in ('ALLOW', 'WARN', 'BLOCK') or type(request['sensitive_enabled']) is not bool or type(request['ml_enabled']) is not bool:
                raise PolicyError('Invalid settings')
            raw, policy = self.read()
            before = self.view(raw, policy)
            if request['expected_version'] != before['version']:
                raise Conflict('Policy changed')
            changes = {k: {'before': before[k], 'after': request[k]} for k in
                       ('thresholds', 'on_error', 'sensitive_enabled', 'ml_enabled') if before[k] != request[k]}
            if not changes or preview:
                return dict(policy=before, changes=changes, saved=False)
            policy['thresholds'] = request['thresholds']
            policy['on_error'] = request['on_error']
            policy['sensitive_alerts'] = dict(enabled=request['sensitive_enabled'], mode='rules', action='WARN')
            if 'ml_alerts' in policy:
                policy['ml_alerts']['enabled'] = request['ml_enabled']
            elif request['ml_enabled']:
                raise PolicyError('ML model is not configured')
            data = yaml.safe_dump(policy, allow_unicode=True, sort_keys=False).encode()
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=self.path.parent, delete=False) as f:
                    temporary = Path(f.name)
                    os.fchmod(f.fileno(), stat.S_IMODE(self.path.stat().st_mode))
                    f.write(data); f.flush(); os.fsync(f.fileno())
                load_policy(temporary)
                if self.path.is_symlink() or self.path.read_bytes() != raw:
                    raise Conflict('Policy changed')
                self.backups.mkdir(parents=True, exist_ok=True, mode=0o700)
                prefix = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-')
                with tempfile.NamedTemporaryFile(dir=self.backups, prefix=prefix, suffix='.yaml', delete=False) as backup:
                    backup.write(raw); backup.flush(); os.fsync(backup.fileno())
                if self.path.is_symlink() or self.path.read_bytes() != raw:
                    raise Conflict('Policy changed')
                os.replace(temporary, self.path)
                return dict(policy=self.view(data, policy), changes=changes, saved=True,
                            backup=Path(backup.name).name, restart_required=True)
            finally:
                if temporary: temporary.unlink(missing_ok=True)
