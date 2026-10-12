"""Explicit executable identities; no basename or command-line heuristics."""
from dataclasses import dataclass
import os
from pathlib import Path
from .policy import StrictLoader, PolicyError, keys
import yaml


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    executable: str
    start_ticks: int
    device: int
    inode: int


def identify(pid, proc=Path('/proc')):
    def snapshot():
        base = proc / str(pid)
        # comm may contain spaces and parentheses; fields after its last ')' start at field 3.
        fields = (base/'stat').read_text().rsplit(')', 1)[1].split()
        start = int(fields[19])
        uids = next(line.split()[1:] for line in (base/'status').read_text().splitlines() if line.startswith('Uid:'))
        if len(uids) != 4 or len(set(uids)) != 1:
            raise ValueError('mixed process credentials')
        exe = os.readlink(base/'exe')
        if exe.endswith(' (deleted)'):
            raise ValueError('deleted executable')
        st = (base/'exe').stat()
        return ProcessIdentity(pid, int(uids[0]), exe, start, st.st_dev, st.st_ino)
    if pid <= 0:
        return None
    try:
        first = snapshot()
        return first if first == snapshot() else None
    except (OSError, ValueError, IndexError, StopIteration):
        return None


class ExecutableAdapter:
    def __init__(self, name, paths):
        self.name = name
        self.paths = tuple(paths)

    def matches(self, identity):
        if identity is None:
            return False
        for path in self.paths:
            try:
                expected = Path(path).resolve(strict=True)
                st = expected.stat()
                if str(expected) == identity.executable and (st.st_dev, st.st_ino) == (identity.device, identity.inode):
                    return True
            except OSError:
                continue
        return False

    def capabilities(self):
        return {'process_detection': True, 'draft_text': False, 'send_veto': False, 'local_storage': False}


class TelegramAdapter(ExecutableAdapter):
    pass


class ExpressAdapter(ExecutableAdapter):
    pass


class ProcessFilter:
    def __init__(self, config):
        self.mode = config['mode']
        self.uid = config['uid']
        kinds = {'telegram': TelegramAdapter, 'express': ExpressAdapter}
        self.adapters = [kinds.get(name, ExecutableAdapter)(name, item['executables'])
                         for name, item in config['messengers'].items() if item['enabled']]

    def match(self, identity):
        if identity is None or identity.uid != self.uid:
            return None
        return next((a.name for a in self.adapters if a.matches(identity)), None)


def load_process_config(path):
    path = Path(path)
    try:
        if path.stat().st_size > 65536:
            raise PolicyError('Process config exceeds 64 KiB')
        config = yaml.load(path.read_text(), Loader=StrictLoader)
        keys(config, ('version', 'mode', 'uid', 'messengers'))
        if type(config['version']) is not int or config['version'] != 1:
            raise PolicyError('Unsupported process config version')
        if config['mode'] not in ('all', 'messengers'):
            raise PolicyError('mode must be all or messengers')
        if type(config['uid']) is not int or config['uid'] != os.getuid():
            raise PolicyError('Process filter must target current user UID')
        if not isinstance(config['messengers'], dict):
            raise PolicyError('messengers must be a mapping')
        paths = set()
        for name, item in config['messengers'].items():
            keys(item, ('enabled', 'executables'))
            if not name or type(item['enabled']) is not bool or not isinstance(item['executables'], list):
                raise PolicyError('Invalid messenger entry')
            if item['enabled'] and not item['executables']:
                raise PolicyError('Enabled messenger requires executable paths')
            for executable in item['executables']:
                if not isinstance(executable, str) or not Path(executable).is_absolute() or executable in paths:
                    raise PolicyError('Executable paths must be absolute and unique')
                paths.add(executable)
        if config['mode'] == 'messengers' and not any(m['enabled'] for m in config['messengers'].values()):
            raise PolicyError('Enable at least one messenger')
        return config
    except (ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError) as exc:
        raise PolicyError(f'Invalid process configuration: {exc}') from exc
