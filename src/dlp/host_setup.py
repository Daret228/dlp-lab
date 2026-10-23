"""Unprivileged, explicit setup of the process adapter for a new lab machine."""
import os
from pathlib import Path
import tempfile
import yaml
from .policy import StrictLoader
from .processes import load_process_config


def configure_processes(path, executable):
    if os.geteuid() == 0:
        raise ValueError('Run process setup as the target user, without sudo')
    path = Path(path).resolve(strict=True)
    executable = Path(executable).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('Telegram executable is not executable')
    if path.stat().st_size > 65536:
        raise ValueError('Process configuration too large')
    previous = path.read_bytes()
    try:
        config = yaml.load(previous, Loader=StrictLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError('Invalid process configuration') from exc
    if not isinstance(config,dict) or not isinstance(config.get('messengers'),dict):
        raise ValueError('Invalid process configuration')
    config['uid'] = os.getuid()
    config['mode'] = 'messengers'
    config['messengers']['telegram'] = {'enabled':True, 'executables':[str(executable)]}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,delete=False) as output:
            temporary = Path(output.name)
            yaml.safe_dump(config,output,allow_unicode=True,sort_keys=False)
        load_process_config(temporary)
        if yaml.load(previous, Loader=StrictLoader) == config:
            return False
        if path.read_bytes() != previous:
            raise ValueError('Process configuration changed during setup')
        backup = path.with_suffix(path.suffix+'.previous')
        # Exclusive creation prevents following a preexisting symlink or overwriting backup.
        try:
            with backup.open('xb') as out:
                os.chmod(backup,0o600)
                out.write(previous)
        except FileExistsError:
            raise ValueError('Backup already exists; preserve/remove it before another setup') from None
        os.replace(temporary,path)
        temporary = None
        return True
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
