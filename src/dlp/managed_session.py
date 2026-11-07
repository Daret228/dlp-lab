"""Administrator-owned session supervisor and unprivileged AT-SPI worker.

No user lifecycle API. The worker can be killed by its UID; the supervisor
restarts it and reports unavailable control rather than claiming tamper-proofness.
"""
import json
import os
from pathlib import Path
import pwd
import selectors
import signal
import stat
import subprocess
import sys
import time

STATE = Path('/run/dlp-lab-session/state.json')
POLICY = Path('/etc/dlp-lab/system/policy.yaml')
PROCESSES = POLICY.with_name('processes.yaml')
STATES = {'ready', 'waiting_field', 'unavailable', 'no_session', 'restarting', 'stopped'}


def trusted_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise ValueError('Untrusted state')
        return json.loads(stream.read(8193))


def session_available(uid):
    runtime = Path('/run/user') / str(uid)
    try:
        info = runtime.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            return False
        # Do not traverse the user's 0700 runtime directory as supervisor:
        # it deliberately lacks CAP_DAC_READ_SEARCH. The dropped-UID worker
        # connects to its bus and reports unavailable if that fails.
        result = subprocess.run(['/usr/bin/loginctl', 'show-user', str(uid), '-p', 'Sessions', '--value'],
                                capture_output=True, text=True, timeout=5, check=True)
        for session in result.stdout.split()[:16]:
            if not session.isalnum():
                continue
            data = subprocess.run(['/usr/bin/loginctl', 'show-session', session, '-p', 'Active', '-p', 'Type', '-p', 'Remote'],
                                  capture_output=True, text=True, timeout=5, check=True).stdout
            fields = dict(line.split('=', 1) for line in data.splitlines() if '=' in line)
            if fields.get('Active') == 'yes' and fields.get('Remote') == 'no' and fields.get('Type') in ('x11', 'wayland'):
                return True
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return False


def eligible_field(node, atspi):
    state = node.get_state_set()
    return (node.get_role() != atspi.Role.PASSWORD_TEXT and
            all(state.contains(value) for value in (atspi.StateType.EDITABLE, atspi.StateType.FOCUSED,
                atspi.StateType.SHOWING, atspi.StateType.MULTI_LINE)) and 'Text' in node.get_interfaces())


def worker():
    if os.geteuid() == 0:
        raise ValueError('Worker must be unprivileged')
    from .analysis import ContentAnalyzer
    from .audit import JsonAudit
    from .policy import load_policy
    from .processes import load_process_config, ProcessFilter, identify
    from .accessibility import inspect_tree, outermost_fields
    from .text_monitor import DraftMonitor
    from .notifications import desktop_warning
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    Atspi.set_timeout(500, 500)
    config = load_process_config(PROCESSES)
    if config['uid'] != os.getuid():
        raise ValueError('Wrong desktop identity')
    filt = ProcessFilter(config)
    audit = JsonAudit(sys.stdout)
    monitor = DraftMonitor(ContentAnalyzer(load_policy(POLICY)), audit, desktop_warning)
    previous_binding = None
    while True:
        status = 'waiting_field'
        try:
            desktop = Atspi.get_desktop(0)
            bindings = []
            for i in range(min(desktop.get_child_count(), 100)):
                app = desktop.get_child_at_index(i)
                identity = identify(app.get_process_id())
                messenger = filt.match(identity)
                if messenger not in ('telegram', 'signal'):
                    continue
                app.clear_cache()
                _, candidates = inspect_tree(app, Atspi, require_focus=True, seconds=2)
                for node in outermost_fields(candidates):
                    if eligible_field(node, Atspi):
                        bindings.append((identity, messenger, node))
            if len(bindings) == 1:
                identity, messenger, node = bindings[0]
                if identify(identity.pid) != identity:
                    raise ValueError('Process changed')
                iface = node.get_text_iface()
                count = iface.get_character_count()
                if not 0 <= count <= 16384:
                    raise ValueError('Field too large')
                binding = (identity, node)
                if binding != previous_binding:
                    monitor.previous = None
                previous_binding = binding
                monitor.check(Atspi.Text.get_text(iface, 0, count), messenger, identity.pid)
                status = 'ready'
            elif len(bindings) > 1:
                status = 'unavailable'
            else:
                previous_binding = None
                monitor.previous = None
        except Exception:
            status = 'unavailable'
        print(json.dumps({'session_state': status}), flush=True)
        time.sleep(2)


def supervise():
    if os.geteuid() != 0:
        raise ValueError('Administrator required')
    from .processes import load_process_inventory
    from .central import project
    from .audit import JsonAudit
    config = load_process_inventory(PROCESSES)
    account = pwd.getpwuid(config['uid'])
    if account.pw_uid < 1000:
        raise ValueError('Desktop UID required')
    for path in (POLICY, PROCESSES):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Administrator-owned configuration required')
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    audit = JsonAudit(sys.stdout)
    child = None
    selector = selectors.DefaultSelector()
    last_output = 0
    last_write = 0
    status = 'no_session'
    pending = b''
    def persist(value):
        temporary = STATE.with_suffix('.tmp')
        temporary.write_text(json.dumps({'state': value, 'updated': time.time()}))
        temporary.chmod(0o644)
        temporary.replace(STATE)
    def terminate():
        nonlocal child, pending
        if child:
            selector.unregister(child.stdout)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            child.stdout.close()
            child = None
            pending = b''
    try:
        while not stopped:
            available = session_available(account.pw_uid)
            if not available:
                terminate()
                status = 'no_session'
            elif child and (child.poll() is not None or time.monotonic()-last_output > 30):
                terminate()
                status = 'restarting'
                persist(status)
                audit.emit({'event': 'session_control', 'session_state': status})
                time.sleep(3)
            elif child is None:
                runtime = f'/run/user/{account.pw_uid}'
                env = {'PATH': '/usr/bin:/bin', 'HOME': account.pw_dir, 'LANG': 'C.UTF-8',
                       'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': f'unix:path={runtime}/bus'}
                child = subprocess.Popen(['/usr/libexec/dlp-lab/session-worker'], env=env,
                    user=account.pw_uid, group=account.pw_gid, extra_groups=[], start_new_session=True,
                    cwd='/', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                os.set_blocking(child.stdout.fileno(), False)
                selector.register(child.stdout, selectors.EVENT_READ)
                last_output = time.monotonic()
                status = 'unavailable'
            for key, _ in selector.select(timeout=1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                pending += chunk
                if len(pending) > 262144:
                    terminate()
                    status = 'unavailable'
                    break
                while b'\n' in pending:
                    line, pending = pending.split(b'\n', 1)
                    try:
                        value = json.loads(line)
                        if isinstance(value, dict) and set(value) == {'session_state'} and value['session_state'] in ('ready','waiting_field','unavailable'):
                            status = value['session_state']
                            last_output = time.monotonic()
                        elif isinstance(value, dict) and value.get('event') in ('draft_analysis','notification_delivery'):
                            safe = project(value)
                            if safe:
                                audit.emit(safe)
                    except (ValueError, TypeError):
                        status = 'unavailable'
            if not child:
                time.sleep(1)
            if time.monotonic()-last_write > 10:
                persist(status)
                last_write = time.monotonic()
    finally:
        terminate()
        persist('stopped')
        selector.close()
