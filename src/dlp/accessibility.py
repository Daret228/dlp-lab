"""Read-only, bounded AT-SPI diagnostics for one configured messenger.

No keyboard hooks, actions, UI edits, message history or accessible names.
AT-SPI is imported lazily so the analysis core remains OS independent.
"""
from collections import deque
import time
from .processes import ProcessFilter, identify


def inspect_tree(root, atspi, limit=300, max_depth=10, seconds=8, require_focus=True):
    pending = deque([(root, 0)])
    rows, candidates = [], []
    end = time.monotonic() + seconds
    while pending and len(rows) < limit and time.monotonic() < end:
        node, depth = pending.popleft()
        try:
            state = node.get_state_set()
            interfaces = list(node.get_interfaces())
            row = {'depth': depth, 'role': node.get_role_name(),
                   'editable': state.contains(atspi.StateType.EDITABLE),
                   'focused': state.contains(atspi.StateType.FOCUSED),
                   'showing': state.contains(atspi.StateType.SHOWING),
                   'interfaces': interfaces, 'children': node.get_child_count()}
            rows.append(row)
            if (row['editable'] and (row['focused'] or not require_focus) and row['showing'] and
                    'Text' in interfaces and node.get_role() != atspi.Role.PASSWORD_TEXT):
                candidates.append(node)
            if depth < max_depth:
                for index in range(min(row['children'], max(0, limit-len(rows)-len(pending)))):
                    child = node.get_child_at_index(index)
                    if child is not None:
                        pending.append((child, depth+1))
        except Exception as exc:
            rows.append({'depth': depth, 'error': type(exc).__name__})
    return rows, candidates


def probe(config, messenger, marker=None):
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    Atspi.set_timeout(1000, 1000)
    filt = ProcessFilter(config)
    if messenger not in [a.name for a in filt.adapters]:
        raise ValueError('Messenger must be enabled in process configuration')
    desktop = Atspi.get_desktop(0)
    results = []
    for index in range(min(desktop.get_child_count(), 100)):
        app = desktop.get_child_at_index(index)
        identity = identify(app.get_process_id())
        if filt.match(identity) != messenger:
            continue
        app.clear_cache()
        rows, candidates = inspect_tree(app, Atspi, require_focus=not bool(marker))
        report = {'pid': identity.pid, 'executable': identity.executable,
                  'nodes': rows, 'editable_candidates': len(candidates),
                  'draft_marker_found': False, 'send_veto': 'unverified'}
        if marker:
            for node in candidates:
                # Explicit user-prepared test marker only; never print source text.
                if identify(identity.pid) != identity:
                    break
                text_iface = node.get_text_iface()
                count = text_iface.get_character_count()
                if 0 < count <= 4096:
                    text = Atspi.Text.get_text(text_iface, 0, count)
                    if marker in text:
                        report['draft_marker_found'] = True
        results.append(report)
    return {'event': 'accessibility_probe', 'messenger': messenger, 'applications': results}
