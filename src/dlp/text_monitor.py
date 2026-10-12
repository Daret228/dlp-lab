"""Read-only draft analysis; policy BLOCK is a recommendation, never a send veto."""
from dataclasses import asdict
import sys
import time
from .notifications import desktop_warning, report_warning
from .accessibility import inspect_tree
from .models import TextContent, Decision
from .processes import identify, ProcessFilter


class DraftMonitor:
    def __init__(self, analyzer, audit, notify=None):
        self.analyzer, self.audit, self.notify = analyzer, audit, notify
        self.previous = None

    def check(self, text, messenger, pid):
        if text == self.previous:
            return None
        result = self.analyzer.analyze(TextContent(text, source='atspi_draft'))
        self.previous = text  # Memory only, never persisted or included in audit.
        self.audit.emit({'event': 'draft_analysis', 'messenger': messenger, 'pid': pid,
                         'source': 'atspi_draft', 'result': asdict(result),
                         'enforcement': 'observe_only', 'send_blocked': False,
                         'send_confirmed': False})
        if self.notify and result.decision in (Decision.WARN, Decision.BLOCK):
            report_warning(self.audit, result.decision, "atspi_draft", self.notify)
        return result


def find_draft_bindings(desktop, atspi, filt, messenger, marker):
    bindings = []
    for i in range(min(desktop.get_child_count(), 100)):
        app = desktop.get_child_at_index(i)
        identity = identify(app.get_process_id())
        if filt.match(identity) != messenger:
            continue
        app.clear_cache()
        _, candidates = inspect_tree(app, atspi, require_focus=False)
        for node in candidates:
            count = node.get_text_iface().get_character_count()
            if 0 < count <= 4096:
                text = atspi.Text.get_text(node.get_text_iface(), 0, count)
                if marker in text and not any(node == old[1] for old in bindings):
                    bindings.append((identity, node))
    return bindings


def wait_for_binding(scan, seconds=30):
    deadline = time.monotonic() + seconds
    while True:
        bindings = scan()
        if len(bindings) == 1:
            return bindings
        if len(bindings) > 1:
            raise ValueError('Маркер найден в нескольких полях. Оставьте его только в одном тестовом черновике.')
        if time.monotonic() >= deadline:
            raise ValueError('Поле с маркером не найдено. Полностью выйдите из Telegram и запустите '
                             'QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1 /usr/bin/telegram-desktop; '
                             'затем откройте тестовый чат и введите маркер в поле сообщения, не отправляя.')
        time.sleep(0.5)


def run_text_monitor(config, analyzer, audit, messenger, marker, seconds=60, notifications=True):
    if not marker or not 1 <= seconds <= 3600:
        raise ValueError('Nonempty marker and duration 1..3600 required')
    import gi
    gi.require_version('Atspi', '2.0')
    from gi.repository import Atspi
    Atspi.set_timeout(1000, 1000)
    filt = ProcessFilter(config)
    desktop = Atspi.get_desktop(0)
    print(f'Ожидаю поле Telegram с маркером {marker!r} (до 30 секунд). '
          'Откройте тестовый чат и оставьте окно Telegram видимым.', file=sys.stderr, flush=True)
    bindings = wait_for_binding(lambda: find_draft_bindings(desktop, Atspi, filt, messenger, marker))
    identity, node = bindings[0]
    monitor = DraftMonitor(analyzer, audit, desktop_warning if notifications else None)
    audit.emit({'event': 'text_monitor_started', 'messenger': messenger, 'pid': identity.pid,
                'duration_seconds': seconds, 'enforcement': 'observe_only', 'send_veto': False})
    end = time.monotonic() + seconds
    reason = 'duration_elapsed'
    try:
        while time.monotonic() < end:
            if identify(identity.pid) != identity:
                reason = 'process_changed'
                break
            node.clear_cache()
            state = node.get_state_set()
            if (node.get_role() == Atspi.Role.PASSWORD_TEXT or
                    not state.contains(Atspi.StateType.EDITABLE) or
                    not state.contains(Atspi.StateType.SHOWING)):
                reason = 'bound_field_unavailable'
                break
            text_iface = node.get_text_iface()
            count = text_iface.get_character_count()
            if count < 0 or count > analyzer.policy['limits']['max_bytes']:
                audit.emit({'event': 'draft_unavailable', 'reason': 'size_limit', 'send_blocked': False})
                reason = 'size_limit'
                break
            text = Atspi.Text.get_text(text_iface, 0, count)
            # A concurrent edit is sampled again next cycle; this is not an atomic send hook.
            if text_iface.get_character_count() == count:
                monitor.check(text, messenger, identity.pid)
            time.sleep(0.3)
    except KeyboardInterrupt:
        reason = 'interrupted'
    except Exception:
        reason = 'accessibility_error'
        raise
    finally:
        monitor.previous = None
        audit.emit({'event': 'text_monitor_stopped', 'reason': reason, 'send_blocked': False})
