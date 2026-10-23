"""Desktop warning delivery with explicit, auditable outcome."""
import os
from pathlib import Path
import shutil
import subprocess


def desktop_warning(decision):
    title = 'DLP: обнаружен риск в тексте'
    body = (f'Решение политики: {decision}. Найдены риски или текст не удалось проверить. '
            'Отправка НЕ заблокирована. Подробности: scripts/dlp agent logs.')
    return deliver_notification(title, body)


def desktop_file_warning(event):
    # Escape markup and control characters in user-controlled filenames.
    from html import escape
    name = escape(''.join(c if c.isprintable() else '?' for c in event['filename'])[:160])
    denied = event.get('enforcement') == 'DENY'
    title = 'DLP: открытие файла заблокировано' if denied else 'DLP: предупреждение о файле'
    action = 'Доступ к файлу запрещён.' if denied else 'Доступ к этому файлу разрешён.'
    body = f'{name}: {action} Решение политики: {event["decision"]}. Это событие открытия файла, не подтверждение отправки.'
    return deliver_notification(title, body)


def deliver_notification(title, body):
    executable = shutil.which('notify-send')
    if executable:
        command = [executable, '-a', 'DLP Lab', '-u', 'normal', '-t', '10000', title, body]
    else:
        executable = shutil.which('gdbus')
        if executable is None:
            return 'unavailable'
        command = [executable, 'call', '--session', '--dest', 'org.freedesktop.Notifications',
                   '--object-path', '/org/freedesktop/Notifications',
                   '--method', 'org.freedesktop.Notifications.Notify',
                   'DLP Lab', '0', '', title, body, '[]', "{'urgency': <byte 1>}", '10000']
    try:
        env = dict(os.environ)
        # The fixed gateway clears the environment before dropping privileges.
        # Reconnect only to this UID's standard session bus.
        bus = Path(f"/run/user/{os.getuid()}/bus")
        if not env.get("DBUS_SESSION_BUS_ADDRESS") and bus.exists() and bus.stat().st_uid == os.getuid():
            env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + str(bus)
        result = subprocess.run(command, timeout=5, check=False, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 'accepted' if result.returncode == 0 else 'failed'
    except subprocess.TimeoutExpired:
        return 'timeout'
    except OSError:
        return 'failed'


def report_warning(audit, decision, source, sender=desktop_warning):
    status = sender(decision)
    audit.emit({'event':'notification_delivery', 'source':source, 'decision':str(decision),
                'status':status, 'display_confirmed':False, 'send_blocked':False})
    return status
