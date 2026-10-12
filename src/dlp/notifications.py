"""Desktop warning delivery with explicit, auditable outcome."""
import shutil
import subprocess


def desktop_warning(decision):
    title = 'DLP: обнаружен риск в тексте'
    body = (f'Решение политики: {decision}. Найдены риски или текст не удалось проверить. '
            'Отправка НЕ заблокирована. Подробности: scripts/dlp agent logs.')
    executable = shutil.which('notify-send')
    if executable:
        command = [executable, '-a', 'DLP Lab', '-u', 'critical', '-t', '10000', title, body]
    else:
        executable = shutil.which('gdbus')
        if executable is None:
            return 'unavailable'
        command = [executable, 'call', '--session', '--dest', 'org.freedesktop.Notifications',
                   '--object-path', '/org/freedesktop/Notifications',
                   '--method', 'org.freedesktop.Notifications.Notify',
                   'DLP Lab', '0', '', title, body, '[]', "{'urgency': <byte 2>}", '10000']
    try:
        result = subprocess.run(command, timeout=5, check=False,
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
