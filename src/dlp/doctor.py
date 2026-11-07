"""Read-only diagnostics. Never read credentials or print arbitrary journal entries."""
import json
from pathlib import Path
import subprocess

UNITS = {
    'dlp-lab-files.service': 'Файловая защита',
    'dlp-lab-session.service': 'Сеансовая служба',
    'dlp-lab-forwarder.service': 'Отправщик событий',
    'dlp-lab-central.service': 'Центральный сервер (необязательно)',
    'dlp-lab-central-tls.service': 'HTTPS сервера (необязательно)',
}


def service_state(unit):
    try:
        result = subprocess.run(
            ['/usr/bin/systemctl', 'show', unit, '--no-pager',
             '--property=LoadState,ActiveState,SubState,Result,NRestarts'],
            capture_output=True, text=True, timeout=5)
        if result.returncode:
            return None
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    except (OSError, subprocess.TimeoutExpired):
        return None


def collect(config=Path('/etc/dlp-lab/system'), state_reader=service_state):
    checks = []

    def add(name, status, detail, action=''):
        checks.append(dict(name=name, status=status, detail=detail, action=action))

    try:
        from .policy import load_policy
        load_policy(config/'policy.yaml')
        add('Политика', 'OK', 'Конфигурация анализа читается и проходит проверку.')
    except PermissionError:
        add('Политика', 'UNKNOWN', 'Недостаточно прав для проверки.')
    except Exception:
        add('Политика', 'ERROR', 'Политика отсутствует или не проходит проверку.',
            'Проверьте /etc/dlp-lab/system/policy.yaml; содержимое в отчёт не выводится.')
    try:
        from .processes import load_process_inventory
        data = load_process_inventory(config/'processes.yaml')
        enabled = [v for v in data['messengers'].values() if v.get('enabled')]
        paths = [p for v in enabled for p in v.get('executables', [])]
        if not paths or not all(Path(p).is_file() for p in paths):
            raise ValueError('missing executable')
        add('Мессенджеры', 'OK', 'Настроенные исполняемые файлы доступны.')
    except PermissionError:
        add('Мессенджеры', 'UNKNOWN', 'Недостаточно прав для проверки.')
    except Exception:
        add('Мессенджеры', 'ERROR', 'Нет корректной настройки или исполняемого файла.',
            'Для новой установки: sudo dlp-lab-configure --wizard')

    for unit, label in UNITS.items():
        state = state_reader(unit)
        optional = unit not in ('dlp-lab-files.service', 'dlp-lab-session.service')
        if state is None:
            add(label, 'UNKNOWN', 'Состояние systemd недоступно.',
                f'systemctl status {unit} --no-pager')
        elif state.get('LoadState') == 'not-found':
            add(label, 'INFO' if optional else 'ERROR', 'Служба не установлена.')
        elif state.get('ActiveState') == 'active' and state.get('SubState') == 'running':
            add(label, 'OK', 'Процесс работает; это не проверка обработки событий.')
        elif state.get('ActiveState') in ('failed', 'activating'):
            add(label, 'ERROR', 'Ошибка запуска или служба ещё запускается.',
                f'sudo journalctl -u {unit} -n 20 --no-pager')
        else:
            add(label, 'INFO' if optional else 'ERROR', 'Служба остановлена или пропущена.',
                f'systemctl status {unit} --no-pager')
        if state and state.get('NRestarts', '0').isdigit() and int(state.get('NRestarts', '0')):
            add(label + ': перезапуски', 'INFO',
                f'Накопленный счётчик: {state["NRestarts"]}. Сам по себе не означает текущий сбой.')

    add('Текст и локальные базы', 'INFO', 'Проверяются отдельными модулями; данный отчёт их работу не подтверждает.',
        'Смотрите актуальное состояние текста в центральной панели; sudo systemctl status dlp-lab-session.service')
    add('Доставка и очередь', 'UNKNOWN',
        'В этой версии диагностики сеть, сертификат и очередь не проверяются.',
        'Сверьте журнал отправщика и событие устройства в центральной панели.')
    return checks


def run(json_output=False):
    checks = collect()
    errors = sum(c['status'] == 'ERROR' for c in checks)
    if json_output:
        print(json.dumps({'checks': checks, 'errors': errors, 'read_only': True}, ensure_ascii=False))
    else:
        print('DLP: диагностика пакетной установки (без изменений)')
        for check in checks:
            print(f'[{check["status"]}] {check["name"]}: {check["detail"]}')
            if check['action']:
                print('  ' + check['action'])
        print(f'Ошибок: {errors}. Полную готовность подтверждает тестовое событие.')
    unavailable = any(c['status'] == 'UNKNOWN' and c['name'] in UNITS.values() for c in checks)
    return 1 if errors else (2 if unavailable else 0)
