"""User-systemd lifecycle for the laboratory; no privileged Python or PID files."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKAGED = ROOT == Path("/usr/lib/dlp-lab")
GATEWAY = "/usr/local/libexec/dlp-lab/fanotify-gateway"
UNITS = {name: f"dlp-lab-{name}.service" for name in ("files", "text", "export", "local", "notification-test", "signal-local")}


def _run(argv, *, capture=True, check=True):
    try:
        result = subprocess.run(argv, text=True, capture_output=capture,
                                timeout=15 if capture else None)
    except subprocess.TimeoutExpired:
        raise ValueError("systemd не ответил за 15 секунд; проверьте agent status") from None
    if check and result.returncode:
        raise ValueError("Команда systemd не выполнена. Проверьте пользовательский сеанс "
                         "и agent logs." + ("\n" + result.stderr.strip() if capture else ""))
    return result


def unit_status(component):
    result = _run(["systemctl", "--system" if PACKAGED and component == "files" else "--user", "show", UNITS[component],
                   "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
                   "-p", "Result", "-p", "MainPID", "-p", "ExecMainStatus"])
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)


def status():
    labels = {"files": "Файлы", "text": "Поле ввода", "export": "Разовая проверка экспорта", "local": "Локальное хранилище (разово)", "notification-test": "Проверка уведомления", "signal-local": "Сохранённые сообщения Signal"}
    for component in UNITS:
        data = unit_status(component)
        active = data.get("ActiveState", "unknown")
        state = {"active": "ПРОЦЕСС ЗАПУЩЕН", "inactive": "ОСТАНОВЛЕН",
                 "failed": "ОШИБКА", "activating": "ЗАПУСК",
                 "deactivating": "ОСТАНОВКА"}.get(active, "НЕИЗВЕСТНО")
        print(f"{labels[component]}: {state}; {data.get('SubState', '?')}; "
              f"PID={data.get('MainPID', '0')}; result={data.get('Result', '?')}")
    print("Статус относится к запускам через agent. Ручные процессы сюда не входят.\n"
          "Готовность файлов: событие monitor_started в журнале; привязка поля: "
          "text_monitor_started. Запущенный процесс не доказывает полноту контроля.\n"
          "Текст: только наблюдение. Экспорт и local: разовые проверки истории.\n"
          "Для local Telegram должен быть закрыт. Итог: local_check_finished в agent logs.\n"
          "Запрет отправки текста отсутствует.")
    return 0


def launch_command(component, policy, *, marker=None, seconds=120, file=None, root=None, expected_path=None):
    if PACKAGED and component == "files":
        raise ValueError("Пакет: используйте sudo systemctl start dlp-lab-files.service")
    command = ["systemd-run", "--user", "--no-ask-password",
               f"--unit={UNITS[component]}", "--service-type=exec",
               f"--description=DLP Lab: {component}",
               "--expand-environment=no", f"--working-directory={ROOT}",
               "--property=Restart=no", "--property=KillMode=control-group",
               "--property=KillSignal=SIGINT", "--property=TimeoutStopSec=5s",
               "--property=UMask=0077", "--property=StandardOutput=journal",
               "--property=StandardError=journal", "--property=SyslogIdentifier=dlp-lab",
               f"--setenv=PYTHONPATH={ROOT / 'src'}:{ROOT / '.deps'}",
               "--setenv=PYTHONUNBUFFERED=1"]
    # Do not import the complete shell environment into the user manager.
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        if name in os.environ:
            command.append(f"--setenv={name}={os.environ[name]}")
    python = [sys.executable, "-m", "dlp.cli", "--policy", str(Path(policy).resolve())]
    if component == "files":
        command.append("--property=SuccessExitStatus=130")
        if Path(policy).resolve() != ROOT / "config/policy.yaml":
            raise ValueError("Установленный gateway использует только config/policy.yaml проекта")
        worker = ["/usr/bin/sudo", "-n", GATEWAY]
    elif component == "text":
        command.append("--property=SuccessExitStatus=130")
        if not marker or not 1 <= seconds <= 3600:
            raise ValueError("Для текста нужны --marker и --seconds от 1 до 3600")
        worker = python + ["text-monitor", "--marker", marker, "--seconds", str(seconds)]
    elif component == "signal-local":
        # A single explicit check; fixed profile and journal, no browser paths.
        command += ["--property=StateDirectory=dlp-lab", "--property=StateDirectoryMode=0700"]
        if PACKAGED:
            python = ["/usr/bin/dlp-agent", "--policy", str(Path(policy).resolve())]
        worker = python + ["signal-local-check", "--root", str(Path.home()/".config/Signal"),
                           "--journal", str(Path.home()/".local/state/dlp-lab/signal-local.jsonl")]
    elif component == "local":
        if root is None:
            raise ValueError("Для локальной проверки нужен --root")
        command.append("--wait")
        worker = python + ["local-check", "--root", str(Path(root).absolute()),
                           "--profile-closed", "--no-passcode", "--marker", marker or "DLP_STORAGE_TEST"]
        if expected_path is not None:
            worker += ["--expected-path", str(Path(expected_path).absolute())]
    elif component == "notification-test":
        command.append("--wait")
        worker = python + ["notification-test-worker"]
    else:
        if file is None:
            raise ValueError("Для экспорта нужен --file")
        command.append("--wait")
        worker = python + ["analyze-export", "--file", str(Path(file).resolve())]
    return command + ["--"] + worker


def start(component, policy, **kwargs):
    command = launch_command(component, policy, **kwargs)
    data = unit_status(component)
    if data.get("ActiveState") not in ("inactive", "failed"):
        raise ValueError("Этот модуль уже запущен или меняет состояние; используйте agent status")
    if data.get("ActiveState") == "failed":
        _run(["systemctl", "--user", "reset-failed", UNITS[component]])
    # systemd arbitrates concurrent starts under the fixed unit name.
    result = _run(command, capture=False, check=False)
    if result.returncode:
        print("Запуск или выполнение завершились ошибкой. Смотрите agent logs.", file=sys.stderr)
        return 2
    if component in ("export", "local", "notification-test"):
        print("Проверка завершена. Решения и сводка: agent logs. BLOCK не означает запрет отправки.")
    else:
        print("Процесс запущен. Проверьте agent status и событие готовности в agent logs.")
    return 0


def stop(component):
    if PACKAGED and component in ("all", "files"):
        raise ValueError("Пакет: используйте sudo systemctl stop dlp-lab-files.service; пользовательские модули останавливайте отдельно")
    components = list(UNITS) if component == "all" else [component]
    for name in components:
        data = unit_status(name)
        if data.get("LoadState") == "not-found":
            continue
        _run(["systemctl", "--user", "stop", UNITS[name]])
        if data.get("ActiveState") == "failed":
            _run(["systemctl", "--user", "reset-failed", UNITS[name]], check=False)
    print("Выбранные модули остановлены. Файловая защита остановленного монитора снята.")
    return 0


def logs(lines=50, follow=False):
    if PACKAGED:
        raise ValueError("Пакет: sudo journalctl -u dlp-lab-files.service; для сессионных модулей journalctl --user")
    if not 1 <= lines <= 10000:
        raise ValueError("Число строк должно быть от 1 до 10000")
    command = ["journalctl", "--user", "--no-pager", "-o", "cat", "-n", str(lines)]
    for unit in UNITS.values():
        command += ["-u", unit]
    if follow:
        command.append("--follow")
    return _run(command, capture=False, check=False).returncode


def manage(args):
    if PACKAGED:
        raise ValueError("Управление пакетным агентом: sudo systemctl; пользовательские units отключены")
    if os.geteuid() == 0:
        raise ValueError("Команды agent запускаются от обычного пользователя, без sudo")
    if args.action == "status":
        return status()
    if args.action == "stop":
        return stop(args.component)
    if args.action == "logs":
        return logs(args.lines, args.follow)
    if args.action == "local":
        return start("local", args.policy, root=args.root, marker=args.marker, expected_path=args.expected_path)
    if args.action == "notification-test":
        return start("notification-test", args.policy)
    if args.action == "export":
        return start("export", args.policy, file=args.file)
    return start(args.component, args.policy, marker=args.marker, seconds=args.seconds)
