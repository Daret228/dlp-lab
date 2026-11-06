import argparse
from dataclasses import asdict
import os
from pathlib import Path
import sys
from .analysis import ContentAnalyzer
from .audit import JsonAudit
from .models import TextContent, FileContent
from .policy import load_policy, load_policy_snapshot, PolicyError


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "central":
        from .central import main as central_main
        return central_main(sys.argv[2:])
    packaged = Path(__file__).resolve().parents[2] == Path('/usr/lib/dlp-lab')
    config_directory = Path('/etc/dlp-lab/system') if packaged else Path('config')
    parser = argparse.ArgumentParser(description="Linux endpoint DLP laboratory prototype")
    parser.add_argument("--policy", default=str(config_directory / "policy.yaml"))
    sub = parser.add_subparsers(dest="command", required=True)
    central = sub.add_parser("central", help="Центральный сервер и отправка событий", add_help=False)
    central.add_argument("arguments", nargs=argparse.REMAINDER)
    doctor = sub.add_parser("doctor", help="Диагностика пакетной установки без изменения настроек")
    doctor.add_argument("--json", action="store_true", help="Машиночитаемый отчёт")
    analyze = sub.add_parser("analyze")
    sources = analyze.add_mutually_exclusive_group(required=True)
    sources.add_argument("--text")
    sources.add_argument("--file", type=Path)
    export = sub.add_parser("analyze-export", help="Audit text in a single Telegram JSON chat export")
    export.add_argument("--file", type=Path, required=True)
    signal_local = sub.add_parser("signal-local-check", help="Offline Signal text analysis; client must be closed")
    signal_local.add_argument("--root", type=Path, required=True)
    signal_local.add_argument("--executable", type=Path, default=Path('/opt/Signal/signal-desktop'))
    signal_local.add_argument("--sqlcipher-library", type=Path, default=Path("libsqlcipher.so.1"))
    signal_local.add_argument("--journal", type=Path, required=True)
    signal_local.add_argument("--limit", type=int, default=100)
    signal_local.add_argument("--no-notify", action="store_true")
    sub.add_parser("monitor", help="Internal: launch through fanotify-launcher")
    processes = sub.add_parser("processes", help="List configured messenger processes of current user")
    processes.add_argument("--config", default=str(config_directory / "processes.yaml"))
    mode = sub.add_parser("process-mode", help="Select file monitoring scope; restart monitor afterward")
    mode.add_argument("mode", choices=["all", "messengers"])
    mode.add_argument("--config", default=str(config_directory / "processes.yaml"))
    host_setup = sub.add_parser("configure-processes", help="Configure Telegram adapter for this user and machine")
    host_setup.add_argument("--telegram", type=Path, required=True)
    host_setup.add_argument("--config", type=Path, default=config_directory / "processes.yaml")
    text_monitor = sub.add_parser("text-monitor", help="Analyze an explicitly bound draft; does NOT block sending")
    text_monitor.add_argument("--marker", required=True, help="Marker you entered in your own test draft")
    text_monitor.add_argument("--messenger", default="telegram")
    text_monitor.add_argument("--seconds", type=int, default=60)
    text_monitor.add_argument("--no-notify", action="store_true")
    agent = sub.add_parser("agent", help="Управление модулями через пользовательский systemd")
    actions = agent.add_subparsers(dest="action", required=True)
    start = actions.add_parser("start")
    start.add_argument("component", choices=["files", "text"])
    start.add_argument("--marker")
    start.add_argument("--seconds", type=int, default=120)
    stop = actions.add_parser("stop")
    stop.add_argument("component", choices=["all", "files", "text", "export", "local", "notification-test"], nargs="?", default="all")
    actions.add_parser("status")
    logs = actions.add_parser("logs")
    logs.add_argument("--lines", type=int, default=50)
    logs.add_argument("--follow", action="store_true")
    export_job = actions.add_parser("export")
    export_job.add_argument("--file", type=Path, required=True)
    for parent, name in ((actions, "local"), (sub, "local-check")):
        job = parent.add_parser(name, help="Разовая проверка закрытого тестового Telegram")
        job.add_argument("--root", type=Path, default=Path.home()/".local/share/TelegramDesktop/tdata")
        job.add_argument("--profile-closed", action="store_true", required=True)
        job.add_argument("--no-passcode", action="store_true", required=True)
        job.add_argument("--marker", default="DLP_STORAGE_TEST")
        job.add_argument("--expected-path", type=Path)
    actions.add_parser("notification-test", help="Проверка предупреждения на искусственном тексте")
    sub.add_parser("notification-test-worker", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.command == "doctor":
            from .doctor import run
            return run(json_output=args.json)
        if args.command == "central":
            from .central import main as central_main
            return central_main(args.arguments)
        if args.command == "agent":
            from .service import manage
            return manage(args)
        if args.command == "configure-processes":
            from .host_setup import configure_processes
            changed = configure_processes(args.config,args.telegram)
            print("Настройка процессов сохранена. Перезапустите модули." if changed else "Настройка процессов уже соответствует этому компьютеру.")
            return 0
        from .processes import ProcessFilter, identify, load_process_config
        if args.command in ("processes", "process-mode"):
            config = load_process_config(args.config)
            if args.command == "process-mode":
                import yaml
                import tempfile
                config['mode'] = args.mode
                if args.mode == 'messengers' and not any(x['enabled'] for x in config['messengers'].values()):
                    raise ValueError('Enable at least one messenger')
                path = Path(args.config).resolve()
                with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as tmp:
                    yaml.safe_dump(config, tmp, allow_unicode=True, sort_keys=False)
                os.replace(tmp.name, path)
                print(f"Режим: {args.mode}. Перезапустите monitor, чтобы применить изменение.")
                return 0
            process_filter = ProcessFilter(config)
            matches = []
            for path in Path('/proc').iterdir():
                if path.name.isdigit():
                    identity = identify(int(path.name))
                    name = process_filter.match(identity)
                    if name:
                        matches.append({'messenger': name, **asdict(identity)})
            JsonAudit(sys.stdout).emit({'event': 'process_inventory', 'matches': matches})
            return 0
        if args.command == "signal-local-check":
            from .signal_local import run_signal_local
            return run_signal_local(args, JsonAudit(sys.stdout))
        if args.command == "local-check":
            from .local_job import run_local
            return run_local(args, JsonAudit(sys.stdout))
        policy, policy_version = load_policy_snapshot(args.policy)
        analyzer = ContentAnalyzer(policy)
        audit = JsonAudit(sys.stdout)
        if args.command in ('text-monitor', 'monitor'):
            audit.emit({'event': 'policy_loaded', 'policy_version': policy_version})
        if args.command == "notification-test-worker":
            from .notifications import report_warning
            result = analyzer.analyze(TextContent("DLP_TEST коммерческая тайна", source="synthetic_notification_test"))
            audit.emit({"event":"notification_test_analysis", "synthetic":True, "result":asdict(result), "send_blocked":False})
            if result.decision not in ("WARN", "BLOCK"):
                return 2
            return 0 if report_warning(audit,result.decision,"synthetic_notification_test") == "accepted" else 2
        if args.command == "analyze-export":
            from .telegram_export import analyze_export
            return analyze_export(args.file, analyzer, audit)
        if args.command == "text-monitor":
            from .text_monitor import run_text_monitor
            config = load_process_config(Path(args.policy).resolve().with_name('processes.yaml'))
            run_text_monitor(config, analyzer, audit, args.messenger, args.marker, args.seconds, not args.no_notify)
            return 0
        if args.command == "analyze":
            content = TextContent(args.text) if args.text is not None else FileContent(args.file)
            result = analyzer.analyze(content)
            audit.emit({"event": "analysis", "result": asdict(result)})
            return 0 if result.complete else 2
        from .fanotify import run
        if os.geteuid() == 0:
            raise ValueError("Worker must run without root privileges")
        config_path = Path(args.policy).resolve().with_name('processes.yaml')
        process_filter = ProcessFilter(load_process_config(config_path)) if config_path.exists() else None
        run(int(os.environ["DLP_FAN_FD"]), analyzer, audit, process_filter)
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, KeyError, ImportError, PolicyError) as exc:
        print(f"dlp-agent: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
