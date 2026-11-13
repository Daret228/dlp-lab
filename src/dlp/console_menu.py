"""Interactive administrator console for an installed DLP Lab stand.

A thin wrapper over the documented maintenance commands. The console grants
no privileges of its own: actions that require root invoke sudo explicitly,
state-changing actions ask for confirmation, and every command is executed
as an argument list without a shell. Menu texts are Russian by design.
"""
import json
import os
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path

SERVICES = ('dlp-lab-files.service', 'dlp-lab-session.service',
            'dlp-lab-forwarder.service', 'dlp-lab-admin-control.service')
SERVER_COMPOSE = '/etc/dlp-lab/docker/compose.json'
AGENT_PROFILE = '/etc/dlp-lab/central-agent.json'
CA_SOURCE = '/etc/dlp-lab/tls/ca.crt'
PANEL_URL = 'http://127.0.0.1:8766/'
NAME_RULE = '^[a-z0-9][a-z0-9-]{0,31}$'


def as_root(argv):
    """Return an argv that runs with root privileges; never a shell string."""
    argv = list(argv)
    if os.geteuid() == 0:
        return argv
    if shutil.which('sudo') is None:
        raise SystemExit('Действие требует root, sudo не найден: ' + ' '.join(argv))
    return ['sudo', *argv]


class Console:
    def __init__(self, runner=None, prompter=None, paths=None):
        self.run = runner or self._run
        self.ask = prompter or input
        paths = paths or {}
        self.server_compose = Path(paths.get('server_compose', SERVER_COMPOSE))
        self.agent_profile = Path(paths.get('agent_profile', AGENT_PROFILE))
        self.ca_source = Path(paths.get('ca_source', CA_SOURCE))
        self.panel_url = paths.get('panel_url', PANEL_URL)
        self.home = Path(paths.get('home', Path.home()))

    @staticmethod
    def _run(argv, capture=False):
        return subprocess.run(argv, capture_output=capture, text=capture)

    # --- helpers ---------------------------------------------------------
    def server_role(self):
        try:
            if self.server_compose.exists():
                return True
        except OSError:
            pass
        # The directory may be root-only; the loopback panel is the fallback sign.
        return self.panel_state() != 'недоступна'

    def dc(self):
        return ['docker', 'compose', '-p', 'dlp-central-migrated',
                '-f', str(self.server_compose)]

    def find_repo(self):
        for candidate in (os.environ.get('DLP_LAB_REPO'),
                          str(self.home / 'dlp-lab'), '/root/dlp-lab'):
            if not candidate:
                continue
            try:
                if (Path(candidate) / 'scripts' / 'build-connection.py').exists():
                    return Path(candidate)
            except OSError:
                continue
        return None

    def default_server_url(self):
        try:
            data = json.loads(self.agent_profile.read_text())
            url = data.get('server') if isinstance(data, dict) else None
            if isinstance(url, str) and url.startswith('https://'):
                return url
        except (OSError, ValueError):
            pass
        return None

    def panel_state(self):
        try:
            with urllib.request.urlopen(self.panel_url, timeout=3) as response:
                return 'HTTP ' + str(response.status)
        except OSError:
            return 'недоступна'

    def confirm(self, question):
        answer = self.ask(question + ' [да/Нет]: ').strip().lower()
        return answer in ('да', 'y', 'yes', 'д')

    def pause(self):
        try:
            self.ask('\nEnter — назад... ')
        except EOFError:
            pass

    def execute(self, argv, capture=False):
        return self.run(argv, capture=capture)

    def root_execute(self, argv, capture=False):
        return self.execute(as_root(argv), capture=capture)

    # --- actions ---------------------------------------------------------
    def status(self):
        result = self.execute(['dpkg-query', '-W', '-f=${Version}\n', 'dlp-lab'], capture=True)
        print('Пакет dlp-lab:', result.stdout.strip() or 'не установлен')
        for unit in SERVICES:
            state = self.execute(['systemctl', 'show', unit, '-p', 'ActiveState', '--value'], capture=True)
            print(f'{unit}: {state.stdout.strip() or "неизвестно"}')
        print('Панель (loopback):', self.panel_state())
        if self.server_role():
            print('Серверные контейнеры:')
            self.root_execute(self.dc() + ['ps'])

    def doctor(self):
        self.root_execute(['dlp-agent', 'doctor'])

    def add_device(self):
        if not self.server_role():
            print('Пункт доступен на машине с сервером DLP (не найден', self.server_compose, ').')
            return
        name = self.ask('Имя нового устройства (латиница, цифры, дефис): ').strip()
        if not re.fullmatch(NAME_RULE, name):
            print('Недопустимое имя устройства.')
            return
        default = self.default_server_url()
        hint = f' (по умолчанию {default})' if default else ''
        url = self.ask('Адрес сервера для агентов, https://...' + hint + ': ').strip() or default
        if not (isinstance(url, str) and url.startswith('https://')):
            print('Нужен адрес схемы https.')
            return
        provision = self.home / 'dlp-provision'
        provision.mkdir(mode=0o700, exist_ok=True)
        registration = f'/var/lib/dlp-central/{name}.json'
        if self.root_execute(self.dc() + ['exec', 'local', 'python3', '/app/entrypoint.py',
                                          'add-agent', '--name', name, '--server', url,
                                          '--out', registration]).returncode != 0:
            print('Регистрация не выполнена; устройство не создано.')
            return
        agent_json = provision / 'central-agent.json'
        if (self.root_execute(self.dc() + ['cp', f'local:{registration}', str(agent_json)]).returncode != 0
                or self.root_execute(['chown', f'{os.getuid()}:{os.getgid()}', str(agent_json)]).returncode != 0):
            print('Не удалось забрать файл регистрации.')
            return
        if agent_json.exists():
            os.chmod(agent_json, 0o600)
        ca_file = provision / 'central-ca.crt'
        if self.root_execute(['install', '-o', 'root', '-g', 'root', '-m', '644',
                              str(self.ca_source), str(ca_file)]).returncode != 0:
            print('Не удалось скопировать CA.')
            return
        connection = provision / 'connection.json'
        repo = self.find_repo()
        if repo is None:
            print('Исходники проекта не найдены; соберите профиль вручную командой')
            print('python3 scripts/build-connection.py --registration', agent_json,
                  '--ca', ca_file, '--output', connection)
        elif self.execute(['python3', str(repo / 'scripts' / 'build-connection.py'),
                           '--registration', str(agent_json), '--ca', str(ca_file),
                           '--output', str(connection)]).returncode != 0:
            print('Профиль не собран; проверьте сообщения выше.')
            return
        print('Готово:', connection)
        print('Передайте его на новую машину и выполните там:')
        print('  sudo apt install ./dlp-lab_<версия>_amd64.deb')
        print('  sudo dlp-setup connection.json')

    def service_state(self):
        for unit in SERVICES:
            state = self.execute(['systemctl', 'show', unit, '-p', 'ActiveState', '--value'], capture=True)
            print(f'{unit}: {state.stdout.strip() or "неизвестно"}')

    def service_logs(self, unit):
        self.root_execute(['journalctl', '-u', unit, '-n', '30', '--no-pager', '--output', 'cat'])

    def restart_services(self):
        if not self.confirm('Перезапустить файловую и сеансовую защиту? Контроль кратко прервётся.'):
            return
        self.root_execute(['systemctl', 'restart', 'dlp-lab-files.service',
                           'dlp-lab-session.service', 'dlp-lab-forwarder.service'])
        self.service_state()

    def server_ps(self):
        self.root_execute(self.dc() + ['ps'])

    def admin_token(self):
        self.root_execute(['dlp-admin-token'])

    def server_backup(self):
        if not self.confirm('Создать резервную копию сервера? Контейнеры кратко остановятся.'):
            return
        result = self.root_execute(['mktemp', '-d', '/var/backups/dlp-central-docker.XXXXXXXX'], capture=True)
        backup_dir = result.stdout.strip()
        if result.returncode != 0 or not backup_dir.startswith('/var/backups/'):
            print('Не удалось создать каталог копии.')
            return
        self.root_execute(['chmod', '700', backup_dir])
        try:
            self.root_execute(self.dc() + ['stop'])
            self.root_execute(['cp', '-a', '/var/lib/dlp-central', backup_dir + '/state'])
            self.root_execute(['cp', '-a', '/etc/dlp-lab', backup_dir + '/config'])
        finally:
            self.root_execute(self.dc() + ['start'])
        print('Резервная копия:', backup_dir)
        print('Копия содержит секреты; не публикуйте её.')

    def update_stand(self):
        repo = self.find_repo()
        if repo is None:
            print('Исходники проекта не найдены; обновление выполняется из каталога репозитория.')
            return
        if not self.confirm(f'Обновить сервер и локальный агент из {repo}?'):
            return
        self.root_execute(['python3', str(repo / 'scripts' / 'update-managed-agent.py')])

    # --- menus -----------------------------------------------------------
    def loop(self, title, items, nested):
        while True:
            print('\n==', title, '==')
            for index, (label, _) in enumerate(items, 1):
                print(f' {index}. {label}')
            print(' 0. Назад' if nested else ' 0. Выход')
            choice = self.ask('Выбор: ').strip()
            if choice == '0':
                return
            if choice.isdigit() and 1 <= int(choice) <= len(items):
                try:
                    items[int(choice) - 1][1]()
                except SystemExit as error:
                    print(error)
                self.pause()
            else:
                print('Нет такого пункта.')

    def update_agent(self):
        if not self.confirm('Установить новый пакет агента из ~/dlp-build-input?'):
            return
        self.root_execute(['dlp-lab-update'])

    def services_menu(self):
        self.loop('Службы агента', [
            ('Состояние служб', self.service_state),
            ('Журнал файловой службы', lambda: self.service_logs('dlp-lab-files.service')),
            ('Журнал отправщика', lambda: self.service_logs('dlp-lab-forwarder.service')),
            ('Перезапустить защиту', self.restart_services),
            ('Обновить агент', self.update_agent),
        ], True)

    def server_menu(self):
        self.loop('Сервер', [
            ('Состояние контейнеров', self.server_ps),
            ('Токен администратора', self.admin_token),
            ('Резервная копия', self.server_backup),
            ('Обновить стенд', self.update_stand),
        ], True)

    def main(self):
        role = 'сервер + агент' if self.server_role() else 'агент'
        print(f'DLP Lab — консоль управления · роль: {role}')
        print('Действия, требующие root, вызывают sudo; меняющие состояние — просят подтверждение.')
        items = [
            ('Статус стенда', self.status),
            ('Диагностика агента', self.doctor),
            ('Добавить устройство', self.add_device),
            ('Службы агента', self.services_menu),
        ]
        if self.server_role():
            items.append(('Сервер', self.server_menu))
        self.loop('DLP Lab', items, False)
        return 0


def main():
    try:
        return Console().main()
    except (KeyboardInterrupt, EOFError):
        print()
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
