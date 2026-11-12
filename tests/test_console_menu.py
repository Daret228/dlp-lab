"""Console menu tests: navigation, safety of commands, role detection."""
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dlp.console_menu import Console, as_root, NAME_RULE  # noqa: E402


class FakeResult:
    def __init__(self, returncode=0, stdout=''):
        self.returncode = returncode
        self.stdout = stdout


class Script:
    """Replays queued answers and records executed commands."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.commands = []
        self.stdout = io.StringIO()

    def ask(self, question=''):
        self.stdout.write(question + '\n')
        return self.answers.pop(0) if self.answers else '0'

    def run(self, argv, capture=False):
        self.commands.append(list(argv))
        return FakeResult(stdout='ok\n')


def make_console(answers, paths=None):
    script = Script(answers)
    paths = dict(paths or {})
    paths.setdefault('panel_url', 'http://127.0.0.1:1/')  # hermetic: never reachable
    console = Console(runner=script.run, prompter=script.ask, paths=paths)
    return console, script


class NavigationTests(unittest.TestCase):
    def test_zero_exits_and_invalid_reprompts(self):
        console, script = make_console(['9', 'x', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        output = script.stdout.getvalue()
        self.assertIn('0. Выход', output)
        self.assertIn('Нет такого пункта.', output)
        self.assertEqual(script.commands, [])  # nothing executed

    def test_main_menu_lists_documented_items(self):
        console, script = make_console(['0'])
        with redirect_stdout(script.stdout):
            console.main()
        output = script.stdout.getvalue()
        for label in ('Статус стенда', 'Диагностика агента', 'Добавить устройство',
                      'Службы агента'):
            self.assertIn(label, output)
        self.assertIn('роль: агент', output)

    def test_server_role_adds_server_menu(self):
        with tempfile.TemporaryDirectory() as root:
            compose = Path(root) / 'compose.json'
            compose.write_text('{}')
            console, script = make_console(['0'], paths={'server_compose': compose})
            with redirect_stdout(script.stdout):
                console.main()
        self.assertIn('Сервер', script.stdout.getvalue())
        self.assertIn('роль: сервер + агент', script.stdout.getvalue())

    def test_panel_alone_detects_server_role(self):
        # Root-only compose directory: the loopback panel is the fallback sign.
        console, script = make_console(['0'], paths={
            'server_compose': Path('/nonexistent-dlp/compose.json'),
            'panel_url': 'http://127.0.0.1:1/'})
        with mock.patch.object(console, 'panel_state', return_value='HTTP 200'), \
                redirect_stdout(script.stdout):
            console.main()
        self.assertIn('роль: сервер + агент', script.stdout.getvalue())

    def test_submenu_zero_returns_not_exits(self):
        console, script = make_console(['4', '0', '0'])
        with redirect_stdout(script.stdout):
            code = console.main()
        self.assertEqual(code, 0)
        self.assertIn('Службы агента', script.stdout.getvalue())
        self.assertIn('Назад', script.stdout.getvalue())


class SafetyTests(unittest.TestCase):
    def test_as_root_prepends_sudo_for_user(self):
        with mock.patch('dlp.console_menu.os.geteuid', return_value=1000), \
                mock.patch('dlp.console_menu.shutil.which', return_value='/usr/bin/sudo'):
            self.assertEqual(as_root(['dlp-agent', 'doctor']),
                             ['sudo', 'dlp-agent', 'doctor'])

    def test_as_root_direct_for_root_and_reports_missing_sudo(self):
        with mock.patch('dlp.console_menu.os.geteuid', return_value=0):
            self.assertEqual(as_root(['x']), ['x'])
        with mock.patch('dlp.console_menu.os.geteuid', return_value=1000), \
                mock.patch('dlp.console_menu.shutil.which', return_value=None):
            with self.assertRaises(SystemExit):
                as_root(['x'])

    def test_no_shell_strings_in_commands(self):
        console, script = make_console(['1', '', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        for argv in script.commands:
            for arg in argv:
                self.assertNotIn(';', arg)
                self.assertNotIn('|', arg)
            self.assertTrue(all(isinstance(a, str) for a in argv))

    def test_restart_requires_confirmation(self):
        console, script = make_console(['4', '4', 'нет', '', '0', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        self.assertFalse(any('restart' in ' '.join(c) for c in script.commands))

    def test_restart_runs_after_confirmation(self):
        console, script = make_console(['4', '4', 'да', '', '0', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        restarts = [c for c in script.commands if 'restart' in ' '.join(c)]
        self.assertEqual(len(restarts), 1)
        self.assertIn('systemctl', restarts[0])

    def test_doctor_uses_dlp_agent(self):
        console, script = make_console(['2', '', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        self.assertIn(['sudo', 'dlp-agent', 'doctor'], script.commands)


class DeviceFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / 'compose.json').write_text('{}')
        (self.base / 'central-agent.json').write_text('{"server": "https://sec.example:8767"}')
        self.paths = {
            'server_compose': self.base / 'compose.json',
            'agent_profile': self.base / 'central-agent.json',
            'ca_source': self.base / 'ca.crt',
            'home': self.base,
        }
        repo_scripts = self.base / 'dlp-lab' / 'scripts'
        repo_scripts.mkdir(parents=True)
        (repo_scripts / 'build-connection.py').write_text('# fake\n')

    def make_server_console(self, answers):
        return make_console(answers, paths=self.paths)

    def test_name_rejected(self):
        console, script = self.make_server_console(['3', 'Bad Name!', '0', '', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        self.assertFalse(any('add-agent' in ' '.join(c) for c in script.commands))
        self.assertIn('Недопустимое имя', script.stdout.getvalue())

    def test_default_url_from_profile_and_command_sequence(self):
        console, script = self.make_server_console(
            ['3', 'kiosk-01', '', '', '0', '', '0'])
        # answers: menu 3; name; url (empty→default); confirm? none; back etc.
        with redirect_stdout(script.stdout):
            console.main()
        joined = [' '.join(c) for c in script.commands]
        add = [c for c in joined if 'add-agent' in c]
        self.assertEqual(len(add), 1)
        self.assertIn('--name kiosk-01', add[0])
        self.assertIn('--server https://sec.example:8767', add[0])
        self.assertTrue(any('build-connection.py' in c for c in joined),
                        'profile assembly invoked: ' + '; '.join(joined))
        self.assertIn('sudo dlp-setup connection.json', script.stdout.getvalue())

    def test_no_server_role_blocks_device_item(self):
        console, script = make_console(['3', '', '0'])
        with redirect_stdout(script.stdout):
            console.main()
        self.assertIn('доступен на машине с сервером', script.stdout.getvalue())


class HelperTests(unittest.TestCase):
    def test_name_rule(self):
        import re
        self.assertTrue(re.fullmatch(NAME_RULE, 'kiosk-01'))
        self.assertFalse(re.fullmatch(NAME_RULE, 'Kiosk'))
        self.assertFalse(re.fullmatch(NAME_RULE, '-x'))
        self.assertFalse(re.fullmatch(NAME_RULE, 'a' * 40))

    def test_default_url_ignores_bad_profile(self):
        with tempfile.TemporaryDirectory() as root:
            profile = Path(root) / 'central-agent.json'
            profile.write_text('not json')
            console, _ = make_console([], paths={'agent_profile': profile})
            self.assertIsNone(console.default_server_url())
            profile.write_text('{"server": "http://insecure"}')
            self.assertIsNone(console.default_server_url())


if __name__ == '__main__':
    unittest.main()
