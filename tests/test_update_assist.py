"""Update helper tests: name rules, candidate choice, downgrade refusal,
real dpkg-deb output format, sudo home resolution."""
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dlp.update_assist import (  # noqa: E402
    build_install_command, candidate_from_name, invoking_home,
    read_fields, select_candidate)


def touch(directory, name):
    path = Path(directory) / name
    path.write_bytes(b'')
    return path


class NameTests(unittest.TestCase):
    def test_valid_names(self):
        self.assertEqual(candidate_from_name('dlp-lab_0.2.34_amd64.deb'), ('0.2.34', 'amd64'))
        self.assertEqual(candidate_from_name('dlp-lab_0.2.34~deb12u1_amd64.deb'),
                         ('0.2.34~deb12u1', 'amd64'))
        self.assertEqual(candidate_from_name('dlp-lab_1.0+really1_all.deb'), ('1.0+really1', 'all'))

    def test_invalid_names(self):
        for bad in ('other_1.0_amd64.deb', 'dlp-lab_1.0_evil_arch.deb',
                    'dlp-lab__amd64.deb', 'dlp-lab_1.0_amd64.deb.exe',
                    '../dlp-lab_1.0_amd64.deb', 'dlp-lab_1.0_amd64.DEB'):
            self.assertIsNone(candidate_from_name(bad), bad)


class SelectionTests(unittest.TestCase):
    def make_reader(self, mapping):
        return lambda path, fields: mapping.get(Path(path).name)

    def test_picks_newest_valid_candidate(self):
        with tempfile.TemporaryDirectory() as root:
            touch(root, 'dlp-lab_0.2.33_amd64.deb')
            newest = touch(root, 'dlp-lab_0.2.34~deb12u1_amd64.deb')
            touch(root, 'readme.txt')
            touch(root, 'dlp-lab_0.2.99_amd64.deb')  # wrong Package below
            reader = self.make_reader({
                'dlp-lab_0.2.33_amd64.deb': {'Package': 'dlp-lab', 'Architecture': 'amd64', 'Version': '0.2.33'},
                'dlp-lab_0.2.34~deb12u1_amd64.deb': {'Package': 'dlp-lab', 'Architecture': 'amd64', 'Version': '0.2.34~deb12u1'},
                'dlp-lab_0.2.99_amd64.deb': {'Package': 'evil', 'Architecture': 'amd64', 'Version': '0.2.99'},
            })
            chosen = select_candidate(Path(root), installed='0.2.30', architecture='amd64',
                                      field_reader=reader,
                                      compare=lambda a, b: subprocess.run(
                                          ['dpkg', '--compare-versions', a, 'gt', b]).returncode == 0)
            self.assertEqual(chosen, (newest, '0.2.34~deb12u1'))

    def test_refuses_equal_or_older_and_wrong_arch(self):
        with tempfile.TemporaryDirectory() as root:
            touch(root, 'dlp-lab_0.2.30_amd64.deb')   # equal -> refused
            touch(root, 'dlp-lab_0.2.29_amd64.deb')    # older -> refused
            touch(root, 'dlp-lab_0.2.40_i386.deb')     # other arch -> refused
            reader = self.make_reader({
                'dlp-lab_0.2.30_amd64.deb': {'Package': 'dlp-lab', 'Architecture': 'amd64', 'Version': '0.2.30'},
                'dlp-lab_0.2.29_amd64.deb': {'Package': 'dlp-lab', 'Architecture': 'amd64', 'Version': '0.2.29'},
                'dlp-lab_0.2.40_i386.deb': {'Package': 'dlp-lab', 'Architecture': 'i386', 'Version': '0.2.40'},
            })
            chosen = select_candidate(Path(root), installed='0.2.30', architecture='amd64',
                                      field_reader=reader, compare=lambda a, b: a > b)
            self.assertIsNone(chosen)

    def test_missing_directory_is_not_an_error(self):
        self.assertIsNone(select_candidate(Path('/nonexistent-dlp-input'),
                                           installed='1', architecture='amd64',
                                           field_reader=lambda p, f: None,
                                           compare=lambda a, b: True))


class ReadFieldsTests(unittest.TestCase):
    """Real dpkg-deb -f output: multi-field lines carry `Field: ` prefixes."""

    def run_with_stdout(self, stdout, returncode=0):
        result = subprocess.CompletedProcess(args=[], returncode=returncode,
                                             stdout=stdout, stderr='')
        with mock.patch('dlp.update_assist.subprocess.run', return_value=result):
            return read_fields(Path('/tmp/x.deb'), ['Package', 'Architecture', 'Version'])

    def test_multi_field_output_is_parsed_without_prefixes(self):
        # Recorded from dpkg-deb 1.22 on a real package (2026-11-15).
        self.assertEqual(
            self.run_with_stdout('Package: dlp-lab\nArchitecture: amd64\nVersion: 0.2.34\n'),
            {'Package': 'dlp-lab', 'Architecture': 'amd64', 'Version': '0.2.34'})

    def test_single_field_bare_value_is_kept(self):
        result = subprocess.CompletedProcess(args=[], returncode=0,
                                             stdout='0.2.34\n', stderr='')
        with mock.patch('dlp.update_assist.subprocess.run', return_value=result):
            self.assertEqual(read_fields(Path('/tmp/x.deb'), ['Version']),
                             {'Version': '0.2.34'})

    def test_failure_and_truncated_output_return_none(self):
        self.assertIsNone(self.run_with_stdout('', returncode=2))
        self.assertIsNone(self.run_with_stdout('Package: dlp-lab\nArchitecture: amd64\n'))


class InvokingHomeTests(unittest.TestCase):
    def test_sudo_context_resolves_sudo_user_home(self):
        # Under sudo HOME points at /root; the invoking user lives in SUDO_USER.
        user = pwd.getpwuid(os.getuid()).pw_name
        with mock.patch.dict(os.environ, {'SUDO_USER': user, 'HOME': '/root'}):
            self.assertEqual(invoking_home(), Path(pwd.getpwnam(user).pw_dir))

    def test_without_sudo_user_falls_back_to_home(self):
        # patch.dict merges into os.environ; SUDO_USER must go explicitly
        # because a test run itself started under sudo would carry it.
        with mock.patch.dict(os.environ, {'HOME': '/tmp/dlp-sentinel-home'}):
            os.environ.pop('SUDO_USER', None)
            self.assertEqual(invoking_home(), Path('/tmp/dlp-sentinel-home'))

    def test_unknown_sudo_user_returns_none(self):
        with mock.patch.dict(os.environ, {'SUDO_USER': 'no-such-dlp-user'}):
            self.assertIsNone(invoking_home())


@unittest.skipUnless(shutil.which('dpkg-deb') and shutil.which('dpkg'),
                     'dpkg-deb/dpkg not available')
class RealDebTests(unittest.TestCase):
    """End-to-end selection against a package built by the real dpkg-deb."""

    VERSION = '9.9.9'

    def build_deb(self, root):
        bundle = Path(root) / 'pkg'
        # dpkg-deb requires the control directory to be 0755..0775; set the
        # mode explicitly so a leaked process umask cannot break the build.
        (bundle / 'DEBIAN').mkdir(parents=True)
        (bundle / 'DEBIAN').chmod(0o755)
        (bundle / 'DEBIAN' / 'control').write_text(
            'Package: dlp-lab\n'
            f'Version: {self.VERSION}\n'
            'Architecture: all\n'
            'Maintainer: DLP Lab Tests <tests@localhost>\n'
            'Description: mini package for updater tests\n')
        name = f'dlp-lab_{self.VERSION}_all.deb'
        result = subprocess.run(['dpkg-deb', '--build', '--root-owner-group',
                                 str(bundle), str(Path(root) / name)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(root) / name

    def test_real_deb_is_selected_against_installed_version(self):
        with tempfile.TemporaryDirectory() as root:
            deb = self.build_deb(root)
            self.assertEqual(read_fields(deb, ['Package', 'Architecture', 'Version']),
                             {'Package': 'dlp-lab', 'Architecture': 'all',
                              'Version': self.VERSION})
            chosen = select_candidate(Path(root), installed='0.2.34', architecture='all')
            self.assertEqual(chosen, (deb, self.VERSION))
            self.assertIsNone(select_candidate(Path(root), installed=self.VERSION,
                                               architecture='all'))


class InstallCommandTests(unittest.TestCase):
    def test_install_command_is_fixed_argument_list(self):
        command = build_install_command(Path('/tmp/x/dlp-lab_1.0_amd64.deb'))
        self.assertEqual(command[:3], ['apt-get', 'install', '-y'])
        self.assertIn('Dpkg::Options::=--force-confold', command)
        self.assertTrue(all(isinstance(a, str) for a in command))
        for arg in command:
            self.assertNotIn(';', arg)
            self.assertNotIn('|', arg)


if __name__ == '__main__':
    unittest.main()
