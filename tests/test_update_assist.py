"""Update helper tests: name rules, candidate choice, downgrade refusal."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dlp.update_assist import (  # noqa: E402
    build_install_command, candidate_from_name, select_candidate)


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
