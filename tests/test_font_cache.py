import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dlp.filesystem_scope import protected_font_cache

PATH='/var/cache/fontconfig/'+'a'*32+'-le64.cache-9'

def meta(mode,uid=0,ino=1,links=1):
    return SimpleNamespace(st_mode=mode,st_uid=uid,st_ino=ino,st_dev=1,st_nlink=links)

class FontCacheTests(unittest.TestCase):
    def check(self, file=None, directory=None, entry=None, path=PATH):
        file=file or meta(stat.S_IFREG|0o644)
        directory=directory or meta(stat.S_IFDIR|0o755)
        with patch('dlp.filesystem_scope.os.fstat',return_value=file), patch(
            'dlp.filesystem_scope.os.lstat',side_effect=lambda p: (entry or file) if p==PATH else directory):
            return protected_font_cache(path,99)

    def test_protected_cache_allowed(self):
        self.assertTrue(self.check())

    def test_untrusted_or_replaced_file_is_not_exempt(self):
        for file in (meta(stat.S_IFREG|0o644,uid=1000),meta(stat.S_IFREG|0o666),
                     meta(stat.S_IFREG|0o664),meta(stat.S_IFREG|0o644,links=2),meta(stat.S_IFIFO|0o644)):
            self.assertFalse(self.check(file=file))
        self.assertFalse(self.check(entry=meta(stat.S_IFLNK|0o777)))
        self.assertFalse(self.check(entry=meta(stat.S_IFREG|0o644,ino=2)))

    def test_untrusted_parent_is_not_exempt(self):
        for directory in (meta(stat.S_IFDIR|0o777),meta(stat.S_IFDIR|0o755,uid=1000),meta(stat.S_IFLNK|0o777)):
            self.assertFalse(self.check(directory=directory))

    def test_other_locations_names_and_deleted_files_are_checked(self):
        for path in ('/tmp/'+PATH.rsplit('/',1)[1],PATH+' (deleted)',
                     '/var/cache/fontconfig/secret.txt',PATH.replace('fontconfig/','fontconfig-other/'),
                     PATH.replace('fontconfig/','fontconfig/subdir/')):
            self.assertFalse(self.check(path=path))

    def test_metadata_failure_is_not_exempt(self):
        with patch('dlp.filesystem_scope.os.lstat',side_effect=OSError):
            self.assertFalse(protected_font_cache(PATH,99))
