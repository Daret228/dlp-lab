"""Read-only storage probe; never opens config, key stores or message rows."""
import os
from pathlib import Path
import stat


def probe_signal_storage(root: Path):
    """Inspect an explicitly selected profile; no recursion or symlink following.

    A non-SQLite header is not proof of encryption: damaged/unknown files have
    the same observation. No database connection or recovery is attempted.
    """
    result = {'messenger': 'signal', 'source': 'local_storage_probe',
              'messages_read': 0, 'content_analysis': False,
              'database_header': 'unchecked', 'files': {}}
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, directory_flags)
    except OSError:
        result['status'] = 'profile_unavailable'
        return result
    try:
        try:
            config = os.stat('config.json', dir_fd=root_fd, follow_symlinks=False)
            result['files']['config'] = 'regular' if stat.S_ISREG(config.st_mode) else 'unsupported'
        except FileNotFoundError:
            result['files']['config'] = 'missing'
        try:
            sql_fd = os.open('sql', directory_flags, dir_fd=root_fd)
        except OSError:
            result['status'] = 'database_directory_unavailable'
            return result
        try:
            for label, name in (('database', 'db.sqlite'), ('wal', 'db.sqlite-wal'), ('shm', 'db.sqlite-shm')):
                try:
                    st = os.stat(name, dir_fd=sql_fd, follow_symlinks=False)
                    result['files'][label] = 'regular' if stat.S_ISREG(st.st_mode) else 'unsupported'
                except FileNotFoundError:
                    result['files'][label] = 'missing'
            if result['files']['database'] != 'regular':
                result['status'] = 'database_unavailable'
                return result
            fd = os.open('db.sqlite', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=sql_fd)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    result['status'] = 'database_unavailable'
                    return result
                header = os.read(fd, 16)
            finally:
                os.close(fd)
            result['database_header'] = ('sqlite_plaintext' if header == b'SQLite format 3\x00'
                                         else 'short_or_empty' if len(header) < 16
                                         else 'not_plaintext_sqlite')
            result['status'] = 'probe_only'
            return result
        finally:
            os.close(sql_fd)
    except OSError:
        result['status'] = 'io_error'
        return result
    finally:
        os.close(root_fd)
