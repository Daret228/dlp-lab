"""Own-profile metadata inventory, without reading messages, keys or media.

Only settingss/maps/configs receive an 8-byte container header check.
All other files: stat only. No SQLite connection or decryptor is used.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import struct

HEADER_NAMES = {'settingss', 'maps', 'configs'}
KNOWN_EXTENSIONS = {'.json', '.db', '.sqlite', '.sqlite3', '.db-wal', '.db-shm'}


def inspect_storage(root, max_entries=10000, max_depth=5, *, read_headers=True, records=None):
    if not 1 <= max_entries <= 100000 or not 0 <= max_depth <= 10:
        raise ValueError('Invalid inventory limits')
    counts, extensions, headers = Counter(), Counter(), []
    # Linux: refuse a symlink root and do not update atime while reading.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME
    root_fd = os.open(root, flags)
    if os.fstat(root_fd).st_uid != os.getuid():
        os.close(root_fd)
        raise PermissionError('Only current-user-owned profiles are allowed')
    counts['directories'] = 1
    errors = []
    def visit(dir_fd, depth, relative=()):
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                if counts['entries'] >= max_entries:
                    counts['entry_limit_reached'] = 1
                    return
                counts['entries'] += 1
                try:
                    st = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
                    if stat.S_ISLNK(st.st_mode):
                        counts['symlinks_skipped'] += 1
                        continue
                    if st.st_uid != os.getuid():
                        counts['foreign_owner_skipped'] += 1
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        counts['directories'] += 1
                        if depth >= max_depth:
                            counts['depth_pruned_directories'] += 1
                            continue
                        child = os.open(entry.name, flags, dir_fd=dir_fd)
                        try:
                            after = os.fstat(child)
                            if (after.st_dev, after.st_ino, after.st_uid) != (st.st_dev, st.st_ino, st.st_uid):
                                counts['changed_entries_skipped'] += 1
                                continue
                            visit(child, depth+1, relative + (entry.name,))
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(st.st_mode):
                        # Private in-memory comparison input; never included in the report.
                        if records is not None:
                            records[relative + (entry.name,)] = (
                                st.st_dev, st.st_ino, st.st_size,
                                st.st_mtime_ns, st.st_ctime_ns,
                            )
                        counts['regular_files'] += 1
                        counts['logical_bytes'] += st.st_size
                        suffix = Path(entry.name).suffix.lower()
                        extensions[suffix if suffix in KNOWN_EXTENSIONS else 'other_or_no_extension'] += 1
                        if not read_headers or entry.name not in HEADER_NAMES:
                            counts['content_not_opened'] += 1
                            continue
                        fd = os.open(entry.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOATIME, dir_fd=dir_fd)
                        try:
                            before = os.fstat(fd)
                            if (before.st_dev, before.st_ino, before.st_uid) != (st.st_dev, st.st_ino, st.st_uid) or not stat.S_ISREG(before.st_mode):
                                counts['changed_entries_skipped'] += 1
                                continue
                            header = os.pread(fd, 8, 0)
                            after = os.fstat(fd)
                            stable = (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            tdf = len(header) == 8 and header[:4] == b'TDF$'
                            headers.append({'kind': entry.name, 'depth': depth,
                                            'format': 'TDF' if tdf and stable else 'unknown_or_changed',
                                            'writer_version_le': struct.unpack('<I', header[4:])[0] if tdf and stable else None,
                                            'size': before.st_size, 'stable_during_header_read': stable})
                            counts['header_bytes_read'] += len(header)
                        finally:
                            os.close(fd)
                    else:
                        counts['special_files_skipped'] += 1
                except OSError as exc:
                    errors.append(type(exc).__name__)  # No profile paths or opaque IDs.
    try:
        visit(root_fd, 0)
    finally:
        os.close(root_fd)
    return {'observed_at': datetime.now(timezone.utc).isoformat(),
            'scope': 'metadata_inventory_and_allowlisted_8_byte_headers' if read_headers else 'filesystem_metadata_only',
            'limits': {'max_entries': max_entries, 'max_depth': max_depth},
            'counts': dict(counts), 'extensions_by_name_only': dict(extensions),
            'headers': headers, 'errors': errors,
            'complete_within_limits': not errors and not any(counts[k] for k in ('entry_limit_reached','depth_pruned_directories','changed_entries_skipped','foreign_owner_skipped')),
            'sqlite_content_scan_performed': False,
            'message_content_read': False, 'key_content_read': False,
            'consistent_profile_snapshot': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.home()/'.local/share/TelegramDesktop/tdata')
    parser.add_argument('--max-entries', type=int, default=10000)
    parser.add_argument('--max-depth', type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(inspect_storage(args.root, args.max_entries, args.max_depth), ensure_ascii=False, indent=2))
