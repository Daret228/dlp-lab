"""Bounded offline file-location metadata research, not a sent-message reader."""
from datetime import date
from pathlib import Path

from .telegram_local import (Reader, StorageError, container, decrypt, unlock_key,
                             map_references, file_part)

MAX_LOCATIONS = 10000


def modified_time(stream):
    # Telegram writes QDataStream::Qt_5_1: Julian day, milliseconds, private Spec.
    julian, millis, spec = stream.number('>q'), stream.u32(), stream.number('>b')
    bases = {-1:'local_unknown', 0:'local_standard', 1:'local_dst',
             2:'utc', 3:'offset_not_serialized', 4:'timezone_not_serialized'}
    if spec not in bases or (millis >= 86400000 and millis != 0xffffffff):
        raise StorageError('invalid_location_datetime')
    value = None
    if millis != 0xffffffff:
        try:
            day = date.fromordinal(julian - 1721425)
            seconds, ms = divmod(millis, 1000)
            minutes, second = divmod(seconds, 60)
            hour, minute = divmod(minutes, 60)
            value = f'{day.isoformat()}T{hour:02}:{minute:02}:{second:02}.{ms:03}'
            if spec == 2:
                value += 'Z'
        except (ValueError, OverflowError):
            pass  # Qt dates can be invalid or outside Python's representable range.
    return {'value':value, 'time_basis':bases[spec], 'meaning':'file_modification_time'}


def validate_target(expected_path):
    path = Path(expected_path)
    if not path.is_absolute() or '..' in path.parts or path.name != 'DLP_STORAGE_ATTACHMENT_TEST.txt':
        raise StorageError('requires_absolute_test_file_path')


def parse_locations(data, key, expected_path):
    validate_target(expected_path)
    outer = container(data)
    encrypted = outer.blob(); outer.end()
    stream = Reader(decrypt(encrypted, key))
    count = cached = 0
    matches = []
    while True:
        first, second, legacy = stream.u64(), stream.u64(), stream.u32()
        name = stream.text()
        bookmark = stream.blob()
        modified = modified_time(stream)
        size = stream.u32()
        if not first and not second and not legacy and not name and not size:
            break
        count += 1
        if count > MAX_LOCATIONS:
            raise StorageError('record_count_limit')
        cached += name == '*media_cache*'
        if name == str(expected_path):
            matches.append({'size_bytes':size, 'modified':modified,
                            'bookmark_present':bool(bookmark)})
    aliases = stream.count(MAX_LOCATIONS)
    stream.take(aliases * 32)
    # Reader accepts the historical optional tails as Telegram itself does.
    web_count = downloads_size = 0
    if stream.pos < len(stream.data):
        web_count = stream.count(MAX_LOCATIONS)
        for _ in range(web_count):
            stream.text(); stream.take(12)
        if stream.pos < len(stream.data):
            downloads_size = len(stream.blob())
    stream.end()
    return {'location_records':count, 'media_cache_records':cached,
            'aliases':aliases, 'legacy_web_records':web_count,
            'unparsed_downloads_bytes':downloads_size,
            'target_matches':len(matches), 'target_records':matches}


def collect_locations(profile, password):
    account = profile.account()
    files = {('key_datas',):profile.read(('key_datas',)),
             (account,'maps'):profile.read((account,'maps'))}
    key = unlock_key(files[('key_datas',)], password)
    _, reference = map_references(files[(account,'maps')], key)
    if reference:
        parts = (account, file_part(reference)+'s')
        files[parts] = profile.read(parts)
    if any(profile.read(parts) != data for parts,data in files.items()):
        raise StorageError('profile_changed_during_collection')
    return account, files


def inspect_locations(account, files, password, expected_path):
    validate_target(expected_path)
    key = unlock_key(files[('key_datas',)], password)
    _, reference = map_references(files[(account,'maps')], key)
    if not reference:
        return {'locations_reference_present':False, 'target_matches':0,
                'target_records':[]}
    parts = (account, file_part(reference)+'s')
    if parts not in files:
        raise StorageError('missing_locations_file')
    return {'locations_reference_present':True,
            **parse_locations(files[parts],key,expected_path)}
