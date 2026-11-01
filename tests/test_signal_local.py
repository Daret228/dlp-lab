import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from dlp.audit import JsonAudit
from dlp.signal_local import snapshot,LocalCheckError,notify_summary

class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'profile';self.root.mkdir();(self.root/'sql').mkdir()
        (self.root/'config.json').write_text('{}')
        (self.root/'sql/db.sqlite').write_bytes(b'synthetic encrypted data')
        self.dest=Path(self.tmp.name)/'copy';self.dest.mkdir()

    @patch('dlp.signal_local.require_stopped')
    def test_copy_private_and_source_unchanged(self,stopped):
        with snapshot(self.root,self.dest,'unused') as (db,config):
            self.assertEqual(db.read_bytes(),b'synthetic encrypted data')
            self.assertEqual(db.stat().st_mode & 0o777,0o600)
            self.assertEqual(config,{})
            self.assertFalse((self.dest/'config.json').exists())
        self.assertEqual(stopped.call_count,3)

    @patch('dlp.signal_local.require_stopped')
    def test_new_wal_rejected(self,_):
        with self.assertRaisesRegex(LocalCheckError,'source_changed'):
            with snapshot(self.root,self.dest,'unused'):
                (self.root/'sql/db.sqlite-wal').write_bytes(b'changed')

    @patch('dlp.signal_local.require_stopped')
    def test_changed_config_rejected(self,_):
        with self.assertRaisesRegex(LocalCheckError,'source_changed'):
            with snapshot(self.root,self.dest,'unused'):
                (self.root/'config.json').write_text('{"changed":true}')

    @patch('dlp.signal_local.require_stopped')
    def test_symlink_database_rejected(self,_):
        p=self.root/'sql/db.sqlite';p.unlink();p.symlink_to('/dev/zero')
        with self.assertRaises(OSError):
            with snapshot(self.root,self.dest,'unused'):pass

    @patch('dlp.signal_local.require_stopped',side_effect=LocalCheckError('signal_running'))
    def test_running_client_rejected_before_copy(self,_):
        with self.assertRaisesRegex(LocalCheckError,'signal_running'):
            with snapshot(self.root,self.dest,'unused'):pass
        self.assertEqual(list(self.dest.iterdir()),[])

class WarningTests(unittest.TestCase):
    @patch('dlp.notifications.deliver_notification',return_value='accepted')
    def test_one_warning_and_audit_without_display_claim(self,send):
        out=io.StringIO();summary={'decisions':{'BLOCK':2,'WARN':1},'incomplete':0,'skipped_oversize':0}
        notify_summary(summary,[JsonAudit(out)])
        send.assert_called_once()
        event=json.loads(out.getvalue());self.assertFalse(event['display_confirmed'])
        self.assertFalse(event['send_blocked'])

    @patch('dlp.notifications.deliver_notification')
    def test_allow_and_disabled_do_not_notify(self,send):
        summary={'decisions':{'BLOCK':0,'WARN':0},'incomplete':0,'skipped_oversize':0}
        notify_summary(summary,[])
        summary['decisions']['BLOCK']=1
        notify_summary(summary,[],False)
        send.assert_not_called()

from types import SimpleNamespace
from dlp.signal_local import require_stopped

_real_readlink = __import__('os').readlink


def inaccessible_proc_link(path, *args, **kwargs):
    if str(path).startswith('/proc/'):
        raise PermissionError()
    return _real_readlink(path, *args, **kwargs)


class ProcessGuardTests(unittest.TestCase):
    def fake_process(self,name):
        from unittest.mock import MagicMock
        process=MagicMock();process.name='123'
        process.stat.return_value=SimpleNamespace(st_uid=__import__('os').getuid())
        process.__truediv__.return_value.read_text.return_value=name
        comm=process.__truediv__.return_value
        process.__truediv__.side_effect=lambda part: Path('/proc/123/exe') if part == 'exe' else comm
        return process

    @patch('dlp.signal_local.os.readlink',side_effect=inaccessible_proc_link)
    @patch('dlp.signal_local.Path.iterdir')
    def test_known_hidden_session_helper(self,listing,_):
        listing.return_value=[self.fake_process('ssh-agent')]
        require_stopped(__import__('sys').executable)

    @patch('dlp.signal_local.os.readlink',side_effect=inaccessible_proc_link)
    @patch('dlp.signal_local.Path.iterdir')
    def test_unknown_hidden_process_fails_closed(self,listing,_):
        listing.return_value=[self.fake_process('signal-desktop')]
        with self.assertRaisesRegex(LocalCheckError,'process_visibility_unavailable'):
            require_stopped(__import__('sys').executable)


class PackagedWorkerTests(unittest.TestCase):
    @patch('dlp.signal_local.__file__','/usr/lib/dlp-lab/src/dlp/signal_local.py')
    def test_isolated_worker(self):
        from dlp.signal_local import worker_command
        args=SimpleNamespace(root='/profile',executable='/signal',sqlcipher_library='libsqlcipher.so.1',policy='/policy',limit=2)
        command=worker_command(args,'/copy')
        self.assertEqual(command[1:3],['-I','-c'])
        self.assertEqual(command[-6:],['/profile','/copy','/signal','libsqlcipher.so.1','/policy','2'])
