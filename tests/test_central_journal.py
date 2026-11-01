import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from dlp.central import Forwarder, connect


class JournalScopeTests(unittest.TestCase):
    def test_system_unit_reads_split_journals_and_keeps_cursor(self):
        with tempfile.TemporaryDirectory() as folder:
            worker=Forwarder(Path(folder)/'queue', {'server':'http://127.0.0.1:8766','agent_id':'synthetic','token':'synthetic'})
            # journalctl -u selects the system unit, independent of worker UID.
            entry={'__CURSOR':'synthetic-cursor', '_UID':'1000', '_SYSTEMD_UNIT':'dlp-lab-files.service',
                   'MESSAGE':json.dumps({'event':'file_access_attempt','result':{'decision':'BLOCK'},'enforcement':'DENY'})}
            with patch('dlp.central.subprocess.Popen') as popen:
                child=popen.return_value
                child.stdout=io.BytesIO((json.dumps(entry)+'\n').encode())
                child.wait.return_value=0
                child.poll.return_value=0
                worker.collect(system=True)
                command=popen.call_args.args[0]
                self.assertNotIn('--system',command)
                self.assertNotIn('--user',command)
                self.assertIn('--unit=dlp-lab-files.service',command)
            with connect(worker.state) as db:
                self.assertEqual(db.execute('SELECT value FROM cursors').fetchone()[0],'synthetic-cursor')
                payload=json.loads(db.execute('SELECT payload FROM queue').fetchone()[0])
                self.assertEqual((payload['decision'],payload['enforcement']),('BLOCK','DENY'))
            with patch('dlp.central.subprocess.Popen') as popen:
                child=popen.return_value;child.stdout=io.BytesIO(b'');child.wait.return_value=0;child.poll.return_value=0
                worker.collect(system=True)
                self.assertIn('--after-cursor=synthetic-cursor',popen.call_args.args[0])
                child.stdout=io.BytesIO(b'')
                worker.collect(system=False)
                self.assertIn('--user',popen.call_args.args[0])
