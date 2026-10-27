import json
import unittest
from dlp.dashboard import project

class SignalProjectionTests(unittest.TestCase):
    def test_counts_allowlisted_and_secrets_excluded(self):
        raw={'event':'signal_local_analysis_summary','timestamp':'2026-10-27T10:00:00Z',
             'analyzed':2,'incomplete':0,'skipped_oversize':0,'sample_limit':100,
             'decisions':{'ALLOW':1,'WARN':0,'BLOCK':1,'secret':'hidden'},
             'body':'private message','key':'private key','more_text_rows':False}
        event=project({'MESSAGE':json.dumps(raw),'_SYSTEMD_USER_UNIT':'dlp-lab-signal-local.service'})
        self.assertEqual(event['signal_summary']['decisions'],{'ALLOW':1,'WARN':0,'BLOCK':1})
        self.assertNotIn('private',json.dumps(event))
        self.assertIsNone(event['decision'])
        raw['analyzed']=True;raw['decisions']['BLOCK']=-1
        event=project({'MESSAGE':json.dumps(raw)})
        self.assertIsNone(event['signal_summary']['analyzed'])
        self.assertIsNone(event['signal_summary']['decisions']['BLOCK'])
