import copy
import unittest
from dlp.central import project, group_access_events


class AccessGroupingTests(unittest.TestCase):
    def event(self, group='a'*32):
        return dict(agent='device-one', event='file_access_attempt', access_group=group,
                    messenger='telegram', decision='BLOCK', enforcement='DENY', complete=True,
                    categories=['confidential'], received='2026-11-05T12:00:01+00:00')

    def test_three_attempts_one_row_raw_unchanged(self):
        events=[self.event() for _ in range(3)]
        events[1]['received']='2026-11-05T12:00:00+00:00'
        original=copy.deepcopy(events)
        rows=group_access_events(events)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['attempts_in_view'],3)
        self.assertEqual(rows[0]['first_received'],events[1]['received'])
        self.assertEqual(events,original)

    def test_separate_devices_files_and_outcomes(self):
        base=self.event()
        variants=[base,dict(base,agent='device-two'),self.event('b'*32),
                  dict(base,decision='WARN',enforcement='ALLOW'),dict(base,complete=False),
                  dict(base,categories=['credentials']),dict(base,messenger='signal')]
        self.assertEqual(len(group_access_events(variants)),len(variants))

    def test_legacy_events_and_notifications_never_guessed(self):
        event=self.event();event.pop('access_group')
        notification=dict(self.event(),event='notification_delivery')
        self.assertEqual(len(group_access_events([event,event,notification,notification])),4)

    def test_projection_is_canonical_and_private(self):
        raw={'event':'file_access_attempt','correlation':{'group_id':'a'*32,'repeat_count':3},
             'path':'/private/file','result':{'decision':'BLOCK'}}
        value=project(raw)
        self.assertEqual(value['access_group'],'a'*32)
        self.assertEqual(project(value),value)
        self.assertNotIn('path',value)
        self.assertNotIn('correlation',value)
        for invalid in ('private filename', 'a'*33, 1, None):
            raw['correlation']['group_id']=invalid
            self.assertNotIn('access_group',project(raw))
