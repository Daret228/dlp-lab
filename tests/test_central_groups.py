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

    def test_separate_devices_files_but_merge_outcomes(self):
        base=self.event()
        variants=[base,dict(base,agent='device-two'),self.event('b'*32),
                  dict(base,decision='WARN',enforcement='ALLOW'),dict(base,complete=False),
                  dict(base,categories=['credentials']),dict(base,messenger='signal')]
        rows=group_access_events(variants)
        self.assertEqual(len(rows),4)
        self.assertEqual(rows[0]['decision'],'BLOCK')
        self.assertEqual(rows[0]['enforcement'],'DENY')
        self.assertFalse(rows[0]['complete'])
        self.assertEqual(rows[0]['categories'],['confidential','credentials'])

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


class AllowedFileGroups(unittest.TestCase):
    def test_allow_warn_and_deny_merge_with_strongest_result(self):
        base=dict(agent='device',event='file_access_attempt',access_group='a'*32,
                  decision='ALLOW',enforcement='ALLOW',complete=True,categories=[],received='2026-11-08T12:00:00Z')
        rows=group_access_events([base,base,dict(base,decision='WARN'),dict(base,enforcement='DENY')])
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['attempts_in_view'],4)
        self.assertEqual(rows[0]['decision'],'WARN')
        self.assertEqual(rows[0]['enforcement'],'DENY')

class FileExplanationTests(unittest.TestCase):
    def test_only_bounded_metadata_and_no_content(self):
        raw=dict(event='file_access_attempt',path='/tmp/a\n.txt',text='private',result={
            'decision':'WARN','reason':'sensitive_alerts_incomplete',
            'findings':[{'analyzer':'ml','rule_id':'ml_credentials','category':'credentials','metadata':{'match':'private'}}]})
        p=project(raw)
        self.assertEqual(p['file_path'],'/tmp/a.txt')
        self.assertEqual(p['rules'],['ml_credentials'])
        self.assertNotIn('private',str(p))
        raw['path']='/'+'x'*4096
        self.assertNotIn('file_path',project(raw))
        raw['result']['reason']='raw content not a code'
        self.assertNotIn('reasons',project(raw))

    def test_distinct_paths_not_collapsed_even_with_bad_reused_group(self):
        base=dict(event='file_access_attempt',agent='a',access_group='a'*32,
                  decision='ALLOW',received='2026-11-09T00:00:00Z')
        self.assertEqual(len(group_access_events([dict(base,file_path='/a/report.txt'),dict(base,file_path='/b/report.txt')])),2)


class HealthPolicyFieldsTests(unittest.TestCase):
    def test_policy_fields_projected_canonically_for_new_agents(self):
        raw={'event':'endpoint_health','timestamp':'2026-11-09T12:00:00+00:00',
             'management_ready':True,'policy_channel':True,'policy_version':'c'*64,
             'files_state':'active','session_state':'ready'}
        value=project(raw)
        self.assertEqual(value['policy_version'],'c'*64)
        self.assertIs(value['policy_channel'],True)
        self.assertEqual(project(value),value)
        for invalid in ('short', 'X'*64, 42, None, 'c'*63):
            raw['policy_version']=invalid
            self.assertNotIn('policy_version',project(raw))
        raw['policy_version']='c'*64
        for invalid in ('yes', 1, None):
            raw['policy_channel']=invalid
            self.assertNotIn('policy_channel',project(raw))
        raw['policy_channel']=False
        self.assertIs(project(raw)['policy_channel'],False)
        # Old agents without the fields stay accepted and unchanged.
        legacy={k:v for k,v in raw.items() if k not in ('policy_version','policy_channel')}
        self.assertNotIn('policy_version',project(legacy))
        self.assertNotIn('policy_channel',project(legacy))
