import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dlp.managed_session import eligible_field, trusted_json, session_available
from dlp.endpoint_health import snapshot
from dlp.central import project, ServerStore


class ManagedSessionTests(unittest.TestCase):
    def test_packaged_command_rejects_user_before_imports(self):
        if os.geteuid() == 0:
            self.skipTest('Requires ordinary user')
        script = Path(__file__).resolve().parents[1]/'packaging/dlp-agent'
        for args in (['agent','stop','all'], ['configure-processes','--telegram','/tmp/x'], ['text-monitor','--marker','x'], ['--help']):
            r = subprocess.run([sys.executable,'-I',str(script),*args],capture_output=True,text=True)
            self.assertEqual(r.returncode,2)
            self.assertIn('администратору',r.stderr)

    def test_requires_focused_visible_multiline_and_not_password(self):
        atspi=SimpleNamespace(StateType=SimpleNamespace(EDITABLE=1,FOCUSED=2,SHOWING=3,MULTI_LINE=4),Role=SimpleNamespace(PASSWORD_TEXT=9))
        for states,role,expected in [({1,2,3,4},1,True),({1,2,3},1,False),({1,3,4},1,False),({1,2,3,4},9,False)]:
            node=SimpleNamespace(get_state_set=lambda:SimpleNamespace(contains=lambda v:v in states),get_role=lambda:role,get_interfaces=lambda:['Text'])
            self.assertEqual(eligible_field(node,atspi),expected)

    def test_user_state_and_symlinks_not_trusted(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'state';p.write_text('{}');p.chmod(0o666)
            with self.assertRaises(ValueError): trusted_json(p)
            link=Path(folder)/'link';link.symlink_to(p)
            with self.assertRaises(OSError): trusted_json(link)

    def test_health_separates_running_service_from_accessible_field(self):
        for active,stored,expected in [('active',{'state':'ready','updated':time.time()},'ready'),('active',{'state':'ready','updated':0},'unavailable'),('inactive',{},'stopped')]:
            with patch('dlp.endpoint_health.service_state',return_value=active),patch('dlp.endpoint_health.trusted_json',return_value=stored):
                h=snapshot();self.assertEqual(h['session_state'],expected)
        with patch('dlp.endpoint_health.service_state',return_value='active'),patch('dlp.endpoint_health.trusted_json',side_effect=ValueError):
            self.assertEqual(snapshot()['session_state'],'unavailable')

    def test_health_projection_bounded_and_canonical(self):
        p=project({'event':'endpoint_health','session_state':'ready','files_state':'active','text':'secret','path':'/private'})
        self.assertNotIn('secret',json.dumps(p));self.assertNotIn('path',p)
        self.assertEqual(project(p),p)
        self.assertNotIn('session_state',project({'event':'endpoint_health','session_state':'arbitrary'}))

    def test_health_survives_event_window_and_cannot_regress_on_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            store=ServerStore(folder)
            identity=store.add('test','http://127.0.0.1:8766',Path(folder)/'agent.json')
            config=json.loads((Path(folder)/'agent.json').read_text());agent=config['agent_id']
            new=project({'event':'endpoint_health','timestamp':'2026-11-06T12:00:00+00:00','session_state':'unavailable'})
            old=project({'event':'endpoint_health','timestamp':'2026-11-06T11:00:00+00:00','session_state':'ready'})
            store.ingest(agent,[{'id':'a'*64,'payload':new}])
            store.ingest(agent,[{'id':'b'*64,'payload':old}])
            self.assertEqual(store.report()['agents'][0]['health']['session_state'],'unavailable')

    def test_pending_health_coalesces_without_removing_audit(self):
        from dlp.central import Forwarder, connect
        with tempfile.TemporaryDirectory() as folder:
            f=Forwarder(folder,{'server':'http://127.0.0.1:8766','agent_id':'test','token':'x'})
            f.enqueue([('1',{'event':'analysis'})],'test')
            for _ in range(50):
                f.queue_health({'event':'endpoint_health','session_state':'ready'})
            with connect(folder) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM queue').fetchone()[0],2)

    def test_supervisor_restarts_exited_worker_and_persists_shutdown(self):
        # Exercise lifecycle without root, systemd or accessing a real desktop.
        import dlp.managed_session as module
        with tempfile.TemporaryDirectory() as folder:
            from unittest.mock import Mock
            child=Mock();child.pid=12345;child.poll.return_value=1
            state=Path(folder)/'state.json'
            selector=Mock();selector.select.return_value=[]
            calls=[]
            def available(uid):
                calls.append(uid)
                if len(calls)==4:
                    raise KeyboardInterrupt
                return True
            account=SimpleNamespace(pw_uid=1000,pw_gid=1000,pw_dir='/home/test')
            trusted=SimpleNamespace(st_mode=0o100644,st_uid=0)
            with patch.object(module.os,'geteuid',return_value=0),patch('dlp.processes.load_process_inventory',return_value={'uid':1000}),patch.object(module.pwd,'getpwuid',return_value=account),patch.object(Path,'lstat',return_value=trusted),patch.object(module,'STATE',state),patch.object(module,'session_available',side_effect=available),patch.object(module.selectors,'DefaultSelector',return_value=selector),patch.object(module.subprocess,'Popen',return_value=child) as launch,patch.object(module.os,'set_blocking'),patch.object(module.os,'killpg') as kill,patch.object(module.signal,'signal'),patch.object(module.time,'sleep'):
                with self.assertRaises(KeyboardInterrupt):module.supervise()
                self.assertEqual(launch.call_args.kwargs['user'],1000)
                self.assertEqual(launch.call_args.kwargs['extra_groups'],[])
                self.assertEqual(launch.call_count,2)
                self.assertEqual(kill.call_count,2)
                self.assertEqual(json.loads(state.read_text())['state'],'stopped')

    def test_session_detection_does_not_traverse_private_runtime(self):
        from dlp.managed_session import session_available
        info=SimpleNamespace(st_mode=0o40700,st_uid=1000)
        def metadata(path):
            if str(path).endswith('/bus'):
                raise PermissionError('Root supervisor has no DAC override')
            return info
        replies=[SimpleNamespace(stdout='2'),SimpleNamespace(stdout='Active=yes\nType=wayland\nRemote=no\n')]
        with patch.object(Path,'lstat',metadata),patch('dlp.managed_session.subprocess.run',side_effect=replies):
            self.assertTrue(session_available(1000))
