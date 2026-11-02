import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bootstrap', Path(__file__).resolve().parents[1]/'scripts/install-dlp.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def identity(self):
        return {'server':'https://192.0.2.1:8767','agent_id':'12345678-1234-1234-1234-123456789abc','token':'x'*43}

    def test_identity_https_exact_schema(self):
        value=self.identity()
        self.assertEqual(bootstrap.registration(json.dumps(value)),value)
        for change in ({'server':'http://192.0.2.1:8767'}, {'server':'https://user:pass@example.org:8767'},
                       {'server':'https://example.org:8767/path'}, {'token':'short'}, {'command':'id'}):
            with self.assertRaises(ValueError): bootstrap.registration(json.dumps({**value,**change}))

    def test_private_file_symlink_and_size_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'secret'; p.write_text('data'); p.chmod(0o600)
            self.assertEqual(bootstrap.read_file(p,private=True),b'data')
            p.chmod(0o644)
            with self.assertRaises(ValueError): bootstrap.read_file(p,private=True)
            with self.assertRaises(ValueError): bootstrap.read_file(p,limit=2)
            link=Path(folder)/'link'; link.symlink_to(p)
            with self.assertRaises(OSError): bootstrap.read_file(link)

    def test_wrong_package_arch_and_debian_release_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)/'test.deb'; p.touch()
            for values in (['other','amd64','0.2.13',''], ['dlp-lab','arm64','0.2.13',''],
                           ['dlp-lab','amd64','0.2.13','']):
                with patch.object(bootstrap,'run',side_effect=values):
                    with self.assertRaises(ValueError): bootstrap.package_info(p,'dlp-lab','amd64','12')
            with patch.object(bootstrap,'run',side_effect=['dlp-lab','amd64','0.2.13~deb12u1','']):
                self.assertEqual(bootstrap.package_info(p,'dlp-lab','amd64','12')[1],'0.2.13~deb12u1')

    def test_existing_identity_never_replaced(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap,'protected'):
            p=Path(folder)/'config'; p.write_bytes(b'original'); p.chmod(0o600)
            self.assertTrue(bootstrap.check_existing(p,b'original',0o600))
            with self.assertRaises(ValueError): bootstrap.check_existing(p,b'new',0o600)
            self.assertEqual(p.read_bytes(),b'original')

    def run_flow(self, folder, extra):
        calls=[]
        def fake_run(args,capture=False):
            calls.append(args)
            return 'amd64' if args[0]=='/usr/bin/dpkg' and '--print-architecture' in args else ''
        with patch.object(bootstrap,'CONFIG',Path(folder)/'etc'), \
             patch.object(bootstrap,'DROPIN',Path(folder)/'dropin'), \
             patch.object(bootstrap,'package_info',return_value=(Path('/tmp/test.deb'),'0.2.13')), \
             patch.object(bootstrap,'choose_user',return_value=SimpleNamespace(pw_name='testuser')), \
             patch.object(bootstrap,'executable',return_value=Path('/usr/bin/telegram-desktop')), \
             patch.object(bootstrap,'run',side_effect=fake_run), \
             patch.object(bootstrap.os,'geteuid',return_value=0), \
             patch.object(bootstrap,'atomic_write') as write, \
             patch.object(bootstrap.subprocess,'run') as process, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc=bootstrap.main(['--package','/tmp/test.deb','--telegram','/usr/bin/telegram-desktop','--no-signal',*extra])
            return rc,calls,write.call_count,process.call_count

    def test_check_does_not_install_or_write(self):
        with tempfile.TemporaryDirectory() as folder:
            rc,calls,writes,processes=self.run_flow(folder,['--local-only','--check'])
        self.assertEqual(rc,0)
        self.assertEqual((writes,processes),(0,0))
        self.assertTrue(any('--simulate' in c for c in calls))
        self.assertFalse(any(c[0]=='/usr/bin/systemctl' for c in calls))
        self.assertFalse(any('-y' in c for c in calls))

    def test_missing_registration_fails_before_install(self):
        with tempfile.TemporaryDirectory() as folder:
            rc,calls,writes,processes=self.run_flow(folder,['--check'])
        self.assertEqual(rc,2)
        self.assertEqual((writes,processes),(0,0))
        self.assertFalse(any(c[0]=='/usr/bin/apt-get' for c in calls))

    def test_local_apply_configures_before_start_and_no_server(self):
        with tempfile.TemporaryDirectory() as folder:
            rc,calls,writes,processes=self.run_flow(folder,['--local-only','--yes'])
        self.assertEqual(rc,0)
        configure=next(i for i,c in enumerate(calls) if c[0]=='/usr/sbin/dlp-lab-configure')
        start=next(i for i,c in enumerate(calls) if 'enable' in c)
        self.assertLess(configure,start)
        self.assertFalse(any('dlp-lab-forwarder.service' in c for c in calls))
        self.assertEqual(processes,1)  # debconf preseed only; no shell invocation

    def test_https_apply_writes_identity_ca_dropin_before_enable(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(bootstrap.ssl,'create_default_context'):
            config=Path(folder)/'identity.json'; config.write_text(json.dumps(self.identity())); config.chmod(0o600)
            ca=Path(folder)/'ca.crt'; ca.write_text('synthetic test CA')
            rc,calls,writes,processes=self.run_flow(folder,['--yes','--central-config',str(config),'--ca',str(ca)])
        self.assertEqual(rc,0)
        self.assertEqual(writes,3)
        self.assertTrue(any('dlp-lab-forwarder.service' in c and 'enable' in c for c in calls))



class DebianVersionTests(unittest.TestCase):
    def test_native_bookworm_revision_meets_minimum(self):
        import subprocess
        for version, expected in [('0.2.13',0),('0.2.13~deb12u1',0),('0.2.12',1)]:
            result=subprocess.run(['/usr/bin/dpkg','--compare-versions',version,'ge','0.2.13~'])
            self.assertEqual(result.returncode,expected)
