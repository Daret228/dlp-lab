"""Run maintainer-script control flow with fake debconf/systemd, never host changes."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DebianInstallTests(unittest.TestCase):
    def run_install(self, *, configured=False, username='testuser', configure=True, fail=False, central_active=False, profile=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            log = root/'calls'
            conf = root/'system-gateway.conf'
            if configured:
                conf.touch()
            profile_path = root/'connection.json'
            if profile: profile_path.touch()
            module = root/'confmodule'
            module.write_text('''db_get() {
 case "$1" in
 dlp-lab/configure) RET=$SETUP;;
 dlp-lab/user) RET=$TARGET_USER;;
 dlp-lab/telegram) RET='/opt/Telegram Desktop/Telegram';;
 esac
}
db_stop() { :; }
''')
            helper = root/'helper'
            helper.write_text('''#!/bin/sh
printf '%s\\n' "$0 $*" >> "$CALLS"
case "$0" in
 *systemctl)
   if [ "$2" = is-active ]; then [ "$CENTRAL_ACTIVE" = 1 ]; exit $?; fi;;
 *dlp-lab-configure)
   [ "$FAIL_SETUP" = 0 ] || exit 2
   touch "$CONFIG_FILE";;
esac
''')
            helper.chmod(0o755)
            for name in ('dlp-setup','dlp-lab-configure','deb-systemd-helper','deb-systemd-invoke','systemctl','systemd-sysusers'):
                (root/name).symlink_to(helper)
            script = (ROOT/'debian/postinst').read_text()
            script = script.replace('/etc/dlp-lab/connection.json', str(profile_path)).replace('/usr/sbin/dlp-setup', str(root/'dlp-setup'))
            script = script.replace('/usr/share/debconf/confmodule', str(module))
            script = script.replace('/etc/dlp-lab/system-gateway.conf', str(conf))
            script = script.replace('/usr/sbin/dlp-lab-configure', str(root/'dlp-lab-configure'))
            script = script.replace('/run/systemd/system', str(root))
            env = dict(os.environ, PATH=str(root)+':/usr/bin:/bin', CALLS=str(log),
                       CONFIG_FILE=str(conf), SETUP=str(configure).lower(),
                       TARGET_USER=username, FAIL_SETUP=str(int(fail)), CENTRAL_ACTIVE=str(int(central_active)))
            result = subprocess.run(['sh','-c',script,'postinst','configure'], env=env,
                                    text=True,capture_output=True)
            return result, log.read_text() if log.exists() else ''

    def test_first_install_configures_then_starts(self):
        result, calls = self.run_install()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--user testuser --telegram /opt/Telegram Desktop/Telegram',calls)
        self.assertLess(calls.index('dlp-lab-configure'),calls.index('deb-systemd-invoke'))
        self.assertIn('restart dlp-lab-files.service',calls)

    def test_existing_configuration_not_overwritten(self):
        result, calls = self.run_install(configured=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('dlp-lab-configure',calls)
        self.assertIn('restart dlp-lab-files.service',calls)

    def test_unconfigured_install_does_not_start(self):
        for kwargs in ({'username':''},{'configure':False}):
            result,calls=self.run_install(**kwargs)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotIn('dlp-lab-configure',calls)
            self.assertNotIn('deb-systemd-invoke',calls)

    def test_configuration_failure_does_not_claim_start(self):
        result,calls=self.run_install(fail=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('deb-systemd-invoke',calls)

    def test_foreground_rejects_arguments_before_root_or_execution(self):
        result=subprocess.run(['sh',str(ROOT/'packaging/dlp-lab-run-files'),'unexpected'],
                              capture_output=True,text=True)
        self.assertEqual(result.returncode,2)
        self.assertIn('Usage:',result.stderr)

    def test_only_active_central_roles_restart(self):
        result, calls = self.run_install(configured=True, central_active=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('restart dlp-lab-central.service', calls)
        self.assertIn('restart dlp-lab-forwarder.service', calls)
        result, calls = self.run_install(configured=True)
        self.assertNotIn('restart dlp-lab-central.service', calls)
        self.assertNotIn('restart dlp-lab-forwarder.service', calls)

    def test_provisioned_profile_invokes_installed_setup(self):
        result,calls=self.run_install(profile=True,configure=False)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('dlp-setup',calls)
        self.assertIn('connection.json',calls)
