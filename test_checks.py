import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

import sentinel_checks as c


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_fingerprint_metadata_content_missing_and_symlink(self):
        path = self.root / 'rules'
        self.assertEqual(c.fingerprint(path), {'missing': True})
        path.write_text('expected')
        first = c.fingerprint(path)
        path.write_text('changed')
        self.assertNotEqual(first['sha256'], c.fingerprint(path)['sha256'])
        link = self.root / 'link'
        link.symlink_to(path)
        self.assertIn('link_sha256', c.fingerprint(link))
        self.assertNotIn('sha256', c.fingerprint(link))
        with self.assertRaises(ValueError):
            c.fingerprint(path, 1)

    def test_baseline_drift_and_permission_rejection(self):
        old = {'files': {'/etc/ufw/user.rules': {'sha256': 'a'}}, 'listeners': {'tcp 127.0.0.1:22': ['sshd uid=0']}}
        new = {'files': {'/etc/ufw/user.rules': {'sha256': 'b'}}, 'listeners': {'tcp 0.0.0.0:22': ['sshd uid=0']}}
        baseline = Mock()
        baseline.exists.return_value = True
        baseline.is_symlink.return_value = False
        baseline.stat.return_value = SimpleNamespace(st_uid=0, st_mode=0o100600, st_size=300)
        baseline.read_text.return_value = json.dumps({'inventory': old, 'digest': c.digest(old)})
        with patch.object(c, 'BASELINE', baseline):
            self.assertEqual(c.baseline_compare(old)['changes'], [])
            changes = c.baseline_compare(new)['changes']
            self.assertEqual(len(changes), 3)
            self.assertEqual({x['change'] for x in changes}, {'added', 'removed', 'changed'})
            baseline.stat.return_value.st_mode = 0o100666
            with self.assertRaises(ValueError):
                c.baseline_compare(new)
            baseline.exists.return_value = False
            self.assertEqual(c.baseline_compare(old)['status'], 'not approved')

    def test_interpreter_tools_and_arguments_not_reported(self):
        for comm, cmdline, expected in [
            ('python3', b'python3\0-m\0pip\0install\0secret\0', 'pip'),
            ('python3', b'python3\0/usr/bin/pip3\0secret\0', 'pip'),
            ('node', b'node\0/usr/lib/npm/bin/npm-cli.js\0secret\0', 'npm'),
            ('node', b'node\0gunbot.js\0secret\0', None),
            ('python3', b'python3\0server.py\0pip\0', None)]:
            (self.root / 'cmdline').write_bytes(cmdline)
            self.assertEqual(c.tool_name(comm, self.root), expected)
        (self.root / 'cmdline').unlink()
        for name in ('curl', 'wget', 'apt', 'apt-get', 'npm', 'pip3'):
            self.assertEqual(c.tool_name(name, self.root), name)

    def test_package_log_tail_partial_rotation_and_oversize(self):
        path = self.root / 'dpkg.log'
        record = '2026-09-26 12:00:00 upgrade openssl:amd64 1 2\n'
        path.write_text(record)
        log = c.PackageLog(path)
        self.assertEqual(log.read(), [])  # Do not replay historical actions at startup.
        with path.open('a') as f:
            f.write(record[:-1])
        self.assertEqual(log.read(), [])
        with path.open('a') as f:
            f.write('\n')
        self.assertEqual(log.read()[0]['package'], 'openssl:amd64')
        self.assertEqual(log.read(), [])
        path.rename(self.root / 'dpkg.log.1')
        path.write_text(record)
        self.assertEqual(log.read()[0]['action'], 'upgrade')
        with path.open('a') as f:
            f.write('x' * 4096 + '\n' + record)
        with self.assertRaises(ValueError):
            log.read()
        self.assertEqual(log.read()[0]['action'], 'upgrade')

    def test_filesystem_inode_and_failures(self):
        usage = SimpleNamespace(f_blocks=100, f_bfree=8, f_files=200, f_ffree=2)
        with patch.object(c.os, 'statvfs', side_effect=[usage, OSError()]):
            result = c.filesystem_usage(['/data', '/missing'])
        self.assertEqual(result['/data'], {'disk': 92, 'inodes': 99})
        self.assertIn('error', result['/missing'])

    def test_endpoint_ipv4_ipv6(self):
        self.assertEqual(c.endpoint('0100007F:0016'), ('127.0.0.1', 22))
        self.assertEqual(c.endpoint('00000000000000000000000001000000:01BB'), ('::1', 443))

    def proc_fixture(self):
        proc = self.root / 'proc'
        (proc / 'net').mkdir(parents=True)
        boot = proc / 'sys/kernel/random'
        boot.mkdir(parents=True)
        (boot / 'boot_id').write_text('boot-id')
        (proc / 'net/tcp').write_text('header\n0: 00000000:0016 00000000:0000 0A 0 0 0 0 0 123\n')
        process = proc / '42'
        (process / 'fd').mkdir(parents=True)
        (process / 'fd/3').symlink_to('socket:[123]')
        (process / 'comm').write_text('curl')
        (process / 'stat').write_text('42 (curl) ' + ' '.join(['0'] * 19 + ['999']))
        return process

    def test_host_listener_ownership_and_boot_scoped_tool_identity(self):
        self.proc_fixture()
        with patch.object(c, 'Path', side_effect=lambda path: self.root / str(path).lstrip('/')):
            listeners, details, tools = c.host_processes()
        self.assertIn('tcp 0.0.0.0:22', listeners)
        self.assertEqual(details[0]['pid'], 42)
        self.assertTrue(any('curl PID 42 UID' in x for x in details[0]['processes']))
        self.assertEqual(tools['boot-id:42:999']['tool'], 'curl')

    def test_permission_error_from_exited_process_does_not_abort_scan(self):
        process = self.proc_fixture()
        survivor = process.parent / '43'
        (survivor / 'fd').mkdir(parents=True)
        (survivor / 'comm').write_text('sshd')
        (survivor / 'fd/4').symlink_to('socket:[123]')
        readlink = os.readlink

        def exit_during_readlink(fd):
            if fd.parent.parent == process:
                process.rename(self.root / 'exited')
                raise PermissionError(13, 'private detail')
            return readlink(fd)

        with patch.object(c, 'Path', side_effect=lambda path: self.root / str(path).lstrip('/')), \
             patch.object(c.os, 'readlink', side_effect=exit_during_readlink):
            listeners, _, _ = c.host_processes()
        self.assertEqual(listeners['tcp 0.0.0.0:22'], ['sshd uid=' + str(survivor.stat().st_uid)])

    def test_live_process_denial_still_aborts_with_safe_operation_context(self):
        self.proc_fixture()
        with patch.object(c, 'Path', side_effect=lambda path: self.root / str(path).lstrip('/')), \
             patch.object(c.os, 'readlink', side_effect=PermissionError(13, 'SECRET', '/secret/path')):
            with self.assertRaises(c.ProcessInspectionError) as raised:
                c.host_processes()
        self.assertEqual(c.failure_reason(raised.exception),
                         'Permission denied during inspection (errno 13); read descriptor link; PID 42; FD 3')

    def test_inconclusive_exit_recheck_preserves_original_permission_error(self):
        for recheck_error in (PermissionError(1, 'stat denied'), OSError(5, 'read failed')):
            process = Mock()
            process.stat.side_effect = recheck_error
            original = PermissionError(13, 'original')
            with patch.object(c.os, 'readlink', side_effect=original):
                with self.assertRaises(PermissionError) as raised:
                    c.process_link(process, Mock())
            self.assertIs(raised.exception, original)

    def test_non_fd_permission_failure_is_not_treated_as_process_exit(self):
        self.proc_fixture()
        original = Path.read_text

        def read_text(path, *args, **kwargs):
            if path.name == 'comm':
                raise PermissionError(13, 'SECRET')
            return original(path, *args, **kwargs)

        with patch.object(c, 'Path', side_effect=lambda path: self.root / str(path).lstrip('/')), \
             patch.object(Path, 'read_text', read_text):
            with self.assertRaises(c.ProcessInspectionError) as raised:
                c.host_processes()
        self.assertIn('read process name; PID 42', c.failure_reason(raised.exception))

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'O_PATH'), 'Linux procfs required')
    def test_real_procfs_exited_task_returns_eacces_for_resolved_link(self):
        # Pin the proc inode to deterministically exercise the task-exit window
        # between the kernel's path lookup and proc_pid_readlink access check.
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'], stdin=subprocess.DEVNULL)
        descriptor = None
        try:
            process = Path('/proc') / str(child.pid)
            link = process / 'fd/0'
            descriptor = os.open(link, os.O_PATH | os.O_NOFOLLOW)
            self.assertEqual(os.readlink('', dir_fd=descriptor), '/dev/null')
            child.terminate()
            child.wait(timeout=5)
            readlink = os.readlink
            with self.assertRaises(PermissionError) as raised:
                readlink('', dir_fd=descriptor)
            self.assertEqual(raised.exception.errno, 13)
            with patch.object(c.os, 'readlink', side_effect=lambda _: readlink('', dir_fd=descriptor)):
                with self.assertRaises(ProcessLookupError):
                    c.process_link(process, link)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            if descriptor is not None:
                os.close(descriptor)

    def test_clock_status_is_not_assumed(self):
        with patch.object(c.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='yes\n')):
            self.assertEqual(c.system_status()['clock_sync'], 'yes')
        with patch.object(c.subprocess, 'run', side_effect=OSError):
            self.assertEqual(c.system_status()['clock_sync'], 'unknown')

    def test_listener_failure_does_not_claim_file_hashing_failed(self):
        host = c.HostChecks()
        with patch.object(c, 'host_processes', side_effect=PermissionError(13, 'private detail')), \
             patch.object(c, 'security_files', return_value={}), \
             patch.object(c, 'system_status', return_value={}), \
             patch.object(host.packages, 'read', return_value=[]), \
             patch.object(c, 'fingerprint', return_value={'sha256': 'a' * 64}), \
             patch.object(c, 'baseline_compare') as compare:
            result = host.sample()
        self.assertEqual(result['health']['listeners_tools'], 'unavailable')
        self.assertTrue(result['health']['security_files'].startswith('ok'))
        self.assertEqual(result['health']['baseline'], 'blocked (requires listener inventory)')
        self.assertEqual(result['errors']['listeners_tools'], 'Permission denied during inspection (errno 13)')
        self.assertNotIn('security_files', result['errors'])
        self.assertNotIn('baseline_inventory', result)
        compare.assert_not_called()

    def test_file_and_baseline_failures_are_independent(self):
        for file_failure in (True, False):
            with self.subTest(file_failure=file_failure):
                host = c.HostChecks()
                with patch.object(c, 'host_processes', return_value=({}, [], {})), \
                     patch.object(c, 'security_files', side_effect=ValueError('File changed during hashing') if file_failure else None, return_value={}), \
                     patch.object(c, 'system_status', return_value={}), \
                     patch.object(host.packages, 'read', return_value=[]), \
                     patch.object(c, 'fingerprint', return_value={'sha256': 'a' * 64}), \
                     patch.object(c, 'baseline_compare', side_effect=ValueError('Unsafe baseline file')):
                    result = host.sample()
                self.assertEqual(result['health']['listeners_tools'], 'ok')
                if file_failure:
                    self.assertEqual(result['errors']['security_files'], 'File changed during hashing')
                    self.assertEqual(result['health']['baseline'], 'blocked (requires security file inventory)')
                else:
                    self.assertTrue(result['health']['security_files'].startswith('ok'))
                    self.assertEqual(result['health']['baseline'], 'unavailable')
                    self.assertEqual(result['errors']['baseline'], 'Unsafe baseline file')
                self.assertEqual(result['baseline']['status'], 'unavailable')

    def test_failure_reasons_never_expose_exception_content(self):
        secret = 'PRIVATE_TOKEN_AND_PATH'
        for error in (ValueError(secret), OSError(5, secret, secret), PermissionError(13, secret, secret), KeyError(secret), TypeError(secret)):
            self.assertNotIn(secret, c.failure_reason(error))
        self.assertEqual(c.failure_reason(ValueError('FD inspection limit exceeded')), 'FD inspection limit exceeded')

    def test_failed_inventory_does_not_become_approved_empty_state(self):
        host = c.HostChecks()
        with patch.object(c, 'host_processes', side_effect=PermissionError), patch.object(c, 'security_files', side_effect=PermissionError), patch.object(c, 'system_status', return_value={}), patch.object(host.packages, 'read', side_effect=OSError), patch.object(c, 'fingerprint', side_effect=OSError):
            result = host.sample()
        self.assertEqual(result['baseline']['status'], 'unavailable')
        self.assertEqual(result['health']['package_inventory'], 'unavailable')
        self.assertEqual(result['health']['listeners_tools'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
