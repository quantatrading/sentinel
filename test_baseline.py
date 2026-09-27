import copy
import json
from pathlib import Path
import queue
import tempfile
import time
import unittest
from unittest.mock import patch

import sentinel as s
import sentinel_baseline as b
import sentinel_checks as c


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'sentinel.json'
        cfg = s.validate({})
        cfg['runtime'] = s.fresh()
        self.app = s.Sentinel(cfg, self.path, queue.Queue(), {123})
        self.inventory = {'files': {'/etc/ssh/sshd_config': {'sha256': 'a' * 64, 'mode': 384, 'uid': 0, 'gid': 0}},
                          'listeners': {'tcp 127.0.0.1:22': ['sshd uid=0']}}
        self.host = {'baseline_inventory': self.inventory, 'inventory_at': time.time(),
                     'baseline': {'status': 'not approved', 'digest': c.digest(self.inventory), 'changes': []}}
        self.app.observation = {'at': time.time()}
        self.app.observe_host(self.host)
        self.update = 10

    def command(self, text, actor=123, chat=123):
        self.update += 1
        return s.audit_action(self.app, {'text': text, 'from': {'id': actor}, 'chat': {'id': chat}}, self.update)

    def approve(self):
        self.command('/baseline review')
        return self.command('/baseline approve ' + c.digest(self.inventory))

    def test_review_approval_persistence_drift_and_audit(self):
        with self.assertLogs(s.LOG, level='INFO') as logged:
            self.assertTrue(self.approve().startswith('Baseline approved'))
        self.assertIn('"action": "/baseline"', '\n'.join(logged.output))
        self.assertIn('"outcome": "applied"', '\n'.join(logged.output))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        cfg = s.load(self.path)
        self.assertTrue(b.valid_approval(cfg['runtime']['approved_baseline']))
        restarted = s.Sentinel(cfg, self.path, queue.Queue(), {123})
        restarted.observe_host(self.host)
        self.assertEqual(restarted.host['baseline']['status'], 'matches approved baseline')
        changed = copy.deepcopy(self.host)
        changed['baseline_inventory']['files']['/etc/ssh/sshd_config']['sha256'] = 'b' * 64
        restarted.observe_host(changed)
        self.assertEqual(restarted.host['baseline']['status'], 'drift')
        self.assertEqual(restarted.host['baseline']['changes'][0]['name'], '/etc/ssh/sshd_config')

    def test_requires_review_same_sender_chat_and_digest(self):
        command = '/baseline approve ' + c.digest(self.inventory)
        self.assertIn('Review this inventory first', self.command(command))
        self.command('/baseline review')
        self.assertIn('Review this inventory first', self.command(command, actor=456))
        self.assertIn('Review this inventory first', self.command(command, chat=456))
        self.assertIn('Review this inventory first', self.command('/baseline approve ' + 'f' * 64))
        self.assertIsNone(self.app.s['approved_baseline'])
        self.assertIn('authorised Telegram', self.app.command('/baseline review'))

    def test_expired_stale_changed_and_incomplete_inventory_rejected(self):
        command = '/baseline approve ' + c.digest(self.inventory)
        self.command('/baseline review')
        self.app.baseline_reviews[(123, 123)]['at'] -= 301
        self.assertIn('Review this inventory first', self.command(command))
        self.command('/baseline review')
        self.app.host['baseline_inventory']['listeners']['tcp 0.0.0.0:443'] = ['server uid=1000']
        self.assertIn('changed', self.command(command))
        self.app.host['inventory_at'] -= 100
        self.assertIn('stale', self.command('/baseline review'))
        self.app.host['inventory_at'] = time.time()
        self.app.host['baseline'] = {'status': 'unavailable'}
        self.assertIn('unavailable', self.command('/baseline review'))
        self.assertIsNone(self.app.s['approved_baseline'])

    def test_new_local_root_baseline_supersedes_telegram(self):
        self.approve()
        host = copy.deepcopy(self.host)
        host['baseline']['expected_digest'] = 'b' * 64
        host['baseline']['status'] = 'drift'
        self.app.observe_host(host)
        self.assertIsNone(self.app.s['approved_baseline'])
        self.assertEqual(self.app.host['baseline'], host['baseline'])

    def test_persistence_failure_does_not_acknowledge_approval(self):
        self.command('/baseline review')
        with patch.object(s, 'save', side_effect=OSError('disk full')):
            with self.assertLogs(s.LOG, level='ERROR') as logged:
                with self.assertRaises(OSError):
                    self.command('/baseline approve ' + c.digest(self.inventory))
        self.assertIn('persistence_failed', '\n'.join(logged.output))
        self.assertIsNone(json.loads(self.path.read_text())['runtime']['approved_baseline'])

    def test_paging_is_bounded_and_invalid_page_cannot_authorize(self):
        self.inventory['files'] = {f'/etc/example/{i}': {'sha256': 'a' * 64} for i in range(100)}
        self.assertIn('page from 1', self.command('/baseline review 9999'))
        self.assertFalse(self.app.baseline_reviews)
        response = self.command('/baseline review')
        self.assertIn('including other pages', response)
        self.assertLess(len(response), 3800)
        self.assertIn('/baseline approve ' + c.digest(self.inventory), response)
        self.assertIn('/etc/example/', self.command('/baseline review 2'))

    def test_collector_exports_complete_metadata_and_fails_closed(self):
        host = c.HostChecks()
        with patch.object(c, 'host_processes', return_value=(self.inventory['listeners'], [], {})), \
             patch.object(host.packages, 'read', return_value=[]), \
             patch.object(c, 'system_status', side_effect=lambda: {}), \
             patch.object(c, 'fingerprint', return_value={'sha256': 'a' * 64}), \
             patch.object(c, 'security_files', return_value=self.inventory['files']), \
             patch.object(c, 'baseline_compare', return_value=self.host['baseline']):
            result = host.sample()
            self.assertEqual(result['baseline_inventory'], dict(self.inventory, listener_processes={}))
            self.assertLess(abs(result['inventory_at'] - time.time()), 5)
            host.next_slow = 0
            with patch.object(c, 'security_files', side_effect=ValueError('incomplete')):
                result = host.sample()
            self.assertEqual(result['baseline']['status'], 'unavailable')
            self.assertNotIn('baseline_inventory', result)
            self.assertNotIn('inventory_at', result)

    def test_runtime_upgrade_and_invalid_approval_validation(self):
        legacy = self.app.cfg
        del legacy['runtime']['approved_baseline']
        s.save(self.path, legacy)
        self.assertIsNone(s.load(self.path)['runtime']['approved_baseline'])
        self.assertFalse(b.valid_approval({'inventory': {}}))
        self.assertFalse(b.valid_inventory({'files': {}, 'listeners': {'a': 'invalid'}}))


if __name__ == '__main__':
    unittest.main()
