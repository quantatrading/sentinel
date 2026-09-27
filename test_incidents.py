import copy
import json
from pathlib import Path
import queue
import tempfile
import time
import unittest
from unittest.mock import patch

import sentinel as s
import sentinel_checks as c
import sentinel_incidents as inc


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'sentinel.json'
        cfg = s.validate({})
        cfg['runtime'] = s.fresh()
        self.app = s.Sentinel(cfg, self.path, queue.Queue(), {123})
        self.before = {'files': {}, 'listeners': {'tcp 127.0.0.1:35353': ['gunthy uid=1000'], 'tcp 0.0.0.0:22': ['sshd uid=0']},
                       'listener_processes': {'tcp 127.0.0.1:35353': ['gunthy PID 12345 UID 1000'], 'tcp 0.0.0.0:22': ['sshd PID 100 UID 0']}}
        self.expected = {'inventory': self.before, 'digest': c.inventory_digest(self.before)}
        self.current = copy.deepcopy(self.before)
        self.current['listeners'].pop('tcp 127.0.0.1:35353')
        self.current['listener_processes'].pop('tcp 127.0.0.1:35353')
        self.update = 0

    def sample(self, now=None):
        now = time.time() if now is None else now
        host = {'baseline_inventory': copy.deepcopy(self.current), 'inventory_at': now,
                'baseline': c.compare_inventory(self.current, self.expected)}
        self.app.observation = {'at': now}
        with patch.object(s.time, 'time', return_value=now):
            self.app.observe_host(host)

    def command(self, text):
        self.update += 1
        return s.audit_action(self.app, {'text': text, 'from': {'id': 123}, 'chat': {'id': 123}}, self.update)

    def record(self):
        return next(iter(self.app.s['incidents'].values()))

    def test_3222_checks_are_one_alert_with_stable_reference_and_owner(self):
        start = time.time()
        self.sample(start)
        record = self.record()
        self.assertEqual(record['state'], 'detected')
        key = 'incident:' + record['ref']
        pending = self.app.s['pending'][key]
        self.assertEqual(pending['id'][:8].upper(), record['ref'])
        report = s.telegram_report('Example', dict(pending, anomaly=True, key=key))
        self.assertIn('ACTION REQUIRED', report)
        self.assertIn('gunthy PID 12345', report)
        self.app.delivered((key, pending['id'], 123, 'delivered'), now=start)
        for n in range(1, 3222):
            self.sample(start + n * 10)
        self.assertEqual(record['state'], 'persistent')
        self.assertEqual(record['count'], 3222)
        self.assertNotIn(key, self.app.s['pending'])
        details = inc.render(record)
        self.assertIn('Checks: 3,222', details)
        self.assertIn('Currently: not listening', details)
        self.assertIn('/sentinel approve ' + record['ref'], details)
        report = s.telegram_report('Example', dict(pending, text=details, anomaly=True, key=key, incident_state='persistent'))
        self.assertNotIn('ACTION REQUIRED', report)
        # Even if generic event retention/eviction loses its entry, the record stays settled.
        self.app.s['events'].pop(key)
        self.sample(start + 40000)
        self.assertNotIn(key, self.app.s['pending'])

    def test_approval_changes_one_listener_only_and_recurrence_has_new_reference(self):
        self.current['listeners'].pop('tcp 0.0.0.0:22')
        self.sample()
        record = next(r for r in self.app.s['incidents'].values() if ':35353' in r['name'])
        other = next(r for r in self.app.s['incidents'].values() if ':22' in r['name'])
        with self.assertLogs(s.LOG, level='INFO') as logged:
            result = self.command('/sentinel approve ' + record['ref'])
        self.assertTrue(result.startswith('Change approved'))
        self.assertIn('"incident_operation": "approve"', '\n'.join(logged.output))
        expected = self.app.s['approved_baseline']['inventory']['listeners']
        self.assertNotIn('tcp 127.0.0.1:35353', expected)
        self.assertIn('tcp 0.0.0.0:22', expected)
        self.sample()
        self.assertEqual(record['state'], 'approved')
        self.assertEqual(other['state'], 'persistent')
        self.assertEqual(len(self.app.host['baseline']['changes']), 1)
        self.current['listeners']['tcp 127.0.0.1:35353'] = ['gunthy uid=1000']
        self.sample()
        added = next(r for r in self.app.s['incidents'].values() if r['change'] == 'added')
        self.assertNotEqual(added['ref'], record['ref'])

    def test_acknowledgement_is_durable_and_suppresses_buffered_notice(self):
        self.sample()
        record = self.record()
        key = 'incident:' + record['ref']
        self.app.dispatch()
        job = self.app.outgoing.get_nowait()
        self.assertTrue(self.command('/sentinel acknowledge ' + record['ref']).startswith('Change acknowledged'))
        self.assertIsNone(self.app.s['approved_baseline'])
        self.assertNotIn(key, self.app.s['pending'])
        self.assertTrue(inc.all_reviewed(self.app))
        self.assertEqual(self.app.report_actions('/baseline', 'drift'), '')
        cfg = s.load(self.path)
        self.assertEqual(cfg['runtime']['incidents'][record['ref']]['state'], 'acknowledged')
        self.app = s.Sentinel(cfg, self.path, queue.Queue(), {123})
        self.sample()
        self.assertNotIn(key, self.app.s['pending'])
        with patch.dict(s.os.environ, {'TELEGRAM_BOT_TOKEN': '123:' + 'x' * 30, 'TELEGRAM_CHAT_IDS': '123', 'TELEGRAM_USER_IDS': '123'}):
            telegram = s.Telegram(queue.Queue(), queue.Queue(), s.threading.Event(), 0)
        telegram.incidents = self.app.s['incidents']
        telegram.outgoing.put(job)
        with patch.object(telegram, 'api') as api:
            telegram.send_step(time.time())
        api.assert_not_called()
        self.assertEqual(telegram.receipts.get_nowait()[3], 'muted')

    def test_unavailable_is_not_recovery_but_return_to_baseline_resolves(self):
        self.sample()
        first = self.record()
        self.app.observe_host({'baseline': {'status': 'unavailable'}})
        self.assertEqual(first['state'], 'detected')
        self.app.observe_host({'baseline': {'status': 'not approved', 'changes': []}})
        self.assertEqual(first['state'], 'detected')
        self.current = copy.deepcopy(self.before)
        self.sample()
        self.assertEqual(first['state'], 'resolved')
        self.current['listeners'].pop('tcp 127.0.0.1:35353')
        self.sample()
        self.assertEqual(len(self.app.s['incidents']), 2)
        self.assertEqual(sum(r['state'] == 'detected' for r in self.app.s['incidents'].values()), 1)

    def test_pid_only_change_does_not_change_digest_or_generate_drift(self):
        changed = copy.deepcopy(self.before)
        changed['listener_processes']['tcp 127.0.0.1:35353'] = ['gunthy PID 54321 UID 1000']
        self.assertEqual(c.inventory_digest(changed), c.inventory_digest(self.before))
        self.assertEqual(c.compare_inventory(changed, self.expected)['changes'], [])
        legacy = copy.deepcopy(self.before)
        legacy.pop('listener_processes')
        comparison = c.compare_inventory(self.current, {'inventory': legacy, 'digest': c.digest(legacy)})
        self.assertIn('gunthy uid=1000 (PID not recorded)', inc.description(comparison['changes'][0], True))

    def test_stale_incomplete_or_changed_evidence_cannot_be_approved(self):
        self.sample()
        ref = self.record()['ref']
        self.app.observation['at'] -= 100
        self.assertIn('stale', self.command('/sentinel approve ' + ref))
        self.sample()
        self.app.host['baseline']['changes_complete'] = False
        self.assertIn('Complete change list unavailable', self.command('/sentinel approve ' + ref))
        self.assertIsNone(self.app.s['approved_baseline'])
        self.app.host['baseline']['changes'] = []
        self.assertIn('changed or resolved', self.command('/sentinel approve ' + ref))

    def test_legacy_counter_migrates_without_hourly_realert(self):
        change = c.compare_inventory(self.current, self.expected)['changes'][0]
        key = 'drift:' + c.digest((change['kind'], change['name'], change['fingerprint']))
        now = time.time()
        self.app.s['events'][key] = {'first': now - 30000, 'last': now - 10, 'count': 3221, 'notified': now - 3600, 'settled': now - 3600}
        self.sample(now)
        self.assertEqual(self.record()['count'], 3222)
        self.assertEqual(self.record()['state'], 'persistent')
        self.assertFalse(self.app.s['pending'])
        self.assertNotIn(key, self.app.s['events'])
        self.assertTrue(inc.valid_state(self.app.s['incidents']))

    def test_investigation_reference_and_invalid_runtime_are_safe(self):
        self.sample()
        record = self.record()
        text = self.command('/sentinel investigate ' + record['ref'])
        report = s.telegram_report('Example', {'command': '/sentinel', 'text': text,
            'id': 'f' * 32, 'reference': record['ref'], 'created': time.time()})
        self.assertIn('Ref: ' + record['ref'], report)
        self.assertNotIn('ACTION REQUIRED', report)
        malformed = copy.deepcopy(self.app.s['incidents'])
        malformed[record['ref']]['state'] = []
        self.assertFalse(inc.valid_state(malformed))
        self.assertIn('Unknown change reference', self.command('/sentinel investigate ABCD1234'))
        self.assertIn('page from 1', self.command('/sentinel 999'))

    def test_full_baseline_approval_closes_pending_changes(self):
        self.sample()
        self.command('/baseline review')
        response = self.command('/baseline approve ' + c.inventory_digest(self.current))
        self.assertTrue(response.startswith('Baseline approved'))
        self.assertEqual(self.record()['state'], 'approved')
        self.assertFalse(self.app.s['pending'])

    def test_failed_save_never_acknowledges_and_old_runtime_migrates(self):
        self.sample()
        self.command('/sentinel')
        original = self.path.read_bytes()
        with patch.object(s, 'save', side_effect=OSError('disk full')), self.assertLogs(s.LOG, level='ERROR'):
            with self.assertRaises(OSError):
                self.command('/sentinel approve ' + self.record()['ref'])
        self.assertEqual(self.path.read_bytes(), original)
        cfg = json.loads(original)
        cfg['runtime'].pop('incidents')
        self.path.write_text(json.dumps(cfg))
        self.assertEqual(s.load(self.path)['runtime']['incidents'], {})
        self.assertFalse(inc.valid_state({'12345678': {'state': []}}))


if __name__ == '__main__':
    unittest.main()
