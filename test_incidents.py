import copy
import datetime as dt
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

    def snap_refresh(self, now):
        directory = '/etc/systemd/system/multi-user.target.wants/'
        old = directory + 'snap-core24-1643.mount'
        new = directory + 'snap-core24-2307.mount'
        self.before['files'][old] = {'uid': 0, 'gid': 0, 'mode': 511,
                                     'link_sha256': 'a00edcf6ae86bdf8a162b66c8510d3c9d3f3abdb28f3e07f76681f57ec25af4c'}
        self.current['files'][new] = {'uid': 0, 'gid': 0, 'mode': 511,
                                      'link_sha256': '37f3bf71026156f398c3c07df06148fd2aa19e33b2fb4c850acf68f43d53ea65'}
        self.expected['digest'] = c.inventory_digest(self.before)

        def stamp(offset):
            return dt.datetime.fromtimestamp(now + offset, dt.timezone.utc).isoformat()

        change = {'id': '151', 'kind': 'auto-refresh', 'status': 'Done', 'ready': True,
                  'spawn-time': stamp(-25), 'ready-time': stamp(-1),
                  'tasks': [{'kind': 'mount-snap', 'summary': 'Mount snap "core24" (2307)',
                             'status': 'Done', 'ready-time': stamp(-15)},
                            {'kind': 'discard-snap', 'summary': 'Remove snap "core24" (1643) from the system',
                             'status': 'Done', 'ready-time': stamp(-2)}]}
        return old, new, change

    def test_verified_snap_pair_persists_and_accepts_both_with_one_command(self):
        now = time.time()
        old, new, change = self.snap_refresh(now)
        self.app.cfg['auto_approve_snap_refresh'] = False
        with patch.object(inc, 'snap_history', return_value=[change]):
            self.sample(now)
        self.assertIsNone(self.app.s['approved_baseline'])
        records = self.app.s['incidents']
        pair = next(record for record in records.values() if 'snap' in record)
        self.assertEqual(len(records), 2)  # One Snap alert and one unrelated listener alert.
        self.assertEqual(len(self.app.s['pending']), 2)
        self.assertTrue(inc.valid_state(json.loads(json.dumps(records))))
        key = 'incident:' + pair['ref']
        report = s.telegram_report('Example', dict(self.app.s['pending'][key], key=key, anomaly=True))
        self.assertIn('LEGITIMATE SNAP AUTO-REFRESH · CHANGE 151', report)
        self.assertIn('both symlink fingerprints matched the expected targets', report)
        self.assertIn('Both changes are awaiting approval', report)
        self.assertIn('/sentinel approve ' + pair['ref'], report)
        with patch.object(inc, 'snap_history', return_value=[]) as history:
            self.sample(now)
        history.assert_not_called()
        ref = pair['ref']
        self.assertIn('CHANGE 151', self.command('/sentinel investigate ' + ref))
        self.assertIn('Both Snap mount links were accepted', self.command('/sentinel approve ' + ref))
        self.assertNotIn(old, self.app.s['approved_baseline']['inventory']['files'])
        self.assertIn(new, self.app.s['approved_baseline']['inventory']['files'])
        self.assertEqual([item['kind'] for item in self.app.host['baseline']['changes']], ['listeners'])

    def test_exact_snap_pair_can_be_auto_approved_and_reported(self):
        now = time.time()
        old, new, change = self.snap_refresh(now)
        with patch.object(inc, 'snap_history', return_value=[change]):
            self.sample(now)
        pair = next(record for record in self.app.s['incidents'].values() if 'snap' in record)
        self.assertEqual(pair['state'], 'approved')
        self.assertIsNone(pair['actor'])
        self.assertTrue(s.baselines.valid_approval(self.app.s['approved_baseline']))
        self.assertNotIn(old, self.app.s['approved_baseline']['inventory']['files'])
        self.assertIn(new, self.app.s['approved_baseline']['inventory']['files'])
        self.assertEqual([item['kind'] for item in self.app.host['baseline']['changes']], ['listeners'])
        self.assertNotIn('incident:' + pair['ref'], self.app.s['pending'])
        key = 'snap-approved:' + pair['ref']
        self.app.s['mute_until'] = now + 5
        self.app.dispatch(now)
        self.assertTrue(all(identity[0] != key for identity in self.app.inflight))
        self.assertIn(key, self.app.s['pending'])
        self.app.dispatch(now + 5)
        jobs = [self.app.outgoing.get_nowait() for _ in range(self.app.outgoing.qsize())]
        job, = [job for job in jobs if job['key'] == key]
        report = s.telegram_report('Example', job)
        self.assertIn('LEGITIMATE SNAP AUTO-REFRESH · CHANGE 151', report)
        self.assertIn('Sentinel automatically accepted both changes into the security baseline. No action needed.', report)
        self.assertIn('Ref: ' + pair['ref'], report)
        self.assertNotIn('ACTION REQUIRED', report)
        self.assertNotIn('/sentinel approve', report)

    def test_snap_pair_stays_pending_review_if_confirmation_cannot_be_queued(self):
        now = time.time()
        _, _, change = self.snap_refresh(now)
        self.app.cfg['auto_approve_snap_refresh'] = True
        pending = self.app.s['pending']
        pending.update({f'busy:{i}': {'priority': 0} for i in range(s.MAX_PENDING)})
        with patch.object(inc, 'snap_history', return_value=[change]):
            self.sample(now)
        pair = next(record for record in self.app.s['incidents'].values() if 'snap' in record)
        self.assertIsNone(self.app.s['approved_baseline'])
        self.assertEqual(pair['state'], 'detected')
        pending.clear()
        self.sample(now)
        self.assertIn('incident:' + pair['ref'], pending)
        self.assertIsNone(self.app.s['approved_baseline'])

    def test_snap_verification_fails_closed(self):
        now = time.time()
        _, new, change = self.snap_refresh(now)
        self.app.cfg['auto_approve_snap_refresh'] = True
        for history in ([], [change, dict(change, id='152')], [dict(change, status='Error')],
                        [dict(change, tasks=change['tasks'][:1])],
                        [dict(change, **{'ready-time': ''})]):
            with self.subTest(history=history):
                self.assertIsNone(inc.snap_match(history, 'core24', '1643', '2307', now))
        self.assertIsNone(inc.snap_match([change], 'core24', '1643', '2307', now + 121))
        self.current['files'][new]['link_sha256'] = '0' * 64
        with patch.object(inc, 'snap_history', return_value=[change]) as history:
            self.sample(now)
        history.assert_not_called()
        self.assertIsNone(self.app.s['approved_baseline'])
        self.assertEqual(len(self.app.s['incidents']), 3)
        self.assertTrue(all('snap' not in record for record in self.app.s['incidents'].values()))

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
