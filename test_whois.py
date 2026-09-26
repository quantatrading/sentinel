import time
import unittest
from unittest.mock import patch, Mock
import sentinel_whois as w


class WhoisTests(unittest.TestCase):
    def test_public_only_and_mapped_normalization(self):
        self.assertEqual(w.public_address('ip:::ffff:8.8.8.8'), '8.8.8.8')
        for value in ['192.168.1.1', '127.0.0.1', '::1', '224.0.0.1', '100.64.0.1', '8.8.8.8?bad', 'fe80::1%eth0']:
            self.assertIsNone(w.public_address('ip:' + value))

    def test_registry_fields_and_fixed_referral(self):
        with patch.object(w, 'query', side_effect=['whois: whois.arin.net\n',
                'NetName: EXAMPLE-NET\nOrgName: Example Organisation\nCIDR: 192.0.2.0/24\nCountry: US\n']) as query:
            result = w.lookup('192.0.2.14')
        self.assertIn('Example Organisation', result)
        self.assertIn('192.0.2.0/24', result)
        self.assertEqual(query.call_args.args, ('whois.arin.net', 'n + 192.0.2.14'))
        with patch.object(w, 'query', return_value='whois: attacker.example\n') as query:
            with self.assertRaises(ValueError):
                w.lookup('8.8.8.8')
            self.assertEqual(query.call_count, 1)

    def test_failures_are_not_fabricated_registration(self):
        with patch.object(w, 'query', side_effect=['whois: whois.arin.net\n', 'Rate limit exceeded']):
            with self.assertRaises(ValueError):
                w.lookup('8.8.8.8')
        with self.assertRaises(ValueError):
            w.query('localhost', '8.8.8.8')

    def test_prepare_cache_timeout_and_nonblocking_poll(self):
        e = w.Enricher()
        e.worker = Mock()  # Deliberately stalled worker; no network call.
        job = {'key': 'ip:8.8.8.8', 'anomaly': True}
        self.assertFalse(e.prepare(job, 100))
        self.assertEqual(job['next'], 100.2)
        self.assertTrue(e.prepare({'key': 'other', 'anomaly': False}, 100))
        job['whois_deadline'] = time.monotonic() - 1
        self.assertTrue(e.prepare(job, 105))
        self.assertIn('time limit', job['whois'])
        e.cache['8.8.8.8'] = (time.monotonic() + 60, 'Registrant: cached')
        cached = {'key': 'ip:8.8.8.8', 'anomaly': True}
        self.assertTrue(e.prepare(cached, 106))
        self.assertEqual(cached['whois'], 'Registrant: cached')

    def test_private_and_capacity_fallback(self):
        e = w.Enricher()
        job = {'key': 'ip:10.0.0.1', 'anomaly': True}
        self.assertTrue(e.prepare(job, 0))
        self.assertIn('Not applicable', job['whois'])
        e.next_request = time.monotonic() + 60
        job = {'key': 'ip:8.8.8.8', 'anomaly': True}
        self.assertTrue(e.prepare(job, 0))
        self.assertIn('capacity limit', job['whois'])


if __name__ == '__main__':
    unittest.main()
