import json
import os
from pathlib import Path
import queue
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import sentinel as s


class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'sentinel.json'
        self.cfg = s.validate(json.loads(Path(__file__).with_name('sentinel.json.example').read_text()))
        self.cfg['runtime'] = s.fresh()
        self.out = queue.Queue(100)
        self.app = s.Sentinel(self.cfg, self.path, self.out, {123})

    def test_two_process_families_are_two_instances(self):
        processes = {'a': {'pid': 10, 'ppid': 1}, 'b': {'pid': 11, 'ppid': 10},
                     'c': {'pid': 20, 'ppid': 1}, 'd': {'pid': 21, 'ppid': 20}}
        self.cfg['expected_gunbot_instances'] = 2
        self.run_check(processes)
        self.assertEqual(s.instance_roots(processes), {'a', 'c'})
        self.assertNotIn('gunbot:count', self.app.s['events'])
        self.assertEqual(len(self.app.procs), 4)
        self.assertIn('Gunbot instances: 2 / expected 2', self.app.selftest())
        self.assertIn('Matching Gunbot processes: 4', self.app.selftest())
        without_child = {k: v for k, v in processes.items() if k != 'b'}
        self.run_check(without_child)
        self.run_check(without_child)
        self.assertIn('process:b', self.app.s['events'])
        self.assertNotIn('gunbot:count', self.app.s['events'])

    def test_nested_children_and_independent_roots(self):
        processes = {'a': {'pid': 10, 'ppid': 1}, 'b': {'pid': 11, 'ppid': 10},
                     'c': {'pid': 12, 'ppid': 11}, 'd': {'pid': 20, 'ppid': 1}}
        self.assertEqual(s.instance_roots(processes), {'a', 'd'})
        self.assertEqual(s.instance_roots({}), set())
        self.assertEqual(s.instance_roots({'old': {'pid': 1}}), {'old'})

    def test_all_command_outputs_share_reporting_envelope(self):
        commands = ['/status', '/selftest', '/security', '/health', '/network', '/listeners',
                    '/baseline', '/processes', '/updates', '/recent', '/known', '/help',
                    '/mute 1m', '/unmute', '/maintenance 1m', '/maintenance off',
                    '/allow example.com', '/remove example.com', '/management', '/management add 203.0.113.1', '/management remove 203.0.113.1', '/status extra', '/typo']
        for command in commands:
            with self.subTest(command=command):
                response = self.app.command(command)
                verb = command.split()[0]
                job = {'command': verb, 'text': response, 'created': 0,
                       'id': 'a' * 32, 'anomaly': False,
                       'attention': self.app.report_attention(verb, response)}
                report = s.telegram_report('Example Server', job)
                for field in ['SENTINEL ·', 'Ref: AAAAAAAA', 'EXAMPLE SERVER', '01 Jan 1970, 00:00 UTC']:
                    self.assertIn(field, report)
                self.assertLessEqual(len(report.encode('utf-16-le')) // 2, 3900)
                self.assertNotIn("{'", report)
                self.assertNotIn('\u2014', report)
                self.assertNotIn('\u2013', report)

    def test_report_severity_recovery_and_invalid_commands(self):
        for key, severity in [('process:abc', 'CRITICAL'), ('gunbot:down:1', 'CRITICAL'),
                              ('gunbot:recovered:2', 'INFO'), ('drift:x', 'WARNING'),
                              ('tool:x', 'NOTICE'), ('collector:dns', 'WARNING')]:
            self.assertEqual(s.report_profile({'anomaly': True, 'key': key})[1], severity)
        self.assertEqual(s.report_profile({'command': '/typo', 'text': s.HELP})[0], 'COMMAND REJECTED')
        self.assertEqual(s.report_profile({'command': '/selftest', 'attention': True})[1], 'WARNING')

    def test_report_truncation_preserves_action_and_handles_unicode(self):
        job = {'text': '🚀' * 5000, 'created': 0, 'id': 'b' * 32, 'command': '/recent'}
        report = s.telegram_report('host\nspoof\x00', job)
        self.assertLess(len(report.encode('utf-16-le')) // 2, 3900)
        self.assertIn('DETAIL OMITTED', report)
        self.assertIn('Ref:', report)
        self.assertTrue(report.endswith('Sentinel ' + s.VERSION))
        self.assertNotIn('\x00', report)
        self.assertIn('· HOST SPOOF\n', report)
        self.assertEqual(report, s.telegram_report('host\nspoof\x00', job))

    def test_sender_formats_legacy_queued_alert(self):
        telegram = self.telegram()
        job = {'key': 'ip:192.0.2.1', 'id': 'c' * 32, 'chat': 123,
               'text': 'Old unformatted alert', 'created': time.time(), 'priority': 1, 'anomaly': True}
        telegram.outgoing.put(job)
        with patch.object(telegram, 'api', return_value={}) as api:
            telegram.send_step(time.time())
        payload = api.call_args.args[1]
        self.assertEqual(payload['link_preview_options'], {'is_disabled': True})
        self.assertTrue(payload['text'].startswith('SENTINEL · CONTACT'))
        self.assertIn('Old unformatted alert', payload['text'])

    def test_help_explains_every_command_without_truncation(self):
        text = self.app.command('/help')
        self.assertTrue(text.startswith('SENTINEL COMMAND GUIDE'))
        for command in ['/status', '/selftest', '/health', '/security', '/processes', '/network',
                        '/listeners', '/recent', '/updates', '/baseline', '/known', '/allow',
                        '/remove', '/mute', '/unmute', '/maintenance', '/help']:
            entries = [line for line in text.splitlines() if line.startswith(command + ' ') ]
            self.assertTrue(entries, command)
            self.assertTrue(all(' - ' in line for line in entries), command)
        report = s.telegram_report('Example-Server', {'command': '/help', 'text': text,
                                                       'created': 0, 'id': 'd' * 32})
        self.assertNotIn('DETAIL OMITTED', report)
        self.assertIn('Sentinel does not block traffic', report)

    def test_colored_checks_distinguish_unknown_limited_and_failed(self):
        text = s.check_lines({'dns': 'running (coverage limited)', 'ssh': 'unavailable (retrying)',
                              'resources': 'ok', 'delivery': 'starting'})
        for expected in ['🔵 DNS monitor: RUNNING', '🔴 SSH journal: FAIL',
                         '🟢 Host resources: PASS', '⚪ Telegram delivery: UNKNOWN']:
            self.assertIn(expected, text)
        self.assertIn('🟠', s.reboot_report(True))
        self.assertIn('⚪', s.reboot_report(None))
        self.assertIn('no Ubuntu reboot flag', s.reboot_report(False))
        self.assertIn('⚪', s.clock_report('unknown'))
        self.assertIn('🟠', s.baseline_report('not approved'))

    def test_host_failure_report_explains_reason_without_cascading_file_alarm(self):
        self.app.observe_host({'health': {'listeners_tools': 'unavailable', 'security_files': 'ok (hashed every 60s)',
                                         'baseline': 'blocked (requires listener inventory)'},
                               'errors': {'listeners_tools': 'FD inspection limit exceeded'},
                               'baseline': {'status': 'unavailable'}, 'clock_sync': 'yes'})
        pending = self.app.s['pending']
        self.assertIn('Reason: FD inspection limit exceeded', pending['collector:listeners_tools']['text'])
        self.assertIn('baseline comparison is paused', pending['collector:listeners_tools']['text'])
        self.assertNotIn('collector:security_files', pending)
        self.assertNotIn('collector:baseline', pending)
        self.assertIn('FD inspection limit exceeded', self.app.command('/health'))
        self.assertIn('changes acknowledged', s.baseline_report('acknowledged drift'))

    def test_readiness_actions_match_actual_outstanding_findings(self):
        self.app.observation = {'at': time.time()}
        self.app.health = {'dns': 'running (coverage limited)', 'telegram': 'ok'}
        self.app.procs = {'a': {'pid': 1}}
        self.app.host = {'baseline': {'status': 'not approved'}, 'clock_sync': 'yes', 'reboot_required': True}
        actions = self.app.report_actions('/selftest', '')
        self.assertEqual(len(actions.splitlines()), 2)
        self.assertIn('/baseline review', actions)
        self.assertIn('controlled server reboot', actions)
        self.assertNotIn('unavailable', actions)
        self.app.host['baseline']['status'] = 'matches approved baseline'
        self.app.host['reboot_required'] = False
        self.assertEqual(self.app.report_actions('/selftest', ''), '')
        self.assertFalse(self.app.report_attention('/selftest', ''))
        self.assertIn('Restore access', self.app.report_actions('/selftest', 'State write/read: FAIL'))

    def test_long_actions_and_findings_remain_within_telegram_limit(self):
        report = s.telegram_report('host', {'id': 'e' * 32, 'created': 0, 'command': '/selftest',
                                           'attention': True, 'action': 'Restore check.\n' * 300,
                                           'text': '🟢 PASS\n' * 700})
        self.assertLessEqual(len(report.encode('utf-16-le')) // 2, 3800)
        self.assertIn('ACTION REQUIRED', report)
        self.assertTrue(report.endswith('Sentinel ' + s.VERSION))
        self.assertIn('🟠 ATTENTION', report)

    def test_starting_delivery_is_initialization_not_failure(self):
        self.app.observation = {'at': time.time()}
        self.app.procs = {'a': {'pid': 1}}
        self.app.host = {'baseline': {'status': 'matches approved baseline'}, 'reboot_required': False, 'clock_sync': 'yes'}
        self.app.health = {'delivery': 'starting', 'telegram': 'ok'}
        self.assertEqual(self.app.report_actions('/selftest', ''), '')
        self.assertIn('awaiting first send', self.app.monitoring_summary())
        self.app.started = time.time() - 61
        self.assertIn('not ready: delivery', self.app.report_actions('/selftest', ''))

    def test_actions_first_and_no_generic_acknowledgement_action(self):
        job = {'command': '/selftest', 'id': 'a' * 32, 'created': 0, 'attention': True,
               'action': 'Review baseline.\nSchedule reboot.', 'text': 'Collector freshness: PASS'}
        report = s.telegram_report('host', job)
        self.assertLess(report.index('ACTION REQUIRED'), report.index('OPERATIONAL STATUS'))
        self.assertIn('2 outstanding actions', report)
        job.update(command='/allow', attention=False, text='Sentinel domain rules updated.\nAdded: example.com')
        self.assertNotIn('ACTION REQUIRED', s.telegram_report('host', job))
        self.assertNotIn('no additional action is prescribed', s.telegram_report('host', job))

    def test_monitoring_summary_explains_scope_without_green_wall(self):
        self.app.health = {'dns': 'running (coverage limited)', 'ssh': 'running (coverage limited)',
                           'kernel': 'running (coverage limited)', 'resources': 'ok', 'package_log': 'ok'}
        text = self.app.monitoring_summary()
        for expected in ['systemd-resolved lookups only', 'available login journal', 'new OOM events only',
                         'Checks passing: package log, resources.']:
            self.assertIn(expected, text)
        self.assertNotIn('sampled / limited', text)

    def test_legacy_and_dynamic_text_cannot_emit_long_dashes(self):
        dash = chr(0x2014)
        short_dash = chr(0x2013)
        job = {'key': 'collector:dns', 'anomaly': True, 'created': 0, 'id': 'f' * 32,
               'text': 'host ' + dash + ' Old alert ' + dash + ' retry ' + short_dash + ' now'}
        report = s.telegram_report('host', job)
        self.assertNotIn(dash, report)
        self.assertNotIn(short_dash, report)
        self.assertIn('Old alert - retry - now', report)
        self.assertNotIn('host - Old alert', report)
        self.assertEqual(s.report_text('first' + dash + 'second'), 'first-second')
        job.update(anomaly=False, command='/selftest', attention=True, action='Check' + dash + 'again')
        self.assertNotIn(dash, s.telegram_report('name' + dash + 'suffix', job))

    def test_only_telegram_is_known_by_default_and_shown_once(self):
        self.assertEqual(self.cfg['known_domains'], ['api.telegram.org'])
        self.assertEqual(self.cfg['known_domain_suffixes'], [])
        self.assertEqual(self.app.command('/known'), 'Always known: api.telegram.org')
        for name in ['api.example.com', 'api.example.org', 'vmi.example.net']:
            self.assertFalse(s.known(name, self.cfg))
        self.app.command('/allow api.example.com')
        self.assertIn('api.example.com', self.app.command('/known'))
        self.assertEqual(self.app.command('/known').count('api.telegram.org'), 1)

    def test_ip_alert_contains_automatic_whois_and_no_lookup_link(self):
        job = {'key': 'ip:192.0.2.14', 'anomaly': True, 'created': 0, 'id': 'a' * 32,
               'text': 'Observation ' * 1000, 'whois': 'Registrant / organisation: Example Network'}
        report = s.telegram_report('host', job)
        self.assertIn('WHOIS', report)
        self.assertIn('Example Network', report)
        self.assertNotIn('https://ipinfo', report)
        self.assertLessEqual(len(report.encode('utf-16-le')) // 2, 3800)

    def test_management_commands_normalize_and_persist_audited_changes(self):
        self.assertIn('None configured', self.app.command('/management'))
        message = {'text': '/management add 203.0.113.10', 'from': {'id': 123}, 'chat': {'id': 123}}
        with self.assertLogs(s.LOG, level='INFO') as logs:
            response = s.audit_action(self.app, message, 1234)
        self.assertIn('203.0.113.10/32', response)
        self.assertEqual(s.load(self.path)['known_management_ips'], ['203.0.113.10/32'])
        self.assertIn('"management_operation": "add"', ' '.join(logs.output))
        self.assertIn('"outcome": "applied"', ' '.join(logs.output))
        self.app.command('/management add 2001:db8::12/64')
        self.assertIn('2001:db8::/64', self.app.command('/management'))
        self.assertIn('removed', self.app.command('/management remove 203.0.113.10'))
        self.assertNotIn('203.0.113.10/32', self.cfg['known_management_ips'])

    def test_management_rejects_invalid_inputs_and_requires_exact_removal(self):
        for text in ['/management add bad', '/management add 1.2.3.4:22', '/management add fe80::1%eth0',
                     '/management clear', '/management add', '/management 0']:
            self.assertTrue(self.app.command(text).startswith('Invalid'), text)
        self.app.command('/management add 203.0.113.99/24')
        self.assertIn('exact rule not found', self.app.command('/management remove 203.0.113.99'))
        self.assertEqual(self.cfg['known_management_ips'], ['203.0.113.0/24'])
        self.assertIn('/management add', self.app.command('/help'))
        self.cfg['known_management_ips'] = [f'10.0.0.{n}/32' for n in range(1, 52)]
        self.assertIn('page 2/2', self.app.command('/management 2'))
        self.assertIn('10.0.0.51/32', self.app.command('/management 2'))

    def test_new_configuration_validation(self):
        for field, value in [('expected_gunbot_instances', 0), ('expected_gunbot_instances', True), ('monitored_paths', ['relative']), ('monitored_paths', ['/data/../etc'])]:
            with self.assertRaises(ValueError):
                s.validate(dict(self.cfg, **{field: value}))

    def test_maintenance_keeps_security_active_and_realerts_missing(self):
        self.app.command('/maintenance 1h')
        self.run_check({})
        self.assertNotIn('gunbot:count', self.app.s['pending'])
        self.app.event('drift:ufw', 'UFW drift')
        self.assertIn('drift:ufw', self.app.s['pending'])
        self.app.command('/maintenance off')
        self.run_check({})
        self.assertIn('gunbot:count', self.app.s['pending'])

    def test_count_restart_storm_and_maintenance_expiry(self):
        self.cfg['thresholds']['restart_starts_10m'] = 2
        self.run_check({'a': {'pid': 1}})
        self.run_check({'b': {'pid': 2}})
        self.run_check({'c': {'pid': 3}})
        self.assertIn('gunbot:restart-storm', self.app.s['events'])
        self.app.command('/maintenance 1m')
        self.app.s['maintenance_until'] = time.time() - 1
        self.run_check({})
        self.assertEqual(self.app.s['maintenance_until'], 0)
        self.assertIn('gunbot:count', self.app.s['pending'])

    def test_host_drift_reboot_tools_and_package_deduplication(self):
        host = {'baseline': {'status': 'drift', 'changes': [{'kind': 'files', 'name': '/etc/ufw/user.rules', 'fingerprint': 'x', 'change': 'changed'}]},
                'tools': {'boot:1:2': {'tool': 'npm', 'pid': 1, 'uid': 1000}},
                'package_inventory': {'sha256': 'a'}, 'reboot_required': True, 'clock_sync': 'no'}
        self.app.observe_host(host)
        first = len(self.app.s['events'])
        self.app.observe_host(host)
        self.assertEqual(len(self.app.s['events']), first)
        tool = next(v for k, v in self.app.s['events'].items() if k.startswith('tool:'))
        self.assertEqual(tool['count'], 1)
        self.assertIn('health:reboot-required', self.app.s['pending'])
        self.assertTrue(any('SECURITY FILE' in x for x in self.app.s['recent']))
        host['package_inventory'] = {'sha256': 'b'}
        self.app.observe_host(host)
        self.assertTrue(any(k.startswith('package-inventory:') for k in self.app.s['pending']))
        s.save(self.path, self.cfg)
        self.assertTrue(s.valid_runtime(s.load(self.path)['runtime']))

    def test_selftest_reports_real_write_and_freshness(self):
        self.app.observation = {'at': time.time()}
        response = self.app.command('/selftest')
        self.assertIn('State write/read: PASS', response)
        self.assertIn('Collector freshness: PASS', response)
        self.assertEqual(list(self.path.parent.glob('.sentinel-selftest-*')), [])
        with patch.object(s.tempfile, 'mkstemp', side_effect=PermissionError):
            self.assertIn('State write/read: FAIL', self.app.command('/selftest'))

    def test_setup_private_chat_defaults_and_permissions(self):
        env = self.path.parent / 'sentinel.env'
        token = '123:' + 'x' * 30
        with patch('builtins.input', side_effect=['Example Server', '300', '', '192.0.2.10']), patch.object(s.getpass, 'getpass', return_value=token):
            s.setup(self.path, env)
        cfg = s.load(self.path)
        self.assertEqual(cfg['server_name'], 'Example Server')
        self.assertEqual(cfg['known_domains'], ['api.telegram.org'])
        self.assertEqual(cfg['known_domain_suffixes'], [])
        self.assertEqual(cfg['known_management_ips'], ['192.0.2.10/32'])
        self.assertIn('TELEGRAM_USER_IDS=300', env.read_text())
        self.assertNotIn(token, self.path.read_text())
        self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_failure_diagnostics_do_not_log_exception_secrets(self):
        try:
            raise PermissionError(13, 'secret-token-in-exception', '/secret/path')
        except PermissionError as error:
            with self.assertLogs(s.LOG, level='ERROR') as output:
                s.report_failure(error)
        text = ' '.join(output.output)
        self.assertIn('errno=13', text)
        self.assertIn('PermissionError', text)
        self.assertNotIn('secret', text)

    def test_invalid_server_label_preserves_hostname_default(self):
        env = self.path.parent / 'sentinel.env'
        with patch.object(s.socket, 'gethostname', return_value='test-host'), patch('builtins.input', side_effect=['bad/name', '', '300', '', '']) as prompt, patch.object(s.getpass, 'getpass', return_value='123:' + 'x' * 30):
            s.setup(self.path, env)
        self.assertEqual(s.load(self.path)['server_name'], 'test-host')
        self.assertIn('[test-host]', prompt.call_args_list[1].args[0])
        with self.assertRaises(ValueError):
            s.validate(dict(self.cfg, gunbot_process='gunbot process'))

    def test_setup_reprompts_and_refuses_overwrite(self):
        env = self.path.parent / 'sentinel.env'
        with patch('builtins.input', side_effect=['VPS', 'bad', '-100', '-300', '300', 'bad-IP', '']), patch.object(s.getpass, 'getpass', side_effect=['bad-token', '123:' + 'x' * 30]):
            s.setup(self.path, env)
        before = env.read_bytes()
        with self.assertRaises(ValueError):
            s.setup(self.path, env)
        self.assertEqual(env.read_bytes(), before)

    def test_setup_save_failure_removes_secret_copy(self):
        env = self.path.parent / 'sentinel.env'
        with patch('builtins.input', side_effect=['VPS', '300', '', '']), patch.object(s.getpass, 'getpass', return_value='123:' + 'x' * 30), patch.object(s, 'save', side_effect=OSError):
            with self.assertRaises(OSError):
                s.setup(self.path, env)
        self.assertFalse(env.exists())

    def test_uninstall_preview_is_read_only(self):
        script = Path(__file__).with_name('uninstall.sh')
        result = subprocess.run(['bash', str(script), '--dry-run'], capture_output=True, text=True, check=True)
        self.assertIn('/var/lib/sentinel', result.stdout)
        self.assertIn('not removed', result.stdout)
        subprocess.run(['bash', '-n', str(script)], check=True)

    def test_configuration(self):
        for key, value in [('check_seconds', True), ('check_seconds', 0),
                           ('retention_days', float('nan')), ('known_domains', 'foo'),
                           ('known_management_ips', ['x.x.x.x']), ('thresholds', {'typo': 1}),
                           ('gunbot_process', 'x' * 16), ('server_name', 'line\nbreak')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                s.validate(dict(self.cfg, **{key: value}))
        with self.assertRaises(ValueError):
            s.validate(dict(self.cfg, typo=True))
        self.assertEqual(s.validate(dict(self.cfg, known_management_ips=['192.0.2.7']))['known_management_ips'], ['192.0.2.7/32'])

    def test_domain_validation_and_suffix_boundary(self):
        self.cfg['known_domain_suffixes'] = ['example.net']
        self.assertEqual(s.domain('API.EXAMPLE.COM.'), 'api.example.com')
        for bad in ['1.2.3.4', '::1', 'foo;reboot.com', 'a..com', '-a.com', 'a_.com',
                    'https://api.example.com', 'a.com/path', '$(id).com', 'foo', '*.com', 'a' * 64 + '.com']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                s.domain(bad)
        self.assertTrue(s.known('vmi.example.net', self.cfg))
        self.assertFalse(s.known('evilexample.net', self.cfg))
        self.assertFalse(s.known('example.net.evil.com', self.cfg))
        self.assertFalse(s.known('example.net', self.cfg))
        self.assertEqual(s.domain('*.EXAMPLE.NET', wildcard=True), '*.example.net')

    def test_domain_commands_and_no_self_alert_loop(self):
        self.app.command('/allow *.example.com')
        self.assertTrue(s.known('child.example.com', self.cfg))
        self.app.command('/remove *.example.com')
        self.assertFalse(s.known('child.example.com', self.cfg))
        self.app.command('/remove api.telegram.org')
        self.cfg['known_domains'] = []
        for _ in range(20):
            self.app.dns({'question': [{'name': 'api.telegram.org'}]})
        self.assertFalse(self.app.s['events'])
        self.assertIn('no arguments', self.app.command('/status extra'))
        self.assertEqual(self.app.command('/exec reboot'), 'This command takes no arguments.')
        self.assertEqual(self.app.command('/reboot'), s.HELP)

    def test_duplicate_cooldown_and_counts(self):
        self.app.event('dns:bad.example', 'unknown', now=10000)
        self.app.event('dns:bad.example', 'unknown', now=10001)
        self.app.dispatch(10001)
        self.assertEqual(self.out.qsize(), 1)
        first = self.out.queue[0]
        self.app.delivered((first['key'], first['id'], first['chat'], 'delivered'), now=10001)
        self.app.event('dns:bad.example', 'unknown', now=14000)
        self.app.dispatch(14000)
        self.assertEqual(self.out.qsize(), 2)
        e = self.app.s['events']['dns:bad.example']
        self.assertEqual((e['first'], e['last'], e['count']), (10000, 14000, 3))

    def test_direct_ip_once_per_retained_observation(self):
        self.app.event('ip:192.0.2.1', 'new IP', now=10000, once=True)
        self.app.event('ip:192.0.2.1', 'new IP', now=20000, once=True)
        self.app.dispatch(20000)
        self.assertEqual(self.out.qsize(), 1)
        self.assertEqual(self.app.s['events']['ip:192.0.2.1']['count'], 2)

    def test_mute_unmute_and_duration_validation(self):
        self.app.command('/mute 1h')
        self.app.event('one', 'muted')
        self.assertEqual(self.out.qsize(), 0)
        self.assertEqual(len(self.app.s['recent']), 1)
        self.app.command('/unmute')
        self.app.event('two', 'unmuted')
        self.app.dispatch()
        self.assertEqual(self.out.qsize(), 1)
        for value in ['0h', '-1h', '100d', 'banana', '1s', '1h;id']:
            self.app.command('/mute ' + value)
            self.assertEqual(self.app.s['mute_until'], 0)

    def test_persistence_permissions_and_restart_dedupe(self):
        self.app.command('/allow foo.example')
        self.app.command('/mute 1h')
        self.app.event('dns:bad.example', 'unknown')
        s.save(self.path, self.cfg)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        loaded = s.load(self.path)
        self.assertEqual(loaded, self.cfg)
        new = s.Sentinel(loaded, self.path, self.out, {123})
        new.command('/unmute')
        new.event('dns:bad.example', 'unknown')
        self.assertEqual(self.out.qsize(), 0)

    def test_interrupted_replace_preserves_state(self):
        s.save(self.path, self.cfg)
        before = self.path.read_bytes()
        self.cfg['server_name'] = 'CHANGED'
        with patch.object(s.os, 'replace', side_effect=OSError('simulated interruption')):
            with self.assertRaises(OSError):
                s.save(self.path, self.cfg)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob('.sentinel-*')), [])

    def test_invalid_runtime_recovers_but_invalid_configuration_fails_closed(self):
        self.cfg['runtime']['events'] = {'bad': 'broken'}
        self.path.write_text(json.dumps(self.cfg))
        loaded = s.load(self.path)
        self.assertEqual(loaded['runtime'], s.fresh())
        self.assertEqual(loaded['known_domains'], self.cfg['known_domains'])
        self.path.write_text('{bad json')
        with self.assertRaises(ValueError):
            s.load(self.path)

    def test_bounded_state_and_global_rate(self):
        with self.assertLogs('sentinel', level='WARNING') as logs:
            for i in range(s.LIMIT + 20):
                self.app.event('dns:' + str(i), 'unknown', now=10000)
            self.app.dispatch(10000)
        self.assertLessEqual(len(logs.output), 5)
        self.assertEqual(len(self.app.s['events']), s.LIMIT)
        self.assertEqual(len(self.app.s['recent']), 100)
        self.assertEqual(self.out.qsize(), 5)
        self.assertGreater(self.app.dropped, 0)
        s.save(self.path, self.cfg)
        self.assertLess(self.path.stat().st_size, s.MAX_STATE)
        self.assertTrue(s.valid_runtime(s.load(self.path)['runtime']))

    def test_dns_json_and_ephemeral_address_correlation(self):
        self.cfg['known_domains'].append('api.example.com')
        self.app.dns({'question': [{'name': 'api.example.com', 'type': 1, 'class': 1}],
                      'answer': [{'rr': {'key': {'name': 'api.example.com'}, 'address': [192, 0, 2, 1]}}]})
        until, names = self.app.correlations['192.0.2.1']
        self.assertEqual(names, ['api.example.com'])
        self.assertLessEqual(until, time.time() + 60)
        self.assertFalse(self.app.s['events'])
        self.app.dns({'question': [{'name': 'bad.example'}, {'name': 'bad.example'}]})
        self.assertEqual(self.app.s['events']['dns:bad.example']['count'], 1)

    def test_telegram_cname_chain_cannot_generate_alerts(self):
        self.app.dns({'collectedQuestions': [{'name': 'api.telegram.org'}],
                      'question': [{'name': 'cdn.example.net'}]})
        self.assertFalse(self.app.s['events'])
        self.app.dns({'collectedQuestions': [{'name': 'evil.example'}],
                      'question': [{'name': 'api.telegram.org'}]})
        self.assertIn('dns:evil.example', self.app.s['events'])

    def test_ssh_counts_cidr_authorisation_and_dedupe(self):
        self.cfg['known_management_ips'] = ['192.0.2.0/24']
        def row(cursor, message, age=0):
            return {'__CURSOR': cursor, '__REALTIME_TIMESTAMP': str(int((time.time() - age) * 1e6)), 'MESSAGE': message}
        good = row('a', 'Accepted publickey for trader from 192.0.2.10 port 2222 ssh2')
        self.app.ssh_event(good)
        self.app.ssh_event(good)
        self.assertEqual(sum(v[0] for v in self.app.ssh.values()), 1)
        self.assertFalse(self.app.s['events'])
        self.app.ssh_event(row('b', 'Accepted password for root from 198.51.100.2 port 22 ssh2'))
        self.assertIn('ssh:198.51.100.2', self.app.s['events'])
        self.app.ssh_event(row('c', 'Failed password for invalid user test from 198.51.100.2 port 22 ssh2'))
        self.assertEqual(sum(v[1] for v in self.app.ssh.values()), 1)
        self.app.ssh_event(row('d', 'Accepted publickey for root from 203.0.113.1 port 22 ssh2', age=5000))
        self.assertNotIn('ssh:203.0.113.1', self.app.s['events'])

    def run_check(self, procs, connections=None):
        self.app.next_ufw = time.time() + 10000
        metrics = {'memory': 20, 'disk': 20, 'load': 0, 'uptime': 100, 'cpu': 1}
        with patch.object(s, 'proc_snapshot', return_value=(procs, connections or [])), patch.object(s, 'resources', return_value=(metrics, (1, 1))):
            self.app.check()

    def test_process_disappearance_no_repeated_down_and_recovery(self):
        self.run_check({'boot:10:100': {'pid': 10}})
        self.run_check({})
        self.assertFalse(self.app.s['down'])
        self.run_check({})
        self.assertTrue(self.app.s['down'])
        recent = len(self.app.s['recent'])
        self.run_check({})
        self.assertEqual(len(self.app.s['recent']), recent)
        self.run_check({'boot:10:200': {'pid': 10}})  # Reused PID is a new instance.
        self.assertFalse(self.app.s['down'])
        self.assertTrue(any('recovered' in x for x in self.app.s['recent']))

    def test_partial_instance_recovery(self):
        a, b = {'a': {'pid': 1}}, {'b': {'pid': 2}}
        self.run_check(dict(a, **b))
        self.run_check(a)
        self.run_check(a)
        self.assertFalse(self.app.s['down'])
        self.run_check(dict(a, **b))
        self.assertTrue(any('recovered' in x for x in self.app.s['recent']))

    def test_health_thresholds_failed_ssh_and_retention(self):
        self.app.next_ufw = time.time() + 10000
        self.app.ssh[int(time.time() // 60)] = [0, 40]
        self.app.event('expired', 'old observation', now=time.time() - 8 * 86400)
        metrics = {'memory': 95, 'disk': 95, 'load': 999999, 'uptime': 100, 'cpu': 1}
        with patch.object(s, 'proc_snapshot', return_value=({'a': {'pid': 1}}, [])), patch.object(s, 'resources', return_value=(metrics, (1, 1))):
            self.app.check()
        for key in ['health:memory', 'health:disk', 'health:load', 'ssh:failures']:
            self.assertIn(key, self.app.s['events'])
        self.assertNotIn('expired', self.app.s['events'])

    def test_read_failure_does_not_report_process_death(self):
        self.run_check({'a': {'pid': 1}})
        with patch.object(s, 'proc_snapshot', side_effect=PermissionError), patch.object(s, 'resources', side_effect=OSError):
            self.app.check()
        self.assertEqual(self.app.s['processes']['a']['misses'], 0)
        self.assertFalse(self.app.s['down'])
        self.assertEqual(self.app.health['processes'], 'unavailable')

    def telegram(self):
        with patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': '123:' + 'x' * 30,
                                     'TELEGRAM_CHAT_IDS': '100,-200', 'TELEGRAM_USER_IDS': '300'}):
            return s.Telegram(queue.Queue(), queue.Queue(), threading.Event(), 0)

    def test_telegram_both_ids_required(self):
        bot = self.telegram()
        msg = {'chat': {'id': 100}, 'from': {'id': 300}}
        self.assertTrue(bot.authorised(msg))
        for other in [{'chat': {'id': 101}, 'from': {'id': 300}},
                      {'chat': {'id': 100}, 'from': {'id': 301}},
                      dict(msg, sender_chat={'id': 100}), {},
                      {'chat': {'id': '100'}, 'from': {'id': 300}}]:
            self.assertFalse(bot.authorised(other))

    def test_telegram_unavailable_redacts_token_and_backoff(self):
        bot = self.telegram()
        def fail(*args):
            bot.stop.set()
            raise OSError('secret token ' + bot.token)
        with patch.object(bot, 'api', side_effect=fail), self.assertLogs('sentinel', level='WARNING') as logs:
            bot.run()
        self.assertEqual(bot.health, 'unavailable')
        self.assertNotIn(bot.token, '\n'.join(logs.output))
        self.app.event('still-working', 'Monitoring unaffected')
        self.assertIn('still-working', self.app.s['events'])

    def test_queued_notifications_honor_mute(self):
        bot = self.telegram()
        bot.mute_until = time.time() + 3600
        bot.outgoing.put(self.job())
        with patch.object(bot, 'api') as api:
            bot.send_step(time.time())
            api.assert_not_called()
        self.assertEqual(bot.receipts.get_nowait()[-1], 'muted')

    @staticmethod
    def job(chat=100, priority=1):
        return {'key': 'dns:test', 'id': 'a' * 32, 'chat': chat, 'text': 'test',
                'created': time.time(), 'priority': priority, 'anomaly': True}

    def test_critical_notice_survives_dns_flood(self):
        for i in range(2500):
            self.app.event(f'dns:{i}', 'routine', now=10000)
        self.app.event('process:lost', 'critical', now=10001, once=True)
        self.app.dispatch(10001)
        self.assertTrue(any(j['key'] == 'process:lost' for j in self.out.queue))
        self.assertEqual(self.app.s['events']['process:lost']['notified'], 0)
        self.assertLessEqual(len(self.app.s['pending']), s.MAX_PENDING)

    def test_full_queue_and_restart_retry_critical(self):
        self.app.outgoing = queue.Queue(1)
        self.app.outgoing.put('full')
        self.app.event('process:lost', 'critical', once=True)
        self.app.dispatch()
        self.assertFalse(self.app.inflight)
        s.save(self.path, self.cfg)
        new = s.Sentinel(s.load(self.path), self.path, self.out, {123})
        new.dispatch()
        self.assertEqual(self.out.qsize(), 1)
        job = self.out.get()
        new.delivered((job['key'], job['id'], job['chat'], 'delivered'))
        self.assertGreater(new.s['events']['process:lost']['notified'], 0)
        self.assertFalse(new.s['pending'])

    def test_failed_recipient_does_not_block_other_recipient_or_polling(self):
        bot = self.telegram()
        bot.outgoing.put(self.job(100))
        bot.outgoing.put(self.job(-200))
        calls = []
        def api(method, payload):
            calls.append((method, payload.get('chat_id')))
            if method == 'getUpdates':
                bot.stop.set()
                return []
            if payload['chat_id'] == 100:
                raise s.APIError(403)
            return {}
        with patch.object(bot, 'api', side_effect=api):
            bot.send_step(time.time())
            bot.send_step(time.time())
            bot.run()
        self.assertEqual(calls, [('sendMessage', 100), ('sendMessage', -200), ('getUpdates', None)])

    def test_rate_limit_respects_retry_after(self):
        bot = self.telegram()
        bot.outgoing.put(self.job())
        with patch.object(bot, 'api', side_effect=s.APIError(429, 30)) as api:
            bot.send_step(100)
            bot.send_step(129)
            self.assertEqual(api.call_count, 1)
            bot.send_step(131)
            self.assertEqual(api.call_count, 2)

    def test_saturated_sender_reserves_critical_capacity(self):
        bot = self.telegram()
        bot.pending = [dict(self.job(), next=time.time()+600, attempts=1) for _ in range(100)]
        bot.outgoing.put(self.job(priority=0))
        with patch.object(bot, 'api', return_value={}) as api:
            bot.send_step(time.time())
        api.assert_called_once()
        self.assertEqual(bot.receipts.get_nowait()[-1], 'deferred')
        self.assertEqual(bot.receipts.get_nowait()[-1], 'delivered')

    def test_admin_audit_has_actor_target_and_durable_outcome(self):
        message = {'text': '/allow example.com', 'from': {'id': 300}, 'chat': {'id': 100}}
        with self.assertLogs('sentinel', level='INFO') as logs:
            s.audit_action(self.app, message, 77)
        log = '\n'.join(logs.output)
        for expected in ['"actor": 300', '"chat": 100', '"target": "example.com"', '"outcome": "applied"']:
            self.assertIn(expected, log)
        self.assertIn('example.com', s.load(self.path)['known_domains'])

    def test_privilege_drop_clears_supplementary_groups_before_uid(self):
        from types import SimpleNamespace
        calls = []
        with patch.object(s.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=991, pw_gid=991)), patch.object(s.os, 'setgroups', side_effect=lambda value: calls.append(('groups', value))), patch.object(s.os, 'setgid', side_effect=lambda value: calls.append(('gid', value))), patch.object(s.os, 'setuid', side_effect=lambda value: calls.append(('uid', value))), patch.object(s.os, 'geteuid', return_value=991):
            s.drop_privileges()
        self.assertEqual(calls, [('groups', []), ('gid', 991), ('uid', 991)])

    def test_delivery_failure_notice_excludes_failed_chat_and_cannot_loop(self):
        self.app.chats = {123, 456}
        self.app.event('process:one', 'critical')
        item = self.app.s['pending']['process:one']
        self.app.delivered(('process:one', item['id'], 123, 'permanent_failure'))
        warning = self.app.s['pending']['delivery:123']
        self.assertEqual(warning['remaining'], [456])
        self.app.delivered(('delivery:123', warning['id'], 456, 'permanent_failure'))
        self.assertNotIn('delivery:456', self.app.s['pending'])

    def test_legacy_notification_state_does_not_claim_delivery(self):
        self.cfg['runtime'] = {'events': {'dns:x': {'first': 1, 'last': 2, 'count': 3, 'notified': 2}},
                               'recent': [], 'processes': {}, 'mute_until': 0, 'offset': 0, 'down': False}
        self.path.write_text(json.dumps(self.cfg))
        state = s.load(self.path)['runtime']
        self.assertEqual(state['events']['dns:x']['settled'], 2)
        self.assertEqual(state['events']['dns:x']['notified'], 0)

    def test_removed_destinations_do_not_leak_pending_slots(self):
        self.app.event('process:one', 'critical')
        self.app.chats = {456}
        self.app.dispatch()
        self.assertFalse(self.app.s['pending'])
        self.assertEqual(self.app.s['delivery_gaps'], 1)

    def test_proc_fixture_inodes_ipv4_ipv6_and_inbound_exclusion(self):
        root = Path(self.temp.name) / 'proc'
        (root / 'sys/kernel/random').mkdir(parents=True)
        (root / 'sys/kernel/random/boot_id').write_text('test-boot')
        (root / 'uptime').write_text('1000 0')
        (root / 'net').mkdir()
        p = root / '42'
        (p / 'fd').mkdir(parents=True)
        (p / 'comm').write_text('gunthy-linux\n')
        fields = ['0'] * 22
        fields[0], fields[11], fields[12], fields[19], fields[21] = 'S', '100', '50', '200', '1000'
        (p / 'stat').write_text('42 (gunthy-linux) ' + ' '.join(fields))
        for inode in ['100', '101', '102', '103']:
            (p / 'fd' / inode).symlink_to('socket:[' + inode + ']')
        header = 'header\n'
        def row(local, remote, state, inode):
            return f'0: {local} {remote} {state} 0 0 0 0 0 {inode}\n'
        (root / 'net/tcp').write_text(header +
            row('00000000:1F90', '00000000:0000', '0A', '100') +
            row('0100007F:1F90', '020200C0:A000', '01', '101') +
            row('0100007F:A000', '010200C0:01BB', '01', '102'))
        (root / 'net/tcp6').write_text(header +
            row('00000000000000000000000001000000:A000', 'B80D0120000000000000000001000000:01BB', '01', '103'))
        real_path = Path
        def fake_path(value):
            text = str(value)
            return root / text.removeprefix('/proc/').removeprefix('/proc') if text.startswith('/proc') else real_path(value)
        with patch.object(s, 'Path', side_effect=fake_path):
            procs, connections = s.proc_snapshot('gunthy-linux', {}, 30)
        self.assertEqual(len(procs), 1)
        self.assertEqual(next(iter(procs.values()))['listen'], [8080])
        self.assertEqual({x['ip'] for x in connections}, {'192.0.2.1', '2001:db8::1'})
        self.assertEqual({x['port'] for x in connections}, {443})


if __name__ == '__main__':
    unittest.main()
