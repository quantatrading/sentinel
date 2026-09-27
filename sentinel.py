#!/usr/bin/env python3
"""Sentinel: passive Linux observations, bounded JSON state, outbound Telegram UI."""
import argparse
import collections
import datetime as dt
import fcntl
import getpass
import pwd
import uuid
import urllib.error
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import queue
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

# Only the installed root-owned application directory is added under Python -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sentinel_checks as checks
import sentinel_whois as whois
import sentinel_baseline as baselines
import sentinel_incidents as incidents

LOG = logging.getLogger('sentinel')
MAX_STATE = 4 * 1024 * 1024
LIMIT = 2000
VERSION = '0.3.15'
MAX_PENDING = 200
HELP = """SENTINEL COMMAND GUIDE
Purpose: inspect host security, monitoring readiness and Gunbot activity.

STATUS AND READINESS
/status - Overall host resources, Gunbot instance/process counts and monitoring status.
/selftest - Test state storage; report collector freshness, coverage and delivery status.
/health - Disk/inode usage, clock synchronization and reboot-required status.
/security - Saved UFW policy, SSH activity, network observations and delivery gaps.

ACTIVITY AND EVIDENCE
/processes - Matching Gunbot processes: PID, runtime, CPU, memory and listening ports.
/network - Sampled Gunbot outbound connections and available DNS correlation.
/listeners - System listening/bound endpoints and their observed process owners.
/recent - Recent alerts, observation counts and first/last observation times.
/updates - Observed package/download tools, dpkg changes and reboot status.
/sentinel [page] - List tracked security changes.
/sentinel investigate <ref> - Explain one change and its process history.
/sentinel acknowledge <ref> - Mark reviewed; keep the baseline unchanged.
/sentinel approve <ref> - Accept only this current change into the baseline.
/baseline - Security baseline status and detected changes.
/baseline review [page] - Review current file/listener metadata.
/baseline approve <digest> - Accept the inventory you reviewed within 5 minutes.

DOMAIN RULES
/known - Show approved domain rules. These are Sentinel rules, not firewall rules.
/allow <domain|*.suffix> - Approve an exact domain or its subdomains for DNS alerts.
/remove <domain|*.suffix> - Remove an approval. api.telegram.org remains always known.
Example: /allow api.example.com
Example: /allow *.example.com (subdomains only; excludes example.com)

MANAGEMENT IPs
/management [page] - List trusted SSH source IPs/CIDRs (50 per page).
/management add <IP/CIDR> - Trust an SSH source, for example /management add 203.0.113.10
/management remove <IP/CIDR> - Remove that exact rule. Firewall rules are unchanged.

NOTIFICATION CONTROL
/mute <duration> - Suppress all anomaly notifications; command replies remain available.
/unmute - Resume future anomaly notifications; muted history is retained.
/maintenance <duration> - Suppress Gunbot lifecycle/count/restart notices only; security alerts continue unless globally muted.
/maintenance off - End maintenance and resume Gunbot lifecycle checks.
Durations: 1m to 7d. Examples: /mute 30m or /maintenance 1h.

ASSISTANCE
/help - Display this command guide.
Status key: 🟢 PASS | 🟠 ATTENTION | 🔴 FAIL | ⚪ UNKNOWN | 🔵 RUNNING/INFO

LIMITS
Monitoring is sampled and passive. Sentinel does not block traffic, modify UFW, restart Gunbot or reboot the host."""


def domain(value, wildcard=False):
    if not isinstance(value, str):
        raise ValueError('Invalid domain')
    value = value.lower().rstrip('.')
    prefix = '*.' if wildcard and value.startswith('*.') else ''
    name = value[len(prefix):]
    if len(name) > 253 or '.' not in name or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
            for x in name.split('.')):
        raise ValueError('Use a valid ASCII domain, optionally prefixed with *.')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return prefix + name
    raise ValueError('IP addresses are not domain rules')


def known(name, cfg):
    return (name == 'api.telegram.org' or name in cfg['known_domains'] or
            any(name.endswith('.' + suffix) for suffix in cfg['known_domain_suffixes']))


def validate(cfg):
    allowed = {'server_name', 'gunbot_process', 'known_domains', 'known_domain_suffixes',
               'known_management_ips', 'thresholds', 'alert_cooldown_minutes',
               'check_seconds', 'retention_days', 'runtime', 'expected_gunbot_instances', 'monitored_paths'}
    if not isinstance(cfg, dict) or set(cfg) - allowed:
        raise ValueError('Unknown configuration fields')
    for key, default in [('server_name', socket.gethostname()), ('gunbot_process', 'gunthy-linux')]:
        cfg.setdefault(key, default)
        pattern = r'[A-Za-z0-9_. -]{1,64}' if key == 'server_name' else r'[A-Za-z0-9_.-]{1,64}'
        if not isinstance(cfg[key], str) or not re.fullmatch(pattern, cfg[key]) or not cfg[key].strip():
            raise ValueError('Invalid ' + key)
    if len(cfg['gunbot_process']) > 15:
        raise ValueError('gunbot_process must fit Linux comm (15 characters)')
    for key in ['known_domains', 'known_domain_suffixes', 'known_management_ips']:
        cfg.setdefault(key, [])
        if not isinstance(cfg[key], list) or len(cfg[key]) > LIMIT:
            raise ValueError('Invalid ' + key)
        cfg[key] = sorted(set(str(ipaddress.ip_network(x, strict=False)) if key.endswith('ips')
                              else domain(x) for x in cfg[key]))
    cfg.setdefault('expected_gunbot_instances', 1)
    if type(cfg['expected_gunbot_instances']) is not int or not 1 <= cfg['expected_gunbot_instances'] <= 256:
        raise ValueError('Invalid expected_gunbot_instances')
    cfg.setdefault('monitored_paths', ['/'])
    if not isinstance(cfg['monitored_paths'], list) or not 1 <= len(cfg['monitored_paths']) <= 16 or not all(
            isinstance(x, str) and x.startswith('/') and len(x) <= 256 and not any(ord(c) < 32 for c in x)
            and '..' not in Path(x).parts for x in cfg['monitored_paths']):
        raise ValueError('Invalid monitored_paths')
    cfg.setdefault('thresholds', {})
    if not isinstance(cfg['thresholds'], dict) or set(cfg['thresholds']) - {
            'disk_percent', 'memory_percent', 'load_per_cpu', 'ssh_failures_10m', 'inode_percent', 'restart_starts_10m'}:
        raise ValueError('Invalid thresholds')
    specs = {'disk_percent': (90, 1, 100), 'memory_percent': (90, 1, 100),
             'load_per_cpu': (2, .1, 100), 'ssh_failures_10m': (30, 1, 1000000),
             'inode_percent': (90, 1, 100), 'restart_starts_10m': (5, 2, 256)}
    for obj, values in [(cfg['thresholds'], specs), (cfg, {
            'alert_cooldown_minutes': (60, 1, 10080), 'check_seconds': (30, 10, 3600),
            'retention_days': (7, 1, 30)})]:
        for key, (default, low, high) in values.items():
            obj.setdefault(key, default)
            if type(obj[key]) not in (int, float) or not math.isfinite(obj[key]) or not low <= obj[key] <= high:
                raise ValueError('Invalid ' + key)
    return cfg


def fresh():
    return {'events': {}, 'recent': [], 'processes': {}, 'mute_until': 0,
            'offset': 0, 'down': False, 'pending': {}, 'delivery_gaps': 0,
            'maintenance_until': 0, 'process_starts': [], 'tracking_started': False,
            'incidents': {}, 'approved_baseline': None, 'count_mismatch': False, 'seen_tools': {}, 'package_digest': '', 'selftest_delivery': 0}


def valid_runtime(s):
    if not isinstance(s, dict) or set(s) != set(fresh()):
        return False
    if not incidents.valid_state(s['incidents']):
        return False
    if not baselines.valid_approval(s['approved_baseline']):
        return False
    for key in ('maintenance_until', 'selftest_delivery'):
        if type(s[key]) not in (int, float) or not math.isfinite(s[key]) or s[key] < 0:
            return False
    if type(s['tracking_started']) is not bool or type(s['count_mismatch']) is not bool:
        return False
    if not isinstance(s['process_starts'], list) or len(s['process_starts']) > 256 or not all(
            type(x) in (int, float) and math.isfinite(x) and x >= 0 for x in s['process_starts']):
        return False
    if not isinstance(s['seen_tools'], dict) or len(s['seen_tools']) > 512 or not all(
            isinstance(k, str) and len(k) <= 160 and type(v) in (int, float) and math.isfinite(v)
            for k, v in s['seen_tools'].items()):
        return False
    if not isinstance(s['package_digest'], str) or not re.fullmatch(r'[a-f0-9]{0,64}', s['package_digest']):
        return False
    if type(s['delivery_gaps']) is not int or s['delivery_gaps'] < 0:
        return False
    if not isinstance(s['pending'], dict) or len(s['pending']) > MAX_PENDING:
        return False
    for key, item in s['pending'].items():
        if not isinstance(key, str) or len(key) > 300 or not isinstance(item, dict):
            return False
        if set(item) != {'id', 'text', 'created', 'priority', 'remaining'}:
            return False
        if not isinstance(item['id'], str) or len(item['id']) != 32 or not isinstance(item['text'], str) or len(item['text']) > 1200:
            return False
        if type(item['created']) not in (int, float) or not math.isfinite(item['created']) or item['created'] < 0:
            return False
        if type(item['priority']) is not int or item['priority'] not in (0, 1):
            return False
        if not isinstance(item['remaining'], list) or len(item['remaining']) > 10 or not all(type(x) is int for x in item['remaining']):
            return False
    if type(s['offset']) is not int or s['offset'] < 0 or type(s['down']) is not bool:
        return False
    if type(s['mute_until']) not in (int, float) or not math.isfinite(s['mute_until']):
        return False
    if not isinstance(s['recent'], list) or len(s['recent']) > 100:
        return False
    if not all(isinstance(x, str) and len(x) <= 1000 for x in s['recent']):
        return False
    if not isinstance(s['events'], dict) or len(s['events']) > LIMIT:
        return False
    for key, e in s['events'].items():
        if not isinstance(key, str) or len(key) > 300 or not isinstance(e, dict):
            return False
        if set(e) != {'first', 'last', 'count', 'notified', 'settled'}:
            return False
        if not all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in e.values()):
            return False
    if not isinstance(s['processes'], dict) or len(s['processes']) > 256:
        return False
    return all(isinstance(k, str) and len(k) < 150 and isinstance(v, dict) and
               set(v) == {'pid', 'last', 'misses'} and
               all(type(n) in (int, float) and math.isfinite(n) and n >= 0 for n in v.values())
               for k, v in s['processes'].items())


def load(path):
    if path.stat().st_size > MAX_STATE:
        raise ValueError('State/config file too large')
    cfg = validate(json.loads(path.read_text()))
    runtime = cfg.get('runtime', fresh())
    if isinstance(runtime, dict):
        if isinstance(runtime.get('events'), dict):
            for event in runtime['events'].values():
                if isinstance(event, dict) and 'settled' not in event:
                    event['settled'] = event.get('notified', 0)
                    event['notified'] = 0  # Legacy data did not prove delivery.
        runtime.setdefault('pending', {})
        runtime.setdefault('delivery_gaps', 0)
        for key, value in fresh().items():
            runtime.setdefault(key, value)
    if not valid_runtime(runtime):
        LOG.warning('Invalid runtime state; resetting observations, preserving configuration')
        runtime = fresh()
    cfg['runtime'] = runtime
    return cfg


def save(path, cfg):
    data = json.dumps(cfg, indent=2, allow_nan=False).encode() + b'\n'
    if len(data) > MAX_STATE:
        raise ValueError('State size limit exceeded')
    fd, temp = tempfile.mkstemp(prefix='.sentinel-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def stamp(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime('%d %b %H:%M UTC')


def put(q, item):
    try:
        q.put_nowait(item)
        return True
    except queue.Full:
        return False


def report_text(value):
    """Plain Telegram text: retain line breaks, remove controls and decorative symbols."""
    value = str(value).replace('\u2014', '-').replace('\u2013', '-')
    for symbol in ('⚠️',):
        value = value.replace(symbol, '')
    return ''.join(c for c in value if c == '\n' or (c.isprintable() and c not in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')).strip()


STATUS_ICONS = {'PASS': '🟢', 'ATTENTION': '🟠', 'FAIL': '🔴', 'UNKNOWN': '⚪', 'RUNNING': '🔵'}


def status_line(label, status, detail=''):
    return f"{STATUS_ICONS[status]} {label}: {status}" + (f" - {detail}" if detail else '')


def check_lines(health):
    names = {'listeners_tools': 'Listeners / tool detection', 'package_inventory': 'Package inventory',
             'package_log': 'Package log', 'security_files': 'Security files', 'dns': 'DNS monitor',
             'ssh': 'SSH journal', 'kernel': 'Kernel journal', 'telegram': 'Telegram polling',
             'delivery': 'Telegram delivery', 'processes': 'Process inspection', 'resources': 'Host resources'}
    lines = []
    for name, value in sorted(health.items()):
        if value.startswith('ok'):
            status, detail = 'PASS', value[2:].strip(' ()')
        elif value.startswith('running'):
            status, detail = 'RUNNING', {'dns': 'systemd-resolved lookups only', 'ssh': 'available login journal', 'kernel': 'new OOM events only'}.get(name, 'observed collector activity')
        elif value.startswith(('unavailable', 'invalid', 'oversize', 'degraded')):
            status, detail = 'FAIL', value
        else:
            status, detail = 'UNKNOWN', value
        lines.append(status_line(names.get(name, name.replace('_', ' ').capitalize()), status, detail))
    return '\n'.join(lines) or status_line('Collectors', 'UNKNOWN', 'not yet sampled')


def clock_report(value):
    return status_line('Clock synchronization', {'yes': 'PASS', 'no': 'ATTENTION'}.get(value, 'UNKNOWN'),
                       {'yes': 'synchronized', 'no': 'not synchronized'}.get(value, 'status unavailable'))


def reboot_report(value):
    return status_line('Reboot requirement', 'ATTENTION' if value is True else 'PASS' if value is False else 'UNKNOWN',
                       'REQUIRED - schedule manually' if value is True else 'no Ubuntu reboot flag' if value is False else 'status unavailable')


def baseline_report(value):
    if value == 'acknowledged drift':
        return status_line('Baseline', 'INFO', 'changes acknowledged; reference unchanged; see /sentinel')
    state = 'PASS' if value == 'matches approved baseline' else 'ATTENTION' if value in ('not approved', 'drift') else 'UNKNOWN'
    return status_line('Baseline', state, {'not approved': 'NOT APPROVED', 'drift': 'CHANGE DETECTED',
                       'matches approved baseline': 'matches approved state'}.get(value, 'inspection unavailable'))


def report_profile(job):
    """Severity describes the finding, independently of delivery queue priority."""
    key = job.get('key', '')
    if job.get('anomaly'):
        if 'recovered' in key:
            return 'RECOVERY', 'INFO', 'Recovery observed; continue monitoring.'
        if key.startswith(('process:', 'gunbot:down:', 'oom:')):
            return 'INCIDENT', 'CRITICAL', 'Investigate affected processes and host resources. Sentinel has taken no corrective action.'
        if key.startswith(('dns:', 'ip:')):
            return 'CONTACT', 'WARNING', 'Verify the destination against expected activity. DNS correlation is limited; compromise is not established.'
        if key.startswith('incident:'):
            return 'CHANGE', ('WARNING' if job.get('incident_state', 'detected') == 'detected' else 'NOTICE'), 'Review the change using its /sentinel investigate command; approve only if expected.'
        if key.startswith('drift:'):
            return 'CHANGE', 'WARNING', 'Verify the change locally. Approve a new baseline only after review.'
        if key.startswith(('tool:', 'packages:', 'package-inventory:')):
            return 'ACTIVITY', 'NOTICE', 'Confirm this activity was expected. Tool presence alone does not prove installation or download.'
        if key == 'health:reboot-required':
            return 'HEALTH', 'WARNING', 'Schedule and perform a reboot manually when appropriate.'
        if key.startswith('baseline:'):
            return 'READINESS', 'WARNING', 'Use /baseline review, then approve its digest if expected.'
        if key.startswith(('collector:', 'delivery:')):
            return 'READINESS', 'WARNING', 'Investigate the affected monitoring or delivery component; coverage may be incomplete.'
        return 'ALERT', 'WARNING', 'Review the finding and investigate unexpected activity. No automatic remediation.'
    command = job.get('command', '/help')
    report = {'/status': 'SITREP', '/selftest': 'READINESS', '/security': 'SECURITY',
              '/health': 'HEALTH', '/network': 'CONTACT', '/listeners': 'LISTENERS',
              '/baseline': 'BASELINE', '/processes': 'PROCESS STATE',
              '/updates': 'ACTIVITY', '/recent': 'EVENT LOG', '/known': 'KNOWN DOMAINS',
              '/sentinel': 'CHANGE RECORD', '/help': 'COMMAND GUIDE', '/management': 'MANAGEMENT IPs'}.get(command, 'COMMAND ACK')
    # Do not confuse receipt of an acknowledgement with proof of host readiness.
    text = job.get('text', '')
    commands = set(HELP.replace('\n', ' ').split())
    unknown_command = command not in {x for x in commands if x.startswith('/')}
    rejected = unknown_command or text.startswith(('Invalid', 'Exactly one', 'This command takes', 'Use /mute',
                                'Mute must', 'Maintenance must', 'Domain rule limit'))
    if rejected:
        return 'COMMAND REJECTED', 'WARNING', 'Correct the command and retry. See /help.'
    if job.get('attention'):
        return report, 'WARNING', job.get('action') or 'Review the outstanding findings and unavailable checks above.'
    action = {'/baseline': 'Review changes locally before approving any baseline.',
              '/selftest': 'Receiving this reply confirms delivery. Review each check; sampled coverage remains limited.',
              '/help': 'Send one listed command per message.'}.get(command, 'Review the reported observations; no additional action is prescribed by this reply.')
    return report, 'INFO', action


def telegram_report(host, job):
    report, severity, action = report_profile(job)
    when = dt.datetime.fromtimestamp(job['created'], dt.timezone.utc)
    identifier = re.sub('[^a-zA-Z0-9]', '', str(job.get('reference') or job.get('id', '')))[:8].upper() or 'UNASSIGNED'
    subject = report_text(host).replace('\n', ' ')[:64]
    body = report_text(job.get('text', '')) or 'No observations available.'
    # Use colour for exceptions; healthy observations remain easy to scan.
    body = re.sub(r'(?m)^[🟢🔵]\s*', '', body)
    if job.get('command') == '/help':
        body = body.removeprefix('SENTINEL COMMAND GUIDE\n')
    if job.get('anomaly'):
        body = body.removeprefix(report_text(host) + ' - ')
    icon = {'INFO': '🔵', 'NOTICE': '🔵', 'WARNING': '🟠', 'CRITICAL': '🔴'}[severity]
    required = job.get('attention') or severity in ('WARNING', 'CRITICAL')
    actions = report_text(action) if required else ''
    count = len(actions.splitlines()) if job.get('action') else 0
    headline = ('ATTENTION' + (f' - {count} outstanding action' + ('s' if count != 1 else '') if count else '')) if severity == 'WARNING' else severity
    header = f'SENTINEL · {report} · {subject.upper()}\n{icon} {headline}\n'
    if actions:
        if len(actions.encode('utf-16-le')) > 2800:
            actions = actions.encode('utf-16-le')[:2700].decode('utf-16-le', errors='ignore') + '\n[Further actions omitted; inspect /health and /security.]'
        header += '\nACTION REQUIRED\n' + actions + '\n'
    section = 'OBSERVATION' if job.get('anomaly') else 'OPERATIONAL STATUS' if job.get('command') in ('/status', '/selftest') else 'DETAILS'
    if job.get('anomaly') and job.get('key', '').startswith(('ip:', 'dns:')):
        section = 'NETWORK OBSERVATION'
        body = re.sub(r'^\s*NETWORK\s*\n', '', body, count=1)
    lookup = ('\n\nWHOIS\n' + report_text(job.get('whois', 'Unavailable: registration data not received.'))) if job.get('anomaly') and job.get('key', '').startswith('ip:') else ''
    footer = lookup + f'\n\nRef: {identifier} · {when.strftime("%d %b %Y, %H:%M UTC")} · Sentinel {VERSION}'
    budget = 3800 - len((header + section + footer + '\n\n').encode('utf-16-le')) // 2
    if len(body.encode('utf-16-le')) // 2 > budget:
        marker = '\n[DETAIL OMITTED: report length limit]'
        body = body.encode('utf-16-le')[:2 * (budget - len(marker))].decode('utf-16-le', errors='ignore').rstrip() + marker
    return report_text(header + '\n' + section + '\n' + body + footer)


class APIError(Exception):
    def __init__(self, code=0, retry_after=0):
        self.code = code
        self.retry_after = max(0, min(float(retry_after), 3600))
        super().__init__('Telegram request failed')


class Telegram(threading.Thread):
    """Independent polling and delivery threads; no host inspection or shell access."""
    def __init__(self, incoming, outgoing, stop, offset, receipts=None):
        super().__init__(daemon=True)
        self.incoming, self.outgoing, self.stop = incoming, outgoing, stop
        self.receipts = receipts if receipts is not None else queue.Queue(500)
        self.offset = offset
        self.token = os.environ.pop('TELEGRAM_BOT_TOKEN', '')
        if not re.fullmatch(r'\d+:[A-Za-z0-9_-]{20,}', self.token):
            raise ValueError('Missing/invalid TELEGRAM_BOT_TOKEN')
        self.chats = self.ids('TELEGRAM_CHAT_IDS')
        self.users = self.ids('TELEGRAM_USER_IDS')
        self.health = 'starting'
        self.delivery_health = 'starting'
        self.mute_until = 0
        self.maintenance_until = 0
        self.pending = []
        self.chat_next = {}
        self.global_next = 0
        self.whois = whois.Enricher()
        self.sender = threading.Thread(target=self.send_loop, daemon=True)

    @staticmethod
    def ids(key):
        values = os.environ.get(key, '').split(',')
        if not 1 <= len(values) <= 10 or not all(re.fullmatch(r'-?\d{1,20}', x.strip()) for x in values):
            raise ValueError('Missing/invalid ' + key)
        ids = {int(x.strip()) for x in values}
        if 0 in ids or (key.endswith('USER_IDS') and min(ids) < 1):
            raise ValueError('Invalid ' + key)
        return ids

    def api(self, method, payload):
        req = urllib.request.Request('https://api.telegram.org/bot' + self.token + '/' + method,
                                     data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=15) as response:
                raw = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            try:
                result = json.loads(error.read(65536))
                delay = result.get('parameters', {}).get('retry_after', 0)
            except (ValueError, TypeError, AttributeError):
                delay = 0
            raise APIError(error.code, delay) from None
        if len(raw) > 1024 * 1024:
            raise APIError()
        result = json.loads(raw)
        if not result.get('ok'):
            raise APIError(result.get('error_code', 0), result.get('parameters', {}).get('retry_after', 0))
        return result['result']

    def authorised(self, msg):
        if not isinstance(msg, dict) or not isinstance(msg.get('chat'), dict) or not isinstance(msg.get('from'), dict):
            return False
        return (type(msg['chat'].get('id')) is int and msg['chat']['id'] in self.chats and
                type(msg['from'].get('id')) is int and msg['from']['id'] in self.users and
                not msg.get('sender_chat') and not msg['from'].get('is_bot', False))

    def run(self):
        backoff = 1
        while not self.stop.is_set():
            try:
                updates = self.api('getUpdates', {'offset': self.offset, 'timeout': 10,
                                                  'limit': 20, 'allowed_updates': ['message']})
                for update in updates:
                    msg = update.get('message', {})
                    if self.authorised(msg) and 0 <= time.time() - msg.get('date', 0) <= 300:
                        if not put(self.incoming, update):
                            break
                    self.offset = update['update_id'] + 1
                if self.health != 'ok':
                    LOG.warning('Telegram polling available')
                self.health = 'ok'
                backoff = 1
            except Exception:
                if self.health != 'unavailable':
                    LOG.warning('Telegram polling unavailable; monitoring continues')
                self.health = 'unavailable'
                self.stop.wait(backoff)
                backoff = min(60, backoff * 2)

    def receipt(self, job, outcome):
        # Backpressure rather than losing delivery acknowledgements.
        while not self.stop.is_set():
            try:
                self.receipts.put((job['key'], job['id'], job['chat'], outcome), timeout=.5)
                return
            except queue.Full:
                pass

    def send_step(self, now):
        for _ in range(100):
            try:
                job = self.outgoing.get_nowait()
            except queue.Empty:
                break
            if len(self.pending) >= 100:
                routine = next((j for j in self.pending if j['priority'] > job['priority']), None)
                if routine:
                    self.pending.remove(routine)
                    self.receipt(routine, 'deferred')
                else:
                    self.receipt(job, 'deferred')
                    continue
            self.pending.append(dict(job, next=0, attempts=0))
        eligible = [j for j in self.pending if j['next'] <= now and
                    self.chat_next.get(j['chat'], 0) <= now]
        if not eligible or now < self.global_next:
            return
        job = min(eligible, key=lambda j: (j['priority'], j['created']))
        outcome = None
        record = getattr(self, 'incidents', {}).get(job.get('key', '').removeprefix('incident:')) if job.get('key', '').startswith('incident:') else None
        if record:
            job.update(text=incidents.render(record), incident_state=record['state'])
        if job.get('key', '').startswith('incident:') and hasattr(self, 'incidents') and (not record or record['state'] in ('acknowledged', 'approved', 'resolved')):
            outcome = 'muted'
        elif job['anomaly'] and (now < self.mute_until or (now < self.maintenance_until and job['key'].startswith(('process:', 'gunbot:')))):
            outcome = 'muted'
        elif not job['anomaly'] and now - job['created'] > 300:
            outcome = 'expired'
        else:
            if not self.whois.prepare(job, now):
                return
            try:
                self.api('sendMessage', {'chat_id': job['chat'], 'text': telegram_report(getattr(self, 'server_name', 'Sentinel'), job),
                                         'link_preview_options': {'is_disabled': True}})
                outcome = 'delivered'
                self.delivery_health = 'ok'
                self.chat_next[job['chat']] = now + (3.1 if job['chat'] < 0 else 1.1)
            except Exception as error:
                code = error.code if isinstance(error, APIError) else 0
                job['attempts'] += 1
                if code in (400, 403):
                    outcome = 'permanent_failure'
                else:
                    delay = error.retry_after if code == 429 else min(60, 2 ** min(job['attempts'], 6))
                    job['next'] = now + max(1, delay)
                    if code == 429:
                        self.global_next = job['next']
                if self.delivery_health != 'degraded':
                    LOG.warning('Telegram delivery degraded (HTTP category %s); polling remains independent', code)
                self.delivery_health = 'degraded'
        if outcome:
            self.pending.remove(job)
            self.receipt(job, outcome)

    def send_loop(self):
        while not self.stop.is_set():
            self.send_step(time.time())
            self.stop.wait(.2)


class Streams:
    """Bounded, nonblocking native JSON streams. Restart failed collectors with backoff."""
    COMMANDS = {'dns': ['/usr/bin/resolvectl', '--json=short', 'monitor'],
                'ssh': ['/usr/bin/journalctl', '--no-pager', '-o', 'json', '-f',
                        '--since', '24 hours ago', '_COMM=sshd'],
                'kernel': ['/usr/bin/journalctl', '--no-pager', '-o', 'json', '-k', '-f', '--since', 'now']}

    def __init__(self, commands=None):
        self.commands = self.COMMANDS if commands is None else commands
        self.selector = selectors.DefaultSelector()
        self.running, self.retry, self.health = {}, {}, {}
        self.ssh_generation = 0

    def maintain(self, now):
        for name, args in self.commands.items():
            if name in self.running:
                if self.running[name][0].poll() is None:
                    continue
                self.close_one(name)
                self.health[name] = 'unavailable (retrying)'
                self.retry[name] = now + 60
            if now < self.retry.get(name, 0):
                continue
            try:
                p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                                     env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C',
                                          'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'})
                os.set_blocking(p.stdout.fileno(), False)
                self.running[name] = [p, bytearray()]
                self.selector.register(p.stdout, selectors.EVENT_READ, name)
                self.health[name] = 'running (coverage limited)'
                if name == 'ssh':
                    self.ssh_generation += 1
            except OSError:
                self.health[name] = 'unavailable (retrying)'
                self.retry[name] = now + 60

    def read(self):
        results = []
        for key, _ in self.selector.select(timeout=.2):
            name = key.data
            p, buf = self.running[name]
            chunk = os.read(p.stdout.fileno(), 65536)
            if not chunk:
                self.close_one(name)
                self.retry[name] = time.time() + 60
                self.health[name] = 'unavailable (retrying)'
                continue
            buf.extend(chunk)
            if len(buf) > 1024 * 1024:
                self.close_one(name)
                self.retry[name] = time.time() + 60
                self.health[name] = 'oversize stream record; retrying'
                continue
            while b'\n' in buf:
                line, _, rest = buf.partition(b'\n')
                buf[:] = rest
                try:
                    value = json.loads(line)
                    if isinstance(value, dict):
                        results.append((name, value))
                except (ValueError, UnicodeError):
                    self.health[name] = 'invalid collector output'
        return results

    def close_one(self, name):
        p, _ = self.running.pop(name)
        self.selector.unregister(p.stdout)
        p.stdout.close()
        if p.poll() is None:
            p.terminate()  # Only Sentinel's own child collectors.
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

    def close(self):
        for name in list(self.running):
            self.close_one(name)
        self.selector.close()


def instance_roots(processes):
    """Count matching parent/child chains once, retaining every process for monitoring."""
    by_pid = {p['pid']: identity for identity, p in processes.items()}
    roots = set()
    for identity in processes:
        current, visited = identity, set()
        while current not in visited:
            visited.add(current)
            parent = by_pid.get(processes[current].get('ppid'))
            if parent is None:
                roots.add(current)
                break
            current = parent
        else:
            # A racing/inconsistent snapshot must remain bounded and deterministic.
            roots.add(min(visited))
    return roots


def proc_snapshot(process_name, previous, elapsed):
    uptime = float(Path('/proc/uptime').read_text().split()[0])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    hz, page = os.sysconf('SC_CLK_TCK'), os.sysconf('SC_PAGE_SIZE')
    procs, inodes = {}, {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            if (path / 'comm').read_text().strip() != process_name:
                continue
            fields = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] == 'Z':
                continue
            ticks = int(fields[11]) + int(fields[12])
            start = int(fields[19])
            identity = f'{boot}:{path.name}:{start}'
            old = previous.get(identity)
            procs[identity] = {'pid': int(path.name), 'ppid': int(fields[1]), 'ticks': ticks,
                              'cpu': max(0, (ticks - old['ticks']) / hz / elapsed * 100) if old else None,
                              'runtime': max(0, uptime - start / hz),
                              'memory': int(fields[21]) * page / 1048576, 'listen': []}
            for fd in (path / 'fd').iterdir():
                try:
                    link = os.readlink(fd)
                    if link.startswith('socket:['):
                        inodes[link[8:-1]] = identity
                        if len(inodes) > 65536:
                            raise ValueError('Socket inspection limit exceeded')
                except FileNotFoundError:
                    pass
        except (FileNotFoundError, ProcessLookupError):
            continue
        # Permission failures propagate: an unreadable process must not look dead.
    if len(procs) > 256:
        raise ValueError('Too many monitored processes')
    rows, listeners = [], set()
    for table in ['tcp', 'tcp6', 'udp', 'udp6']:
        path = Path('/proc/net') / table
        if not path.exists():
            continue
        with path.open() as f:
            next(f)
            for line in f:
                parts = line.split()
                identity = inodes.get(parts[9])
                if not identity:
                    continue
                local = int(parts[1].split(':')[1], 16)
                if parts[3] == '0A':
                    listeners.add((identity, local))
                    procs[identity]['listen'].append(local)
                elif parts[3] in ('01', '02'):
                    address, port = parts[2].split(':')
                    raw = bytes.fromhex(address)
                    raw = b''.join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
                    ip = str(ipaddress.ip_address(raw))
                    if not ipaddress.ip_address(ip).is_unspecified:
                        rows.append((identity, local, ip, int(port, 16), table))
                        if len(rows) > LIMIT:
                            raise ValueError('Connection inspection limit exceeded')
    connections = [{'pid': procs[i]['pid'], 'ip': ip, 'port': port, 'protocol': proto}
                   for i, local, ip, port, proto in rows if (i, local) not in listeners]
    return procs, connections[:LIMIT]


def resources(previous):
    mem = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        mem[key] = int(value.split()[0])
    ticks = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
    total, idle = sum(ticks), ticks[3] + ticks[4]
    cpu = None
    if previous and total > previous[0]:
        cpu = 100 * (1 - (idle - previous[1]) / (total - previous[0]))
    disk = shutil.disk_usage('/')
    return {'cpu': cpu, 'memory': 100 * (1 - mem['MemAvailable'] / mem['MemTotal']),
            'disk': 100 * disk.used / disk.total, 'load': os.getloadavg()[0],
            'uptime': float(Path('/proc/uptime').read_text().split()[0])}, (total, idle)


class Sentinel:
    def __init__(self, cfg, path, outgoing, chats):
        self.cfg, self.path, self.outgoing, self.chats = cfg, path, outgoing, chats
        self.s = cfg['runtime']
        self.dirty = False
        self.correlations = collections.OrderedDict()
        self.ssh = {}  # Minute buckets; no raw authentication log persistence.
        self.cursors = collections.OrderedDict()
        self.procs, self.connections, self.metrics = {}, [], {}
        self.cpu_ticks = None
        self.checked, self.last_sample = 0, time.monotonic()
        self.health = {}
        self.ufw = 'unknown'
        self.next_ufw = 0
        self.dropped = 0
        self.inflight = set()
        self.rate = {0: collections.deque(), 1: collections.deque()}
        self.observation = None
        self.host = {}
        self.baseline_reviews = {}
        self.filesystems = {}
        self.last_dns = 0
        self.started = time.time()

    def event(self, key, text, now=None, once=False):
        now = time.time() if now is None else now
        e = self.s['events'].get(key)
        if e is None:
            if len(self.s['events']) >= LIMIT:
                oldest = min(self.s['events'], key=lambda k: self.s['events'][k]['last'])
                del self.s['events'][oldest]
            e = self.s['events'][key] = {'first': now, 'last': now, 'count': 0, 'notified': 0, 'settled': 0}
        e['last'], e['count'] = now, min(e['count'] + 1, 10**12)
        self.dirty = True
        if key in self.s['pending'] or (e['settled'] and (once or now - e['settled'] < self.cfg['alert_cooldown_minutes'] * 60)):
            return
        message = text if key.startswith('incident:') else f"{self.cfg['server_name']} - {text}\nFirst seen: {stamp(e['first'])}\nCount: {e['count']}"
        self.s['recent'] = (self.s['recent'] + [f'{stamp(now)} {message[:800]}'])[-100:]
        if now < self.s['mute_until'] or (now < self.s['maintenance_until'] and key.startswith(('process:', 'gunbot:'))):
            # Intentional mute is distinct from a failed delivery; do not replay muted events.
            e['settled'] = now
            return
        priority = 1 if key.startswith(('dns:', 'ip:')) else 0
        pending = self.s['pending']
        routine = [k for k, v in pending.items() if v['priority'] == 1]
        if len(pending) >= MAX_PENDING or (priority == 1 and len(routine) >= 100):
            if priority == 0 and routine:
                del pending[routine[0]]
            else:
                self.s['delivery_gaps'] += 1
                self.dropped += 1
                return
            self.s['delivery_gaps'] += 1
        pending[key] = {'id': uuid.uuid4().hex, 'text': message[:1200], 'created': now,
                        'priority': priority, 'remaining': sorted(self.chats)}

    def dispatch(self, now=None):
        now = time.time() if now is None else now
        for key, item in sorted(self.s['pending'].items(), key=lambda kv: (kv[1]['priority'], kv[1]['created'])):
            rate = self.rate[item['priority']]
            while rate and now - rate[0] >= 60:
                rate.popleft()
            for chat in list(item['remaining']):
                if chat not in self.chats:
                    item['remaining'].remove(chat)
                    self.s['delivery_gaps'] += 1
                    self.dirty = True
                    continue
                identity = (key, item['id'], chat)
                if identity in self.inflight or len(rate) >= 5:
                    continue
                job = dict(item, key=key, chat=chat, anomaly=True)
                if key.startswith('incident:'):
                    record = self.s['incidents'].get(key.split(':', 1)[1])
                    if record:
                        job.update(text=incidents.render(record), incident_state=record['state'])
                if put(self.outgoing, job):
                    rate.append(now)
                    self.inflight.add(identity)
                    LOG.warning('Alert queued: %s', item['text'].replace('\n', ' | '))
            if not item['remaining']:
                if key in self.s['events']:
                    self.s['events'][key]['settled'] = now
                del self.s['pending'][key]
                self.dirty = True

    def delivered(self, receipt, now=None):
        key, identity, chat, outcome = receipt
        self.inflight.discard((key, identity, chat))
        item = self.s['pending'].get(key)
        if not item or item['id'] != identity or chat not in item['remaining']:
            return
        item['remaining'].remove(chat)
        e = self.s['events'].get(key)
        if outcome == 'deferred':
            item['remaining'].append(chat)
            return
        if e and outcome == 'delivered':
            e['notified'] = time.time() if now is None else now
        if outcome not in ('delivered', 'muted'):
            self.s['delivery_gaps'] += 1
            LOG.warning('Alert delivery failed: chat=%s outcome=%s', chat, outcome)
        if not item['remaining']:
            e = self.s['events'].get(key)
            if e:
                e['settled'] = time.time() if now is None else now
            del self.s['pending'][key]
        if outcome == 'permanent_failure' and not key.startswith('delivery:') and self.chats - {chat}:
            self.event('delivery:' + str(chat), f'Telegram destination {chat} rejected an alert; check bot access.', once=True)
            warning = self.s['pending'].get('delivery:' + str(chat))
            if warning:
                warning['remaining'] = sorted(self.chats - {chat})
        self.dirty = True

    def dns(self, item):
        now = time.time()
        self.last_dns = now
        questions = []
        # resolved moves the original lookup into collectedQuestions when following CNAMEs.
        # Observe the original name, not every CDN alias visited internally.
        collected = item.get('collectedQuestions') or []
        queries = collected[:1] if collected else item.get('question', [])
        for question in queries[:100]:
            try:
                name = domain(question['name'])
            except (ValueError, KeyError, TypeError):
                continue
            if name not in questions:
                questions.append(name)
                if not known(name, self.cfg):
                    self.event('dns:' + name, '⚠️ NETWORK\nNew/unknown domain observed: ' + name, now)
        # Correlation is a short-lived hint, never an IP allowlist or attribution proof.
        for answer in item.get('answer', [])[:100]:
            try:
                rr = answer['rr']
                address = rr['address']
                if not isinstance(address, list) or len(address) not in (4, 16) or not all(
                        type(x) is int and 0 <= x <= 255 for x in address):
                    continue
                ip = str(ipaddress.ip_address(bytes(address)))
                if questions:
                    self.correlations[ip] = (now + 60, questions[:8])
                    self.correlations.move_to_end(ip)
            except (KeyError, ValueError, TypeError):
                continue
        while len(self.correlations) > LIMIT:
            self.correlations.popitem(last=False)

    def ssh_event(self, item):
        cursor = item.get('__CURSOR')
        if not isinstance(cursor, str) or len(cursor) > 512 or cursor in self.cursors:
            return
        self.cursors[cursor] = True
        while len(self.cursors) > 10000:
            self.cursors.popitem(last=False)
        try:
            when = int(item['__REALTIME_TIMESTAMP']) / 1000000
        except (ValueError, KeyError, TypeError):
            return
        if not time.time() - 86400 <= when <= time.time() + 60:
            return
        message = item.get('MESSAGE', '')
        if not isinstance(message, str):
            return
        accepted = re.search(r'Accepted \S+ for (\S+) from ([0-9a-fA-F:.]+) port ', message)
        failed = re.search(r'Failed \S+ for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+) port ', message)
        if not accepted and not failed:
            return
        bucket = self.ssh.setdefault(int(when // 60), [0, 0])
        bucket[0 if accepted else 1] += 1
        if accepted and time.time() - when < 120:
            try:
                ip = ipaddress.ip_address(accepted[2])
            except ValueError:
                return
            if not any(ip in ipaddress.ip_network(x) for x in self.cfg['known_management_ips']):
                user = re.sub(r'[^a-zA-Z0-9_.-]', '?', accepted[1])[:64]
                self.event('ssh:' + str(ip), f'⚠️ SSH\nSuccessful login from unrecognised IP\nUser: {user}\nSource: {ip}')

    def check(self):
        now, mono = time.time(), time.monotonic()
        if self.s['maintenance_until'] and now >= self.s['maintenance_until']:
            self.end_maintenance()
        try:
            if self.observation is None:
                current, connections = proc_snapshot(self.cfg['gunbot_process'], self.procs, max(1, mono - self.last_sample))
            else:
                if now - self.observation.get('at', 0) > 45 or 'error' in self.observation:
                    raise OSError('Collector stale/unavailable')
                current, connections = self.observation['processes'], self.observation['connections']
            tracked = self.s['processes']
            if self.s['tracking_started'] and now >= self.s['maintenance_until']:
                self.s['process_starts'].extend(now for identity in current if identity not in tracked)
            self.s['tracking_started'] = True
            self.s['process_starts'] = [x for x in self.s['process_starts'] if now - x < 600][-256:]
            if len(self.s['process_starts']) >= self.cfg['thresholds']['restart_starts_10m']:
                self.event('gunbot:restart-storm', f"Repeated Gunbot starts: {len(self.s['process_starts'])} new process identities in 10 minutes")
            expected = self.cfg['expected_gunbot_instances']
            instance_count = len(instance_roots(current))
            mismatch = instance_count != expected
            if mismatch:
                self.event('gunbot:count', f'Gunbot instance count differs: expected {expected}, observed {instance_count}')
            elif self.s['count_mismatch']:
                self.event('gunbot:count-recovered:' + str(int(now)), f'Gunbot expected count restored: {expected}', once=True)
            self.s['count_mismatch'] = mismatch
            for identity in list(tracked):
                old = tracked[identity]
                if identity not in current:
                    old['misses'] += 1
                    if old['misses'] == 2:
                        self.event('process:' + identity, f"🔴 GUNBOT\nProcess disappeared: PID {old['pid']}\nLast seen: {stamp(old['last'])}", once=True)
                    if now - old['last'] > 86400:
                        del tracked[identity]
            live_before = any(x['misses'] < 2 for x in tracked.values())
            if not current and not live_before and not self.s['down']:
                self.event('gunbot:down:' + str(int(now)), '🔴 GUNBOT\nAll Gunbot processes absent (or none found at startup)', once=True)
                self.s['down'] = True
            if current and (self.s['down'] or any(x['misses'] >= 2 for x in tracked.values()) and any(i not in tracked or tracked[i]['misses'] >= 2 for i in current)):
                self.event('gunbot:recovered:' + str(int(now)), '🟢 GUNBOT\nGunbot recovered; process(es) observed', once=True)
                self.s['down'] = False
                tracked = {k: v for k, v in tracked.items() if v['misses'] < 2}
            for identity, p in current.items():
                tracked[identity] = {'pid': p['pid'], 'last': now, 'misses': 0}
            self.s['processes'] = dict(sorted(tracked.items(), key=lambda kv: kv[1]['last'])[-256:])
            self.procs, self.connections = current, connections
            self.last_sample = mono
            self.health['processes'] = 'ok'
            for c in connections:
                if ipaddress.ip_address(c['ip']).is_loopback:
                    continue
                match = self.correlations.get(c['ip'])
                names = match[1] if match and match[0] > now else []
                c['dns'] = names
                c['classification'] = ('recent known DNS (shared-IP hint)' if names and all(known(n, self.cfg) for n in names)
                                       else 'unknown/unattributed')
                if c['classification'] == 'unknown/unattributed':
                    self.event('ip:' + c['ip'], f"⚠️ NETWORK\nNew outbound destination observed: {c['ip']}:{c['port']}\nPID: {c['pid']}\nNo known DNS correlation; CDN churn or missed DNS is possible. Direct-IP use is not proven.", now, once=True)
        except (OSError, ValueError, IndexError):
            self.health['processes'] = 'unavailable'
            self.event('collector:processes', '⚠️ Sentinel process/network inspection unavailable')
        try:
            self.metrics, self.cpu_ticks = resources(self.cpu_ticks)
            self.health['resources'] = 'ok'
            for metric, setting in [('disk', 'disk_percent'), ('memory', 'memory_percent'), ('load', 'load_per_cpu')]:
                limit = self.cfg['thresholds'][setting] * ((os.cpu_count() or 1) if metric == 'load' else 1)
                if self.metrics[metric] >= limit:
                    self.event('health:' + metric, f'⚠️ HEALTH\n{metric}: {self.metrics[metric]:.1f}, threshold: {limit:.1f}')
        except (OSError, ValueError, KeyError):
            self.health['resources'] = 'unavailable'
            self.event('collector:resources', '⚠️ Sentinel resource inspection unavailable')
        self.filesystems = checks.filesystem_usage(self.cfg['monitored_paths'])
        for path, usage in self.filesystems.items():
            if 'error' in usage:
                self.event('filesystem:' + checks.digest(path), 'Filesystem inspection unavailable: ' + path)
                continue
            for metric, threshold in [('disk', 'disk_percent'), ('inodes', 'inode_percent')]:
                if usage[metric] is not None and usage[metric] >= self.cfg['thresholds'][threshold]:
                    self.event('filesystem:' + metric + ':' + checks.digest(path), f'{path}: {metric} usage {usage[metric]:.1f}%')
        self.ssh = {k: v for k, v in self.ssh.items() if k >= int((now - 86400) // 60)}
        failures = sum(v[1] for k, v in self.ssh.items() if k >= int((now - 600) // 60))
        if failures >= self.cfg['thresholds']['ssh_failures_10m']:
            self.event('ssh:failures', f'⚠️ SSH\nHigh failed login activity: {failures} in approximately 10 minutes')
        if self.observation is not None:
            self.ufw = self.observation.get('ufw', 'unavailable')
        self.s['events'] = {k: v for k, v in self.s['events'].items()
                            if v['last'] >= now - self.cfg['retention_days'] * 86400}
        self.correlations = collections.OrderedDict((k, v) for k, v in self.correlations.items() if v[0] > now)
        self.checked, self.dirty = now, True

    def end_maintenance(self):
        self.s['maintenance_until'] = 0
        self.s['down'] = False
        for key, event in self.s['events'].items():
            if key.startswith(('process:', 'gunbot:')):
                event['settled'] = 0
        for process in self.s['processes'].values():
            if process['misses'] >= 2:
                process['misses'] = 1
        self.dirty = True

    def observe_host(self, host):
        host = baselines.apply(self, host)
        self.host = host
        now = time.time()
        self.health.update(host.get('health', {}))
        for name, status in host.get('health', {}).items():
            if status == 'unavailable':
                self.event('collector:' + name, 'Host check unavailable: ' + name)
        baseline = host.get('baseline', {})
        if baseline.get('status') == 'not approved':
            self.event('baseline:missing', 'Security baseline needs administrator review; use /baseline review.')
        incidents.observe(self, now)
        for identity, item in host.get('tools', {}).items():
            if identity not in self.s['seen_tools']:
                self.event('tool:' + checks.digest(identity),
                           f"TOOL observed: {item['tool']}\nPID: {item['pid']}; UID: {item['uid']}\nSampled process presence, not proof of an install/download.", once=True)
            self.s['seen_tools'][identity] = now
        self.s['seen_tools'] = dict(sorted(((k, v) for k, v in self.s['seen_tools'].items() if now - v < 86400),
                                           key=lambda kv: kv[1])[-512:])
        packages = host.get('packages', [])
        if packages:
            self.event('packages:' + checks.digest(packages), 'PACKAGE actions recorded by dpkg:\n' +
                       '\n'.join(x['action'] + ' ' + x['package'] for x in packages[:12]) +
                       (f'\n{len(packages)} records in this batch.' if len(packages) > 12 else ''), once=True)
        inventory = host.get('package_inventory', {})
        if 'sha256' in inventory:
            current = checks.digest(inventory)
            if self.s['package_digest'] and self.s['package_digest'] != current:
                self.event('package-inventory:' + current, 'PACKAGE inventory changed (dpkg database fingerprint).', once=True)
            self.s['package_digest'] = current
        if host.get('reboot_required') is True:
            self.event('health:reboot-required', 'Ubuntu reports a server reboot is required. Schedule it manually; Sentinel will not reboot.')
        if host.get('clock_sync') == 'no':
            self.event('health:clock', 'System clock is not reported synchronized. Check time synchronization.')
        elif host.get('clock_sync') == 'unknown':
            self.event('collector:clock', 'Clock synchronization status is unavailable.')
        self.dirty = True

    def selftest(self):
        # Probe the actual state directory without changing the configuration or sending a second message.
        path = None
        writable = False
        try:
            fd, name = tempfile.mkstemp(prefix='.sentinel-selftest-', dir=self.path.parent)
            path = Path(name)
            marker = uuid.uuid4().hex.encode()
            with os.fdopen(fd, 'wb') as file:
                file.write(marker)
                file.flush()
                os.fsync(file.fileno())
            writable = path.read_bytes() == marker and stat.S_IMODE(path.stat().st_mode) == 0o600
        except OSError:
            pass
        finally:
            if path is not None:
                path.unlink(missing_ok=True)
        age = time.time() - (self.observation or {}).get('at', 0)
        result = [f'State write/read: {"PASS" if writable else "FAIL"}',
                  f'Collector freshness: {"PASS" if 0 <= age < 45 else "FAIL"}' + (f' - {max(0, int(age))}s since sample' if self.observation else ' - no sample'),
                  f'Gunbot instances: {len(instance_roots(self.procs))} / expected {self.cfg["expected_gunbot_instances"]}',
                  f'Matching Gunbot processes: {len(self.procs)}',
                  f'Alerts: {len(self.s["pending"])} pending · {self.s["delivery_gaps"]} recorded delivery gaps',
                  baseline_report('acknowledged drift' if incidents.all_reviewed(self) else self.host.get('baseline', {}).get('status')),
                  reboot_report(self.host.get('reboot_required')),
                  '\nMONITORING', self.monitoring_summary(),
                  f'DNS last observed: {stamp(self.last_dns) if self.last_dns else "none this run"}',
                  '\n/health provides individual checks and filesystem detail.']
        return '\n'.join(result)

    def monitoring_summary(self):
        lines, passing = [], []
        for name, value in sorted(self.health.items()):
            if name in ('dns', 'ssh', 'kernel'):
                lines.append(check_lines({name: value}))
            elif value == 'starting':
                lines.append(f'{name.capitalize()}: initializing' + (' - awaiting first send' if name == 'delivery' else ''))
            elif value.startswith('ok'):
                passing.append(name.replace('_', ' '))
            else:
                lines.append(check_lines({name: value}))
        if passing:
            lines.append('Checks passing: ' + ', '.join(passing) + '.')
        lines.append(clock_report(self.host.get('clock_sync')))
        return '\n'.join(lines) if self.health else 'Monitoring: no check results yet.'

    def filesystem_report(self):
        lines = []
        for path, usage in self.filesystems.items():
            if 'error' in usage:
                lines.append(status_line(path, 'FAIL', 'filesystem unavailable'))
            else:
                inode = f"{usage['inodes']:.1f}%" if usage['inodes'] is not None else 'not supported'
                state = 'ATTENTION' if usage['disk'] >= self.cfg['thresholds']['disk_percent'] or (usage['inodes'] or 0) >= self.cfg['thresholds']['inode_percent'] else 'PASS'
                lines.append(status_line(path, state, f"disk {usage['disk']:.1f}%; inodes {inode}"))
        return '\n'.join(lines) or status_line('Filesystems', 'UNKNOWN', 'not yet sampled')

    def report_actions(self, command, response):
        if command not in ('/status', '/selftest', '/health', '/security', '/baseline'):
            return ''
        actions = []
        if command == '/baseline':
            if response.startswith(('Baseline approved', 'Baseline review')):
                return ''
            baseline = self.host.get('baseline', {}).get('status')
            if baseline == 'drift' and incidents.all_reviewed(self):
                return ''
            return {'not approved': 'Use /baseline review, then /baseline approve DIGEST only if the inventory is expected.',
                    'drift': 'Use /sentinel to investigate or approve individual changes.',
                    'matches approved baseline': ''}.get(baseline, 'Restore baseline inspection; check Sentinel service logs.')
        if 'State write/read: FAIL' in response:
            actions.append('Restore access to Sentinel state storage; inspect ownership and free space.')
        if not self.observation or not 0 <= time.time() - self.observation.get('at', 0) < 45:
            actions.append('Inspect Sentinel service logs: collector samples are missing or stale.')
        if not self.health:
            actions.append('Wait for initial check results; collector readiness is not yet established.')
        failed = [name.replace('_', ' ') for name, value in self.health.items()
                  if not value.startswith(('ok', 'running')) and not (value == 'starting' and time.time() - self.started < 60)]
        if failed:
            actions.append('Investigate checks that are not ready: ' + ', '.join(sorted(failed)) + '.')
        baseline = self.host.get('baseline', {}).get('status')
        if baseline == 'not approved':
            actions.append('Use /baseline review, then /baseline approve DIGEST only if the inventory is expected.')
        elif baseline == 'drift' and not incidents.all_reviewed(self):
            actions.append('Use /sentinel to investigate or approve individual changes.')
        elif baseline not in ('matches approved baseline', 'drift'):
            actions.append('Restore baseline inspection; review /baseline and service logs.')
        if len(instance_roots(self.procs)) != self.cfg['expected_gunbot_instances']:
            actions.append('Verify missing/extra Gunbot process families against the expected instance count.')
        if self.host.get('reboot_required') is True:
            actions.append('Schedule a controlled server reboot manually; Sentinel will not restart it.')
        if self.host.get('clock_sync') != 'yes':
            actions.append('Verify the host time-synchronization service and its reported status.')
        if self.s['delivery_gaps']:
            actions.append('Review recorded delivery gaps with /security; counts include past failures.')
        if self.s['pending']:
            actions.append('Monitor pending notifications; investigate persistent delivery delays.')
        if any('error' in u or u.get('disk', 0) >= self.cfg['thresholds']['disk_percent'] or
               (u.get('inodes') or 0) >= self.cfg['thresholds']['inode_percent'] for u in self.filesystems.values()):
            actions.append('Review configured volumes with /health; restore access or address disk/inode pressure.')
        if self.metrics.get('memory', 0) >= self.cfg['thresholds']['memory_percent'] or self.metrics.get('load', 0) >= self.cfg['thresholds']['load_per_cpu'] * (os.cpu_count() or 1):
            actions.append('Investigate host memory/load pressure shown by /status.')
        return '\n'.join(f'{i}. {action}' for i, action in enumerate(actions, 1))

    def report_attention(self, command, response):
        return bool(self.report_actions(command, response))

    def management(self, args):
        rules = self.cfg['known_management_ips']
        if not args or len(args) == 1 and args[0].isdigit():
            page = int(args[0]) if args else 1
            pages = max(1, (len(rules) + 49) // 50)
            if not 1 <= page <= pages:
                return f'Invalid page. Use /management 1 to {pages}.'
            selected = rules[(page - 1) * 50:page * 50]
            return (f'Trusted SSH sources: {len(rules)} | page {page}/{pages}\n' +
                    ('\n'.join(selected) if selected else 'None configured. Successful SSH sources are treated as unfamiliar.') +
                    '\n\n/management add <IP/CIDR>\n/management remove <IP/CIDR>\nSentinel alert rules only. Firewall rules are unchanged.')
        if len(args) != 2 or args[0] not in ('add', 'remove'):
            return 'Invalid command. Use /management, /management add <IP/CIDR>, or /management remove <IP/CIDR>.'
        try:
            if '%' in args[1]:
                raise ValueError()
            network = str(ipaddress.ip_network(args[1], strict=False))
        except ValueError:
            return 'Invalid IP/CIDR. Enter an IPv4 or IPv6 address or network, without a port.'
        updated = set(rules)
        if args[0] == 'add':
            if network in updated:
                return 'Management IPs updated. Already trusted: ' + network
            if len(updated) >= LIMIT:
                return 'Invalid update: management IP limit reached.'
            updated.add(network)
        else:
            if network not in updated:
                return 'Invalid removal: exact rule not found: ' + network + '. Check /management for covering CIDRs.'
            updated.remove(network)
        self.cfg['known_management_ips'] = sorted(updated)
        self.dirty = True
        return ('Management IPs updated.\n' + ('Trusted SSH source added: ' if args[0] == 'add' else 'Trusted SSH source removed: ') +
                network + '\nEffective immediately. Firewall rules are unchanged.')

    def command(self, text, actor=None, chat=None):
        if not isinstance(text, str) or len(text) > 300:
            return 'Invalid command. ' + HELP
        parts = text.strip().split()
        if not parts:
            return HELP
        cmd = parts[0].split('@')[0]
        args = parts[1:]
        if cmd == '/sentinel':
            return incidents.command(self, args, actor, chat)
        if cmd == '/baseline':
            return baselines.command(self, args, actor, chat)
        if cmd == '/management':
            return self.management(args)
        if cmd in ('/allow', '/remove', '/mute', '/maintenance'):
            if len(args) != 1:
                return 'Exactly one argument required. ' + HELP
        elif args:
            return 'This command takes no arguments.'
        if cmd in ('/allow', '/remove'):
            name = domain(args[0], wildcard=True)
            key = 'known_domain_suffixes' if name.startswith('*.') else 'known_domains'
            name = name.removeprefix('*.')
            if cmd == '/remove' and name == 'api.telegram.org':
                return 'api.telegram.org is always known to prevent notification loops.'
            items = set(self.cfg[key])
            if cmd == '/allow':
                items.add(name)
            else:
                items.discard(name)
            if len(items) > LIMIT:
                return 'Domain rule limit reached.'
            self.cfg[key] = sorted(items)
            self.dirty = True
            LOG.info('Known-domain configuration changed')
            return 'Sentinel domain rules updated.\n' + ('Added: ' if cmd == '/allow' else 'Removed: ') + ('*.' if key == 'known_domain_suffixes' else '') + name
        if cmd == '/mute':
            match = re.fullmatch(r'([1-9][0-9]{0,5})([smhd])', args[0])
            if not match:
                return 'Use /mute 30m, /mute 1h, or /mute 1d (maximum 7 days).'
            seconds = int(match[1]) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[match[2]]
            if not 60 <= seconds <= 604800:
                return 'Mute must be between 1 minute and 7 days.'
            self.s['mute_until'] = time.time() + seconds
            self.dirty = True
            return 'Anomaly notifications muted until ' + stamp(self.s['mute_until'])
        if cmd == '/unmute':
            self.s['mute_until'] = 0
            self.dirty = True
            return 'Anomaly notifications resumed.'
        if cmd == '/maintenance':
            if args[0] == 'off':
                self.end_maintenance()
            else:
                match = re.fullmatch(r'([1-9][0-9]{0,5})([smhd])', args[0])
                seconds = int(match[1]) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[match[2]] if match else 0
                if not 60 <= seconds <= 604800:
                    return 'Maintenance must be 1m to 7d, or off.'
                self.s['maintenance_until'] = time.time() + seconds
                self.s['process_starts'] = []
            self.dirty = True
            return 'Maintenance updated: ' + ('OFF - Gunbot lifecycle alerts resumed.' if args[0] == 'off' else 'ACTIVE until ' + stamp(self.s['maintenance_until']) + '.\nGunbot lifecycle notices suppressed; security monitoring stays active.')
        if cmd == '/selftest':
            return self.selftest()
        if cmd == '/listeners':
            if not self.host.get('health', {}).get('listeners_tools', self.health.get('listeners_tools', '')).startswith('ok'):
                return status_line('Listeners', 'UNKNOWN', 'inspection unavailable or not yet sampled')
            return ('System listeners (not proof of internet reachability):\n' + ('\n'.join(
                f"{x['protocol']} {x['ip']}:{x['port']} PID {x.get('pid', '?')} {' / '.join(x['owners'])}"
                for x in self.host.get('listener_details', [])[:30]) or status_line('Listeners', 'RUNNING', 'no endpoints in this sample')))[:3800]
        if cmd == '/health':
            return (f"Filesystems:\n{self.filesystem_report()}\n{clock_report(self.host.get('clock_sync'))}\n"
                    f"{reboot_report(self.host.get('reboot_required'))}\nCollectors:\n{check_lines(self.health)}")[:3800]
        if cmd == '/updates':
            return (f"{reboot_report(self.host.get('reboot_required'))}\n"
                    + '\n'.join(x for x in reversed(self.s['recent']) if any(t in x for t in ('PACKAGE', 'TOOL')))
                    + '\nTool detection is sampled; no URL or full command line is captured.')[:3800]
        if cmd == '/known':
            return '\n'.join(['Always known: api.telegram.org'] + [name for name in self.cfg['known_domains'] if name != 'api.telegram.org'] +
                             ['*.' + x for x in self.cfg['known_domain_suffixes']])[:3800]
        if cmd == '/recent':
            observations = sorted(self.s['events'].items(), key=lambda kv: kv[1]['last'], reverse=True)[:5]
            summary = '\n'.join(f"{key}: count {e['count']}, first {stamp(e['first'])}, last {stamp(e['last'])}" for key, e in observations)
            return '\n\n'.join(reversed(self.s['recent'][-5:]))[:3800].strip() or 'No recorded anomalies.'
        if cmd == '/network':
            if self.health.get('processes') != 'ok':
                return status_line('Gunbot connections', 'UNKNOWN', 'process inspection unavailable or not yet sampled')
            lines = [f"{'🔵' if c.get('classification', '').startswith('recent known DNS') else '⚪'} {c['ip']}:{c['port']} {c['protocol']} PID {c['pid']} - {c.get('classification', 'unknown')} {' / '.join(c.get('dns', []))}"
                     for c in sorted(self.connections, key=lambda c: c.get('classification', '').startswith('recent known DNS'))[:25]]
            return ('Current sampled Gunbot connections (up to 25):\n' + ('\n'.join(lines) or 'None') +
                    '\nDNS correlation is a hint, not proof. /recent shows past observations.')[:3800]
        if cmd == '/processes':
            if self.health.get('processes') != 'ok':
                return status_line('Gunbot processes', 'UNKNOWN', 'inspection unavailable or not yet sampled')
            return ('\n'.join(f"PID {p['pid']} | {p['runtime']/3600:.1f}h | CPU {str(round(p['cpu'], 1)) + '%' if p['cpu'] is not None else 'sampling'} | RSS {p['memory']:.1f} MiB | listen {', '.join(str(port) for port in p['listen']) or 'none'}"
                              for p in list(self.procs.values())[:25]) or 'No Gunbot processes observed.')[:3800]
        if cmd == '/security':
            counts = [sum(v[i] for v in self.ssh.values()) for i in range(2)]
            unknown = sum(k.startswith('dns:') and not known(k[4:], self.cfg) for k in self.s['events'])
            ips = sum(k.startswith('ip:') for k in self.s['events'])
            return (f"UFW: {self.ufw}\nSSH last ~24h (available journal): {counts[0]} successful, {counts[1]} failed\n"
                    f"Retained unknown domains: {unknown}\nRetained unattributed IPs: {ips} (direct-IP use unproven)\n"
                    f"Collectors:\n{check_lines(self.health)}\nPending alerts: {len(self.s['pending'])}; delivery gaps: {self.s['delivery_gaps']}\n"
                    'DNS coverage: systemd-resolved only. SSH counts require retained journal; partial during replay.')
        if cmd == '/status':
            m = self.metrics
            pct = lambda name: f'{m[name]:.1f}%' if m.get(name) is not None else 'unknown'
            return (f"Gunbot: {len(instance_roots(self.procs))}/{self.cfg['expected_gunbot_instances']} instances · {len(self.procs)} processes\n"
                    f"CPU: {pct('cpu')} · RAM: {pct('memory')} · root disk: {pct('disk')}\n"
                    f"Load: {m.get('load', 'unknown')} · uptime: {m.get('uptime', 0)/86400:.1f}d\n"
                    f"Alerts: {len(self.s['pending'])} pending · {self.s['delivery_gaps']} recorded gaps\n"
                    f"Notifications: {'MUTED' if time.time() < self.s['mute_until'] else 'ENABLED'} · maintenance: {'ACTIVE' if time.time() < self.s['maintenance_until'] else 'OFF'}\n"
                    f"Last check: {stamp(self.checked) if self.checked else 'not yet sampled'}\n\n"
                    f"{baseline_report('acknowledged drift' if incidents.all_reviewed(self) else self.host.get('baseline', {}).get('status'))}\n"
                    f"{reboot_report(self.host.get('reboot_required'))}\n\nMONITORING\n{self.monitoring_summary()}")
        return HELP


def setup(config_path, env_path):
    """Interactive first install; no token in argv, shell history, or output."""
    if config_path.exists() or env_path.exists() or config_path.is_symlink() or env_path.is_symlink():
        raise ValueError('Setup refuses to overwrite existing configuration')
    cfg = validate({})
    cfg['known_domains'] = ['api.telegram.org']
    cfg['known_domain_suffixes'] = []
    print('Sentinel setup - enter your dedicated Telegram bot details.')
    print('For a private chat, chat ID and your user ID are normally identical.')
    print('Server label identifies this host in alerts; press Enter to use its hostname.')
    while True:
        candidate = input(f"Server label [{cfg['server_name']}]: ").strip() or cfg['server_name']
        try:
            validate(dict(cfg, server_name=candidate))
            cfg['server_name'] = candidate
            break
        except ValueError:
            print('Use 1-64 letters, digits, spaces, dots, underscores or hyphens.')
    while True:
        token = getpass.getpass('Telegram bot token (hidden): ').strip()
        if re.fullmatch(r'\d+:[A-Za-z0-9_-]{20,}', token):
            break
        print('Invalid token format; copy the complete BotFather token.')
    values = {'TELEGRAM_BOT_TOKEN': token}
    for key, prompt in [('TELEGRAM_CHAT_IDS', 'Allowed chat IDs (comma-separated): '),
                        ('TELEGRAM_USER_IDS', 'Allowed user IDs (comma-separated): ')]:
        while True:
            default = values.get('TELEGRAM_CHAT_IDS', '') if key == 'TELEGRAM_USER_IDS' else ''
            default = default if re.fullmatch(r'[1-9][0-9]*', default) else ''
            raw = input(prompt + (f'[{default}] ' if default else '')).strip() or default
            # Reuse the runtime validator without retaining secrets in os.environ.
            old = os.environ.get(key)
            try:
                os.environ[key] = raw
                ids = Telegram.ids(key)
                values[key] = ','.join(str(x) for x in sorted(ids))
                break
            except ValueError:
                print('Enter 1-10 nonzero numeric IDs; user IDs must be positive.')
            finally:
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old
    while True:
        raw = input('Known management IPs/CIDRs (comma-separated, blank for none): ').strip()
        try:
            cfg['known_management_ips'] = [str(ipaddress.ip_network(x.strip(), strict=False))
                                           for x in raw.split(',')] if raw else []
            validate(cfg)
            break
        except ValueError:
            print('Enter valid IPv4/IPv6 addresses or CIDRs.')
    # Complete validation before creating either file. Roll back an incomplete pair.
    created = False
    try:
        with open(env_path, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as output:
            created = True
            output.write(''.join(f'{key}={value}\n' for key, value in values.items()))
            output.flush()
            os.fsync(output.fileno())
        save(config_path, cfg)
    except Exception:
        if created:
            env_path.unlink(missing_ok=True)
        raise
    print('Configuration saved with private permissions. Default monitoring thresholds applied.')


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        if address.startswith('@'):
            address = '\0' + address[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode(), address)


def drop_privileges():
    account = pwd.getpwnam('sentinel-watchdog')
    if account.pw_uid == 0:
        raise ValueError('Invalid service account')
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if os.geteuid() == 0:
        raise ValueError('Privilege drop failed')


def ufw_configuration():
    try:
        enabled = re.search(r'^ENABLED=(yes|no)$', Path('/etc/ufw/ufw.conf').read_text(), re.M)
        policy = re.search(r'^DEFAULT_INPUT_POLICY="?([A-Z]+)"?$', Path('/etc/default/ufw').read_text(), re.M)
        return (f"Configured enabled: {enabled[1] if enabled else 'unknown'}; "
                f"inbound default: {policy[1] if policy else 'unknown'}; live kernel status unverified")
    except OSError:
        return 'configuration unavailable; live kernel status unverified'


def collect(process_name):
    """Fixed-function root collector: no secrets, no incoming IPC or Telegram code paths."""
    if sys.platform != 'linux' or os.geteuid() != 0 or not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', process_name):
        raise ValueError('Invalid collector invocation')
    streams = Streams()
    previous, sampled, next_sample = {}, time.monotonic(), 0
    last_generation = 0
    host = checks.HostChecks()
    def emit(kind, data):
        print(json.dumps({'kind': kind, 'data': data}, separators=(',', ':')), flush=True)
    try:
        while True:
            streams.maintain(time.time())
            if streams.ssh_generation != last_generation:
                emit('ssh_reset', streams.ssh_generation)
                last_generation = streams.ssh_generation
            for name, item in streams.read():
                if name == 'kernel':
                    message = item.get('MESSAGE', '')
                    if isinstance(message, str) and re.search(r'oom-kill:|Out of memory:|Killed process \d+', message):
                        pid = re.search(r'(?:Killed process |pid=)(\d+)', message)
                        emit('oom', {'id': item.get('__CURSOR', ''), 'pid': int(pid[1]) if pid else None})
                else:
                    emit(name, item)
            if time.monotonic() >= next_sample:
                now = time.monotonic()
                value = {'at': time.time(), 'ufw': ufw_configuration(),
                         'health': streams.health, 'ssh_generation': streams.ssh_generation}
                try:
                    previous, connections = proc_snapshot(process_name, previous, max(1, now - sampled))
                    value.update(processes=previous, connections=connections)
                except (OSError, ValueError, IndexError):
                    value['error'] = 'Process inspection unavailable'
                value['host'] = host.sample()
                emit('snapshot', value)
                sampled, next_sample = now, now + 10
    except BrokenPipeError:
        pass
    finally:
        streams.close()


def audit_action(app, message, update_id):
    text = message.get('text', '')
    cmd = text.split()[0].split('@')[0] if isinstance(text, str) and text.split() else ''
    management_change = cmd == '/management' and len(text.split()) > 1 and text.split()[1] in ('add', 'remove')
    incident_change = cmd == '/sentinel' and len(text.split()) > 1 and text.split()[1] in ('acknowledge', 'approve')
    baseline_change = cmd == '/baseline' and len(text.split()) > 1 and text.split()[1] == 'approve'
    mutation = incident_change or baseline_change or cmd in ('/allow', '/remove', '/mute', '/unmute', '/maintenance') or management_change
    before = {'incidents': json.dumps(app.s['incidents'], sort_keys=True), 'approved_baseline': app.s['approved_baseline'], 'known_management_ips': list(app.cfg['known_management_ips']), 'known_domains': list(app.cfg['known_domains']),
              'known_domain_suffixes': list(app.cfg['known_domain_suffixes']), 'mute_until': app.s['mute_until'], 'maintenance_until': app.s['maintenance_until']}
    try:
        response = app.command(text, actor=message['from']['id'], chat=message['chat']['id'])
    except ValueError:
        response = 'Invalid input. ' + HELP
    app.s['offset'] = update_id + 1
    try:
        save(app.path, app.cfg)
    except Exception:
        if mutation:
            LOG.error('AUDIT actor=%s chat=%s update=%s action=%s outcome=persistence_failed',
                      message['from']['id'], message['chat']['id'], update_id, cmd)
        raise
    app.dirty = False
    if mutation:
        target = None
        if cmd in ('/allow', '/remove') and len(text.split()) == 2:
            try:
                target = domain(text.split()[1], wildcard=True)
            except ValueError:
                pass
        if incident_change and len(text.split()) == 3 and re.fullmatch(r'[A-Fa-f0-9]{8}', text.split()[2]):
            target = text.split()[2].upper()
        if baseline_change and len(text.split()) == 3 and re.fullmatch(r'[a-f0-9]{64}', text.split()[2]):
            target = text.split()[2]
        if management_change and len(text.split()) == 3:
            try:
                target = str(ipaddress.ip_network(text.split()[2], strict=False))
            except ValueError:
                pass
        changed = (before['incidents'] != json.dumps(app.s['incidents'], sort_keys=True) or before['approved_baseline'] != app.s['approved_baseline'] or before['known_management_ips'] != app.cfg['known_management_ips'] or before['known_domains'] != app.cfg['known_domains'] or
                   before['known_domain_suffixes'] != app.cfg['known_domain_suffixes'] or
                   before['mute_until'] != app.s['mute_until'] or before['maintenance_until'] != app.s['maintenance_until'])
        LOG.info('AUDIT %s', json.dumps({'at': time.time(), 'actor': message['from']['id'],
                 'chat': message['chat']['id'], 'update': update_id, 'action': cmd,
                 'target': target, 'changed': changed, 'management_operation': text.split()[1] if management_change else None, 'incident_operation': text.split()[1] if incident_change else None, 'mute_before': before['mute_until'],
                 'mute_after': app.s['mute_until'], 'maintenance_before': before['maintenance_until'],
                 'maintenance_after': app.s['maintenance_until'], 'outcome': 'applied' if response.startswith(
                     ('Change approved', 'Change acknowledged', 'Baseline approved', 'Sentinel domain rules updated', 'Anomaly notifications', 'Maintenance updated', 'Management IPs updated')) else 'rejected'}))
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/var/lib/sentinel/sentinel.json'))
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--setup', action='store_true')
    parser.add_argument('--env-file', type=Path, default=Path('/etc/sentinel/sentinel.env'))
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('--process', default='gunthy-linux')
    parser.add_argument('--health-check', action='store_true')
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--accept-baseline')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    if args.baseline or args.accept_baseline:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ValueError('Baseline administration requires local root on Linux')
        current = checks.inventory()
        fingerprint = checks.inventory_digest(current)
        if args.accept_baseline:
            if args.accept_baseline != fingerprint:
                raise ValueError('Inventory changed or digest does not match; inspect --baseline again')
            save(checks.BASELINE, {'inventory': current, 'digest': fingerprint})
            LOG.info('AUDIT local root accepted security baseline digest=%s', fingerprint)
            print('Baseline approved. Collector will pick it up automatically.')
        else:
            print(json.dumps({'inventory': current, 'digest': fingerprint}, indent=2))
            print('Review this inventory; approve only known expected state with --accept-baseline DIGEST.')
        return
    if args.health_check:
        health = json.loads(Path('/run/sentinel/health.json').read_text())
        if not 0 <= time.time() - health['at'] < 90 or not health['collector']:
            raise ValueError('Monitoring stale')
        os.kill(health['pid'], 0)  # Liveness check only: signal zero sends no signal.
        print(json.dumps(health))
        return
    if args.collect:
        collect(args.process)
        return
    if args.setup:
        setup(args.config, args.env_file)
        return
    cfg = load(args.config)
    if args.check_config:
        print('Configuration valid')
        return
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('Start through sentinel.service on Linux')
    # Start the fixed root collector BEFORE dropping privileges, with no secret environment.
    streams = Streams({'collector': [sys.executable, '-I', str(Path(__file__).resolve()),
                                     '--collect', '--process', cfg['gunbot_process']]})
    streams.maintain(time.time())
    if 'collector' not in streams.running:
        raise RuntimeError('Collector could not start')
    drop_privileges()
    # No root actions follow this point. systemd owns collector termination on service exit.
    metadata = args.config.stat()
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError('Config/state must be service-owned mode 0600')
    lock = open(args.config.parent / '.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    for stale in args.config.parent.glob('.sentinel-*'):
        stale.unlink()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    incoming, outgoing, receipts = queue.Queue(50), queue.Queue(100), queue.Queue(500)
    telegram = Telegram(incoming, outgoing, stop, cfg['runtime']['offset'], receipts)
    app = Sentinel(cfg, args.config, outgoing, telegram.chats)
    app.observation = {}
    telegram.incidents = app.s['incidents']
    telegram.server_name = cfg['server_name']
    telegram.mute_until = app.s['mute_until']
    telegram.maintenance_until = app.s['maintenance_until']
    telegram.start()
    telegram.sender.start()
    next_check = next_dispatch = next_heartbeat = 0
    ready = False
    LOG.info('Sentinel %s started uid=%s', VERSION, os.geteuid())
    try:
        while not stop.is_set():
            now, mono = time.time(), time.monotonic()
            for _, envelope in streams.read():
                kind, item = envelope.get('kind'), envelope.get('data')
                if kind == 'snapshot':
                    app.observation = item
                    app.health.update(item['health'])
                    app.observe_host(item.get('host', {}))
                elif kind == 'oom':
                    app.event('oom:' + checks.digest(item), f"Kernel out-of-memory event observed; PID {item.get('pid', 'unknown')}", once=True)
                elif kind == 'ssh_reset':
                    app.ssh.clear()
                    app.cursors.clear()
                elif kind in ('dns', 'ssh'):
                    try:
                        (app.dns if kind == 'dns' else app.ssh_event)(item)
                    except (TypeError, ValueError, KeyError, AttributeError):
                        app.event('collector:' + kind, 'Invalid collector data')
            if 'collector' not in streams.running or streams.running['collector'][0].poll() is not None:
                raise RuntimeError('Privileged collector exited; restarting service')
            app.health.update(telegram=telegram.health, delivery=telegram.delivery_health)
            if mono >= next_check and app.observation:
                app.check()
                for name, status in app.observation.get('health', {}).items():
                    if not status.startswith('running'):
                        app.event('collector:' + name, 'Collector unavailable: ' + name)
                next_check = mono + cfg['check_seconds']
            for _ in range(100):
                try:
                    receipt = receipts.get_nowait()
                    if receipt[0] == 'selftest' and receipt[3] == 'delivered':
                        app.s['selftest_delivery'] = time.time()
                        app.dirty = True
                    else:
                        app.delivered(receipt)
                except queue.Empty:
                    break
            for _ in range(10):
                try:
                    update = incoming.get_nowait()
                except queue.Empty:
                    break
                if update['update_id'] < app.s['offset']:
                    continue
                message = update['message']
                response = audit_action(app, message, update['update_id'])
                telegram.mute_until = app.s['mute_until']
                telegram.maintenance_until = app.s['maintenance_until']
                command = message.get('text', '').strip().split()[0].split('@')[0] if message.get('text', '').strip() else '/help'
                command_parts = message.get('text', '').split()
                reference = command_parts[2].upper() if command == '/sentinel' and len(command_parts) == 3 and command_parts[2].upper() in app.s['incidents'] else None
                put(outgoing, {'reference': reference, 'command': command, 'attention': app.report_attention(command, response), 'action': app.report_actions(command, response), 'key': 'selftest' if message.get('text', '').strip().split('@')[0] == '/selftest' else '', 'id': uuid.uuid4().hex, 'chat': message['chat']['id'],
                              'text': response, 'created': now, 'priority': 0, 'anomaly': False})
            if mono >= next_dispatch:
                if app.dirty:
                    save(args.config, cfg)  # Persist pending notices BEFORE any network send.
                    app.dirty = False
                app.dispatch(now)
                next_dispatch = mono + 5
            collector_ok = now - app.observation.get('at', 0) < 45
            if mono >= next_heartbeat and collector_ok:
                save(Path('/run/sentinel/health.json'), {'at': now, 'collector': True,
                     'version': VERSION, 'pid': os.getpid(), 'uid': os.geteuid(), 'telegram': telegram.health,
                     'delivery': telegram.delivery_health, 'pending': len(app.s['pending'])})
                notify(('READY=1\n' if not ready else '') + 'WATCHDOG=1')
                ready = True
                next_heartbeat = mono + 10
    finally:
        stop.set()
        if app.dirty:
            save(args.config, cfg)
        # Do not signal a root child after dropping UID. systemd's control-group cleanup owns it.
        LOG.info('Sentinel stopped')


def report_failure(error):
    """Report code locations and numeric errno, never exception text or local values."""
    locations = []
    frame = error.__traceback__
    while frame is not None:
        code = frame.tb_frame.f_code
        if code.co_filename == __file__:
            locations.append(f'{code.co_name}:{frame.tb_lineno}')
        frame = frame.tb_next
    errno = getattr(error, 'errno', None)
    LOG.error('Sentinel stopped safely (%s); errno=%s; code=%s',
              type(error).__name__, errno if type(errno) is int else 'n/a',
              ' > '.join(locations) or 'unavailable')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        report_failure(error)
        sys.exit(1)
