"""Bounded, best-effort WHOIS enrichment outside the privileged collector."""
import ipaddress
import queue
import re
import socket
import threading
import time

REGISTRIES = {'whois.arin.net', 'whois.ripe.net', 'whois.apnic.net', 'whois.lacnic.net', 'whois.afrinic.net'}


def public_address(key):
    if not key.startswith('ip:'):
        return None
    try:
        address = ipaddress.ip_address(key[3:])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if '%' in str(address) or not address.is_global or address.is_multicast or address.is_reserved:
        return None
    return str(address)


def query(host, request):
    if host not in REGISTRIES | {'whois.iana.org'}:
        raise ValueError('Unapproved registry')
    deadline = time.monotonic() + 3
    with socket.create_connection((host, 43), timeout=2) as connection:
        connection.sendall((request + '\r\n').encode('ascii'))
        blocks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            connection.settimeout(min(2, remaining))
            block = connection.recv(min(4096, 65537 - size))
            if not block:
                break
            size += len(block)
            if size > 65536:
                raise ValueError('Oversize WHOIS response')
            blocks.append(block)
    return b''.join(blocks).decode('utf-8', errors='replace')


def fields(text):
    result = {}
    for line in text.splitlines():
        if line.startswith(('#', '%')):
            continue
        key, separator, value = line.partition(':')
        if separator:
            key = key.strip().lower()
            if key not in result:
                result[key] = value.strip()
    return result


def clean(value):
    return re.sub(r'[^a-zA-Z0-9 .,()/&+_-]', '?', str(value))[:140]


def lookup(address):
    referral = fields(query('whois.iana.org', address)).get('whois', '').lower()
    if referral not in REGISTRIES:
        raise ValueError('No approved registry referral')
    record = fields(query(referral, ('n + ' if referral == 'whois.arin.net' else '') + address))
    def first(*keys):
        return next((clean(record[k]) for k in keys if record.get(k)), 'not provided')
    owner = first('orgname', 'org-name', 'owner', 'organisation', 'descr')
    network = first('netname')
    allocation = first('cidr', 'netrange', 'inetnum', 'inet6num')
    if owner == network == allocation == 'not provided':
        raise ValueError('WHOIS record unavailable')
    return (f'Registrant / organisation: {owner}\nNetwork: {network}\nRange: {allocation}\n'
            f'Registry country: {first("country")}\nSource: {referral}\n'
            'Registration data does not prove service identity, location or safety.')


class Enricher:
    def __init__(self):
        self.cache = {}
        self.pending = set()
        self.lock = threading.Lock()
        self.jobs = queue.Queue(16)
        self.worker = None
        self.next_request = 0

    def run(self):
        while True:
            address = self.jobs.get()
            try:
                result = lookup(address)
                ttl = 86400
            except Exception:
                result, ttl = 'Unavailable: registry lookup failed or timed out. Alert delivered without registration data.', 300
            with self.lock:
                if len(self.cache) >= 256:
                    self.cache.pop(next(iter(self.cache)))
                self.cache[address] = (time.monotonic() + ttl, result)
                self.pending.discard(address)

    def prepare(self, job, now):
        """Return False only while this alert awaits lookup; other sends continue."""
        if 'whois' in job or not job.get('anomaly') or not job.get('key', '').startswith('ip:'):
            return True
        address = public_address(job['key'])
        if address is None:
            job['whois'] = 'Not applicable: non-public or special-use address.'
            return True
        mono = time.monotonic()
        with self.lock:
            cached = self.cache.get(address)
            if cached and cached[0] > mono:
                job['whois'] = cached[1]
                return True
            if 'whois_deadline' not in job:
                if address not in self.pending:
                    if mono < self.next_request or self.jobs.full():
                        job['whois'] = 'Unavailable: lookup capacity limit. Alert delivered without registration data.'
                        return True
                    self.pending.add(address)
                    self.jobs.put_nowait(address)
                    self.next_request = mono + 2
                    if self.worker is None:
                        self.worker = threading.Thread(target=self.run, daemon=True, name='sentinel-whois')
                        self.worker.start()
                job['whois_deadline'] = mono + 4
            if mono >= job['whois_deadline']:
                job['whois'] = 'Unavailable: lookup time limit reached. Alert delivered without registration data.'
                return True
        job['next'] = now + .2
        return False
