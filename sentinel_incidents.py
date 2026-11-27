"""Bounded security-change records and scoped Telegram acknowledgement/approval."""
import copy
import datetime as dt
import hashlib
import http.client
import json
import math
import re
import socket
import struct
import time
import uuid

import sentinel_baseline as baselines
import sentinel_checks as checks

LIMIT = 256
STATES = {'detected', 'persistent', 'acknowledged', 'approved', 'resolved'}
FIELDS = {'ref', 'signature', 'kind', 'name', 'change', 'before', 'after',
          'first', 'last', 'count', 'state', 'settled', 'actor', 'chat', 'reviewed_at'}


UNIT_DIR = '/etc/systemd/system/'
SNAP_LINK = re.compile(UNIT_DIR + r'multi-user\.target\.wants/'
                       r'(snap-([a-z0-9]+(?:\\x2d[a-z0-9]+)*)-([1-9][0-9]{0,15})\.mount)')
SNAP_WINDOW = 120
OPEN = ('detected', 'persistent', 'acknowledged')


class SnapConnection(http.client.HTTPConnection):
    def connect(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(self.timeout)
            peer.connect('/run/snapd.socket')
            credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if struct.unpack('3i', credentials)[1] != 0:
                raise OSError('snapd peer is not root')
            self.sock = peer.dup()


def snap_history():
    if not hasattr(socket, 'SO_PEERCRED'):
        return []
    conn = SnapConnection('localhost', timeout=1)
    try:
        conn.request('GET', '/v2/changes?select=all')
        response = conn.getresponse()
        if response.status == 200:
            limit = 1024 * 1024
            payload = response.read(limit + 1)
            if len(payload) <= limit:
                body = json.loads(payload)
                if isinstance(body, dict) and body.get('type') == 'sync' and isinstance(body.get('result'), list):
                    return body['result']
    except (OSError, ValueError, http.client.HTTPException):
        pass
    finally:
        conn.close()
    return []


def snap_time(value):
    try:
        # Older Python fromisoformat supports at most six fractional digits.
        value = re.sub(r'(\.\d{6})\d+', r'\1', value.replace('Z', '+00:00'))
        when = dt.datetime.fromisoformat(value)
        return when.timestamp() if when.tzinfo is not None else 0
    except (AttributeError, ValueError, OverflowError, OSError):
        return 0


def exact_snap_link(change):
    match = SNAP_LINK.fullmatch(change['name'])
    if change['kind'] != 'files' or not match or change['change'] not in ('added', 'removed'):
        return None
    expected = {'uid': 0, 'gid': 0, 'mode': 511,
                'link_sha256': hashlib.sha256((UNIT_DIR + match[1]).encode()).hexdigest()}
    before, after = (None, expected) if change['change'] == 'added' else (expected, None)
    return match if change.get('before') == before and change.get('after') == after else None


def snap_match(history, snap, old, new, observed):
    matches = []
    for entry in history:
        if not isinstance(entry, dict) or entry.get('kind') != 'auto-refresh':
            continue
        change_id = entry.get('id')
        start, end = snap_time(entry.get('spawn-time')), snap_time(entry.get('ready-time'))
        if (not isinstance(change_id, str) or not re.fullmatch(r'[0-9]{1,20}', change_id)
                or entry.get('status') != 'Done' or entry.get('ready') is not True
                or not 0 < start <= end <= observed or observed - end > SNAP_WINDOW):
            continue
        tasks = entry.get('tasks')
        if not isinstance(tasks, list):
            continue
        required = [('mount-snap', f'Mount snap "{snap}" ({new})'),
                    ('discard-snap', f'Remove snap "{snap}" ({old}) from the system')]
        if all(sum(isinstance(task, dict) and task.get('status') == 'Done'
                   and (task.get('kind'), task.get('summary')) == evidence
                   and max(start, observed - SNAP_WINDOW) <= snap_time(task.get('ready-time')) <= end
                   for task in tasks) == 1 for evidence in required):
            matches.append(change_id)
    return matches[0] if len(matches) == 1 else None


def active_changes(app, baseline, now):
    active = {signature(change): change for change in baseline.get('changes', [])}
    records = app.s['incidents'].values()
    # Persist the evidence so a verified pair survives restart and history expiry.
    for record in records:
        group = record.get('snap')
        if group and record['state'] in OPEN and all(sig in active for sig in group['members']):
            group_pair(active, group)
    if not baseline.get('changes_complete'):
        return active
    tracked = {r['signature'] for r in records if r['state'] in OPEN}
    candidates = {}
    for sig, change in active.items():
        match = SNAP_LINK.fullmatch(change['name'])
        if match and 'snap' not in change:
            name = match[2].replace(r'\x2d', '-')
            candidates.setdefault(name, []).append((sig, change, match[3]))
    pairs = {name: sorted(items, key=lambda item: item[1]['change'])
             for name, items in candidates.items() if len(items) == 2
             and {item[1]['change'] for item in items} == {'added', 'removed'}
             and all(sig not in tracked and exact_snap_link(change) for sig, change, _ in items)}
    if pairs and baselines.available(app, now):
        history = snap_history()
        for name, ((added, _, new), (removed, _, old)) in pairs.items():
            change_id = snap_match(history, name, old, new, app.host.get('inventory_at', now))
            if change_id and not any(r.get('snap', {}).get('id') == change_id
                                     and r['name'] == active[added]['name'] for r in records):
                group_pair(active, {'id': change_id, 'members': [added, removed],
                                    'removed': active[removed]['name']})
    return active


def group_pair(active, group):
    added, removed = (active.pop(sig) for sig in group['members'])
    active[checks.digest(group['members'])] = dict(added, snap=group, entries=[added, removed])


def valid_group(group):
    return (isinstance(group, dict) and set(group) == {'id', 'members', 'removed'}
            and isinstance(group['id'], str) and re.fullmatch(r'[0-9]{1,20}', group['id'])
            and isinstance(group['removed'], str) and SNAP_LINK.fullmatch(group['removed'])
            and isinstance(group['members'], list) and len(group['members']) == 2
            and all(isinstance(sig, str) and re.fullmatch(r'[a-f0-9]{64}', sig) for sig in group['members'])
            and group['members'][0] != group['members'][1])


def valid_state(records):
    if not isinstance(records, dict) or len(records) > LIMIT:
        return False
    for ref, record in records.items():
        if not isinstance(ref, str) or not re.fullmatch(r'[A-F0-9]{8}', ref):
            return False
        if not isinstance(record, dict) or set(record) - {'snap'} != FIELDS or record['ref'] != ref:
            return False
        if 'snap' in record and (not valid_group(record['snap'])
                                 or record['signature'] != checks.digest(record['snap']['members'])):
            return False
        if any(not isinstance(record[k], str) for k in ('state', 'kind', 'change')):
            return False
        if type(record['settled']) is not bool:
            return False
        if record['state'] not in STATES or record['kind'] not in ('files', 'listeners') or record['change'] not in ('added', 'removed', 'changed'):
            return False
        if not isinstance(record['signature'], str) or not re.fullmatch(r'[a-f0-9]{64}', record['signature']):
            return False
        if any(not isinstance(record[k], str) or len(record[k]) > 1024 for k in ('name', 'before', 'after')):
            return False
        if type(record['count']) is not int or not 1 <= record['count'] <= 10**12:
            return False
        if any(type(record[k]) not in (int, float) or not math.isfinite(record[k]) or record[k] < 0 for k in ('first', 'last', 'reviewed_at')):
            return False
        if any(record[k] is not None and type(record[k]) is not int for k in ('actor', 'chat')):
            return False
    return True


def signature(change):
    return checks.digest((change['kind'], change['name'], change.get('before'),
                          change.get('after'), change['fingerprint']))


def description(change, previous):
    value = change.get('before' if previous else 'after')
    if value is None:
        return 'not listening' if change['kind'] == 'listeners' else 'not present'
    if change['kind'] == 'listeners':
        processes = change.get('previous_processes' if previous else 'current_processes', [])
        return ('; '.join(processes) if processes else '; '.join(value) + ' (PID not recorded)')[:1024] or 'owner unavailable'
    return json.dumps(value, sort_keys=True, ensure_ascii=True)[:1024]


def render(record):
    elapsed = max(0, int(record['last'] - record['first']))
    when = dt.datetime.fromtimestamp(record['first'], dt.timezone.utc).strftime('%d %b %H:%M UTC')
    label = ('LISTENER' if record['kind'] == 'listeners' else 'SECURITY FILE') + ' ' + record['change'].upper()
    state = {'detected': 'CHANGE DETECTED', 'persistent': 'PERSISTENT - unchanged observation',
             'acknowledged': 'ACKNOWLEDGED - baseline unchanged', 'approved': 'APPROVED - reference updated',
             'resolved': 'RESOLVED - difference no longer observed'}[record['state']]
    result = (f"{label}\n{checks.label(record['name'])}\nState: {state}\n"
              f"Previously: {record['before']}\nCurrently: {record['after']}\n"
              f"First detected: {when}\nObserved duration: {elapsed // 3600}h {(elapsed % 3600) // 60:02d}m\n"
              f"Checks: {record['count']:,}\nLast observed: "
              + dt.datetime.fromtimestamp(record['last'], dt.timezone.utc).strftime('%d %b %H:%M UTC'))
    if 'snap' in record:
        group = record['snap']
        result = (f"LEGITIMATE SNAP AUTO-REFRESH · CHANGE {group['id']}\n"
                  "Sentinel verified that snapd completed the mount and removal tasks for these exact "
                  "revisions and that both symlink fingerprints matched the expected targets.\n"
                  f"Added: {record['name']}\nRemoved: {group['removed']}\n"
                  f"First detected: {when}")
        if record['state'] == 'approved':
            if record['actor'] is None:
                result += '\nSentinel automatically accepted both changes into the security baseline. No action needed.'
            else:
                result += '\nBoth changes were accepted into the security baseline.'
        elif record['state'] in ('detected', 'persistent'):
            result += '\nBoth changes are awaiting approval. One approval accepts the pair.'
        else:
            result += f'\nState: {state}'
    if record['state'] == 'resolved':
        result += '\nAbove details describe the historical change; it is no longer active.'
    result += f"\n/sentinel investigate {record['ref']}"
    if record['state'] in ('detected', 'persistent', 'acknowledged'):
        result += f"\n/sentinel acknowledge {record['ref']}\n/sentinel approve {record['ref']}"
    return result


def observe(app, now):
    baseline = app.host.get('baseline', {})
    if baseline.get('status') not in ('drift', 'matches approved baseline'):
        return  # Missing/incomplete observations are not recovery.
    records = app.s['incidents']
    # Old hourly drift jobs must not replay alongside the new records after upgrade.
    for key in list(app.s['pending']):
        if key.startswith('drift:'):
            del app.s['pending'][key]
            app.dirty = True
    active = active_changes(app, baseline, now)
    for record in records.values():
        if record['state'] in OPEN and record['signature'] not in active:
            if 'snap' in record and not baseline.get('changes_complete'):
                for sig in record['snap']['members']:
                    active.pop(sig, None)
                continue
            record['state'] = 'resolved'
            app.s['pending'].pop('incident:' + record['ref'], None)
            app.dirty = True
    for sig, change in active.items():
        record = next((r for r in records.values() if r['signature'] == sig and r['state'] in OPEN), None)
        new_record = record is None
        if new_record:
            if len(records) >= LIMIT:
                closed = [r for r in records.values() if r['state'] in ('approved', 'resolved')]
                if not closed:
                    app.event('change-capacity', 'Security change record capacity reached; inspect /baseline for remaining changes.', once=True)
                    continue
                del records[min(closed, key=lambda r: r['last'])['ref']]
            ref = uuid.uuid4().hex[:8].upper()
            while ref in records:
                ref = uuid.uuid4().hex[:8].upper()
            legacy_key = 'drift:' + checks.digest((change['kind'], change['name'], change['fingerprint']))
            legacy = app.s['events'].pop(legacy_key, None)
            record = {'ref': ref, 'signature': sig, 'kind': change['kind'], 'name': change['name'][:1024],
                      'change': change['change'], 'before': description(change, True), 'after': description(change, False),
                      'first': legacy['first'] if legacy else now, 'last': now, 'count': legacy['count'] if legacy else 0,
                      'state': 'detected', 'settled': bool(legacy and legacy['settled']), 'actor': None, 'chat': None, 'reviewed_at': 0}
            if 'snap' in change:
                record['snap'] = change['snap']
            records[ref] = record
            if legacy:
                app.s['events']['incident:' + ref] = legacy
        record['last'] = now
        record['count'] = min(10**12, record['count'] + 1)
        record['after'] = description(change, False)
        if record['state'] == 'detected' and record['count'] > 1:
            record['state'] = 'persistent'
        app.dirty = True
        key = 'incident:' + record['ref']
        # Only the first observation enters the alert lifecycle; retry until settled.
        # Acknowledgement closes notifications without changing the reference.
        if record['state'] == 'acknowledged':
            continue
        if (new_record and 'snap' in record and app.cfg.get('auto_approve_snap_refresh') is True
                and baselines.available(app, now)
                and approve(app, record, change['entries'], None, None, now) is None):
            continue
        event = app.s['events'].get(key)
        if event:
            event['last'] = now
            record['settled'] = record['settled'] or bool(event['settled'])
        if not record['settled']:
            app.event(key, render(record), now=now, once=True)
            if key in app.s['pending']:
                job = app.s['pending'][key]
                job['id'] = record['ref'].lower() + job['id'][8:]


def all_reviewed(app):
    changes = app.host.get('baseline', {}).get('changes', [])
    reviewed = {sig for r in app.s['incidents'].values() if r['state'] == 'acknowledged'
                for sig in r.get('snap', {}).get('members', [r['signature']])}
    return bool(changes) and all(signature(change) in reviewed for change in changes)


def command(app, args, actor, chat):
    records = app.s['incidents']
    if not args or len(args) == 1 and args[0].isdigit():
        page = int(args[0]) if args else 1
        values = sorted(records.values(), key=lambda r: (r['state'] in ('approved', 'resolved'), -r['last']))
        pages = max(1, (len(values) + 19) // 20)
        if not 1 <= page <= pages:
            return f'Use /sentinel PAGE with a page from 1 to {pages}.'
        return (f'Tracked security changes ({page}/{pages}):\n' + '\n'.join(
            f"{r['ref']} {r['state'].upper()}: {r['change']} {checks.label(r['name'])[:100]} ({r['count']:,} checks)" for r in values[(page - 1) * 20:page * 20])
            + '\n/sentinel PAGE\n/sentinel investigate REF\n/sentinel acknowledge REF\n/sentinel approve REF') if values else 'No tracked security changes.'
    if len(args) != 2 or args[0] not in ('investigate', 'acknowledge', 'approve') or not re.fullmatch(r'[a-fA-F0-9]{8}', args[1]):
        return 'Use /sentinel investigate REF, /sentinel acknowledge REF, or /sentinel approve REF.'
    record = records.get(args[1].upper())
    if record is None:
        return 'Unknown change reference. Use /sentinel for retained change references; older alert references may not be available.'
    if args[0] == 'investigate':
        return render(record) + '\nChecks count repeated samples, not separate incidents. Duration can include observation gaps.'
    if type(actor) is not int or actor <= 0 or type(chat) is not int or chat == 0:
        return 'An authorised Telegram sender and chat are required.'
    if record['state'] in ('approved', 'resolved'):
        return 'This change is already ' + record['state'] + '. No reference changes made.'
    now = time.time()
    if not baselines.available(app, now):
        return 'Observation unavailable or stale. Wait for a fresh sample and investigate again.'
    changes = app.host['baseline'].get('changes', [])
    observed = {signature(c): c for c in changes}
    members = record.get('snap', {}).get('members', [record['signature']])
    if not all(sig in observed for sig in members):
        return 'The observed change has changed or resolved. Use /sentinel to review the current records.'
    if args[0] == 'approve':
        error = approve(app, record, [observed[sig] for sig in members], actor, chat, now)
        if error:
            return error
        response = ('Change approved. Both Snap mount links were accepted.' if 'snap' in record
                    else 'Change approved. Only this difference was accepted; other changes still need review.')
    else:
        record.update(state='acknowledged', actor=actor, chat=chat, reviewed_at=now)
        app.s['pending'].pop('incident:' + record['ref'], None)
        app.dirty = True
        response = 'Change acknowledged. The baseline is unchanged; this condition remains visible without repeat warnings.'
    return response + '\n' + render(record)


def approve(app, record, entries, actor, chat, now):
    changes = app.host['baseline'].get('changes', [])
    if not app.host['baseline'].get('changes_complete', False):
        return 'Complete change list unavailable. Use /baseline review; no individual approval was made.'
    if any('before' not in c or 'after' not in c for c in changes):
        return 'Complete baseline evidence unavailable. Wait for a fresh sample.'
    # Reconstruct the expected inventory, then apply only the selected entries.
    # Other simultaneous differences remain differences; never approve the whole host.
    expected = copy.deepcopy(app.host['baseline_inventory'])
    for item in changes:
        target = expected[item['kind']]
        if item['before'] is None:
            target.pop(item['name'], None)
        else:
            target[item['name']] = copy.deepcopy(item['before'])
        if item['kind'] == 'listeners':
            expected.setdefault('listener_processes', {})[item['name']] = list(item.get('previous_processes', []))
    for change in entries:
        target = expected[change['kind']]
        if change['after'] is None:
            target.pop(change['name'], None)
            if change['kind'] == 'listeners':
                expected.setdefault('listener_processes', {}).pop(change['name'], None)
        else:
            target[change['name']] = copy.deepcopy(change['after'])
            if change['kind'] == 'listeners':
                expected.setdefault('listener_processes', {})[change['name']] = list(change.get('current_processes', []))
    if not baselines.valid_inventory(expected):
        return 'Approved reference would exceed inventory limits. No changes made.'
    approved = {'inventory': expected, 'digest': checks.inventory_digest(expected),
                'local_digest': app.host.get('local_baseline_digest'), 'actor': actor, 'chat': chat, 'at': now}
    if actor is None:
        # Save the notice and approved baseline together before dispatch.
        key = 'snap-approved:' + record['ref']
        app.event(key, render(dict(record, state='approved')), now=now, once=True)
        if key not in app.s['pending']:
            return 'Automatic approval requires a queued Telegram notice.'
    app.s['approved_baseline'] = approved
    source = 'Snap refresh policy' if actor is None else 'Telegram approval'
    app.host['baseline'] = dict(checks.compare_inventory(app.host['baseline_inventory'], approved), source=source)
    app.baseline_reviews.clear()
    record.update(state='approved', actor=actor, chat=chat, reviewed_at=now)
    app.s['pending'].pop('incident:' + record['ref'], None)
    app.dirty = True
