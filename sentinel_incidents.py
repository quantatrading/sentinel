"""Bounded security-change records and scoped Telegram acknowledgement/approval."""
import copy
import datetime as dt
import json
import math
import re
import time
import uuid

import sentinel_baseline as baselines
import sentinel_checks as checks

LIMIT = 256
STATES = {'detected', 'persistent', 'acknowledged', 'approved', 'resolved'}
FIELDS = {'ref', 'signature', 'kind', 'name', 'change', 'before', 'after',
          'first', 'last', 'count', 'state', 'settled', 'actor', 'chat', 'reviewed_at'}


def valid_state(records):
    if not isinstance(records, dict) or len(records) > LIMIT:
        return False
    for ref, record in records.items():
        if not isinstance(ref, str) or not re.fullmatch(r'[A-F0-9]{8}', ref):
            return False
        if not isinstance(record, dict) or set(record) != FIELDS or record['ref'] != ref:
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
    changes = baseline.get('changes', [])
    active = {signature(c): c for c in changes}
    for record in records.values():
        if record['state'] in ('detected', 'persistent', 'acknowledged') and record['signature'] not in active:
            record['state'] = 'resolved'
            app.s['pending'].pop('incident:' + record['ref'], None)
            app.dirty = True
    for sig, change in active.items():
        record = next((r for r in records.values() if r['signature'] == sig and r['state'] in ('detected', 'persistent', 'acknowledged')), None)
        if record is None:
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
    reviewed = {r['signature'] for r in app.s['incidents'].values() if r['state'] == 'acknowledged'}
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
    change = next((c for c in changes if signature(c) == record['signature']), None)
    if change is None:
        return 'The observed change has changed or resolved. Use /sentinel to review the current records.'
    if args[0] == 'approve':
        if not app.host['baseline'].get('changes_complete', False):
            return 'Complete change list unavailable. Use /baseline review; no individual approval was made.'
        if any('before' not in c or 'after' not in c for c in changes):
            return 'Complete baseline evidence unavailable. Wait for a fresh sample.'
        # Reconstruct the expected inventory, then change exactly the approved entry.
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
        app.s['approved_baseline'] = approved
        app.host['baseline'] = dict(checks.compare_inventory(app.host['baseline_inventory'], approved), source='Telegram approval')
        app.baseline_reviews.clear()
        record['state'] = 'approved'
        response = 'Change approved. Only this difference was accepted; other changes still need review.'
    else:
        record['state'] = 'acknowledged'
        response = 'Change acknowledged. The baseline is unchanged; this condition remains visible without repeat warnings.'
    record.update(actor=actor, chat=chat, reviewed_at=now)
    app.s['pending'].pop('incident:' + record['ref'], None)
    app.dirty = True
    return response + '\n' + render(record)
