"""Telegram baseline review and service-owned approval; no privileged commands."""
import copy
import json
import math
import re
import time

import sentinel_checks as checks


def valid_inventory(value):
    if not isinstance(value, dict) or not {'files', 'listeners'} <= set(value) or set(value) - {'files', 'listeners', 'listener_processes'}:
        return False
    if any(not isinstance(value[k], dict) or len(value[k]) > 512 for k in value):
        return False
    if not all(isinstance(k, str) and len(k) <= 1024 and isinstance(v, dict)
               for k, v in value['files'].items()):
        return False
    if not all(isinstance(k, str) and len(k) <= 1024 and isinstance(v, list)
               and all(isinstance(owner, str) and len(owner) <= 320 for owner in v)
               for k, v in list(value['listeners'].items()) + list(value.get('listener_processes', {}).items())):
        return False
    try:
        return len(json.dumps(value, allow_nan=False)) <= 512 * 1024
    except (ValueError, TypeError):
        return False


def valid_approval(value):
    if value is None:
        return True
    return (isinstance(value, dict) and set(value) == {'inventory', 'digest', 'local_digest', 'actor', 'chat', 'at'}
            and valid_inventory(value['inventory'])
            and value['digest'] == checks.inventory_digest(value['inventory'])
            and (value['local_digest'] is None or isinstance(value['local_digest'], str)
                 and re.fullmatch(r'[a-f0-9]{64}', value['local_digest']) is not None)
            and type(value['actor']) is int and value['actor'] > 0
            and type(value['chat']) is int and value['chat'] != 0
            and type(value['at']) in (int, float) and math.isfinite(value['at']) and value['at'] >= 0)


def apply(app, host):
    host = dict(host)
    local = host.get('baseline', {})
    host['local_baseline_digest'] = local.get('expected_digest')
    approved = app.s['approved_baseline']
    current = host.get('baseline_inventory')
    if approved and local.get('status') != 'unavailable' and valid_inventory(current):
        if approved['local_digest'] != host['local_baseline_digest']:
            # A subsequent local-root approval supersedes a Telegram approval.
            app.s['approved_baseline'] = None
            app.baseline_reviews.clear()
            app.dirty = True
        else:
            host['baseline'] = checks.compare_inventory(current, approved)
            host['baseline']['source'] = 'Telegram approval'
    return host


def available(app, now):
    host = app.host
    return (app.observation and 0 <= now - app.observation.get('at', 0) < 45
            and 0 <= now - host.get('inventory_at', 0) < 90
            and host.get('baseline', {}).get('status') in ('not approved', 'drift', 'matches approved baseline')
            and valid_inventory(host.get('baseline_inventory')))


def command(app, args, actor, chat):
    baseline = app.host.get('baseline', {})
    if not args:
        changes = '\n'.join(x['change'] + ': ' + checks.label(x['name']) for x in baseline.get('changes', [])[:15])
        return (f"Baseline: {baseline.get('status', 'unavailable')}\n"
                f"Observed digest: {baseline.get('digest', 'unknown')}\n{changes}\n"
                'To accept the current setup: /baseline review, then /baseline approve DIGEST.\n'
                'Approval records your reference point; it does not prove the server is secure.')
    if (args[0] == 'review' and (len(args) == 1 or len(args) == 2 and args[1].isdigit())):
        operation = 'review'
    elif len(args) == 2 and args[0] == 'approve' and re.fullmatch(r'[a-f0-9]{64}', args[1]):
        operation = 'approve'
    else:
        return 'Use /baseline, /baseline review [page], or /baseline approve DIGEST.'
    if type(actor) is not int or actor <= 0 or type(chat) is not int or chat == 0:
        return 'Baseline review and approval require an authorised Telegram sender and chat.'
    now = time.time()
    if not available(app, now):
        return 'Baseline unavailable or stale. Wait for a complete fresh collector sample, then /baseline review.'
    current = app.host['baseline_inventory']
    digest = checks.inventory_digest(current)
    app.baseline_reviews = {key: value for key, value in app.baseline_reviews.items()
                            if 0 <= now - value['at'] < 300}
    key = (actor, chat)
    if operation == 'review':
        # Every page refers to this digest; no raw file contents leave the collector.
        lines = [f"Files: {len(current['files'])}; listening endpoints: {len(current['listeners'])}."]
        for kind in ('files', 'listeners', 'listener_processes'):
            for name, metadata in sorted(current.get(kind, {}).items()):
                line = kind + ': ' + json.dumps(checks.label(name), ensure_ascii=True) + '\n' + json.dumps(metadata, sort_keys=True, ensure_ascii=True)
                lines.extend(line[i:i + 1800] for i in range(0, len(line), 1800))
        pages, page = [], ''
        for line in lines:
            if len(page) + len(line) + 1 > 2400:
                pages.append(page)
                page = ''
            page += line + '\n'
        if page:
            pages.append(page)
        number = int(args[1]) if len(args) == 2 else 1
        if not 1 <= number <= len(pages):
            return f'Use /baseline review PAGE with a page from 1 to {len(pages)}.'
        if len(app.baseline_reviews) >= 100 and key not in app.baseline_reviews:
            app.baseline_reviews.pop(next(iter(app.baseline_reviews)))
        app.baseline_reviews[key] = {'digest': digest, 'at': now, 'local_digest': app.host.get('local_baseline_digest')}
        return (f'Baseline review {number}/{len(pages)}\n{pages[number - 1]}\n'
                f'Other pages: /baseline review PAGE (1-{len(pages)}).\n'
                'Approving accepts ALL files and listeners in this inventory, including other pages.\n'
                'Only if this is the expected setup, confirm within 5 minutes:\n'
                f'/baseline approve {digest}')
    review = app.baseline_reviews.get(key)
    if not review or review['digest'] != args[1]:
        return 'Review this inventory first in this chat with /baseline review; approval expires after 5 minutes.'
    if args[1] != digest or review['local_digest'] != app.host.get('local_baseline_digest'):
        app.baseline_reviews.pop(key, None)
        return 'Inventory or local baseline changed. Run /baseline review again before approving.'
    app.s['approved_baseline'] = {'inventory': copy.deepcopy(current), 'digest': digest,
                                'local_digest': review['local_digest'], 'actor': actor, 'chat': chat, 'at': now}
    app.host['baseline'] = dict(checks.compare_inventory(current, app.s['approved_baseline']), source='Telegram approval')
    app.baseline_reviews.clear()
    for record in app.s['incidents'].values():
        if record['state'] in ('detected', 'persistent', 'acknowledged'):
            record.update(state='approved', actor=actor, chat=chat, reviewed_at=now)
            app.s['pending'].pop('incident:' + record['ref'], None)
    app.dirty = True
    return ('Baseline approved. Future changes will be compared with this inventory.\n'
            f'Digest: {digest}\nThis records expected state; it is not a security assessment.')
