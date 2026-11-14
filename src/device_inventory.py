#!/usr/bin/env python3
"""Observed log devices and reversible/permanent retirement; never deletes events."""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time

spec = importlib.util.spec_from_file_location('device_privacy', Path(__file__).with_name('sanitize_logs.py'))
privacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(privacy)
spec = importlib.util.spec_from_file_location('device_dns', Path(__file__).with_name('device_dns.py'))
local_dns = importlib.util.module_from_spec(spec); spec.loader.exec_module(local_dns)
VERSION = 1
MAX_DEVICES = 10000
MAX_ALIASES = 20000
DEFAULT_RETIRE_DAYS = 10
MAX_RETIRE_DAYS = 3650
LIFECYCLE_WINDOW_DAYS = 7


def ensure_lifecycle(db):
    """Add optional v1-compatible tables without relabeling existing devices new."""
    migrated = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle'").fetchone()
    if migrated and not db.execute("SELECT 1 FROM metadata WHERE key='auto_retirement'").fetchone():
        raise ValueError('Auto-retirement settings are missing; inspect the device store')
    db.execute('''CREATE TABLE IF NOT EXISTS lifecycle(device_id TEXT PRIMARY KEY,
        added_utc INTEGER, received_utc INTEGER, auto_retired_utc INTEGER,
        auto_retired_received_utc INTEGER)''')
    db.execute('''INSERT OR IGNORE INTO lifecycle(device_id)
        SELECT id FROM devices''')
    db.execute('CREATE INDEX IF NOT EXISTS device_audit_latest ON audit(device_id,id)')
    db.execute('''CREATE TABLE IF NOT EXISTS device_links(device_id TEXT PRIMARY KEY,
        cluster_id TEXT NOT NULL,canonical TEXT NOT NULL,verified_utc INTEGER NOT NULL,
        expires_utc INTEGER NOT NULL)''')
    db.execute('CREATE TABLE IF NOT EXISTS dns_conflicts(device_id TEXT PRIMARY KEY,checked_utc INTEGER NOT NULL)')
    db.execute('''CREATE TABLE IF NOT EXISTS device_action_groups(audit_id INTEGER PRIMARY KEY,
        event_key TEXT NOT NULL,member_count INTEGER NOT NULL)''')
    db.execute("INSERT OR IGNORE INTO metadata VALUES('auto_retirement',?)",
               (compact({'enabled': True, 'days': DEFAULT_RETIRE_DAYS, 'version': 1}),))


def read_settings(db):
    row = db.execute("SELECT value FROM metadata WHERE key='auto_retirement'").fetchone()
    if not row and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle'").fetchone():
        raise ValueError('Auto-retirement settings are missing; inspect the device store')
    value = json.loads(row[0]) if row else {'enabled': True, 'days': DEFAULT_RETIRE_DAYS, 'version': 1}
    if (not isinstance(value, dict) or type(value.get('enabled')) is not bool or
            type(value.get('days')) is not int or not 1 <= value['days'] <= MAX_RETIRE_DAYS or
            type(value.get('version')) is not int or value['version'] < 1):
        raise ValueError('Invalid auto-retirement settings')
    return dict(value, revision=hashlib.sha256(compact(value).encode()).hexdigest())


def set_settings(base, enabled, days, revision):
    if type(enabled) is not bool or type(days) is not int or not 1 <= days <= MAX_RETIRE_DAYS:
        raise ValueError('Days must be a whole number from 1 to 3650')
    with closing(connect(database_path(base), write=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        ensure_lifecycle(db)
        current = read_settings(db)
        if current['revision'] != revision:
            raise ValueError('Device settings changed; reload the page')
        value = {'enabled': enabled, 'days': days, 'version': current['version'] + 1}
        db.execute("UPDATE metadata SET value=? WHERE key='auto_retirement'", (compact(value),))
    return value


def lifecycle_summary(base, now=None):
    """Read seven-day physical-device changes without counting each DNS alias."""
    now = int(time.time() if now is None else now)
    since = now - LIFECYCLE_WINDOW_DAYS * 86400
    counts = {key: 0 for key in ('added', 'retired', 'restored', 'permanent')}
    mapping = {'retire': 'retired', 'auto_retire': 'retired',
               'restore': 'restored', 'auto_restore': 'restored', 'permanent': 'permanent'}
    with closing(connect(database_path(base))) as db:
        db.execute('BEGIN')
        settings = read_settings(db)
        evaluation = db.execute("SELECT value FROM metadata WHERE key='lifecycle_evaluation'").fetchone()
        evaluation = json.loads(evaluation[0]) if evaluation else None
        catalog_rows = inventory_rows(db)
        by_member = {member: item for item in catalog_rows for member in item['members']}
        changes = []
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle'").fetchone():
            additions = dict(db.execute('SELECT device_id,added_utc FROM lifecycle'))
            for item in catalog_rows:
                stamps = [additions.get(member) for member in item['members']]
                # Existing/baseline members make this a newly linked alias, not a new device.
                if any(value is None for value in stamps): continue
                first = min(stamps)
                if since <= first <= now:
                    changes.append(dict(device_id=item['id'], name=item['name'], site=item['scope']['site'],
                        action='added', changed_utc=first, member_count=item['member_count'],
                        reason='Automatically discovered from received NAS logs'))
                    counts['added'] += 1
        linked = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_links'").fetchone()
        action_groups = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_action_groups'").fetchone()
        cluster = 'COALESCE(l.cluster_id,d.id)' if linked else 'd.id'
        join = ' LEFT JOIN device_links l ON l.device_id=d.id ' if linked else ' '
        event_key = 'COALESCE(g.event_key,' + cluster + ')' if action_groups else cluster
        member_count = 'MAX(COALESCE(g.member_count,1))' if action_groups else '1'
        if action_groups: join += ' LEFT JOIN device_action_groups g ON g.audit_id=a.id '
        grouped = ("SELECT MIN(d.id) device_id,a.action,a.reason,a.changed_utc," + member_count + " members FROM audit a "
            "JOIN devices d ON d.id=a.device_id" + join +
            "WHERE a.changed_utc>=? AND a.changed_utc<=? "
            "AND a.action IN ('retire','restore','permanent','auto_retire','auto_restore') "
            "GROUP BY " + event_key + ",a.action,a.reason,a.changed_utc")
        for action,total in db.execute('SELECT action,COUNT(*) FROM (' + grouped + ') GROUP BY action', (since,now)):
            counts[mapping[action]] += total
        for row in db.execute(grouped + ' ORDER BY a.changed_utc DESC LIMIT 10001', (since,now)):
            item = by_member[row[0]]
            changes.append(dict(device_id=item['id'], name=item['name'], site=item['scope']['site'],
                action=row[1], reason=clean(row[2]), changed_utc=row[3], member_count=max(row[4],item['member_count'])))
    changes.sort(key=lambda item: (-item['changed_utc'], item['device_id'], item['action']))
    return {'settings': settings, 'window_days': LIFECYCLE_WINDOW_DAYS, 'since_utc': since,
            'changes': changes[:500], 'counts': counts, 'truncated': len(changes) > 500,
            'evaluation': evaluation}


def healthy_collection_sites(entries, now):
    """Only the collector's fresh, complete results may trigger retirement."""
    result = set()
    for site, entry in (entries or {}).items():
        if site not in ('home', 'work') or not isinstance(entry, dict): continue
        if entry.get('status') != 'complete' or entry.get('warnings') != []: continue
        if any(type(entry.get(key)) is not int or not now - 7200 <= entry[key] <= now + 300
               for key in ('collected_utc', 'exported_utc')): continue
        sources = entry.get('sources')
        if not isinstance(sources, dict) or not sources: continue
        if any(not isinstance(info, dict) or info.get('warnings') != [] for info in sources.values()): continue
        result.add(site)
    return result


def database_path(base):
    return Path(base) / 'devices' / 'devices.sqlite'


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def clean(value):
    return privacy.text(str(value or ''))[:512]


def scope(site, source, raw):
    if site not in ('home', 'work') or not isinstance(source, str) or not source:
        raise ValueError('Invalid device site or source')
    # NAS transfer records contain client IPs, not the NAS's management address.
    if source.startswith('NAS/'):
        return {'site': site, 'kind': 'nas-local', 'host': 'NAS', 'ip': ''}
    host = clean(raw.get('host')).strip()
    ip = clean(raw.get('ip')).strip()
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        pass
    # Only DNS-style names are case-insensitive; arbitrary labels stay exact.
    normalized = host.lower().rstrip('.') if re.fullmatch(r'[A-Za-z0-9_.:-]+', host) else host
    return {'site': site, 'kind': 'host' if host else 'source',
            'host': normalized if host else source, 'ip': ip}


def identity(site, source, raw):
    return hashlib.sha256(compact(scope(site, source, raw)).encode()).hexdigest()


def connect(path, write=False):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Device store must not be a symlink')
    db = sqlite3.connect(path.resolve().as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA trusted_schema=OFF')
    if not write:
        db.execute('PRAGMA query_only=ON')
    if db.execute('PRAGMA user_version').fetchone()[0] != VERSION:
        db.close(); raise ValueError('Unsupported device database version')
    return db


def initialize(path):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Device store must not be a symlink')
    if path.exists():
        with closing(connect(path, write=True)) as db, db:
            db.execute('SELECT id FROM devices LIMIT 1').fetchall()
            ensure_lifecycle(db)
        mark_enabled(path)
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('''CREATE TABLE devices(id TEXT PRIMARY KEY, scope_json TEXT NOT NULL,
            name TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
            retained_records INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'active'
            CHECK(state IN ('active','retired','permanent')), reason TEXT NOT NULL DEFAULT '', changed_utc INTEGER)''')
        db.execute('''CREATE TABLE aliases(device_id TEXT NOT NULL, source TEXT NOT NULL,
            host TEXT NOT NULL, ip TEXT NOT NULL, first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL, retained_records INTEGER NOT NULL,
            PRIMARY KEY(device_id,source,host,ip))''')
        db.execute('''CREATE TABLE audit(id INTEGER PRIMARY KEY, device_id TEXT NOT NULL,
            action TEXT NOT NULL, reason TEXT NOT NULL, changed_utc INTEGER NOT NULL)''')
        db.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
        ensure_lifecycle(db)
        db.execute('PRAGMA user_version=1')
    if os.name == 'posix': path.chmod(0o600)
    mark_enabled(path)


def mark_enabled(path):
    marker = Path(path).parent / 'enabled'
    if marker.is_symlink(): raise ValueError('Unexpected device marker symlink')
    marker.write_text('Device inventory configured.\n', encoding='ascii')
    if os.name == 'posix': marker.chmod(0o600)


def decode(row):
    item = dict(row)
    item['scope'] = json.loads(item.pop('scope_json'))
    if (hashlib.sha256(compact(item['scope']).encode()).hexdigest() != item['id'] or
            item['scope'].get('site') not in ('home', 'work') or
            item['state'] not in ('active', 'retired', 'permanent')):
        raise ValueError('Invalid stored device identity')
    return privacy.record(item)


def linked_groups(db, items):
    """Original identities stay immutable; DNS links only connect their behavior."""
    links = {}
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='device_links'").fetchone():
        links = {row['device_id']: dict(row) for row in db.execute('SELECT * FROM device_links')}
    grouped = {}
    for item in items:
        link = links.get(item['id']) if item['scope']['kind'] != 'nas-local' else None
        # Include site even for corrupted/stale maps; cross-site merges are impossible.
        key = (item['scope']['site'], 'linked' if link else 'single', link['cluster_id'] if link else item['id'])
        grouped.setdefault(key, []).append(item)
    return list(grouped.values()), links


def cluster_state(db, members):
    """Manual exclusions cover aliases; automatic exclusions await collection."""
    if any(item['state']=='permanent' for item in members): return 'permanent',False
    retired = [item for item in members if item['state']=='retired']
    active = any(item['state']=='active' for item in members)
    if not retired: return 'active',False
    for item in retired:
        row = db.execute('SELECT auto_retired_utc FROM lifecycle WHERE device_id=?', (item['id'],)).fetchone() if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='lifecycle'").fetchone() else None
        if not row or row[0] is None: return 'retired',False
    return ('active',True) if active else ('retired',False)


def inventory_rows(db):
    originals = [decode(row) for row in db.execute('SELECT * FROM devices ORDER BY name,id LIMIT ?', (MAX_DEVICES+1,))]
    if len(originals) > MAX_DEVICES: raise ValueError('Device limit exceeded')
    aliases = {}
    for row in db.execute('SELECT * FROM aliases ORDER BY last_seen DESC,source,host,ip LIMIT ?', (MAX_ALIASES+1,)):
        aliases.setdefault(row['device_id'], []).append(privacy.record(dict(row)))
    if sum(map(len, aliases.values())) > MAX_ALIASES: raise ValueError('Device alias limit exceeded')
    revisions = dict(db.execute('SELECT device_id,MAX(id) FROM audit GROUP BY device_id'))
    groups, links = linked_groups(db, originals)
    result = []
    rank = {'active': 0, 'retired': 1, 'permanent': 2}
    for members in groups:
        members.sort(key=lambda item: item['id'])
        primary = members[0]
        restricted = max(members, key=lambda item: (rank[item['state']], item['changed_utc'] or 0))
        state, partial_retirement = cluster_state(db,members)
        row = dict(primary)
        row.update(state=state, partial_retirement=partial_retirement, reason=restricted['reason'], changed_utc=restricted['changed_utc'],
            first_seen=min(item['first_seen'] for item in members), last_seen=max(item['last_seen'] for item in members),
            retained_records=sum(item['retained_records'] for item in members),
            members=[item['id'] for item in members], member_count=len(members),
            ips=sorted({item['scope']['ip'] for item in members if item['scope']['ip']}),
            original_names=sorted({item['name'] for item in members}),
            aliases=[alias for item in members for alias in aliases.get(item['id'], [])])
        evidence = [links[item['id']] for item in members if item['id'] in links]
        row['dns_name'] = max(evidence, key=lambda link: link['verified_utc'])['canonical'] if evidence else None
        row['dns_verified_utc'] = max((link['verified_utc'] for link in evidence), default=None)
        if row['dns_name']: row['name'] = row['dns_name']
        row['revision'] = hashlib.sha256(compact([[item['id'], item['state'], revisions.get(item['id'], 0),
            [(a['source'], a['host'], a['ip']) for a in aliases.get(item['id'], [])]] for item in members]).encode()).hexdigest()
        result.append(row)
    return sorted(result, key=lambda item: (item['name'], item['id']))


def state_change(db, members, state, action, reason, now, auto_received=None, auto_time=None, force=False):
    event_key = os.urandom(16).hex()
    for item in members:
        if item['state'] == state and not force: continue
        db.execute('UPDATE devices SET state=?,reason=?,changed_utc=? WHERE id=?', (state,reason,now,item['id']))
        db.execute('UPDATE lifecycle SET auto_retired_utc=?,auto_retired_received_utc=? WHERE device_id=?',
                   (auto_time, auto_received, item['id']))
        audit = db.execute('INSERT INTO audit(device_id,action,reason,changed_utc) VALUES(?,?,?,?)',
                           (item['id'],action,reason,now))
        db.execute('INSERT INTO device_action_groups VALUES(?,?,?)', (audit.lastrowid,event_key,len(members)))


def preserve_exclusions(db, now):
    rows = [decode(row) for row in db.execute('''SELECT d.*,l.auto_retired_utc,l.auto_retired_received_utc
        FROM devices d JOIN lifecycle l ON l.device_id=d.id''')]
    groups, _ = linked_groups(db, rows)
    for members in groups:
        permanent = next((item for item in members if item['state'] == 'permanent'), None)
        manual = next((item for item in members if item['state'] == 'retired' and item['auto_retired_utc'] is None), None)
        if permanent:
            state_change(db, members, 'permanent', 'linked_permanent', 'A verified device alias is permanently retired', now)
        elif manual:
            state_change(db, members, 'retired', 'linked_retire', 'A verified device alias is manually retired', now)
            # A manual exclusion must also override previously automatic markers.
            for item in members: db.execute('UPDATE lifecycle SET auto_retired_utc=NULL,auto_retired_received_utc=NULL WHERE device_id=?', (item['id'],))


def update_dns_links(db, result, now):
    """Keep consistent historical evidence; explicit contradictions detach safely."""
    preserve_exclusions(db, now)
    known = {row['id']: decode(row) for row in db.execute('SELECT * FROM devices')}
    bindings = {}
    for key, binding in result.get('bindings', {}).items():
        if key not in known or not isinstance(binding, dict): continue
        device = known[key]
        canonical = local_dns.hostname(binding.get('canonical'))
        expected = hashlib.sha256((device['scope']['site'] + '\0' + str(canonical)).encode()).hexdigest()
        if (device['scope']['kind'] == 'nas-local' or canonical is None or binding.get('cluster_key') != expected or
                binding.get('ip') != device['scope']['ip'] or local_dns.private_address(binding.get('ip')) is None or
                type(binding.get('verified_utc')) is not int or not now-300 <= binding['verified_utc'] <= now+300 or
                type(binding.get('expires_utc')) is not int or binding['expires_utc'] <= binding['verified_utc']):
            continue
        bindings[key] = binding
    for key in result.get('conflicts', []):
        if key in known:
            db.execute('DELETE FROM device_links WHERE device_id=?', (key,))
            db.execute('INSERT INTO dns_conflicts VALUES(?,?) ON CONFLICT(device_id) DO UPDATE SET checked_utc=excluded.checked_utc', (key,now))
    current = {row['device_id']: dict(row) for row in db.execute('SELECT * FROM device_links')}
    for key, binding in bindings.items():
        if key in current and current[key]['canonical'] != binding.get('canonical'):
            db.execute('DELETE FROM device_links WHERE device_id=?', (key,))
            current.pop(key)
    parent = {key: key for key in known}
    def find(key):
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key
    def union(a,b):
        if known[a]['scope']['site'] != known[b]['scope']['site']: return
        first, second = sorted((find(a),find(b)))
        parent[second] = first
    clusters = {}
    for key, link in current.items():
        if key not in known: continue
        group = (known[key]['scope']['site'], link['cluster_id'])
        if group in clusters: union(key, clusters[group])
        else: clusters[group] = key
    verified = {}
    for key, binding in bindings.items():
        if key not in known or known[key]['scope']['kind'] == 'nas-local': continue
        group = (known[key]['scope']['site'], binding['cluster_key'])
        if group in verified: union(key, verified[group])
        else: verified[group] = key
        current[key] = {'canonical': clean(binding['canonical']), 'verified_utc': int(binding['verified_utc']),
                        'expires_utc': int(binding.get('expires_utc', now))}
        db.execute('DELETE FROM dns_conflicts WHERE device_id=?', (key,))
    for key, link in current.items():
        if key not in known: continue
        db.execute('INSERT OR REPLACE INTO device_links VALUES(?,?,?,?,?)',
            (key,find(key),link['canonical'],link['verified_utc'],link['expires_utc']))
    preserve_exclusions(db, now)
    status = {key: result.get(key) for key in ('checked_utc','resolvers','errors','queries','complete')}
    status['conflicts'] = [row[0] for row in db.execute('SELECT device_id FROM dns_conflicts')]
    db.execute("INSERT INTO metadata VALUES('dns_status',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (compact(status),))


def snapshot(path, now=None, required=False):
    now = int(time.time() if now is None else now)
    if not Path(path).exists() and not required:
        items = []
    else:
        with closing(connect(path)) as db:
            original = [decode(row) for row in db.execute('SELECT * FROM devices ORDER BY id LIMIT ?', (MAX_DEVICES+1,))]
            if len(original) > MAX_DEVICES: raise ValueError('Device limit exceeded')
            groups, _ = linked_groups(db, original)
            items = []
            for members in groups:
                state, partial = cluster_state(db,members)
                if partial: items.extend(item for item in members if item['state']!='active')
                elif state != 'active': items.extend(dict(item,state=state) for item in members)
    if len(items) > MAX_DEVICES: raise ValueError('Device limit exceeded')
    return {'evaluated_utc': now, 'revision': hashlib.sha256(compact(items).encode()).hexdigest(),
            'retired': {item['id']: item for item in items}}


def refresh(base, now=None, seconds=90, collection=None, dns_lookup=None, verify_dns=False):
    """Refresh observations from retained sanitized history; preserve every choice."""
    base = Path(base); path = database_path(base)
    now = int(time.time() if now is None else now)
    deadline = time.monotonic() + seconds
    devices, aliases = {}, {}
    trusted_sites = healthy_collection_sites(collection, now)
    untrusted_sites = set()
    untrusted_devices = set()
    history = base / 'events.sqlite'
    if history.is_symlink(): raise ValueError('Unexpected history symlink')
    with closing(sqlite3.connect(history.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        for site, source, observed, received, event_time, text in db.execute('SELECT site,source,COALESCE(r_utcsec,utcsec,first_seen_utc),r_utcsec,utcsec,raw_json FROM events'):
            if time.monotonic() >= deadline: raise TimeoutError('Device inventory refresh exceeded its deadline')
            try:
                raw = json.loads(text)
                if not isinstance(raw, dict) or type(observed) is not int:
                    untrusted_sites.add(site)
                    continue
                value = scope(site, source, raw)
            except (ValueError, TypeError):
                untrusted_sites.add(site)
                continue  # The reporting scan separately accounts for malformed rows.
            key = hashlib.sha256(compact(value).encode()).hexdigest()
            name = site.title()+' NAS' if value['kind']=='nas-local' else clean(raw.get('host') or source)
            item = devices.setdefault(key, {'scope': value, 'name': name, 'first': observed, 'last': observed, 'count': 0, 'received': None})
            # Local NAS records are created on the receiver and lack r_utcsec.
            # Never use coordinator import time or a remote sender's clock here.
            if received is None and value['kind'] == 'nas-local': received = event_time
            if type(received) is int and 0 < received <= now + 300:
                item['received'] = max(item['received'] or 0, received)
            else:
                untrusted_devices.add(key)
            item['first'] = min(item['first'], observed)
            if observed >= item['last']: item['name'], item['last'] = name, observed
            item['count'] += 1
            alias = (key, source, clean(raw.get('host')), clean(raw.get('ip')))
            seen = aliases.setdefault(alias, [observed, observed, 0])
            seen[0], seen[1], seen[2] = min(seen[0], observed), max(seen[1], observed), seen[2]+1
            if len(devices)>MAX_DEVICES or len(aliases)>MAX_ALIASES:
                raise ValueError('Device inventory size limit exceeded')
    dns_result = None
    if verify_dns or (collection is not None and trusted_sites):
        remaining = max(0, min(8, deadline - time.monotonic() - 1))
        observations = [dict(id=key, scope=item['scope']) for key,item in devices.items()
                        if verify_dns or item['scope']['site'] in trusted_sites]
        try:
            dns_result = (dns_lookup or local_dns.resolve_clusters)(observations, now=now, seconds=remaining)
        except Exception as error:
            dns_result = {'checked_utc': now, 'bindings': {}, 'conflicts': [], 'resolvers': [],
                'errors': ['Local DNS verification unavailable (' + type(error).__name__ + ')'], 'queries': 0, 'complete': False}
    with closing(connect(path, write=True)) as db, db:
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        db.execute('BEGIN IMMEDIATE')
        ensure_lifecycle(db)
        settings = read_settings(db)
        existing = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        new = sum(db.execute('SELECT 1 FROM devices WHERE id=?', (key,)).fetchone() is None for key in devices)
        if existing+new > MAX_DEVICES: raise ValueError('Device inventory size limit exceeded')
        db.execute('UPDATE devices SET retained_records=0')
        db.execute('UPDATE aliases SET retained_records=0')
        for key, item in devices.items():
            if time.monotonic() >= deadline: raise TimeoutError('Device inventory refresh exceeded its deadline')
            existed = db.execute('SELECT 1 FROM devices WHERE id=?', (key,)).fetchone() is not None
            db.execute('''INSERT INTO devices(id,scope_json,name,first_seen,last_seen,retained_records) VALUES(?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET first_seen=MIN(first_seen,excluded.first_seen),
                name=CASE WHEN excluded.last_seen>=last_seen THEN excluded.name ELSE name END,
                last_seen=MAX(last_seen,excluded.last_seen),retained_records=excluded.retained_records''',
                (key, compact(item['scope']), item['name'], item['first'], item['last'], item['count']))
            if not existed:
                db.execute('INSERT INTO lifecycle(device_id,added_utc) VALUES(?,?)', (key, now))
            if item['received'] is not None:
                db.execute('''UPDATE lifecycle SET received_utc=MAX(COALESCE(received_utc,0),?)
                    WHERE device_id=?''', (item['received'], key))
        for alias, values in aliases.items():
            if time.monotonic() >= deadline: raise TimeoutError('Device inventory refresh exceeded its deadline')
            db.execute('''INSERT INTO aliases VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id,source,host,ip)
                DO UPDATE SET first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),
                retained_records=excluded.retained_records''', (*alias, *values))
        if db.execute('SELECT COUNT(*) FROM aliases').fetchone()[0]>MAX_ALIASES:
            raise ValueError('Device alias limit exceeded')
        if dns_result is not None: update_dns_links(db, dns_result, now)
        preserve_exclusions(db, now)
        eligible_sites = trusted_sites - untrusted_sites
        conflicted = {row[0] for row in db.execute('SELECT device_id FROM dns_conflicts')}
        original = [decode(row) for row in db.execute('''SELECT d.*,l.received_utc,l.auto_retired_utc,l.auto_retired_received_utc
                FROM devices d JOIN lifecycle l ON l.device_id=d.id''')]
        groups, _ = linked_groups(db, original)
        for members in groups:
            if time.monotonic() >= deadline: raise TimeoutError('Device inventory refresh exceeded its deadline')
            if members[0]['scope']['site'] not in eligible_sites: continue
            if any(item['id'] in untrusted_devices | conflicted for item in members): continue
            stamps = [item['received_utc'] for item in members if type(item['received_utc']) is int]
            received = max(stamps, default=0)
            if not received or received > now: continue
            grace = 0
            for item in members:
                latest = db.execute('SELECT action FROM audit WHERE device_id=? ORDER BY id DESC LIMIT 1', (item['id'],)).fetchone()
                if latest and latest[0] == 'restore': grace = max(grace, item['changed_utc'] or 0)
            states = {item['state'] for item in members}
            retired = [item for item in members if item['state']=='retired']
            automatic = bool(retired) and all(item['auto_retired_utc'] is not None for item in retired)
            cutoff = now - settings['days'] * 86400
            retire_time = max((item['auto_retired_utc'] or 0 for item in retired),default=0) if states=={'retired'} else 0
            if (states <= {'active','retired'} and automatic and received > max(
                    retire_time, max(item['auto_retired_received_utc'] or 0 for item in retired), cutoff)):
                reason = ('New NAS-received logs arrived after automatic retirement' if states=={'retired'}
                          else 'A verified device alias has recent NAS-received logs')
                state_change(db, members, 'active', 'auto_restore', reason, now)
            elif (settings['enabled'] and (states=={'active'} or (states=={'active','retired'} and automatic))
                    and max(received, grace) <= cutoff):
                reason = 'No NAS-received logs for at least %d days' % settings['days']
                state_change(db, members, 'retired', 'auto_retire', reason, now, received, now)
        db.execute("INSERT INTO metadata VALUES('refreshed_utc',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
        if collection is not None:
            evaluation = {'checked_utc': now, 'sites_checked': sorted(eligible_sites),
                'sites_paused': sorted(set(collection) - eligible_sites),
                'devices_paused': len(untrusted_devices | conflicted)}
            db.execute("INSERT INTO metadata VALUES('lifecycle_evaluation',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (compact(evaluation),))
    return {'devices_observed': len(devices), 'aliases_observed': len(aliases), 'refreshed_utc': now,
            'lifecycle_sites_checked': sorted(eligible_sites)}


def catalog(base, now=None):
    now = int(time.time() if now is None else now)
    with closing(connect(database_path(base))) as db:
        db.execute('BEGIN')
        rows = inventory_rows(db)
        dns_status = db.execute("SELECT value FROM metadata WHERE key='dns_status'").fetchone()
        dns_status = json.loads(dns_status[0]) if dns_status else None
        refreshed = db.execute("SELECT value FROM metadata WHERE key='refreshed_utc'").fetchone()
    registry_path = Path(base)/'site-registry.json'
    registry = {}
    if registry_path.exists():
        if registry_path.is_symlink() or registry_path.stat().st_size>4*1024**2: raise ValueError('Invalid source registry')
        registry = json.loads(registry_path.read_text(encoding='utf-8')).get('sites', {})
    for item in rows:
        item['dns_conflict'] = any(member in (dns_status or {}).get('conflicts', []) for member in item['members'])
        entry = registry.get(item['scope']['site'], {})
        known = entry.get('sources', {})
        item['collection_status'] = entry.get('status', 'unknown')
        item['collection_warnings'] = entry.get('warnings', [])
        for alias in item['aliases']:
            source = known.get(alias['source'], {})
            alias['discovery_status'] = source.get('discovery_status', 'present' if source else 'historical')
            alias['has_live_database'] = source.get('has_live_database', False)
        if item['last_seen'] > now+300: item['observation'] = 'Timestamp ahead of current time'
        elif now-item['last_seen'] <= 86400: item['observation'] = 'Recent messages'
        else: item['observation'] = 'Quiet / historical'
    return {'devices': rows, 'refreshed_utc': int(refreshed[0]) if refreshed else None, 'dns_status': dns_status}


def change(base, key, action, revision, reason='', now=None):
    if action not in ('retire', 'restore', 'permanent'): raise ValueError('Invalid device action')
    if not re.fullmatch('[a-f0-9]{64}', key): raise ValueError('Invalid device identity')
    if not isinstance(reason, str) or len(reason)>240: raise ValueError('Reason must be 240 characters or fewer')
    now = int(time.time() if now is None else now)
    reason = privacy.text(reason).strip()
    with closing(connect(database_path(base), write=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        ensure_lifecycle(db)
        item = next((item for item in inventory_rows(db) if key in item['members']), None)
        if item is None: raise ValueError('Device not found')
        if revision != item['revision']: raise ValueError('Device or DNS aliases changed; reload the confirmation page')
        allowed = {'retire': ('active','retired'), 'restore': ('retired','active'), 'permanent': ('retired','permanent')}
        before, after = allowed[action]
        if item['state'] != before: raise ValueError('That action is not available for this device')
        members = [decode(db.execute('SELECT * FROM devices WHERE id=?', (identity,)).fetchone()) for identity in item['members']]
        state_change(db, members, after, action, reason, now, force=True)
    return after


def source_check(info, now, freshness_hours, checker):
    """Silence/discovery is informational; transport/export failures remain warnings."""
    info = dict(info)
    if info.get('discovery_status') in ('historical','absent'):
        result = dict(info, warnings=list(info.get('warnings', [])))
    else:
        result = checker(info, now, freshness_hours)
    result['notices'] = list(info.get('notices', []))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('initialize','refresh','refresh-dns','status'))
    parser.add_argument('--data-dir', type=Path, default=Path('/var/lib/ai-monitor'))
    args = parser.parse_args()
    if args.command == 'initialize':
        initialize(database_path(args.data_dir)); print('Device store initialized; existing choices preserved.')
    elif args.command in ('refresh','refresh-dns'):
        print(json.dumps(refresh(args.data_dir, verify_dns=args.command=='refresh-dns')))
    else:
        view = catalog(args.data_dir)
        print(json.dumps({'refreshed_utc': view['refreshed_utc'],
            'states': {state: sum(d['state']==state for d in view['devices']) for state in ('active','retired','permanent')}}))
