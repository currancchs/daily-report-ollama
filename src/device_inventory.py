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
VERSION = 1
MAX_DEVICES = 10000
MAX_ALIASES = 20000


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
        with closing(connect(path)) as db:
            db.execute('SELECT id FROM devices LIMIT 1').fetchall()
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


def snapshot(path, now=None, required=False):
    now = int(time.time() if now is None else now)
    if not Path(path).exists() and not required:
        items = []
    else:
        with closing(connect(path)) as db:
            items = [decode(row) for row in db.execute("SELECT * FROM devices WHERE state<>'active' ORDER BY id LIMIT ?", (MAX_DEVICES+1,))]
    if len(items) > MAX_DEVICES: raise ValueError('Device limit exceeded')
    return {'evaluated_utc': now, 'revision': hashlib.sha256(compact(items).encode()).hexdigest(),
            'retired': {item['id']: item for item in items}}


def refresh(base, now=None, seconds=90):
    """Refresh observations from retained sanitized history; preserve every choice."""
    base = Path(base); path = database_path(base)
    now = int(time.time() if now is None else now)
    deadline = time.monotonic() + seconds
    devices, aliases = {}, {}
    history = base / 'events.sqlite'
    if history.is_symlink(): raise ValueError('Unexpected history symlink')
    with closing(sqlite3.connect(history.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        for site, source, observed, text in db.execute('SELECT site,source,COALESCE(r_utcsec,utcsec,first_seen_utc),raw_json FROM events'):
            if time.monotonic() >= deadline: raise TimeoutError('Device inventory refresh exceeded its deadline')
            try:
                raw = json.loads(text)
                if not isinstance(raw, dict) or type(observed) is not int: continue
                value = scope(site, source, raw)
            except (ValueError, TypeError):
                continue  # The reporting scan separately accounts for malformed rows.
            key = hashlib.sha256(compact(value).encode()).hexdigest()
            name = site.title()+' NAS' if value['kind']=='nas-local' else clean(raw.get('host') or source)
            item = devices.setdefault(key, {'scope': value, 'name': name, 'first': observed, 'last': observed, 'count': 0})
            item['first'] = min(item['first'], observed)
            if observed >= item['last']: item['name'], item['last'] = name, observed
            item['count'] += 1
            alias = (key, source, clean(raw.get('host')), clean(raw.get('ip')))
            seen = aliases.setdefault(alias, [observed, observed, 0])
            seen[0], seen[1], seen[2] = min(seen[0], observed), max(seen[1], observed), seen[2]+1
            if len(devices)>MAX_DEVICES or len(aliases)>MAX_ALIASES:
                raise ValueError('Device inventory size limit exceeded')
    with closing(connect(path, write=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        existing = db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        new = sum(db.execute('SELECT 1 FROM devices WHERE id=?', (key,)).fetchone() is None for key in devices)
        if existing+new > MAX_DEVICES: raise ValueError('Device inventory size limit exceeded')
        db.execute('UPDATE devices SET retained_records=0')
        db.execute('UPDATE aliases SET retained_records=0')
        for key, item in devices.items():
            db.execute('''INSERT INTO devices(id,scope_json,name,first_seen,last_seen,retained_records) VALUES(?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET first_seen=MIN(first_seen,excluded.first_seen),
                name=CASE WHEN excluded.last_seen>=last_seen THEN excluded.name ELSE name END,
                last_seen=MAX(last_seen,excluded.last_seen),retained_records=excluded.retained_records''',
                (key, compact(item['scope']), item['name'], item['first'], item['last'], item['count']))
        for alias, values in aliases.items():
            db.execute('''INSERT INTO aliases VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id,source,host,ip)
                DO UPDATE SET first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),
                retained_records=excluded.retained_records''', (*alias, *values))
        if db.execute('SELECT COUNT(*) FROM aliases').fetchone()[0]>MAX_ALIASES:
            raise ValueError('Device alias limit exceeded')
        db.execute("INSERT INTO metadata VALUES('refreshed_utc',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now),))
    return {'devices_observed': len(devices), 'aliases_observed': len(aliases), 'refreshed_utc': now}


def catalog(base, now=None):
    now = int(time.time() if now is None else now)
    with closing(connect(database_path(base))) as db:
        db.execute('BEGIN')
        rows = [decode(row) for row in db.execute('SELECT * FROM devices ORDER BY name,id LIMIT ?', (MAX_DEVICES+1,))]
        if len(rows)>MAX_DEVICES: raise ValueError('Device limit exceeded')
        aliases = {}
        alias_rows = db.execute('SELECT * FROM aliases ORDER BY last_seen DESC,source,host,ip LIMIT ?', (MAX_ALIASES+1,)).fetchall()
        if len(alias_rows)>MAX_ALIASES: raise ValueError('Device alias limit exceeded')
        for row in alias_rows:
            aliases.setdefault(row['device_id'], []).append(privacy.record(dict(row)))
        revisions = dict(db.execute('SELECT device_id,MAX(id) FROM audit GROUP BY device_id'))
        refreshed = db.execute("SELECT value FROM metadata WHERE key='refreshed_utc'").fetchone()
    registry_path = Path(base)/'site-registry.json'
    registry = {}
    if registry_path.exists():
        if registry_path.is_symlink() or registry_path.stat().st_size>4*1024**2: raise ValueError('Invalid source registry')
        registry = json.loads(registry_path.read_text(encoding='utf-8')).get('sites', {})
    for item in rows:
        item['aliases'] = aliases.get(item['id'], [])
        item['revision'] = hashlib.sha256(compact([item['id'], item['state'], revisions.get(item['id'],0),
            [(a['source'],a['host'],a['ip']) for a in item['aliases']]]).encode()).hexdigest()
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
    return {'devices': rows, 'refreshed_utc': int(refreshed[0]) if refreshed else None}


def change(base, key, action, revision, reason='', now=None):
    if action not in ('retire', 'restore', 'permanent'): raise ValueError('Invalid device action')
    if not re.fullmatch('[a-f0-9]{64}', key): raise ValueError('Invalid device identity')
    if not isinstance(reason, str) or len(reason)>240: raise ValueError('Reason must be 240 characters or fewer')
    now = int(time.time() if now is None else now)
    reason = privacy.text(reason).strip()
    with closing(connect(database_path(base), write=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM devices WHERE id=?', (key,)).fetchone()
        if row is None: raise ValueError('Device not found')
        item = decode(row)
        aliases = db.execute('SELECT source,host,ip FROM aliases WHERE device_id=? ORDER BY last_seen DESC,source,host,ip', (key,)).fetchall()
        revision_id = db.execute('SELECT COALESCE(MAX(id),0) FROM audit WHERE device_id=?',(key,)).fetchone()[0]
        current = hashlib.sha256(compact([key,item['state'],revision_id,[tuple(a) for a in aliases]]).encode()).hexdigest()
        if revision != current: raise ValueError('Device changed; reload the confirmation page')
        allowed = {'retire': ('active','retired'), 'restore': ('retired','active'), 'permanent': ('retired','permanent')}
        before, after = allowed[action]
        if item['state'] != before: raise ValueError('That action is not available for this device')
        db.execute('UPDATE devices SET state=?,reason=?,changed_utc=? WHERE id=?', (after,reason,now,key))
        db.execute('INSERT INTO audit(device_id,action,reason,changed_utc) VALUES(?,?,?,?)', (key,action,reason,now))
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
    parser.add_argument('command', choices=('initialize','refresh','status'))
    parser.add_argument('--data-dir', type=Path, default=Path('/var/lib/ai-monitor'))
    args = parser.parse_args()
    if args.command == 'initialize':
        initialize(database_path(args.data_dir)); print('Device store initialized; existing choices preserved.')
    elif args.command == 'refresh': print(json.dumps(refresh(args.data_dir)))
    else:
        view = catalog(args.data_dir)
        print(json.dumps({'refreshed_utc': view['refreshed_utc'],
            'states': {state: sum(d['state']==state for d in view['devices']) for state in ('active','retired','permanent')}}))
