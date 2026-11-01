#!/usr/bin/env python3
"""Exact recurring-group suppression rules. Never deletes log records."""
import argparse
from contextlib import closing
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

_spec = importlib.util.spec_from_file_location('filter_privacy', Path(__file__).with_name('sanitize_logs.py'))
privacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(privacy)
VERSION = 1
MATCHER = 'group-sha256-v1'
MAX_ACTIVE = 1000


def database_path(base):
    return Path(base) / 'suppressions' / 'filters.sqlite'


def connect(path, write=False):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Filter database must not be a symlink')
    db = sqlite3.connect(path.resolve().as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA trusted_schema=OFF')
    if not write:
        db.execute('PRAGMA query_only=ON')
    if db.execute('PRAGMA user_version').fetchone()[0] != VERSION:
        db.close()
        raise ValueError('Unsupported filter database version')
    return db


def initialize(path):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Filter database must not be a symlink')
    if path.exists():
        with closing(connect(path)) as db:
            db.execute('SELECT id FROM filters LIMIT 1').fetchall()
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('''CREATE TABLE filters (
            id TEXT PRIMARY KEY, matcher TEXT NOT NULL, signature TEXT NOT NULL,
            site TEXT NOT NULL, source TEXT NOT NULL, scope_json TEXT NOT NULL,
            reason TEXT NOT NULL, created_utc INTEGER NOT NULL, expires_utc INTEGER,
            deleted_utc INTEGER)''')
        db.execute('CREATE INDEX filter_signature ON filters(signature,deleted_utc,expires_utc)')
        db.execute('''CREATE TABLE audit (
            id INTEGER PRIMARY KEY, filter_id TEXT NOT NULL, action TEXT NOT NULL,
            changed_utc INTEGER NOT NULL)''')
        db.execute('PRAGMA user_version=1')
    if os.name == 'posix':
        path.chmod(0o600)


def decode(row):
    rule = dict(row)
    if (rule['matcher'] != MATCHER or not re.fullmatch(r'[0-9a-f]{64}', rule['signature']) or
            not re.fullmatch(r'[0-9a-f]{32}', rule['id']) or rule['site'] not in ('home', 'work') or
            not isinstance(rule['source'], str) or not rule['source'] or len(rule['source']) > 512):
        raise ValueError('Invalid stored filter')
    rule['scope'] = privacy.record(json.loads(rule.pop('scope_json')))
    if not isinstance(rule['scope'], dict):
        raise ValueError('Invalid filter scope')
    rule['reason'] = privacy.text(rule['reason'])[:240]
    for name in ('created_utc', 'expires_utc', 'deleted_utc'):
        if rule[name] is not None and (not isinstance(rule[name], int) or rule[name] < 0):
            raise ValueError('Invalid filter time')
    return rule


def active(rule, now):
    return rule['deleted_utc'] is None and (rule['expires_utc'] is None or rule['expires_utc'] > now)


def snapshot(path, now=None):
    now = int(time.time() if now is None else now)
    if not Path(path).exists():
        rules = []
    else:
        with closing(connect(path)) as db:
            rules = [decode(row) for row in db.execute('''SELECT * FROM filters
                WHERE deleted_utc IS NULL AND (expires_utc IS NULL OR expires_utc>?)
                ORDER BY signature,id LIMIT ?''', (now, MAX_ACTIVE + 1))]
    if len(rules) > MAX_ACTIVE:
        raise ValueError('Too many active filters')
    signatures = [rule['signature'] for rule in rules]
    if len(set(signatures)) != len(signatures):
        raise ValueError('Duplicate active filters')
    revision = hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'matcher': MATCHER, 'evaluated_utc': now, 'revision': revision, 'rules': rules}


def list_rules(path):
    with closing(connect(path)) as db:
        return [decode(row) for row in db.execute('SELECT * FROM filters WHERE deleted_utc IS NULL ORDER BY created_utc DESC,id')]


def scope_from_group(site, group):
    signature = group.get('suppression_key', '')
    if (site not in ('home', 'work') or not isinstance(signature, str) or
            re.fullmatch(r'[0-9a-f]{64}', signature) is None or
            group.get('id') != site + '-' + signature[:16]):
        raise ValueError('This report lacks a verified recurring-group identifier; wait for the next build')
    source = group.get('source')
    if not isinstance(source, str) or not source or len(source) > 512:
        raise ValueError('Invalid source')
    fields = ('host', 'ip', 'program', 'reported_level', 'reported_priority', 'tag',
              'message', 'message_truncated', 'example_message', 'rollup_rule',
              'grouping_note', 'structured_transfer_rollup', 'normalized_prefix_timestamp',
              'normalized_kernel_uptime')
    scope = privacy.record({key: group[key] for key in fields if key in group})
    scope.update(site=site, source=source)
    if len(json.dumps(scope).encode()) > 16384:
        raise ValueError('Filter scope is too large')
    return signature, source, scope


def create(path, site, group, reason='', duration='forever', now=None):
    now = int(time.time() if now is None else now)
    durations = {'forever': None, '1d': 86400, '7d': 7*86400, '30d': 30*86400}
    if duration not in durations:
        raise ValueError('Invalid filter duration')
    if not isinstance(reason, str) or len(reason) > 240:
        raise ValueError('Reason must be 240 characters or fewer')
    signature, source, scope = scope_from_group(site, group)
    reason = privacy.text(reason).strip()
    expires = now + durations[duration] if durations[duration] is not None else None
    with closing(connect(path, write=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        existing = db.execute('''SELECT * FROM filters WHERE signature=? AND deleted_utc IS NULL
            AND (expires_utc IS NULL OR expires_utc>?)''', (signature, now)).fetchone()
        if existing:
            return decode(existing), False
        count = db.execute('''SELECT COUNT(*) FROM filters WHERE deleted_utc IS NULL
            AND (expires_utc IS NULL OR expires_utc>?)''', (now,)).fetchone()[0]
        if count >= MAX_ACTIVE:
            raise ValueError('Active filter limit reached; remove unused filters first')
        identity = uuid.uuid4().hex
        db.execute('INSERT INTO filters VALUES(?,?,?,?,?,?,?,?,?,NULL)',
                   (identity, MATCHER, signature, site, source, json.dumps(scope), reason, now, expires))
        db.execute('INSERT INTO audit(filter_id,action,changed_utc) VALUES(?,?,?)', (identity, 'created', now))
        return decode(db.execute('SELECT * FROM filters WHERE id=?', (identity,)).fetchone()), True


def delete(path, identity, now=None):
    now = int(time.time() if now is None else now)
    if not isinstance(identity, str) or re.fullmatch(r'[0-9a-f]{32}', identity) is None:
        raise ValueError('Invalid filter identifier')
    with closing(connect(path, write=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        changed = db.execute('UPDATE filters SET deleted_utc=? WHERE id=? AND deleted_utc IS NULL',
                             (now, identity)).rowcount
        if changed:
            db.execute('INSERT INTO audit(filter_id,action,changed_utc) VALUES(?,?,?)', (identity, 'deleted', now))
        return bool(changed)


def matching(rules, site, group):
    rule = rules.get(group.get('suppression_key'))
    return rule if rule and rule['site'] == site and rule['source'] == group.get('source') else None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['initialize'])
    parser.add_argument('--data-dir', type=Path, default=Path('/var/lib/ai-monitor'))
    args = parser.parse_args()
    initialize(database_path(args.data_dir))
    print('Filter database initialized; existing filters preserved.')
