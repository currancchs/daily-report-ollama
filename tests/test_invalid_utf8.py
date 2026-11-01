import ast
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


site = load('nas_export_site')
collect = load('collect_sites')
daily = load('daily_report')
recent = site.recent
NOW = int(time.time())
BAD = b'wifi1: caf\xc3\xa9\xff\x15'
BLOB = b'original blob\xff'
VALID = 'Valid cafe: caf\u00e9 / \u6771\u4eac'
for name in ('nas_export_recent', 'nas_export_site'):
    ast.parse((ROOT / 'src' / (name + '.py')).read_text(), feature_version=(3, 8))

with tempfile.TemporaryDirectory(dir=ROOT / 'work') as temp:
    base = Path(temp)
    nas = base / 'Logs'
    nas.mkdir()
    signatures = {}
    originals = {}
    for table, field in (('logs', 'msg'), ('connection_log', 'luser'),
                         ('general_log', 'msg'), ('transfer_log', 'fname')):
        path = nas / table / ('SYNOSYSLOGDB_' + table + '.DB')
        path.parent.mkdir()
        fields = recent.TABLE_FIELDS[table]
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE ' + table + ' (' + ','.join(
                name + (' INTEGER PRIMARY KEY' if name == 'id' else ' INTEGER' if name in ('utcsec', 'r_utcsec') else ' TEXT')
                for name in fields) + ')')
            db.execute('INSERT INTO ' + table + '(id,host,utcsec,' + field + ') VALUES(1,?,?,CAST(? AS TEXT))',
                       ('device', NOW-30, BAD))
            if table == 'logs':
                db.execute('UPDATE logs SET host=CAST(? AS TEXT) WHERE id=1', (b'host\xfe',))
                db.execute('INSERT INTO logs(id,host,utcsec,msg) VALUES(2,?,?,?)', ('device', NOW-30, VALID))
                db.execute('INSERT INTO logs(id,host,utcsec,msg) VALUES(3,?,?,?)', ('device', NOW-30, BLOB))
            try:
                db.execute('SELECT ' + field + ' FROM ' + table + ' WHERE id=1').fetchone()
                raise AssertionError('Fixture did not reproduce the UTF-8 decoding error')
            except sqlite3.OperationalError as error:
                assert 'decode' in str(error)
        signatures[path] = hashlib.sha256(path.read_bytes()).hexdigest()
        originals[table] = (path, field)

    first = site.export_site(nas, 'home', now=NOW)
    assert first['status'] == 'complete' and first['errors'] == []
    assert sum(a['rows_exported'] for a in first['assets']) == 6
    assert sum(a['invalid_utf8_rows'] for a in first['assets']) == 4

    def getter(site, remote, target, auth_dir):
        shutil.copyfile(nas / 'AI-Monitor-Exports' / remote, target)

    coordinator = base / 'coordinator'
    result = collect.collect(coordinator, sites=('home',), getter=getter)
    assert result['home']['status'] == 'complete' and result['home']['new_rows'] == 6
    registry = json.loads((coordinator / 'site-registry.json').read_text())
    assert all(any('invalid UTF-8' in w for w in info['warnings'])
               for info in registry['sites']['home']['sources'].values())
    with closing(sqlite3.connect(coordinator / 'events.sqlite')) as db:
        entries = [(source, json.loads(raw)) for source, raw in db.execute('SELECT source,raw_json FROM events')]
    for table, (path, field) in originals.items():
        source_name = {'logs': 'logs', 'connection_log': 'NAS/connections',
                       'general_log': 'NAS/system', 'transfer_log': 'NAS/transfers'}[table]
        row = next(row for source, row in entries if source == source_name and row['id'] == 1)
        value = row['msg'] if table == 'logs' else json.loads(row['msg'])[field]
        wrapped = json.loads(value)
        assert wrapped['synology_invalid_utf8'] is True
        assert wrapped['original_bytes_hex'] == '[OMITTED: encoded bytes; original on NAS]'
        assert wrapped['text_preview'] == 'wifi1: caf\u00e9\\xff'
        assert hashlib.sha256(path.read_bytes()).hexdigest() == signatures[path]
    raw_rows = {r['id']: r for s, r in entries if s == 'logs'}
    assert raw_rows[2]['msg'] == VALID
    assert raw_rows[3]['msg'] == {'sqlite_blob_hex': '[OMITTED: encoded bytes; original on NAS]'}
    assert json.loads(raw_rows[1]['host'])['original_bytes_hex'] == '[OMITTED: encoded bytes; original on NAS]'
    repeated = site.export_site(nas, 'home', now=NOW)
    result = collect.collect(coordinator, sites=('home',), getter=getter)
    assert result['home']['new_rows'] == 0 and result['home']['duplicate_rows'] == 6
    report = daily.collect(coordinator / 'events.sqlite', coordinator, now=NOW)
    assert report['sites']['home']['rows_in_window'] == 6
    assert any('invalid UTF-8' in warning for info in report['sites']['home']['sources'].values()
               for warning in info['warnings'])
    rendered = daily.render(report, daily.ZoneInfo('America/New_York'))
    assert 'invalid UTF-8' in rendered
    # Old manifests remain compatible; malformed new counts are rejected.
    old = json.loads(json.dumps(repeated))
    for asset in old['assets']:
        asset.pop('invalid_utf8_rows')
    collect.validate_manifest(old, 'home')
    old['assets'][0]['invalid_utf8_rows'] = -1
    try:
        collect.validate_manifest(old, 'home')
        raise AssertionError('Negative count accepted')
    except ValueError:
        pass

print('PASS: four NAS schemas; valid Unicode retained, encoded original bytes omitted from sanitized history, originals unchanged on NAS; control removal; stable deduplication and visible report warnings; old manifest compatibility; NAS Python 3.8 syntax.')
