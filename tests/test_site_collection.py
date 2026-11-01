import ast
from contextlib import closing, redirect_stdout
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


site_export = load('site_export', 'nas_export_site.py')
collector = load('collector', 'collect_sites.py')
preview = load('registry_preview', 'preview_report.py')
recent = site_export.recent
NOW = int(time.time())
DATE = datetime.fromtimestamp(NOW, timezone.utc).strftime('%Y-%m-%d')


def create_db(path, table='logs', message='test record'):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = recent.TABLE_FIELDS[table]
    types = {'id': 'INTEGER PRIMARY KEY', 'utcsec': 'INTEGER', 'r_utcsec': 'INTEGER',
             'isdir': 'BOOLEAN', 'fsize': 'INTEGER'}
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('CREATE TABLE ' + table + ' (' + ','.join(field + ' ' + types.get(field, 'TEXT') for field in fields) + ')')
        row = {'id': 1, 'host': 'test-host', 'utcsec': NOW-60, 'r_utcsec': NOW-59,
               'luser': 'alice', 'msg': message, 'prog': 'test', 'llevel': 'info',
               'ip': '192.0.2.1', 'event': 'download', 'fname': '/test/file.txt', 'fsize': 42, 'isdir': 0}
        db.execute('INSERT INTO ' + table + ' VALUES (' + ','.join('?' for _ in fields) + ')', [row.get(field) for field in fields])


for filename in ('nas_export_recent.py', 'nas_export_site.py'):
    ast.parse((ROOT / 'src' / filename).read_text(), feature_version=(3, 8))

with tempfile.TemporaryDirectory(dir=ROOT / 'work') as temporary:
    workspace = Path(temporary)
    nas = {site: workspace / site / 'Logs' for site in ('home', 'work')}
    coordinator = workspace / 'coordinator'
    for site, root in nas.items():
        root.mkdir(parents=True)
        device = root / ('ProxmoxVE' if site == 'home' else 'work-hypervisor')
        live = device / ('SYNOSYSLOGDB_' + device.name + '.DB')
        create_db(live)
        create_db(root / 'SYNOSYSLOGDB__LOCALARCH.DB')
        create_db(root / 'SYNOSYSLOGDB__LOCALARCH_CON', 'connection_log')
        create_db(root / 'SYNOSYSLOGDB__LOCALARCH_SYS', 'general_log')
        create_db(root / 'SYNOSYSLOGDB__LOCALARCH_XFER', 'transfer_log')
        create_db(root / 'homeassistant/SYNOSYSLOGDB_homeassistant.DB')
        # A source with no live database is still found through its dated archive.
        archive_only = root / 'switch'
        archive_only.mkdir()
        with zipfile.ZipFile(archive_only / (DATE + '_' + DATE + '.ZIP'), 'w', zipfile.ZIP_DEFLATED) as zipped:
            zipped.write(live, '../../escape.DB')
            zipped.writestr('log.txt', 'A duplicated text representation must not be imported')
        with zipfile.ZipFile(device / (DATE + '_' + DATE + '.ZIP'), 'w', zipfile.ZIP_DEFLATED) as zipped:
            zipped.write(live, 'archive.DB')
        # A large/invalid historical archive is filtered before opening.
        old = device / '2000-01-01_2000-01-02.ZIP'
        old.write_bytes(b'not a ZIP, must not be opened')
        os.utime(old, (NOW-30*86400, NOW-30*86400))
        if site == 'work':
            shutil.copyfile(root / 'SYNOSYSLOGDB__LOCALARCH_SYS', root / (DATE + '_' + DATE + '_LOCAL_SYS'))
            shutil.copyfile(live, root / (DATE + '_' + DATE + '.DB'))
        (root / 'empty-device').mkdir()
        result = site_export.export_site(root, site, now=NOW)
        assert result['status'] == 'complete', result['errors']
        assert result['skipped_old_archives'] == 1
        assert 'empty-device' in result['empty_folders']
        assert result['sources']['switch']['has_live_database'] is False
        assert result['sources']['NAS/system']['has_live_database'] is True
        for asset in result['assets']:
            path = root / 'AI-Monitor-Exports' / asset['file']
            assert path.exists() and site_export.sha256(path) == asset['sha256']
        assert not (workspace / 'escape.DB').exists()

    def getter(site, remote, local, auth_dir):
        shutil.copyfile(nas[site] / 'AI-Monitor-Exports' / remote, local)

    first = collector.collect(coordinator, getter=getter)
    assert all(value['status'] == 'complete' for value in first.values()), first
    assert first['home']['new_rows'] == 7 and first['home']['duplicate_rows'] == 1, first
    assert first['work']['new_rows'] == 8 and first['work']['duplicate_rows'] == 2, first
    registry = json.loads((coordinator / 'site-registry.json').read_text())
    assert registry['sites']['home']['sources']['switch']['notices']
    report = preview.collect(coordinator / 'events.sqlite', coordinator, 24, 0, 2,
                             now=NOW, registry=registry)
    assert report['sites']['home']['rows_in_window'] == 7
    assert report['sites']['work']['rows_in_window'] == 8
    assert 'NAS/connections' in report['sites']['home']['sources']
    assert report['sites']['home']['sources']['switch']['notices']
    # Audit mode must expose every discovered source without calling Ollama or
    # replacing an existing preview report.
    unchanged = coordinator / 'preview.txt'
    unchanged.write_text('previous report')
    captured = io.StringIO()
    with patch('sys.argv', ['preview_report.py', '--history', str(coordinator / 'events.sqlite'),
                           '--data-dir', str(coordinator), '--audit-only',
                           '--max-groups-per-site', '0', '--output', str(unchanged)]), \
         patch.object(preview, 'analyze', side_effect=AssertionError('Audit called AI')), \
         redirect_stdout(captured):
        assert preview.main() == 0
    audited = json.loads(captured.getvalue())
    assert audited['status'] == 'collection_audit'
    assert 'NAS/transfers' in audited['sites']['work']['sources']
    assert unchanged.read_text() == 'previous report'
    second = collector.collect(coordinator, getter=getter)
    assert all(value['new_rows'] == 0 for value in second.values()), second
    with closing(sqlite3.connect(coordinator / 'events.sqlite')) as db:
        assert db.execute('SELECT count(*) FROM events').fetchone()[0] == 15
        transfer = json.loads(db.execute("SELECT raw_json FROM events WHERE source='NAS/transfers' LIMIT 1").fetchone()[0])
        detail = json.loads(transfer['msg'])
        assert detail['fname'] == '/test/file.txt' and detail['luser'] == 'alice' and detail['fsize'] == 42
        assert transfer['r_utcsec'] is None and transfer['llevel'] is None
        connection = json.loads(db.execute("SELECT raw_json FROM events WHERE source='NAS/connections' LIMIT 1").fetchone()[0])
        assert json.loads(connection['msg'])['msg'] == 'test record'
    # Case-sensitive identities survive even on a case-insensitive test filesystem.
    assert site_export.source_name(nas['home'], nas['home'] / 'Device/x.DB', 'logs') == 'Device'
    assert site_export.source_name(nas['home'], nas['home'] / 'device/x.DB', 'logs') == 'device'
    # Same-second runs retain the currently published run regardless of UUID ordering.
    for _ in range(4):
        latest = site_export.export_site(nas['home'], 'home', now=NOW)
    output = nas['home'] / 'AI-Monitor-Exports'
    assert (output / latest['run_id']).is_dir()
    assert len([p for p in output.iterdir() if site_export.RUN_NAME.fullmatch(p.name)]) == 3
    # Failure is reported while valid sources remain importable.
    bad = nas['home'] / (DATE + '_' + DATE + '_BROKEN.ZIP')
    bad.write_bytes(b'broken')
    partial = site_export.export_site(nas['home'], 'home', now=NOW)
    assert partial['status'] == 'partial' and partial['errors']
    received_partial = collector.collect(coordinator, sites=('home',), getter=getter)
    assert received_partial['home']['status'] == 'partial'
    bad.unlink()
    # Quiet historical sources stay visible without inventing a collection failure.
    disappeared = nas['home'] / 'homeassistant/SYNOSYSLOGDB_homeassistant.DB'
    disappeared.unlink()
    site_export.export_site(nas['home'], 'home', now=NOW)
    missing = collector.collect(coordinator, sites=('home',), getter=getter)
    assert missing['home']['status'] == 'complete', missing
    absent = json.loads((coordinator/'site-registry.json').read_text())['sites']['home']['sources']['homeassistant']
    assert absent['discovery_status']=='absent' and absent['notices'] and not absent['warnings']
    # Manifest path traversal must fail before download/import.
    malicious = dict(latest)
    malicious['assets'] = [dict(latest['assets'][0], file='../outside.zip')]
    try:
        collector.validate_manifest(malicious, 'home')
        raise AssertionError('Unsafe manifest path accepted')
    except ValueError:
        pass

    # Only a leading timestamp is normalized. Error codes, IPs and embedded
    # timestamps remain distinct, and the original event is still retained.
    one = '2026-10-29 01:02:03.123 ERROR device 192.0.2.1 failed code 42'
    two = '2026-10-29 02:03:04.567 ERROR device 192.0.2.1 failed code 42'
    assert preview.message_template(one) == preview.message_template(two)
    assert preview.message_template(one)[0].endswith('192.0.2.1 failed code 42')
    embedded = 'Last failure at 2026-10-29 02:03:04 code 43'
    assert preview.message_template(embedded) == (embedded, False)
    importer = collector.importer
    with closing(sqlite3.connect(coordinator / 'events.sqlite')) as db, db:
        for index, message in enumerate((one, two), 100):
            raw = dict.fromkeys(recent.FIELDS)
            raw.update(id=index, host='stamp-device', utcsec=NOW-5, r_utcsec=NOW-4,
                       msg=message, llevel='error', prog='stamp-test')
            # A new fixture source is registered so grouping is tested end to end.
            db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?)',
                       ('stamp-'+str(index), 'home', 'stamp-test', NOW-5, NOW-4, NOW,
                        json.dumps(raw)))
    registry['sites']['home']['sources']['stamp-test'] = {'exported_utc': NOW, 'warnings': []}
    grouped = preview.collect(coordinator / 'events.sqlite', coordinator, 24, 0, 2,
                              now=NOW, registry=registry)
    matching = [g for g in grouped['sites']['home']['groups'] if g['source'] == 'stamp-test']
    assert len(matching) == 1 and matching[0]['count'] == 2
    assert matching[0]['example_message'] in (one, two)
    assert grouped['sites']['home']['prefix_timestamp_rows'] == 2
    with closing(sqlite3.connect(coordinator / 'events.sqlite')) as db:
        assert json.loads(db.execute("SELECT raw_json FROM events WHERE fingerprint='stamp-100'").fetchone()[0])['msg'] == one

print('PASS: four Synology schemas, missing-field preservation, archive catch-up (ZIP and raw DB), legacy deduplication, site/case isolation, archive-only sources, old-archive filtering, safe extraction, checksum-bound imports, repeat runs, retention, partial failures, disappearing sources, manifest path rejection, registry-based reports, audit without AI and timestamp-only grouping')
