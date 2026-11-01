from contextlib import closing, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


daily = load('daily', 'daily_report.py')
mail = load('mail', 'gmail_report.py')
NOW = 1793372400


def row(site, source, number, msg, level='info', event=None, received=None, **extra):
    event = NOW-60 if event is None else event
    received = NOW-59 if received is None else received
    raw = dict(id=number, msg=msg, llevel=level, host=source, ip='192.0.2.1',
               prog='test', prio=None, tag='test', utcsec=event, r_utcsec=received)
    raw.update(extra)
    key = hashlib.sha256(json.dumps([site, source, raw], sort_keys=True).encode()).hexdigest()
    return key, site, source, event, received, NOW, json.dumps(raw)


def answers(batch):
    return [{'id': group['id'], 'classification': 'issue' if group['priority_hint'] < 3 else 'routine',
             'severity': 'warning' if group['priority_hint'] < 3 else 'info',
             'summary': 'Observed test message.', 'suggested_check': ''} for group in batch]


with tempfile.TemporaryDirectory(dir=ROOT / 'work') as temporary:
    base = Path(temporary)
    history = base / 'events.sqlite'
    sources = {'home': ['AAA-noisy', 'quiet', 'NAS/transfers', 'prefix', 'clock', 'malformed'],
               'work': ['NAS/syslog', 'quiet', 'NAS/transfers', 'blank']}
    registry = {'format_version': 1, 'sites': {site: {'status': 'complete', 'warnings': [],
                'sources': {source: {'exported_utc': NOW, 'warnings': []} for source in names}}
                for site, names in sources.items()}}
    (base / 'site-registry.json').write_text(json.dumps(registry))
    with closing(sqlite3.connect(history)) as db, db:
        db.execute('CREATE TABLE events (fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        db.execute('CREATE INDEX by_source ON events(site,source)')
        for site, source, size in [('home', 'AAA-noisy', 60010), ('work', 'NAS/syslog', 60010)]:
            db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                (row(site, source, n, 'Unique routine message '+str(n)) for n in range(size)))
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', row(site, 'quiet', 1, 'Disk failed', 'critical'))
            # Same transfer operation/account/IP, distinct filenames and sizes.
            db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                (row(site, 'NAS/transfers', n, json.dumps({'synology_table': 'transfer_log',
                     'luser': 'alice', 'event': 'download', 'isdir': 0,
                     'fname': '/documents/failed-filename-'+str(n), 'fsize': n}), tag='transfer_log') for n in range(400)))
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', row(site, 'NAS/transfers', 500,
                json.dumps({'synology_table': 'transfer_log', 'luser': 'bob', 'event': 'download',
                            'isdir': 0, 'fname': '/documents/other', 'fsize': 42}), tag='transfer_log'))
        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
            [row('home', 'prefix', 1, '2026-10-30 10:01:01.123 ERROR 192.0.2.10 code 42', 'error'),
             row('home', 'prefix', 2, '2026-10-30 10:02:02.456 ERROR 192.0.2.10 code 42', 'error'),
             row('home', 'prefix', 3, '2026-10-30 10:03:03.789 ERROR 192.0.2.11 code 42', 'error'),
             row('home', 'clock', 1, 'Small skew', event=NOW-58),
             row('home', 'clock', 2, 'Large skew', event=NOW+3600)])
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', ('bad', 'home', 'malformed', NOW-5, NOW-4, NOW, '{broken'))
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', row('home', 'quiet', 3, 'Outside window', event=NOW-90000, received=NOW-89999))
    original = hashlib.sha256(history.read_bytes()).hexdigest()
    began = time.monotonic()
    report = daily.collect(history, base, budget=30, now=NOW)
    elapsed = time.monotonic() - began
    home, work = report['sites']['home'], report['sites']['work']
    assert home['rows_in_window'] == home['rows_scanned'] == 60418, home['rows_in_window']
    assert work['rows_in_window'] == work['rows_scanned'] == 60412
    assert home['grouped_records'] == 60417 and home['rows_not_grouped'] == 1
    assert work['grouped_records'] == 60412 and work['rows_not_grouped'] == 0
    assert home['groups_total'] == 60017 and work['groups_total'] == 60013
    assert all(len(data['groups']) == 30 for data in report['sites'].values())
    assert all(any(group['source'] == 'quiet' and group['priority_hint'] == 0 for group in data['groups']) for data in report['sites'].values())
    for data in report['sites'].values():
        for source, info in data['sources'].items():
            if info['groups_total']:
                assert info['groups_selected'] > 0, source
        transfer = [group for group in data['groups'] if group['source'] == 'NAS/transfers']
        assert len(transfer) == 2 and sorted(group['count'] for group in transfer) == [1,400]
        assert all(group['priority_hint'] == 3 for group in transfer)
        assert all(group['structured_transfer_rollup'] for group in transfer)
        assert all(daily.core.fits(batch) for batch in daily.core.batches(data['groups']))
    assert home['sources']['prefix']['groups_total'] == 2
    assert home['sources']['clock']['event_ahead_of_receive_over_5m'] == 1
    assert home['sources']['clock']['maximum_event_lead_seconds'] == 3659
    assert work['sources']['blank']['warnings']
    assert home['sources']['quiet']['reported_critical_records'] == 1
    assert all(data['records_outside_ai_selection'] > 59000 for data in report['sites'].values())
    # Actual audited counts must never be capped at 5,000 groups or 50,000 rows.
    audited = daily.audit(report)
    assert audited['sites']['home']['groups_total'] > 50000
    # Reversing registry source order must not change the selected evidence.
    reversed_registry = json.loads(json.dumps(registry))
    for entry in reversed_registry['sites'].values():
        entry['sources'] = dict(reversed(list(entry['sources'].items())))
    reverse = daily.collect(history, base, budget=30, now=NOW, registry=reversed_registry)
    assert [[g['id'] for g in d['groups']] for d in report['sites'].values()] == [[g['id'] for g in d['groups']] for d in reverse['sites'].values()]
    # Failed collection and stale exports are visible even with usable old history.
    registry['sites']['work']['status'] = 'unavailable'
    registry['sites']['work']['warnings'] = ['Synthetic SMB outage']
    registry['sites']['work']['sources']['quiet']['exported_utc'] = NOW-10000
    failed = daily.collect(history, base, budget=1, now=NOW, registry=registry)
    assert len(failed['sites']['home']['groups']) == 5  # minimum one per nonempty source
    assert failed['sites']['work']['warnings']
    assert any('older' in warning for warning in failed['sites']['work']['sources']['quiet']['warnings'])
    daily.core.analyze(report, 'http://localhost', 'test-model', 1,
                       caller=lambda url, model, batch, timeout: answers(batch))
    text = daily.render(report, daily.ZoneInfo('America/New_York'))
    assert 'Not AI reviewed:' in text and '60017' in text and 'REPORTED CRITICAL LEVEL' in text
    assert 'malformed' in text and 'clock' in text
    output = base / 'report.txt'
    daily.core.save_atomic(output.with_suffix('.json'), json.dumps(report))
    daily.core.save_atomic(output, text)
    assert mail.load_report(output, now=NOW)[1]['generator'] == daily.VERSION
    # Overall AI timeout preserves the whole-window counts and explicitly marks missing analysis.
    daily.core.analyze(failed, 'http://localhost', 'test-model', 1, max_runtime=0,
                       caller=lambda *args: (_ for _ in ()).throw(AssertionError('Should not call AI')))
    assert failed['status'] == 'preview_with_ai_errors'
    assert 'No validated AI assessments' in daily.render(failed, daily.ZoneInfo('UTC'))
    # Audit-only CLI writes no report and cannot call AI.
    captured = io.StringIO()
    with patch('sys.argv', ['daily_report.py', '--data-dir', str(base), '--audit-only']), \
         patch.object(daily, 'collect', return_value=report), \
         patch.object(daily, 'analyze', side_effect=AssertionError('Audit called AI')), \
         redirect_stdout(captured):
        assert daily.main() == 0
    assert json.loads(captured.getvalue())['sites']['home']['rows_scanned'] == 60418
    # A completed run publishes a concise status and its pre-AI coverage audit.
    with patch('sys.argv', ['daily_report.py', '--data-dir', str(base), '--output', str(base / 'balanced.txt')]), \
         patch.object(daily, 'collect', return_value=report), \
         patch.object(daily, 'analyze'), redirect_stdout(io.StringIO()):
        assert daily.main() == 0
    written_status = json.loads((base / 'balanced-status.json').read_text())
    assert written_status['sites']['home']['sources_with_records'] == 6
    assert written_status['sites']['home']['sources_with_selected_groups'] == 5
    assert written_status['sites']['home']['clock_diagnostics']['clock']['maximum_event_lead_seconds'] == 3659
    assert json.loads((base / 'balanced-audit.json').read_text())['sites']['home']['rows_not_grouped'] == 1
    # A fixed cutoff includes its start and excludes its end.
    fixed = daily.collect(history, base, now=NOW, window=(NOW-89999, NOW-89998))
    assert fixed['window_start'] == NOW-89999 and fixed['window_end_exclusive'] == NOW-89998
    assert fixed['sites']['home']['rows_in_window'] == 1
    excluded = daily.collect(history, base, now=NOW, window=(NOW-90000, NOW-89999))
    assert excluded['sites']['home']['rows_in_window'] == 0
    report.update(report_kind='daily', report_date='2026-10-30', status='daily_partial',
                  pipeline_warnings=['Synthetic partial collection'])
    rendered_daily = daily.render(report, daily.ZoneInfo('America/New_York'))
    assert rendered_daily.startswith('HOME + WORK LOG DIGEST - DAILY\n')
    assert 'PIPELINE: Synthetic partial collection' in rendered_daily
    daily.core.save_atomic(output.with_suffix('.json'), json.dumps(report))
    daily.core.save_atomic(output, rendered_daily)
    assert mail.load_report(output, now=NOW)[1]['report_kind'] == 'daily'
    assert hashlib.sha256(history.read_bytes()).hexdigest() == original
    assert not list(base.glob('.report-aggregate-*'))
    try:
        daily.collect(history, base, now=NOW, aggregation_timeout=0)
        raise AssertionError('Expired grouping deadline was ignored')
    except (TimeoutError, sqlite3.OperationalError):
        pass
    assert not list(base.glob('.report-aggregate-*'))

print('PASS: 120,830-row integration; full-window disk aggregation; late-source critical evidence; balanced selection independent of registry order; structured transfers; precise timestamp grouping; clock diagnostics; stale/failed collection; model failure; email compatibility; read-only history; temporary cleanup; grouping seconds=' + str(round(elapsed, 2)))
