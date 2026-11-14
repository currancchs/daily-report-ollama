from contextlib import closing
from datetime import date, datetime, timedelta
from functools import partial
import importlib.util
import json
from pathlib import Path
import sqlite3
import ssl
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('job', ROOT / 'src/daily_job.py')
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)
# Exercise deterministic briefing integration without ever contacting Ollama.
_real_summary = job.summary.build_summary
def _mock_summary(report, base, url, model, timeout=0):
    return _real_summary(report, base, url, model, timeout=0)
job.summary.build_summary = _mock_summary
NOW = int(datetime(2026, 10, 30, 4, 0, tzinfo=job.ZONE).timestamp())
SEND = NOW + 3600
DAY = job.report_day(NOW)
START, END = job.window_for(DAY)


class SMTP:
    sent = []
    uncertain = False

    def __init__(self, host, port, timeout, context):
        assert host == 'smtp.gmail.com' and port == 465
        assert context.verify_mode == ssl.CERT_REQUIRED

    def login(self, username, password):
        assert username == 'sender@example.com' and password == 'test-password'

    def send_message(self, message, from_addr, to_addrs):
        self.sent.append(message)
        assert to_addrs == ['recipient@example.com']
        if self.uncertain:
            raise TimeoutError('Reply lost')
        return {}

    def quit(self):
        pass

    def close(self):
        pass


sender = partial(job.mail.send_report, smtp_factory=SMTP)


def setup(base):
    base.mkdir()
    config = base / 'gmail.json'
    config.write_text(json.dumps({'username': 'sender@example.com', 'recipient': 'recipient@example.com',
                                 'app_password': 'test-password'}))
    config.chmod(0o600)
    with closing(sqlite3.connect(base / 'events.sqlite')) as db, db:
        db.execute('CREATE TABLE events (fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        db.execute('CREATE TABLE imports(site TEXT,source TEXT,archive_sha256 TEXT,imported_utc INTEGER,summary_json TEXT)')
        for site in ('home', 'work'):
            raw = dict(id=1, host='test-host', ip='192.0.2.1', prog='test', llevel='warning',
                       msg='disk error code 1234', utcsec=END-60, r_utcsec=END-59)
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                       (site, site, 'test-source', END-60, END-59, NOW, json.dumps(raw)))
    return config


def collect(base, folder):
    registry = {'format_version': 1, 'sites': {}}
    for site in ('home', 'work'):
        run = site + '-test-run'
        registry['sites'][site] = {'status': 'complete', 'run_id': run, 'collected_utc': NOW,
            'warnings': [], 'sources': {'test-source': {'exported_utc': NOW-60, 'warnings': []}}}
        manifest = {'run_id': run, 'started_utc': job.iso(NOW-120), 'finished_utc': job.iso(NOW-60),
                    'lookback_hours': 72}
        job.save(base / 'cache' / site / 'last-manifest.json', manifest)
    job.save(base / 'site-registry.json', registry)
    return 0


def analyze(report, url, model, timeout, **kwargs):
    def answers(url, model, batch, timeout):
        return [{'id': group['id'], 'classification': 'issue', 'severity': 'warning',
                 'summary': 'Test disk error', 'suggested_check': 'Check device logs'} for group in batch]
    job.daily.analyze(report, url, model, timeout, caller=answers, **kwargs)


def build(base, **kwargs):
    return job.build(base, now=NOW, collector=collect, checker=lambda: None, analyzer=analyze, **kwargs)


with tempfile.TemporaryDirectory(dir=ROOT / 'work') as tmp, \
        patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=10 * 1024**3)):
    root = Path(tmp)
    for day, hours in ((date(2026, 3, 8), 23), (date(2026, 11, 1), 25), (DAY, 24)):
        start, end = job.window_for(day)
        assert (end - start) / 3600 == hours
        assert job.window_for(day-timedelta(days=1))[1] == start
    base = root / 'happy'
    config = setup(base)
    assert job.build(base, now=NOW-1)['phase'] == 'not_due'
    assert job.send(base, config, now=SEND-1, sender=sender)['status'] == 'not_due'
    assert not (base / 'daily').exists()
    state = build(base)
    assert state['phase'] == 'ready' and state['report_status'] == 'daily_complete'
    folder = base / 'daily' / DAY.isoformat()
    body, metadata = job.verify_ready(folder, DAY, SEND)
    assert metadata['window_start'] == START and metadata['window_end_exclusive'] == END
    assert all(v['rows_in_window'] == 1 for v in metadata['sites'].values())
    assert job.build(base, now=NOW, collector=lambda *a: (_ for _ in ()).throw(AssertionError('Recollected'))) == state
    sent = job.send(base, config, now=SEND, sender=sender)
    assert sent['status'] == 'accepted_by_smtp' and '[DAILY]' in sent['subject']
    before = len(SMTP.sent)
    assert job.send(base, config, now=SEND, sender=sender)['status'] == 'already_sent'
    assert len(SMTP.sent) == before

    # Refresh a saved briefing without rerunning collection/review or changing its generation identity.
    refresh_spec=importlib.util.spec_from_file_location('refresh_test',ROOT/'src/refresh_briefing.py')
    refresher=importlib.util.module_from_spec(refresh_spec); refresh_spec.loader.exec_module(refresher)
    refresher.job=job  # Reuse the mock-only NAS/Ollama/SMTP harness.
    refresh_base=root/'refresh-success'
    setup(refresh_base); build(refresh_base)
    job.daily.devices.initialize(job.daily.devices.database_path(refresh_base))
    refresh_folder=refresh_base/'daily'/DAY.isoformat()
    names=('report.json','report.txt','report.html','state.json')
    original={name:(refresh_folder/name).read_bytes() for name in names}
    previous=json.loads(original['report.json'])
    def fresh_briefing(report,base,url,model,timeout=0):
        result=_real_summary(report,base,url,model,timeout=0)
        result['status']='ai'
        result['items'][0]['text']='Refreshed briefing from the same saved evidence.'
        return result
    with patch.object(refresher.time,'time',return_value=SEND), \
            patch.object(job.summary,'build_summary',side_effect=fresh_briefing), \
            patch.object(job,'run_collection',side_effect=AssertionError('Unexpected recollection')), \
            patch.object(job.daily,'analyze',side_effect=AssertionError('Unexpected repeated analysis')), \
            patch.dict(job.mail.html_report.SETTINGS,{'timezone':'America/New_York','controls_enabled':True},clear=True):
        refreshed=refresher.refresh(refresh_base,timeout=0)
    assert refreshed['summary_status']=='ai' and refreshed['email_sent'] is False
    updated_state,updated=job.verify_ready(refresh_folder,DAY,SEND)
    assert updated['sites']==previous['sites']
    assert all(updated[key]==previous[key] for key in ('generated_utc','window_start','window_end_exclusive','report_date'))
    assert updated['executive_summary']['items'][0]['text'].startswith('Refreshed briefing')
    assert updated_state['sha256']=={name:job.digest(refresh_folder/name) for name in names if name!='state.json'}
    assert updated_state['sha256']['report.json']!=json.loads(original['state.json'])['sha256']['report.json']
    assert (refresh_folder/'report.txt').read_text(encoding='utf-8').splitlines()[1]=='Generated: '+previous['generated_utc']
    assert all((Path(refreshed['backup'])/name).read_bytes()==original[name] for name in names)
    assert len(SMTP.sent)==before

    # An output failure after JSON/text writes restores all four original artifacts byte-for-byte.
    rollback_base=root/'refresh-rollback'
    setup(rollback_base); build(rollback_base)
    job.daily.devices.initialize(job.daily.devices.database_path(rollback_base))
    rollback_folder=rollback_base/'daily'/DAY.isoformat()
    rollback_original={name:(rollback_folder/name).read_bytes() for name in names}
    with patch.object(refresher.time,'time',return_value=SEND), \
            patch.object(job.summary,'build_summary',side_effect=fresh_briefing), \
            patch.object(job.mail.html_report,'save',side_effect=OSError('Simulated HTML write failure')):
        try:
            refresher.refresh(rollback_base,timeout=0)
            raise AssertionError('Refresh output failure was swallowed')
        except OSError as error:
            assert 'Simulated HTML' in str(error)
    assert all((rollback_folder/name).read_bytes()==rollback_original[name] for name in names)
    job.verify_ready(rollback_folder,DAY,SEND)
    assert len(SMTP.sent)==before

    # Time spent collecting/preparing is deducted from the common build budget.
    budgeted = root / 'budgeted'
    setup(budgeted)
    ticks = [0]
    remaining_seen = []
    summary_seen = []

    def slow_collection(base, folder):
        result = collect(base, folder)
        ticks[0] += 120
        return result

    def slow_preflight():
        ticks[0] += 60

    def budget_analyzer(report, *args, **kwargs):
        remaining_seen.append(kwargs['max_runtime'])
        analyze(report, *args, **kwargs)

    def budget_summary(report, base, url, model, timeout):
        summary_seen.append(timeout)
        return _mock_summary(report,base,url,model)

    with patch.object(job.time, 'monotonic', side_effect=lambda: ticks[0]):
        budget_state = job.build(budgeted, now=NOW, collector=slow_collection, checker=slow_preflight,
                                analyzer=budget_analyzer, maintenance=lambda *args: None,
                                summarizer=budget_summary)
    assert budget_state['phase'] == 'ready' and remaining_seen == [2370]
    assert summary_seen == [90]
    # A time-limited review is partial even when collection and AI calls succeeded.
    limited = root / 'limited'
    setup(limited)
    def incomplete_analysis(report, *args, **kwargs):
        analyze(report, *args, **kwargs)
        report['sites']['home']['assessments'].pop()
        report['analysis_stop_reason'] = 'time_budget'
    limited_state = job.build(limited, now=NOW, collector=collect,
                              checker=lambda: None, analyzer=incomplete_analysis)
    assert limited_state['phase'] == 'ready' and limited_state['report_status'] == 'daily_partial'
    assert limited_state['review_limited'] and limited_state['review']['home']['groups_unreviewed'] == 1
    limited_report = job.read(limited / 'daily' / DAY.isoformat() / 'report.json')
    assert not limited_report['pipeline_warnings']
    assert all(not data['ai_errors'] for data in limited_report['sites'].values())
    assert limited_report['pipeline_issue'] is False
    limited_send=job.send(limited,limited/'gmail.json',now=SEND,sender=sender)
    assert 'LIMITED REVIEW' in limited_send['subject'] and 'PIPELINE ISSUE' not in limited_send['subject']
    # A briefing failure must never discard successful collection/review results.
    broken_summary=root/'broken-summary'
    setup(broken_summary)
    def raise_summary(*args,**kwargs):
        raise RuntimeError('Example summary failure')
    summary_state=job.build(broken_summary,now=NOW,collector=collect,checker=lambda:None,
                            analyzer=analyze,summarizer=raise_summary)
    assert summary_state['phase']=='ready'
    saved=job.read(broken_summary/'daily'/DAY.isoformat()/'report.json')
    assert saved['executive_summary']['status']=='fallback'
    before=len(SMTP.sent)
    # A regenerated report on the same date is still not automatically resent.
    build(base, force=True)
    assert job.send(base, config, now=SEND+100, sender=sender)['status'] == 'already_sent'
    assert len(SMTP.sent) == before

    # Retention removes only expired coordinator data and our marked report folders.
    old = NOW - 40*86400
    with closing(sqlite3.connect(base / 'events.sqlite')) as db, db:
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', ('old', 'home', 'old', old, old, old, '{}'))
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', ('late', 'home', 'old', old, old, NOW, '{}'))
    old_day = DAY-timedelta(days=40)
    old_folder = job.folder_for(base, old_day)
    job.save(old_folder / 'state.json', {'producer': job.PRODUCER, 'report_date': old_day.isoformat()})
    unknown = job.folder_for(base, old_day-timedelta(days=1))
    (unknown / 'keep.txt').write_text('User data')
    job.maintain(base, NOW)
    assert not old_folder.exists() and (unknown / 'keep.txt').exists() and folder.exists()
    with closing(sqlite3.connect(base / 'events.sqlite')) as db:
        assert not db.execute("SELECT 1 FROM events WHERE fingerprint='old'").fetchall()
        assert db.execute("SELECT 1 FROM events WHERE fingerprint='late'").fetchall()

    # Offline AI still publishes counts and explicit missing-analysis warnings.
    offline = root / 'offline'
    offline_config = setup(offline)
    state = job.build(offline, now=NOW, collector=collect,
                      checker=lambda: (_ for _ in ()).throw(TimeoutError('offline')), analyzer=analyze)
    assert state['phase'] == 'ready' and state['report_status'] == 'daily_partial'
    text = (offline / 'daily' / DAY.isoformat() / 'report.txt').read_text()
    assert 'Ollama unavailable' in text and 'No validated AI assessments' in text
    assert state['review_limited']
    result = job.send(offline, offline_config, now=SEND, sender=sender)
    assert 'PIPELINE ISSUE' in result['subject']

    # Failed collection retains old data while flagging its missing window coverage.
    stale = root / 'stale'
    stale_config = setup(stale)
    collect(stale, None)
    registry = job.read(stale / 'site-registry.json')
    registry['sites']['work']['collected_utc'] = NOW-86400
    job.save(stale / 'site-registry.json', registry)
    mpath = stale / 'cache' / 'work' / 'last-manifest.json'
    manifest = job.read(mpath)
    manifest['started_utc'] = job.iso(END-3600)
    job.save(mpath, manifest)
    state = job.build(stale, now=NOW, collector=lambda *a: 2, checker=lambda: None, analyzer=analyze)
    assert state['report_status'] == 'daily_partial'
    data = job.read(stale / 'daily' / DAY.isoformat() / 'report.json')
    assert any('before the 3:30' in w for w in data['pipeline_warnings'])
    assert any('no successful collection' in w for w in data['pipeline_warnings'])

    # No build / interrupted / bad checksum never delivers an old or half-written digest.
    for case in ('missing', 'interrupted', 'checksum'):
        base2 = root / case
        config2 = setup(base2)
        f = job.folder_for(base2, DAY)
        if case == 'interrupted':
            job.save(f / 'state.json', {'producer': job.PRODUCER, 'phase': 'building', 'report_date': DAY.isoformat()})
            assert build(base2)['phase'] == 'failed'
        if case == 'checksum':
            build(base2)
            (f / 'report.txt').write_text('Corrupted report')
        result = job.send(base2, config2, now=SEND, sender=sender)
        assert 'REPORT FAILED' in result['subject']
    assert 'health is UNKNOWN' in SMTP.sent[-1].get_body(preferencelist=('plain',)).get_content()

    failed = root / 'failed'
    failed_config = setup(failed)
    state = job.build(failed, now=NOW, collector=lambda *a: 1, checker=lambda: None)
    assert state['phase'] == 'failed'
    assert build(failed) == state  # Failed builds are not automatically rerun at 5 a.m.
    assert build(failed, force=True)['phase'] == 'ready'

    uncertain = root / 'uncertain'
    config3 = setup(uncertain)
    build(uncertain)
    SMTP.uncertain = True
    for attempt in range(2):
        count = len(SMTP.sent)
        try:
            job.send(uncertain, config3, now=SEND, sender=sender)
            raise AssertionError('Uncertain delivery not raised')
        except RuntimeError:
            pass
        assert len(SMTP.sent) == count + (1 if attempt == 0 else 0)
    SMTP.uncertain = False

    # Low disk space fails before NAS collection; the next-day path cannot reuse yesterday.
    low = root / 'low'
    config4 = setup(low)
    with patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=1024)):
        state = build(low)
        assert state['phase'] == 'failed' and '2 GiB' in state['error']
    next_day = int(datetime(2026, 10, 31, 5, 0, tzinfo=job.ZONE).timestamp())
    result = job.send(base, config, now=next_day, sender=sender)
    assert '2026-10-31' in result['subject'] and 'REPORT FAILED' in result['subject']

    # Collector deadline terminates the spawned collector; completed calls keep their exit code.
    class Process:
        pid = 123456
        killed = False

        def wait(self, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired('fake-collector', timeout)
            return -9

        def kill(self):
            self.killed = True

    process = Process()
    with patch.object(job.subprocess, 'Popen', return_value=process), \
            patch.object(job.os, 'killpg', create=True) as kill_group:
        try:
            job.run_collection(base, folder)
            raise AssertionError('Collector deadline ignored')
        except TimeoutError:
            pass
        if job.os.name == 'posix':
            kill_group.assert_called_once_with(process.pid, job.signal.SIGKILL)
        else:
            assert process.killed

print('PASS: real SQLite/report integration; 23/24/25-hour windows; fixed cutoff; build idempotency; fresh/stale/missing exports; offline AI; interrupted/failed builds; low disk; fallback mail; date-based deduplication; uncertain SMTP guard; bounded coordinator retention. Mock NAS/Ollama/SMTP only; no live email sent.')
