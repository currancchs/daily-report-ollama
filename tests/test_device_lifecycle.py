"""Automatic retirement uses receiver evidence, preserves choices and fails closed."""
from contextlib import closing
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location('lifecycle_test_' + name, ROOT / 'src' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


devices = load('device_inventory')
web = load('report_web')
NOW = 1794657600
DAY = 86400


def healthy(now):
    return {site: {'status': 'complete', 'warnings': [], 'collected_utc': now,
        'exported_utc': now - 60, 'sources': {'receiver': {'warnings': []}}}
        for site in ('home', 'work')}


class Form(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.values = {}
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name'):
            self.values[attrs['name']] = attrs.get('value', '')


with tempfile.TemporaryDirectory() as folder:
    base = Path(folder)
    history = base / 'events.sqlite'
    path = devices.database_path(base)
    devices.initialize(path)
    with closing(sqlite3.connect(history)) as db, db:
        db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')

    def add(name, received, site='home', event=None):
        raw = {'host': name, 'ip': '192.0.2.1', 'msg': 'Synthetic event'}
        with closing(sqlite3.connect(history)) as db, db:
            key = str(db.execute('SELECT COUNT(*) FROM events').fetchone()[0])
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                (key, site, name, received if event is None else event, received, NOW, json.dumps(raw)))
        return devices.identity(site, name, raw)

    def item(key):
        return next(d for d in devices.catalog(base, NOW)['devices'] if d['id'] == key)

    def change(key, action, now=NOW):
        return devices.change(base, key, action, item(key)['revision'], now=now)

    old = add('old', NOW - 10 * DAY)
    recent = add('recent', NOW - 10 * DAY + 1)
    manual = add('manual', NOW - 20 * DAY)
    permanent = add('permanent', NOW - 20 * DAY)
    remote = add('remote', NOW - 20 * DAY, site='work')
    devices.refresh(base, NOW)  # Read-only inventory refresh cannot retire anything.
    assert item(old)['state'] == 'active'
    summary = devices.lifecycle_summary(base, NOW)
    assert summary['settings']['enabled'] is True and summary['settings']['days'] == 10
    assert summary['counts']['added'] == 5
    uncertain = add('uncertain-receipt', None, event=NOW - 20 * DAY)
    change(manual, 'retire')
    change(permanent, 'retire')
    change(permanent, 'permanent')
    baseline = history.read_bytes()
    # Partial, stale, malformed and source-warning results must never authorize retirement.
    for mutation in ('partial', 'old', 'future', 'source_warning', 'missing_timestamp'):
        entries = healthy(NOW)
        if mutation == 'partial': entries['home']['status'] = 'partial'
        if mutation == 'old': entries['home']['exported_utc'] = NOW - 7201
        if mutation == 'future': entries['home']['exported_utc'] = NOW + 301
        if mutation == 'source_warning': entries['home']['sources']['receiver']['warnings'] = ['Unreadable bytes']
        if mutation == 'missing_timestamp': del entries['home']['collected_utc']
        entries['work']['status'] = 'unavailable'
        devices.refresh(base, NOW, collection=entries)
        assert item(old)['state'] == 'active' and item(remote)['state'] == 'active'
    entries = healthy(NOW)
    entries['work']['status'] = 'partial'
    devices.refresh(base, NOW, collection=entries)
    assert item(old)['state'] == 'retired' and item(recent)['state'] == 'active'
    assert item(remote)['state'] == 'active' and item(manual)['state'] == 'retired'
    assert item(uncertain)['state'] == 'active'
    assert item(permanent)['state'] == 'permanent'
    assert history.read_bytes() == baseline
    summary = devices.lifecycle_summary(base, NOW)
    assert summary['evaluation']['devices_paused'] == 1
    assert any(e['action'] == 'auto_retire' and e['device_id'] == old for e in summary['changes'])
    # Re-reading retained rows and importing old archives cannot reactivate devices.
    add('old', NOW - DAY, event=NOW + 100)  # Sender clock is irrelevant; NAS receipt predates retirement.
    devices.refresh(base, NOW + 1, collection=healthy(NOW + 1))
    assert item(old)['state'] == 'retired'
    add('old', NOW + 2, event=NOW - 100 * DAY)
    add('manual', NOW + 2)
    add('permanent', NOW + 2)
    devices.refresh(base, NOW + 3, collection=healthy(NOW + 3))
    assert item(old)['state'] == 'active'
    assert item(manual)['state'] == 'retired' and item(permanent)['state'] == 'permanent'
    assert any(e['action'] == 'auto_restore' for e in devices.lifecycle_summary(base, NOW + 3)['changes'])
    # The toggle persists, validates integer limits and rejects stale simultaneous forms.
    settings = devices.lifecycle_summary(base, NOW)['settings']
    devices.set_settings(base, False, 15, settings['revision'])
    try:
        devices.set_settings(base, True, 10, settings['revision'])
        raise AssertionError('Stale settings accepted')
    except ValueError:
        pass
    devices.refresh(base, NOW + 100 * DAY, collection=healthy(NOW + 100 * DAY))
    assert item(old)['state'] == 'active'
    assert devices.lifecycle_summary(base, NOW + 8 * DAY)['counts']['added'] == 0
    for bad in (True, 0, -1, 3651, 1.5, '10'):
        try:
            devices.set_settings(base, True, bad, devices.lifecycle_summary(base, NOW)['settings']['revision'])
            raise AssertionError('Invalid day threshold accepted: %r' % bad)
        except ValueError:
            pass
    # Genuine v1 upgrade: seed existing identities silently; preserve manual state and settings.
    with closing(devices.connect(path, write=True)) as db, db:
        db.execute('DROP TABLE lifecycle')
        db.execute("DELETE FROM metadata WHERE key='auto_retirement'")
    devices.initialize(path)
    devices.refresh(base, NOW + 4)
    assert devices.lifecycle_summary(base, NOW + 4)['counts']['added'] == 0
    assert item(manual)['state'] == 'retired' and item(permanent)['state'] == 'permanent'
    new = add('<script>new</script>', NOW + 4)
    devices.refresh(base, NOW + 5)
    assert devices.lifecycle_summary(base, NOW + 5)['counts']['added'] == 1
    # Manual restoration grants the configured grace period even if the last receipt is old.
    change(manual, 'restore', NOW + 6)
    devices.refresh(base, NOW + 7, collection=healthy(NOW + 7))
    assert item(manual)['state'] == 'active'
    # Settings forms inherit same-origin CSRF protection, HTML escaping and bounded days.
    app = web.create_app(base, secret=b'synthetic-lifecycle-test-secret-123456', clock=lambda: NOW + 7)
    app.config['SESSION_COOKIE_PATH'] = '/'
    client = app.test_client()
    host = 'http://127.0.0.1:8088'
    response = client.get('/devices', base_url=host)
    assert response.status_code == 200
    assert b'&lt;script&gt;new&lt;/script&gt;' in response.data and b'<script>new</script>' not in response.data
    form = Form(response.get_data(as_text=True)).values
    def post(data, origin=host):
        return client.post('/devices/settings', data=data, base_url=host, headers={'Origin': origin})
    assert post(form, 'https://evil.invalid').status_code == 403
    assert post(dict(form, csrf='wrong')).status_code == 403
    for invalid in ('0', '-2', '3651', '1.5', ' 10', 'true'):
        assert post(dict(form, days=invalid)).status_code == 400
    assert post(dict(form, revision='stale')).status_code == 409
    form.pop('enabled', None)
    form['days'] = '25'
    assert post(form).status_code == 303
    assert devices.lifecycle_summary(base, NOW)['settings']['days'] == 25
    assert devices.lifecycle_summary(base, NOW)['settings']['enabled'] is False
    # Corrupt configuration fails closed rather than taking the default and retiring devices.
    with closing(devices.connect(path, write=True)) as db, db:
        db.execute("UPDATE metadata SET value='{}' WHERE key='auto_retirement'")
    try:
        devices.refresh(base, NOW + 100 * DAY, collection=healthy(NOW + 100 * DAY))
        raise AssertionError('Corrupt settings ignored')
    except ValueError:
        pass
    assert item(manual)['state'] == 'active'
    with closing(devices.connect(path, write=True)) as db, db:
        db.execute("DELETE FROM metadata WHERE key='auto_retirement'")
    for operation in (lambda: devices.refresh(base, NOW + 100 * DAY, collection=healthy(NOW + 100 * DAY)),
                      lambda: devices.lifecycle_summary(base, NOW)):
        try:
            operation()
            raise AssertionError('Missing migrated settings silently reset to enabled')
        except ValueError:
            pass


# Delayed archive receipts cannot grant a fresh active period to long-silent devices.
with tempfile.TemporaryDirectory() as folder:
    base = Path(folder)
    devices.initialize(devices.database_path(base))
    raw = {'host': 'delayed', 'ip': '192.0.2.5'}
    key = devices.identity('home', 'delayed', raw)
    with closing(sqlite3.connect(base / 'events.sqlite')) as db, db:
        db.execute('CREATE TABLE events(site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)', ('home', 'delayed', NOW - 11 * DAY, NOW - 11 * DAY, NOW, json.dumps(raw)))
    devices.refresh(base, NOW, collection=healthy(NOW))
    assert devices.catalog(base, NOW)['devices'][0]['state'] == 'retired'
    with closing(sqlite3.connect(base / 'events.sqlite')) as db, db:
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)', ('home', 'delayed', NOW, NOW + DAY, NOW + 20 * DAY, json.dumps(raw)))
    devices.refresh(base, NOW + 20 * DAY, collection=healthy(NOW + 20 * DAY))
    assert devices.catalog(base, NOW)['devices'][0]['state'] == 'retired'
    # A still-recent delayed receipt can restore, but does not get manual-restore grace.
    devices.refresh(base, NOW + 5 * DAY, collection=healthy(NOW + 5 * DAY))
    assert devices.catalog(base, NOW)['devices'][0]['state'] == 'active'
    devices.refresh(base, NOW + 11 * DAY, collection=healthy(NOW + 11 * DAY))
    assert devices.catalog(base, NOW)['devices'][0]['state'] == 'retired'

print('PASS: receive-time retirement boundaries, collection safeguards, restoration, manual/permanent choices, v1 migration, weekly changes, settings persistence, CSRF and validation')
