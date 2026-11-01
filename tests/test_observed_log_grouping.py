from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('daily', ROOT / 'src/daily_report.py')
daily = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daily)
NOW = 1793385000
PROBE = 'ieee80211_send_probereq: chan=64, v54_ie2_size=15 '
ANNOUNCEMENT = 'INFO (MainThread) [supervisor.resolution.checks.base] Run check for dns_server_failed/dns_server'


def entry(n, message, source='AP', program='kernel', level='warning', site='home'):
    raw = dict(id=n, host=source, ip='192.0.2.10', prog=program, llevel=level,
               prio=level, tag='test', msg=message, utcsec=NOW-60-n, r_utcsec=NOW-59-n)
    return str(n), site, source, raw['utcsec'], raw['r_utcsec'], NOW, json.dumps(raw)


rows = [
    entry(1, '[1787675.097083] ' + PROBE),
    entry(2, '[1787675.097108] ' + PROBE),
    entry(3, '[1787675.097108] ' + PROBE.replace('chan=64', 'chan=136')),
    entry(4, '[1787675.097108] ' + PROBE, source='ap'),
    entry(5, '[1787675.097108] ' + PROBE, level='err'),
    entry(6, '[1787675.097083] ' + PROBE, program='stamgr'),
    entry(7, '[1787675.097108] ' + PROBE, program='stamgr'),
    entry(8, '[123.000001] Error peer 192.0.2.1'),
    entry(9, '[124.000001] Error peer 192.0.2.2'),
    entry(10, '[123.000001] Error code -12'),
    entry(11, '[124.000001] Error code -13'),
    entry(12, ANNOUNCEMENT, source='HA', program='hassio_supervisor', level='info'),
    entry(13, ANNOUNCEMENT.replace('dns_server_failed', 'dns_server_ipv6_error'), source='HA', program='hassio_supervisor', level='info'),
    entry(14, 'ERROR (MainThread) [supervisor.resolution.checks.base] DNS server failed', source='HA', program='hassio_supervisor', level='info'),
    entry(15, ANNOUNCEMENT, source='HA', program='hassio_supervisor', level='warning'),
    entry(16, ANNOUNCEMENT, source='HA', program='other', level='info'),
    entry(17, 'SYSTEM: [Local][Local USB Storage] Failed to start backup task. (The backup destination does not exist.) [Path: usbshare1]',
          source='NAS/syslog', program='Hyper_Backup', level='err', site='work'),
]
with tempfile.TemporaryDirectory(dir=ROOT / 'work') as tmp:
    base = Path(tmp)
    history = base / 'events.sqlite'
    with closing(sqlite3.connect(history)) as db, db:
        db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)', rows)
    original = history.read_bytes()
    registry = {'format_version': 1, 'sites': {site: {'status': 'complete', 'warnings': [],
        'sources': {source: {'exported_utc': NOW, 'warnings': []} for source in sorted({r[2] for r in rows if r[1] == site})}}
        for site in ('home', 'work')}}
    result = daily.collect(history, base, now=NOW, registry=registry)
    home = result['sites']['home']
    assert home['rows_in_window'] == 16 and home['groups_total'] == 15
    assert home['kernel_uptime_rows'] == 9 and home['ha_check_announcement_rows'] == 2
    pair = next(g for g in home['groups'] if g['count'] == 2)
    assert pair['message'] == PROBE and pair['priority_hint'] == 1
    assert pair['normalized_kernel_uptime'] and pair['example_message'].startswith('[1787675.')
    assert pair['first'] < pair['last'] and pair['source'] == 'AP' and pair['reported_level'] == 'warning'
    by_id = {int(g['example_fingerprint']): g for g in home['groups']}
    assert by_id[12]['priority_hint'] == by_id[13]['priority_hint'] == 3
    assert by_id[14]['priority_hint'] < 3 and by_id[15]['priority_hint'] == 1 and by_id[16]['priority_hint'] == 2
    assert result['sites']['work']['groups'][0]['priority_hint'] == 1
    assert 'usbshare1' in result['sites']['work']['groups'][0]['message']
    assert by_id[6]['message'].startswith('[1787675.') and by_id[7]['message'].startswith('[1787675.')
    assert by_id[8]['message'] != by_id[9]['message'] and by_id[10]['message'] != by_id[11]['message']
    assert history.read_bytes() == original
    rendered = daily.render(result, daily.ZoneInfo('America/New_York'))
    assert 'leading kernel uptime timestamp in 9 records' in rendered
    assert '2 Home Assistant INFO records announce named DNS checks' in rendered
    audited = daily.audit(result)
    assert audited['sites']['home']['kernel_uptime_rows'] == 9

assert daily.prepare({'prog': 'kernel', 'msg': '[123.0]   '})[3] is False
assert daily.prepare({'prog': 'kernel', 'msg': '[ERROR] code 123'})[3] is False
mac_a = daily.prepare({'prog': 'kernel', 'msg': '[123.0] station aa:bb:cc:dd:ee:01 failed'})[0]
mac_b = daily.prepare({'prog': 'kernel', 'msg': '[124.0] station aa:bb:cc:dd:ee:02 failed'})[0]
assert mac_a == 'station aa:bb:cc:dd:ee:01 failed' and mac_a != mac_b
print('PASS: observed uptime-only variants merge; counts/times/raw history retained; case-distinct sources, severity, channels, IPs, error codes and non-kernel text stay distinct; exact INFO check announcements lose only keyword false flags; actual DNS/backup errors remain flagged.')
