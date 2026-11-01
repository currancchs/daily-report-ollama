from collections import Counter
from contextlib import closing, redirect_stdout
import copy
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('daily', ROOT / 'src/daily_report.py')
daily = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daily)
NOW = 1793395868
MESSAGE = ('acsrvc_receive():mismatch with fqdn query to sta dst:b0:b1:a1:b6:7e:8d '
           'src :9a:6e:78:bc:05:b8 ifname=wlan32,fqdn=,ipv4= 231.252.0.0 tuple: '
           'dst port:37905,src port:6018,l4_proto=17,dst ip:141.207.251.233 , '
           'src ip:192.0.2.106 query_ssid=Example SSID , wificalling cached stored in sta hash table: '
           'dst 00:00:00:00:00:00 src :00:00:00:00:00:00dst port:0,src port: 0 dst ip:0.0.0.0 , src ip:0.0.0.0')
APPARMOR = ('audit: type=1400 audit(1793319712.137:396): apparmor="DENIED" operation="getattr" '
            'class="posix_mqueue" profile="/usr/bin/lxc-start" name="/" pid=1479121 comm="vgs" '
            'requested="getattr" denied="getattr" class="posix_mqueue" fsuid=0 ouid=0 olabel="unconfined"')

def raw(n, message, prog='stamgr', source='AP', level='err'):
    return dict(id=n, host=source, ip='192.0.2.1', prog=prog, llevel=level, prio=level,
                tag='test', msg=message, utcsec=NOW-100, r_utcsec=NOW-99)

rows = []
def add(message, **kw):
    n = len(rows)
    value = raw(n, message, **kw)
    rows.append((str(n), 'home', value['host'], NOW-100, NOW-99, NOW, json.dumps(value)))

for n in range(1000):
    add(MESSAGE.replace('231.252.0.0', f'203.0.{n // 250}.{n % 250 + 1}'))
# Endpoint, port, MAC, FQDN, SSID, source, severity and text after position 600 must stay distinct.
for old, new in [('141.207.251.233', '141.207.251.234'), ('37905', '37906'),
                 ('b0:b1:a1:b6:7e:8d', 'b0:b1:a1:b6:7e:8e'), ('fqdn=,', 'fqdn=example.test,'),
                 ('Example SSID', 'Other SSID')]:
    add(MESSAGE.replace(old, new))
add(MESSAGE, source='ap')
add(MESSAGE, level='warning')
add(MESSAGE + ' ' + 'x' * 300 + 'tail A')
add(MESSAGE + ' ' + 'x' * 300 + 'tail B')
add(APPARMOR, prog='kernel', source='PVE', level='notice')
add(APPARMOR.replace('1793319712.137:396', '1793319713.200:400').replace('1479121', '1479128'),
    prog='kernel', source='PVE', level='notice')
for old, new in [('comm="vgs"', 'comm="lvs"'), ('name="/"', 'name="/private"'),
                 ('fsuid=0', 'fsuid=1000'), ('denied="getattr"', 'denied="write"'),
                 ('profile="/usr/bin/lxc-start"', 'profile="/other"')]:
    add(APPARMOR.replace(old, new), prog='kernel', source='PVE', level='notice')

with tempfile.TemporaryDirectory(dir=ROOT / 'work') as temporary:
    base = Path(temporary)
    history = base / 'events.sqlite'
    with closing(sqlite3.connect(history)) as db, db:
        db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)', rows)
    before_bytes = history.read_bytes()
    registry = {'format_version': 1, 'sites': {site: {'status': 'complete', 'warnings': [],
        'sources': {source: {'exported_utc': NOW, 'warnings': []} for source in ('AP', 'ap', 'PVE')}}
        for site in ('home', 'work')}}
    (base / 'site-registry.json').write_text(json.dumps(registry))
    result = daily.collect(history, base, now=NOW)
    home = result['sites']['home']
    assert home['rows_scanned'] == len(rows)
    assert home['family_groups_collapsed'] == 1000
    assert home['groups_total'] == len(rows) - 1000
    assert sum(g['count'] for g in home['groups']) == len(rows)
    group = next(g for g in home['groups'] if g['count'] == 1000)
    assert group['message_variants'] == 1000 and group['varied_fields']['ipv4']['distinct'] == 1000
    assert len(group['varied_fields']['ipv4']['examples']) == 3 and group['priority_hint'] == 1
    assert '141.207.251.233' in group['message'] and '37905' in group['message']
    assert group['example_message'].startswith('acsrvc_receive()') and 'ipv4= <varies>' not in group['example_message']
    app = next(g for g in home['groups'] if g['count'] == 2)
    assert app['priority_hint'] == 2 and app['varied_fields']['pid']['distinct'] == 2
    assert all('rollup_key' not in g for g in home['groups'])
    packet = json.loads(daily.core.packet([group, app]))
    assert packet['log_groups'][0]['varied_fields']['ipv4']['distinct'] == 1000
    assert packet['log_groups'][1]['message_variants'] == 2
    assert all(daily.core.fits(batch) for batch in daily.core.batches(home['groups']))
    assert daily.review_summary(result)['home']['family_groups_collapsed'] == 1000
    assert 'named field rules' in daily.render(result, daily.ZoneInfo('America/New_York'))
    # Compare exactly the old report window, no LLM, no overwrite, no source DB writes.
    result['aggregation_seconds'] = 0
    path = base / 'saved.json'
    path.write_text(json.dumps(result))
    old_report = path.read_bytes()
    captured = io.StringIO()
    with patch('sys.argv', ['daily_report.py', '--data-dir', str(base), '--audit-only', '--compare-report', str(path)]), \
         patch.object(daily, 'analyze', side_effect=AssertionError('Unexpected AI call')), redirect_stdout(captured):
        assert daily.main() == 0
    compared = json.loads(captured.getvalue())
    assert compared['window_start_utc'] == daily.core.iso(result['window_start'])
    assert compared['sites']['home']['current_records'] == compared['sites']['home']['previous_records']
    assert history.read_bytes() == before_bytes and path.read_bytes() == old_report
    assert not list(base.glob('.report-aggregate-*'))

# Do not normalize unknown lookalikes or malformed values.
for value in [raw(1, MESSAGE, prog='other'), raw(1, MESSAGE.replace('231.252.0.0', '999.0.0.0')),
              raw(1, MESSAGE.replace('acsrvc_receive()', 'other()')),
              raw(1, APPARMOR.replace('"DENIED"', '"ALLOWED"'), prog='kernel')]:
    assert daily.family_rollup(value, value['msg']) == (value['msg'], '', {})

# A noisy error source must not crowd keyword flags from quiet devices out of selection.
with closing(sqlite3.connect(':memory:')) as scratch:
    scratch.execute('CREATE TABLE grouped(key TEXT,site TEXT,source TEXT,priority INT,n INT,first INT,last INT,payload TEXT)')
    for source, priority, n in [('noisy', 1, 200), ('quiet', 2, 12), ('urgent', 0, 1)]:
        for i in range(n):
            key = source + str(i)
            payload = dict(id=key, source=source, host='test', program='test', reported_level='warning',
                           reported_priority='', message='failure', message_truncated=False)
            scratch.execute('INSERT INTO grouped VALUES(?,?,?,?,1,1,2,?)', (key, 'home', source, priority, json.dumps(payload)))
    selected, _ = daily.choose(scratch, 'home', ['noisy', 'quiet', 'urgent'], 40)
    assert Counter(g['source'] for g in selected) == {'noisy': 27, 'quiet': 12, 'urgent': 1}
    report = {'sites': {'home': dict(groups=selected, groups_total=213, rows_not_grouped=0, assessments=[],
              ai_errors=[], batches_attempted=0, batches_completed=0, flagged_groups_total=213)}}
    observed = []
    def caller(url, model, batch, timeout):
        observed.extend(g['source'] for g in batch)
        return [dict(id=g['id'], classification='uncertain', severity='warning', summary='Test', suggested_check='') for g in batch]
    daily.analyze(report, 'http://test', 'mock', 1, caller=caller)
    assert observed[0] == 'urgent'
    assert observed[:25].count('quiet') == 12
print('PASS: exact observed rollups; all counts and variant counts; unchanged raw history; endpoint/MAC/port/path/command/severity distinctions; bounded examples reach model; comparison makes no AI calls or report writes; quiet flags selected and reviewed before noisy backlog.')
