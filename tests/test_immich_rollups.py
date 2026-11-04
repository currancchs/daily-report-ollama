"""Synthetic Immich repeats: useful grouping, precise scope, one stable filter."""
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'src'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rules = load('event_rollups')
daily = load('daily_report')
RAW = {'prog': 'immich-web', 'llevel': 'err'}
BANNER = ('[Nest] 42  - 11/04/2026, 12:00:01 AM   ERROR '
          '[Microservices:MediaRepository] ffmpeg version 7.1.4-Jellyfin '
          'Copyright (c) 2000-2026 the FFmpeg developers')
ID_A = '00000000-0000-4000-8000-000000000001'
ID_B = '00000000-0000-4000-8000-000000000002'
JOB = ('[Nest] 42  - 11/04/2026, 12:00:01 AM   ERROR '
       '[Microservices:{"id":"'+ID_A+'"}] Unable to run job handler '
       '(AssetGenerateThumbnails): Error: ffmpeg exited with code 183: Conversion failed!')

banner = rules.rollup(RAW, BANNER)
variant = BANNER.replace('Nest] 42', 'Nest] 2718').replace('11/04/2026, 12:00:01 AM', '11/05/2026, 1:02:03 PM')
assert rules.rollup(RAW, variant)[0:2] == banner[0:2]
assert banner[1] == 'immich_ffmpeg_banner'
assert banner[2] == {'pid': '42', 'log_timestamp': '11/04/2026, 12:00:01 AM'}
assert 'ERROR [Microservices:MediaRepository] ffmpeg version 7.1.4-Jellyfin' in banner[0]
assert rules.rollup(RAW, BANNER.replace('7.1.4-Jellyfin', '7.1.5-Jellyfin'))[0] != banner[0]

job = rules.rollup(RAW, JOB)
job_variant = JOB.replace(ID_A, ID_B).replace('Nest] 42', 'Nest] 87').replace('12:00:01 AM', '12:00:02 AM')
assert rules.rollup(RAW, job_variant)[0:2] == job[0:2]
assert job[1] == 'immich_job_failure' and job[2]['context_id'] == ID_A
for old, new in [('code 183', 'code 234'), ('AssetGenerateThumbnails', 'AssetExtractMetadata'),
                 ('Conversion failed!', 'Conversion failed! Other diagnostic detail')]:
    assert rules.rollup(RAW, JOB.replace(old, new))[0] != job[0]
# UUIDs, paths and codes in the error text remain distinguishing evidence.
for suffix in [' path=/library/a.jpg', ' path=/library/b.jpg', ' asset='+ID_A, ' asset='+ID_B]:
    assert rules.rollup(RAW, JOB+suffix)[0].endswith(suffix)
assert rules.rollup(RAW, JOB+'\ntrailing diagnostic')[1] == ''

for text in (BANNER, JOB):
    assert rules.rollup({'prog': 'other'}, text) == (text, '', {})
    for changed in [text.replace('11/04/2026', '02/30/2026'), text.replace('12:00:01 AM', '25:00:01 AM'),
                    text.replace('ERROR', 'WARN'), text.replace('Microservices:', 'Api:'),
                    'prefix '+text]:
        assert rules.rollup(RAW, changed) == (changed, '', {})
for changed in [JOB.replace(ID_A, 'not-a-uuid'), JOB.replace('"}', '","extra":1}'),
                JOB.replace('AssetGenerateThumbnails', 'UnknownJob'),
                JOB[:JOB.index('Error: ')+len('Error: ')], BANNER+' unknown extra text']:
    assert rules.rollup(RAW, changed) == (changed, '', {})

# Exercise the real collector and suppression matcher so one filter captures
# future timestamps/PIDs while site, source and reported severity stay scoped.
NOW = 1793800800


def entry(index, message, site='home', source='immich', level='err'):
    raw = dict(host=source, ip='192.0.2.9', prog='immich-web', tag='test',
               llevel=level, prio=level, msg=message)
    return str(index), site, source, NOW-100+index, NOW-100+index, NOW, json.dumps(raw)


rows = [entry(1, BANNER), entry(2, variant), entry(3, JOB), entry(4, job_variant),
        entry(5, JOB.replace('183', '234')), entry(6, BANNER, site='work'),
        entry(7, BANNER, source='other-immich'), entry(8, BANNER, level='warning')]
(ROOT/'work').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=ROOT/'work') as temporary:
    base = Path(temporary)
    history = base/'events.sqlite'
    with closing(sqlite3.connect(history)) as db, db:
        db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)', rows)
    history_before = history.read_bytes()
    registry = {'format_version': 1, 'sites': {site: {'status': 'complete', 'warnings': [],
        'sources': {source: {'exported_utc': NOW, 'warnings': []}
                    for source in {r[2] for r in rows if r[1] == site}}} for site in ('home', 'work')}}
    result = daily.collect(history, base, now=NOW, registry=registry)
    home = result['sites']['home']
    assert home['groups_total'] == 5 and home['rows_in_window'] == 7
    group = next(g for g in home['groups'] if g.get('rollup_rule') == 'immich_ffmpeg_banner' and g['count'] == 2)
    failure = next(g for g in home['groups'] if g.get('rollup_rule') == 'immich_job_failure' and g['count'] == 2)
    assert group['first'] == NOW-99 and group['last'] == NOW-98
    assert group['message_variants'] == 2 and group['varied_fields']['pid']['distinct'] == 2
    assert failure['varied_fields']['context_id']['distinct'] == 2
    assert failure['priority_hint'] == 1 and group['priority_hint'] == 1
    assert group['example_message'] == variant and failure['example_message'] == job_variant
    path = daily.filters.database_path(base)
    daily.filters.initialize(path)
    daily.filters.create(path, 'home', group, now=NOW)
    filtered = daily.collect(history, base, now=NOW, registry=registry)
    assert filtered['sites']['home']['suppressed_records'] == 2
    assert len(filtered['sites']['home']['suppressed_groups']) == 1
    assert filtered['sites']['work']['suppressed_records'] == 0
    assert sum(g['count'] for g in filtered['sites']['home']['groups']) == 5
    assert history.read_bytes() == history_before

print('PASS: Immich repeats collapse with counts, timestamps and IDs retained; distinct failures and scope remain separate; one exact filter covers the repeated banner without changing raw history.')
