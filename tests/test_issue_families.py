"""Presentation families reduce repeats while retaining every distinct evidence row."""
import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('test_issue_families', ROOT / 'src' / 'issue_families.py')
families = importlib.util.module_from_spec(spec)
spec.loader.exec_module(families)


def group(identity, source, message, count=1, **extra):
    return dict(id=identity, source=source, host=source, message=message,
                count=count, first=10, last=20, **extra)


def row(group, site='home', severity='warning'):
    return {'site': site, 'group': group,
            'assessment': {'id': group['id'], 'classification': 'issue', 'severity': severity},
            'rule': None, 'can_ignore': True, 'excluded_at_build': False}


connectivity = [
    'Failed to refresh communications settings for device Kitchen Echo, used cached values.',
    'Cannot connect to host 192.0.2.5:443 ssl:default [Connect call failed]',
    'Error fetching thermostat data: timeout',
    'Referenced entities light.patio are missing or not currently available',
    'Connection refused by device',
    'Unable to reach device',
    'ClientConnectorError: host is unreachable',
    'Device hallway is unavailable',
]
for message in connectivity:
    assert families.classify('home', group('g', 'homeassistant', message))['key'] == 'homeassistant_offline'
for message in (
    'Wrong code provided.',
    'Authentication failed: connection refused',
    'Error fetching service data: HTTP 401 unauthorized',
    'TLS certificate failed while connecting',
    'syslog: write tcp 192.0.2.1:1000->192.0.2.2:514: write: broken pipe',
    'syslog: reconnecting up to 10 times',
    'Malformed directive payload: unexpected fields',
    'Empty JSON data received',
    'Out of memory',
):
    assert families.classify('home', group('g', 'homeassistant', message)) is None, message
assert families.classify('home', group('g', 'another-service', 'Unable to connect')) is None
assert families.classify('invalid', group('g', 'homeassistant', 'Unable to connect')) is None
assert families.classify('home', group('g', 'homeassistant', 'No failure in original text'),
                         {'summary': 'Unable to connect', 'severity': 'warning'}) is None
for severity_field in ('reported_level', 'reported_priority', 'llevel'):
    assert families.classify('home', group('g', 'homeassistant', 'Unable to connect',
        **{severity_field: 'critical'})) is None
for priority in (0, 1, 2, '0', '1', '2'):
    assert families.classify('home', group('g', 'homeassistant', 'Unable to connect',
        reported_priority=priority)) is None
assert families.classify('home', group('g', 'homeassistant', 'Unable to connect'),
                         {'severity': 'critical'}) is None

rows = []
for i in range(80):
    rows.append(row(group('plex-' + str(i), 'plexserver',
        '[MetadataAgent/tv.plex.agents.music] Matching item mbid://item-' + str(i) + ' returned incomplete results')))
for i in range(54):
    rows.append(row(group('jellyfin-' + str(i), 'jellyfin',
        '[ERR] Error in "Screen Grabber" for "/media/file-' + str(i) + '.mp4"; ffmpeg image extraction failed', count=2)))
for i in range(10):
    rows.append(row(group('ha-' + str(i), 'homeassistant',
        'Failed to refresh communications settings for device Light ' + str(i), count=10)))
rows += [row(group('alarm', 'homeassistant', 'Wrong code provided.')),
         row(group('special-jellyfin', 'jellyfin', 'Access denied to secret media directory')),
         row(group('special-plex', 'plexserver', 'FormatSchema: unknown format other')),
         row(group('critical-ha', 'homeassistant', 'Unable to connect to critical controller'), severity='critical'),
         row(group('work-ha', 'homeassistant', 'Unable to connect to a lamp'), site='work')]
original = copy.deepcopy(rows)
cards = families.group_rows(rows)
assert len(cards) == 8
assert cards[0]['severity'] == 'critical' and cards[0]['family'] is None
assert sum(card['count'] for card in cards) == sum(r['group']['count'] for r in rows)
assert sum(card['group_count'] for card in cards) == len(rows)
assert sorted(r['group']['id'] for c in cards for r in c['members']) == sorted(r['group']['id'] for r in rows)
assert rows == original
assert all(member is next(r for r in rows if r['group']['id'] == member['group']['id'])
           for c in cards for member in c['members'])
ha_cards = [c for c in cards if c['family'] and c['family']['key'] == 'homeassistant_offline']
assert len(ha_cards) == 2 and {c['site'] for c in ha_cards} == {'home', 'work'}
assert all(c['family']['title'] == 'Offline or possibly removed devices' for c in ha_cards)
assert all(c['first'] == 10 and c['last'] == 20 for c in cards)
assert len(families.group_rows(rows, include_media=False)) == len(rows) - 9

print('PASS: HA connectivity families, security/critical/pipeline exceptions, media repeats, site separation, exact counts, complete evidence and unchanged input')
