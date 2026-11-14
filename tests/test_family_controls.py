"""Presentation families preserve each original event and per-group Ignore action."""
from datetime import date
from html.parser import HTMLParser
import importlib.util
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('family_web_test', ROOT / 'src' / 'report_web.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)
NOW = 1794657600


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a': self.links.append(attrs.get('href', ''))


with tempfile.TemporaryDirectory() as folder:
    base = Path(folder)
    web.devices.initialize(web.devices.database_path(base))
    web.rules.initialize(web.rules.database_path(base))
    groups = [dict(id='ha-' + str(i), source='homeassistant', host='homeassistant', ip='192.0.2.2',
        program='homeassistant', reported_level='error', reported_priority='3', count=i + 1,
        first=NOW - 100, last=NOW, message='Failed to connect to device sensor-' + str(i),
        example_message='Failed to connect to device sensor-' + str(i)) for i in range(22)]
    groups.append(dict(groups[0], id='ha-auth', message='Authentication failed to connect to device alarm',
                       example_message='Authentication failed to connect to device alarm'))
    assessments = [dict(id=g['id'], classification='issue', severity='warning',
        summary='Connection needs checking', suggested_check='Check this specific integration') for g in groups]
    report = {'window_start': NOW - 86400, 'window_end_exclusive': NOW,
        'sites': {'home': {'groups': groups, 'assessments': assessments, 'sources': {},
                          'rows_in_window': sum(g['count'] for g in groups), 'groups_total': len(groups)}}}
    rows, hidden = web.rows_for(report, {})
    cards = web.display_cards(rows)
    assert not hidden and len(cards) == 2
    assert len([r for card in cards for r in card['rows']]) == len(groups)
    assert sorted(r['group']['id'] for c in cards for r in c['rows']) == sorted(g['id'] for g in groups)
    assert sum(c['count'] for c in cards) == sum(g['count'] for g in groups)
    assert next(c for c in cards if c['family'])['rows'][0]['can_ignore'] is False  # Older report fixture.
    # Per-group controls are generated independently; family membership never widens scope.
    for row in rows: row['can_ignore'] = True
    app = web.create_app(base, secret=b'synthetic-family-control-key-123456', clock=lambda: NOW)
    with patch.object(web, 'current_report', return_value=(report, 'ready', date(2026, 11, 14))), \
            patch.object(web, 'rows_for', return_value=(rows, hidden)):
        result = app.test_client().get('/', base_url='http://127.0.0.1:8088')
    assert result.status_code == 200
    text = result.get_data(as_text=True)
    assert '2 issue summaries covering 23 groups' in text
    assert 'Show all 22 groups, supporting events and Ignore controls' in text
    links = Links(text).links
    for group in groups:
        assert '/ignore/home/' + group['id'] in links
        assert group['example_message'] in text
    assert sum('/ignore/home/' in link for link in links) == len(groups)
    assert 'Authentication failed' in text

print('PASS: family pagination retains all member events, record counts and individual Ignore links; authentication stays standalone')
