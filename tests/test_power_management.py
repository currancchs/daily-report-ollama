from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'src' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

power = load('power_status')
wake = load('wake_ollama')
NOW = int(datetime(2026, 10, 31, 4, 45, tzinfo=power.ZONE).timestamp())
day = power.job.report_day(NOW)
with tempfile.TemporaryDirectory(dir=ROOT / 'work') as temporary:
    base = Path(temporary)
    folder = base / 'daily' / day.isoformat()
    folder.mkdir(parents=True)
    start, end = power.job.window_for(day)
    metadata = dict(report_kind='daily', report_date=day.isoformat(), status='daily_complete',
        generated_utc=power.job.iso(NOW-120), window_start=start, window_end_exclusive=end,
        model=power.job.MODEL, ollama_url=power.job.OLLAMA, analysis_stop_reason='time_budget',
        review_limited=True, sites={'home': {'ai_errors': []}, 'work': {'ai_errors': []}})
    state = dict(producer=power.job.PRODUCER, report_date=day.isoformat(), phase='ready',
        started_utc=power.job.iso(NOW-120), completed_utc=power.job.iso(NOW-30))
    original_metadata, original_state = deepcopy(metadata), deepcopy(state)
    def save():
        (folder / 'report.txt').write_text('TEST REPORT\nGenerated: ' + metadata['generated_utc'] + '\n')
        (folder / 'report.json').write_text(json.dumps(metadata))
        (folder / 'report.html').write_text('<html><body>Synthetic report</body></html>')
        state['sha256'] = {name: power.job.digest(folder / name) for name in ('report.txt','report.json','report.html')}
        (folder / 'state.json').write_text(json.dumps(state))
    def reset():
        metadata.clear()
        metadata.update(deepcopy(original_metadata))
        state.clear()
        state.update(deepcopy(original_state))
        save()
    save()
    assert power.completion(base, NOW)['ready'] is True
    assert power.completion(base, NOW+7200)['ready'] is False  # outside 04-06
    assert power.completion(base, NOW-3600)['ready'] is False
    for name in ('report.txt', 'report.json', 'report.html'):
        (folder / name).write_text('tampered')
        assert power.completion(base, NOW)['ready'] is False
        reset()
    (folder / 'report.json').unlink()
    assert power.completion(base, NOW)['ready'] is False
    reset()
    for phase in ('building', 'failed'):
        state['phase'] = phase
        save()
        assert power.completion(base, NOW)['ready'] is False
    reset()

    # The job can save a verified daily_partial after inference errors. That is
    # a finished run even when one site stopped on a batch and another later
    # exhausted the time budget. Retain the errors in the saved report.
    metadata['status'] = 'daily_partial'
    metadata['sites']['home']['ai_errors'] = ['Batch 60: Remote end closed connection without response']
    metadata['sites']['work']['ai_errors'] = ['Batch 6: Connection timed out']
    for reason in ('ai_error', 'time_budget'):
        metadata['analysis_stop_reason'] = reason
        save()
        result = power.completion(base, NOW)
        assert result['ready'] is True and result['reason'] == 'report_ready'
        assert result['started_utc'] == power.job.stamp(state['started_utc'])
        assert result['completed_utc'] == power.job.stamp(state['completed_utc'])
        assert power.job.read(folder / 'report.json')['sites']['home']['ai_errors']
    for reason in ('ollama_unavailable', 'unknown_stop', None):
        metadata['analysis_stop_reason'] = reason
        save()
        assert power.completion(base, NOW)['ready'] is False
    del metadata['analysis_stop_reason']
    save()
    assert power.completion(base, NOW)['ready'] is False
    reset()
    for reason in ('selected_groups_complete', 'time_budget'):
        metadata['analysis_stop_reason'] = reason
        save()
        assert power.completion(base, NOW)['ready'] is True
    reset()
    for field, value in (('model', 'different:model'), ('ollama_url', 'http://127.0.0.2:11434'),
                         ('report_date', '2026-10-30'), ('window_start', start-1)):
        metadata[field] = value
        save()
        assert power.completion(base, NOW)['ready'] is False
        reset()
    for sites in ({'home': {}}, {'home': {}, 'work': {}, 'extra': {}}, ['home', 'work'],
                  {'home': None, 'work': {}}, {'home': {}, 'work': []}, None):
        metadata['sites'] = sites
        save()
        assert power.completion(base, NOW)['ready'] is False
        reset()
    for field, value in (('completed_utc', power.job.iso(NOW+60)),
                         ('completed_utc', power.job.iso(NOW-7201)),
                         ('started_utc', power.job.iso(NOW-7202)),
                         ('started_utc', power.job.iso(NOW))):
        state[field] = value
        save()
        assert power.completion(base, NOW)['ready'] is False
        reset()
    @contextmanager
    def locked(path):
        raise BlockingIOError('Existing build owns lock')
        yield
    with patch.object(power.job, 'lock', locked):
        assert power.completion(base, NOW)['ready'] is False
    assert power.completion(base, NOW+86400)['ready'] is False
    result = power.completion(base, NOW)
    assert result['ready'] is True
    key = bytes(range(32))
    envelope = power.signed_envelope(result, key, 'a' * 64)
    assert hmac.compare_digest(envelope['signature'], hmac.new(key, envelope['payload'].encode(), hashlib.sha256).hexdigest())
    assert not hmac.compare_digest(envelope['signature'], hmac.new(key, (envelope['payload'] + ' ').encode(), hashlib.sha256).hexdigest())
    # Fixture used by Windows PowerShell 5.1 to verify Python/Windows interoperability.
    (ROOT / 'work' / 'power-signature-fixture.json').write_text(json.dumps(dict(
        key=key.hex(), now=NOW, envelope=envelope)))

packet = wake.magic_packet('02-00-00-00-00-01')
assert len(packet) == 102 and packet[:6] == b'\xff'*6 and packet[6:] == bytes.fromhex('020000000001')*16
sent = []
wake.wake(mac='02:00:00:00:00:01', broadcast='192.0.2.255', sender=lambda packet, address: sent.append((packet, address)))
assert sent == [(packet, ('192.0.2.255', 9))]
try:
    wake.magic_packet('bad')
    raise AssertionError('Invalid MAC was accepted')
except ValueError:
    pass
print('PASS: verified saved partial reports with AI batch errors, report hashes, active-build rejection, stale/missing/future/failed/offline/wrong-model/malformed-site rejection, signed nonce-bound response and WoL packet bytes. No LAN packets or shutdown commands sent.')
