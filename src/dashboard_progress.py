"""Small local progress records. Observability must never interrupt a report."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time

PRODUCER = 'ai-monitor-dashboard-progress-v1'

def iso(now=None):
    return datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).isoformat()

def save(path, value):
    path = Path(path)
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix='.dashboard-', dir=path.parent)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, allow_nan=False)
        os.replace(temporary, path)
    except (OSError, ValueError, TypeError):
        pass
    finally:
        if temporary and os.path.exists(temporary):
            try:
                os.unlink(temporary)
            except OSError:
                pass

class Tracker:
    def __init__(self, folder, started, clock=time.time):
        self.path = Path(folder) / 'progress.json'
        self.clock = clock
        self.value = dict(producer=PRODUCER, report_date=Path(folder).name,
                          started_utc=started, stages={}, sites={}, exports={})

    def stage(self, name, **extra):
        current = self.value.get('stage')
        now = iso(self.clock())
        if current and current != name:
            self.value['stages'][current]['finished_utc'] = now
        self.value.update(stage=name, updated_utc=now, **extra)
        self.value['stages'].setdefault(name, {'started_utc': now})
        save(self.path, self.value)

    def collection(self, base, registry):
        result = {}
        for site in ('home', 'work'):
            entry = registry.get('sites', {}).get(site, {})
            try:
                path = Path(base) / 'cache' / site / 'last-manifest.json'
                if path.stat().st_size > 2 * 1024 ** 2:
                    continue
                manifest = json.loads(path.read_text())
                if manifest.get('run_id') != entry.get('run_id'):
                    continue
                result[site] = {key: manifest.get(key) for key in
                                ('started_utc', 'finished_utc', 'status', 'run_id')}
                result[site].update(collection_status=entry.get('status'),
                                    collected_utc=entry.get('collected_utc'))
            except (OSError, ValueError, TypeError):
                pass
        self.value['exports'] = result
        save(self.path, self.value)

    def counts(self, report):
        self.value['sites'] = {
            site: {'records': data.get('rows_in_window', 0),
                   'groups_total': data.get('groups_total', 0),
                   'groups_selected': len(data.get('groups', [])),
                   'groups_reviewed': len({a['id'] for a in data.get('assessments', [])}),
                   'rows_not_grouped': data.get('rows_not_grouped', 0),
                   'batches_completed': data.get('batches_completed', 0)}
            for site, data in report.get('sites', {}).items()}
        self.value['updated_utc'] = iso(self.clock())
        save(self.path, self.value)

def wake_status(folder, status):
    save(Path(folder) / 'wake.json', {'producer': PRODUCER, 'report_date': Path(folder).name,
                                     'status': status, 'updated_utc': iso()})
