#!/usr/bin/env python3
"""Scan the whole report window, aggregate on disk, and review a source-balanced sample.

Run as ai-monitor on the coordinator. Install beside preview_report.py. Only the
selected groups go to LAN Ollama. Raw history is read-only. No email or scheduling.
"""
import argparse
from collections import deque
from contextlib import closing
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


spec = importlib.util.spec_from_file_location('preview_core', Path(__file__).with_name('preview_report.py'))
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
_rollup_spec = importlib.util.spec_from_file_location('event_rollups', Path(__file__).with_name('event_rollups.py'))
event_rollups = importlib.util.module_from_spec(_rollup_spec)
_rollup_spec.loader.exec_module(event_rollups)
_review_spec = importlib.util.spec_from_file_location('efficient_review', Path(__file__).with_name('efficient_review.py'))
efficient = importlib.util.module_from_spec(_review_spec)
_review_spec.loader.exec_module(efficient)
spec = importlib.util.spec_from_file_location('suppression_store', Path(__file__).with_name('suppression_rules.py'))
filters = importlib.util.module_from_spec(spec)
spec.loader.exec_module(filters)
spec = importlib.util.spec_from_file_location('device_inventory', Path(__file__).with_name('device_inventory.py'))
devices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(devices)
VERSION = 'disk-balanced-v9-devices'
DEFAULT_GROUP_BUDGET = 7500
DEFAULT_ANALYSIS_SECONDS = 2700
KERNEL_UPTIME = re.compile(r'^\[\s*\d{1,12}\.\d{1,9}\]\s+')
HA_DNS_CHECK = re.compile(r'INFO \(MainThread\) \[supervisor\.resolution\.checks\.base\] Run check for (?:dns_server_failed|dns_server_ipv6_error)/dns_server\s*')
STAMGR_IPV4 = re.compile(r',ipv4= (?P<value>[0-9.]+)(?= tuple: dst port:)')
APPARMOR_EVENT = re.compile(r'^audit: type=1400 audit\((\d{10,12}\.\d{1,9}):(\d+)\): (?=apparmor="DENIED" )')
APPARMOR_PID = re.compile(r' pid=(\d+)(?= comm=")')
ROLLUP_NOTES = {
    'stamgr_query_ipv4': 'Repeated FQDN mismatch reports; only the labelled ipv4 field is grouped. Tuple endpoints and other text stay distinct. Varied values are sampled, not fully assessed.',
    'apparmor_event_pid': 'Repeated AppArmor DENIED reports; audit timestamp, serial and process ID are grouped. Operation, profile, path, command, permissions and identities stay distinct.',
}
ROLLUP_NOTES.update(event_rollups.NOTES)
MAX_SCRATCH_BYTES = 1024 ** 3
SQL_UPSERT = '''INSERT INTO grouped
    (key,site,source,priority,n,first,last,payload) VALUES(?,?,?,?,1,?,?,?)
    ON CONFLICT(key) DO UPDATE SET n=grouped.n+1,
      first=MIN(grouped.first,excluded.first), last=MAX(grouped.last,excluded.last),
      priority=MIN(grouped.priority,excluded.priority),
      payload=CASE WHEN excluded.last>=grouped.last THEN excluded.payload ELSE grouped.payload END'''


def prepare(raw):
    """Preserve error codes, IPs, accounts and message text; collapse only explicit fields."""
    message, prefix = core.message_template(raw.get('msg'))
    kernel_prefix = False
    if str(raw.get('prog', '')).lower() == 'kernel' and isinstance(message, str):
        match = KERNEL_UPTIME.match(message)
        if match and message[match.end():].strip():
            message = message[match.end():]
            kernel_prefix = True
    transfer = False
    if raw.get('tag') == 'transfer_log' and isinstance(message, str):
        try:
            detail = json.loads(message)
        except ValueError:
            detail = None
        if isinstance(detail, dict) and detail.get('synology_table') == 'transfer_log':
            # The NAS adapter records these fields as structured JSON. A transfer
            # group may contain different filenames/sizes; retain those in history
            # and the example, not in the grouping key. Keep every other field.
            detail = {key: value for key, value in detail.items() if key not in ('fname', 'fsize')}
            message = 'NAS transfer activity; file names/sizes vary. No success status inferred. ' + core.compact(detail)
            transfer = True
    return message, prefix, transfer, kernel_prefix


def classify_priority(raw, message):
    priority = core.priority(dict(raw, msg=message))
    # This precise INFO line announces execution of a named check. Its name
    # contains "failed"/"error", but the line does not state the check's outcome.
    announcement = (priority == 2 and raw.get('prog') == 'hassio_supervisor' and
                    str(raw.get('llevel', '')).lower() == 'info' and isinstance(message, str) and
                    HA_DNS_CHECK.fullmatch(message) is not None)
    return (3 if announcement else priority), announcement


def family_rollup(raw, message):
    """Only observed, tightly delimited fields vary; never infer a benign outcome."""
    if not isinstance(message, str):
        return message, '', {}
    if raw.get('prog') == 'stamgr' and message.startswith(
            'acsrvc_receive():mismatch with fqdn query to sta '):
        matches = list(STAMGR_IPV4.finditer(message))
        if len(matches) == 1:
            match = matches[0]
            value = match.group('value')
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                return message, '', {}
            normalized = message[:match.start('value')] + '<varies>' + message[match.end('value'):]
            return normalized, 'stamgr_query_ipv4', {'ipv4': value}
    if str(raw.get('prog', '')).lower() == 'kernel':
        event = APPARMOR_EVENT.match(message)
        pids = list(APPARMOR_PID.finditer(message))
        if event and len(pids) == 1:
            pid = pids[0]
            normalized = APPARMOR_EVENT.sub('audit: type=1400 audit(<time>:<serial>): ', message, count=1)
            normalized = APPARMOR_PID.sub(' pid=<varies>', normalized, count=1)
            return normalized, 'apparmor_event_pid', {
                'audit_time': event.group(1), 'audit_serial': event.group(2), 'pid': pid.group(1)}
    return event_rollups.rollup(raw, message)


def add_rollup_evidence(scratch, group):
    if not group.get('rollup_rule'):
        return
    key = group['rollup_key']
    group['grouping_note'] = ROLLUP_NOTES[group['rollup_rule']]
    group['varied_fields'] = {}
    for field, distinct in scratch.execute(
            'SELECT field,COUNT(*) FROM rollup_values WHERE key=? AND field<>? GROUP BY field',
            (key, '__message')):
        examples = scratch.execute('SELECT value FROM rollup_values WHERE key=? AND field=? '
                                   'ORDER BY n DESC,value LIMIT 3', (key, field)).fetchall()
        group['varied_fields'][field] = {'distinct': distinct, 'examples': [row[0] for row in examples]}
    group['message_variants'] = scratch.execute(
        'SELECT COUNT(*) FROM rollup_values WHERE key=? AND field=?', (key, '__message')).fetchone()[0]
    del group['rollup_key']


def materialize(row):
    key, priority, count, first, last, payload = row
    group = json.loads(payload)
    group.update(count=count, first=first, last=last, priority_hint=priority)
    return group


def choose(scratch, site, sources, budget):
    """Reserve representation, then choose by priority with round-robin sources."""
    candidates = {}
    for source in sorted(sources):
        rows = scratch.execute('''SELECT key,priority,n,first,last,payload FROM grouped
            WHERE site=? AND source=? ORDER BY priority,n DESC,last DESC,key LIMIT ?''',
            (site, source, budget)).fetchall()
        candidates[source] = [materialize(row) for row in rows]
    active = [source for source, items in candidates.items() if items]
    positions = {source: 0 for source in active}
    selected = []
    # If there are more sources than the requested budget, expand only enough to
    # represent each nonempty source once. Otherwise reserve up to five per source.
    effective = max(budget, len(active))
    reserve = min(5, effective // len(active)) if active else 0
    for _ in range(reserve):
        for source in active:
            index = positions[source]
            if index < len(candidates[source]):
                selected.append(candidates[source][index])
                positions[source] += 1
    # Critical groups first. For other flags, exhaust quiet sources alongside
    # noisy ones instead of making all keyword flags wait for every warning.
    for priorities in ((0,), (1, 2), (3,)):
        while len(selected) < effective:
            added = False
            for source in active:
                index = positions[source]
                if index < len(candidates[source]) and candidates[source][index]['priority_hint'] in priorities:
                    selected.append(candidates[source][index])
                    positions[source] += 1
                    added = True
                    if len(selected) >= effective:
                        break
            if not added:
                break
    return selected, effective


def collect(history, base, hours=24, budget=DEFAULT_GROUP_BUDGET, freshness_hours=2, now=None,
            registry=None, aggregation_timeout=600, window=None):
    now = int(time.time() if now is None else now)
    base = Path(base)
    if registry is None:
        registry = json.loads((base / 'site-registry.json').read_text(encoding='utf-8'))
    if registry.get('format_version') != 1 or not isinstance(registry.get('sites'), dict):
        raise ValueError('Invalid source registry; run collect_sites.py first')
    start, end = (now + 1 - hours * 3600, now + 1) if window is None else window
    if not isinstance(start, int) or not isinstance(end, int) or not 0 < end-start <= 168*3600 or end > now+1:
        raise ValueError('Invalid report window')
    filter_error = None
    try:
        filter_path = filters.database_path(base)
        if SETTINGS['controls_enabled'] and not filter_path.is_file():
            raise FileNotFoundError('Configured suppression store is missing')
        filter_snapshot = filters.snapshot(filter_path, now)
    except Exception as error:
        # Keep every log eligible when rules cannot be read; never silently hide data.
        filter_snapshot = {'matcher': filters.MATCHER, 'evaluated_utc': now, 'revision': None, 'rules': []}
        filter_error = 'Suppression filters could not be loaded; none were applied (' + type(error).__name__ + ').'
    device_error = None
    try:
        device_snapshot = devices.snapshot(devices.database_path(base), now,
            required=(base/'devices/enabled').exists())
    except Exception as error:
        device_snapshot = {'evaluated_utc': now, 'revision': None, 'retired': {}}
        device_error = 'Device retirement settings could not be loaded; all devices remain eligible (' + type(error).__name__ + ').'
    report = {'status': 'preview','devices': {'revision': device_snapshot['revision'], 'error': device_error,
        'retired_count': len(device_snapshot['retired']), 'policy': 'Retired identities are excluded before grouping. Original logs follow the normal retention policy.'}, 'generator': VERSION, 'generated_utc': core.iso(now),
              'window_start': start, 'window_end_exclusive': end,
              'scope': 'All stored records in this window are scanned; AI reviews a prioritized sample balanced across sources.',
              'time_basis': 'NAS receive time, then event time, then first import time when both are missing.',
              'coverage_note': 'Counts describe imported records, not unique real-world actions. Related NAS streams can describe the same activity. Source silence is not proof of health.',
              'selection_policy': 'Up to five groups per nonempty source first; remaining slots choose critical groups, then round-robin flagged sources, then unflagged groups. Severity is ordered within each source; frequency and recency break ties.',
              'suppression': {key: value for key, value in filter_snapshot.items() if key != 'rules'},
              'sites': {}}
    report['suppression'].update(active_filters=len(filter_snapshot['rules']), error=filter_error,
        policy='Exact recurring groups are excluded before AI selection. Filters are frozen at build time. Raw history is retained under the normal retention policy.')
    deadline = time.monotonic() + aggregation_timeout
    base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.report-aggregate-', dir=str(base)) as temporary, \
         closing(sqlite3.connect(Path(history).resolve().as_uri() + '?mode=ro', uri=True, timeout=15)) as database, \
         closing(sqlite3.connect(str(Path(temporary) / 'groups.sqlite'))) as scratch:
        database.execute('PRAGMA query_only=ON')
        database.execute('PRAGMA trusted_schema=OFF')
        database.execute('PRAGMA cache_size=-8192')
        database.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        database.execute('BEGIN')
        scratch.execute('PRAGMA page_size=4096')
        scratch.execute('PRAGMA max_page_count=' + str(MAX_SCRATCH_BYTES // 4096))
        scratch.execute('PRAGMA journal_mode=OFF')  # disposable scratch only, never history
        scratch.execute('PRAGMA synchronous=OFF')
        scratch.execute('PRAGMA temp_store=FILE')
        scratch.execute('PRAGMA cache_size=-8192')
        scratch.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10000)
        scratch.execute('''CREATE TABLE grouped (key TEXT PRIMARY KEY, site TEXT, source TEXT,
            priority INTEGER, n INTEGER, first INTEGER, last INTEGER, payload TEXT)''')
        scratch.execute('''CREATE TABLE rollup_values (key TEXT,field TEXT,value TEXT,n INTEGER,
            PRIMARY KEY(key,field,value))''')
        for site in ('home', 'work'):
            entry = registry['sites'].get(site, {})
            known = entry.get('sources', {})
            sources = sorted(set(known) | {row[0] for row in database.execute(
                'SELECT DISTINCT source FROM events WHERE site=?', (site,))})
            data = {'sources': {}, 'warnings': list(entry.get('warnings', [])), 'groups': [],
                    'assessments': [], 'ai_errors': [], 'rows_in_window': 0, 'rows_scanned': 0,
                    'rows_not_grouped': 0, 'malformed_rows': 0, 'prefix_timestamp_rows': 0,
                    'transfer_rollup_rows': 0, 'kernel_uptime_rows': 0, 'ha_check_announcement_rows': 0,
                    'family_rollup_rows': {}, 'family_groups_collapsed': 0,
                    'batches_completed': 0, 'batches_attempted': 0,
                    'suppressed_groups': [], 'suppressed_records': 0, 'retired_records': 0, 'retired_devices': {}}
            if filter_error:
                data['warnings'].append(filter_error)
            if device_error:
                data['warnings'].append(device_error)
            if entry.get('status') != 'complete':
                data['warnings'].append('Collection status: ' + str(entry.get('status', 'missing')))
            if not sources:
                data['warnings'].append('No sources available; coverage is unknown.')
            for source in sources:
                print(site + ': grouping ' + json.dumps(source), file=sys.stderr, flush=True)
                check = devices.source_check(known.get(source, {
                    'exported_utc': None, 'discovery_status': 'historical', 'warnings': [], 'notices': ['Source retained in history; no current export was discovered.']}), now, freshness_hours, core.registry_export_check)
                check.update(records=0, rows_scanned=0, malformed_rows=0, first_record=None, last_record=None,
                             suppressed_records=0, suppressed_groups=0, retired_records=0,
                             event_ahead_of_receive_over_5m=0, maximum_event_lead_seconds=0)
                data['sources'][source] = check
                stamp = 'COALESCE(r_utcsec,utcsec,first_seen_utc)'
                cursor = database.execute('SELECT raw_json,' + stamp + ',fingerprint,utcsec,r_utcsec FROM events '
                    'WHERE site=? AND source=? AND ' + stamp + '>=? AND ' + stamp + '<?', (site, source, start, end))
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Whole-window grouping exceeded its time budget; no new report was published')
                    batch = cursor.fetchmany(500)
                    if not batch:
                        break
                    aggregate = []
                    variants = []
                    for raw_json, observed, fingerprint, event, received in batch:
                        data['rows_in_window'] += 1
                        data['rows_scanned'] += 1
                        check['records'] += 1
                        check['rows_scanned'] += 1
                        check['first_record'] = observed if check['first_record'] is None else min(check['first_record'], observed)
                        check['last_record'] = observed if check['last_record'] is None else max(check['last_record'], observed)
                        if event is not None and received is not None:
                            lead = event - received
                            check['maximum_event_lead_seconds'] = max(check['maximum_event_lead_seconds'], lead)
                            if lead > 300:
                                check['event_ahead_of_receive_over_5m'] += 1
                        try:
                            raw = core.privacy.record(json.loads(raw_json))
                            if not isinstance(raw, dict):
                                raise ValueError('Expected a log object')
                            device_id = devices.identity(site, source, raw)
                            retired = device_snapshot['retired'].get(device_id)
                            if retired:
                                data['retired_records'] += 1
                                check['retired_records'] += 1
                                excluded = data['retired_devices'].setdefault(device_id, {'name': retired['name'],
                                    'state': retired['state'], 'records': 0, 'scope': retired['scope']})
                                excluded['records'] += 1
                                continue
                            message, prefix, transfer, kernel_prefix = prepare(raw)
                            before_rollup = message
                            message, rule, varied = family_rollup(raw, message)
                            identity = [site, source] + [raw.get(key) for key in ('host', 'ip', 'prog', 'llevel', 'prio', 'tag')] + [message]
                            if rule:
                                identity += [rule]
                            key = hashlib.sha256(core.compact(identity).encode()).hexdigest()
                            priority, announcement = classify_priority(raw, message)
                            payload = {'id': site + '-' + key[:16], 'source': source, 'suppression_key': key, 'device_id': device_id,
                                'host': core.clean(raw.get('host') or raw.get('ip'), 100),
                                'ip': core.clean(raw.get('ip'), 100), 'tag': core.clean(raw.get('tag'), 100),
                                'program': core.clean(raw.get('prog'), 100),
                                'reported_level': core.clean(raw.get('llevel'), 40),
                                'reported_priority': core.clean(raw.get('prio'), 20),
                                'message': core.clean(message, 600), 'message_truncated': len(str(message)) > 600,
                                'example_message': core.clean(raw.get('msg'), 600), 'example_fingerprint': fingerprint,
                                'normalized_prefix_timestamp': prefix, 'normalized_kernel_uptime': kernel_prefix,
                                'structured_transfer_rollup': transfer, 'check_announcement': announcement}
                            if rule:
                                payload.update(rollup_rule=rule, rollup_key=key)
                                variants.extend((key, field, value) for field, value in varied.items())
                                variants.append((key, '__message', hashlib.sha256(before_rollup.encode()).hexdigest()))
                                data['family_rollup_rows'][rule] = data['family_rollup_rows'].get(rule, 0) + 1
                            aggregate.append((key, site, source, priority, observed, observed, core.compact(payload)))
                            data['prefix_timestamp_rows'] += int(prefix)
                            data['transfer_rollup_rows'] += int(transfer)
                            data['kernel_uptime_rows'] += int(kernel_prefix)
                            data['ha_check_announcement_rows'] += int(announcement)
                        except (ValueError, TypeError):
                            data['malformed_rows'] += 1
                            data['rows_not_grouped'] += 1
                            check['malformed_rows'] += 1
                    scratch.executemany(SQL_UPSERT, aggregate)
                    scratch.executemany('''INSERT INTO rollup_values VALUES(?,?,?,1)
                        ON CONFLICT(key,field,value) DO UPDATE SET n=rollup_values.n+1''', variants)
                if not check['records']:
                    check['notices'].append('No recent qualifying messages; device health is unknown.')
                if check['malformed_rows']:
                    check['warnings'].append(str(check['malformed_rows']) + ' malformed records could not be grouped.')
                if check['event_ahead_of_receive_over_5m']:
                    check['warnings'].append('Event time is over five minutes ahead of NAS receive time in ' +
                        str(check['event_ahead_of_receive_over_5m']) + ' records; inspect source/NAS clocks.')
            report['sites'][site] = data
        scratch.commit()
        scratch.execute('CREATE INDEX selection ON grouped(site,source,priority,n DESC,last DESC,key)')
        for rule in filter_snapshot['rules']:
            row = scratch.execute('''SELECT key,priority,n,first,last,payload FROM grouped
                WHERE key=? AND site=? AND source=?''', (rule['signature'], rule['site'], rule['source'])).fetchone()
            if row is None:
                continue
            group = materialize(row)
            add_rollup_evidence(scratch, group)
            group['suppression_filter'] = {key: rule[key] for key in ('id', 'reason', 'created_utc', 'expires_utc')}
            data = report['sites'][rule['site']]
            data['suppressed_groups'].append(group)
            data['suppressed_records'] += group['count']
            check = data['sources'][rule['source']]
            check['suppressed_records'] += group['count']
            check['suppressed_groups'] += 1
            scratch.execute('DELETE FROM grouped WHERE key=?', (rule['signature'],))
        for site, data in report['sites'].items():
            selected, effective = choose(scratch, site, data['sources'], budget)
            for group in selected:
                add_rollup_evidence(scratch, group)
            data['family_groups_collapsed'] = scratch.execute('''SELECT COALESCE(SUM(variants-1),0) FROM
                (SELECT COUNT(*) AS variants FROM rollup_values v JOIN grouped g ON v.key=g.key
                 WHERE g.site=? AND v.field='__message' GROUP BY v.key)''', (site,)).fetchone()[0]
            data['groups'] = selected
            data['requested_group_budget'] = budget
            data['effective_group_budget'] = effective
            data['groups_total'] = scratch.execute('SELECT COUNT(*) FROM grouped WHERE site=?', (site,)).fetchone()[0]
            data['groups_total_before_suppression'] = data['groups_total'] + len(data['suppressed_groups'])
            data['omitted_groups'] = data['groups_total'] - len(selected)
            data['records_in_selected_groups'] = sum(group['count'] for group in selected)
            data['records_outside_ai_selection'] = data['rows_in_window'] - data['retired_records'] - data['suppressed_records'] - data['records_in_selected_groups']
            data['eligible_records'] = scratch.execute('SELECT COALESCE(SUM(n),0) FROM grouped WHERE site=?', (site,)).fetchone()[0]
            data['grouped_records'] = data['eligible_records'] + data['suppressed_records']
            if data['grouped_records'] + data['retired_records'] + data['malformed_rows'] != data['rows_scanned']:
                raise ValueError('Internal row accounting mismatch; report not published')
            data['flagged_groups_total'] = 0
            data['flagged_groups_outside_ai_selection'] = 0
            for source, check in data['sources'].items():
                total, flagged = scratch.execute('SELECT COUNT(*),COALESCE(SUM(priority<3),0) FROM grouped WHERE site=? AND source=?',
                                                (site, source)).fetchone()
                chosen = [group for group in selected if group['source'] == source]
                check.update(groups_total=total, groups_selected=len(chosen),
                             records_in_selected_groups=sum(group['count'] for group in chosen),
                             flagged_groups=flagged,
                             flagged_groups_outside_ai_selection=flagged-sum(group['priority_hint']<3 for group in chosen))
                check['reported_critical_records'] = scratch.execute('SELECT COALESCE(SUM(n),0) FROM grouped WHERE site=? AND source=? AND priority=0',
                                                                    (site, source)).fetchone()[0]
                data['flagged_groups_total'] += flagged
                data['flagged_groups_outside_ai_selection'] += check['flagged_groups_outside_ai_selection']
            if data['malformed_rows']:
                data['warnings'].append('Some malformed records could not be grouped; inspect the source counts.')
    return report


def review_summary(report):
    result = {}
    for site, data in report['sites'].items():
        assessed = {item['id'] for item in data['assessments']}
        result[site] = {
            'groups_total': data['groups_total'], 'groups_selected': len(data['groups']),
            'groups_assessed': len(assessed), 'groups_unreviewed': data['groups_total'] - len(assessed),
            'flagged_groups_unreviewed': data['flagged_groups_total'] - sum(
                group['priority_hint'] < 3 for group in data['groups'] if group['id'] in assessed),
            'kernel_uptime_rows': data.get('kernel_uptime_rows', 0),
            'ha_check_announcement_rows': data.get('ha_check_announcement_rows', 0),
            'family_rollup_rows': data.get('family_rollup_rows', {}),
            'family_groups_collapsed': data.get('family_groups_collapsed', 0),
            'suppressed_groups': len(data.get('suppressed_groups', [])),
            'suppressed_records': data.get('suppressed_records', 0),
            'retired_records': data.get('retired_records', 0),
            'time_limit_reached': bool(data.get('review_limit_notes')),
            'ai_errors': data['ai_errors']}
    return result


def analyze(report, url, model, timeout, caller=None, max_runtime=DEFAULT_ANALYSIS_SECONDS,
            clock=time.monotonic, progress=None, batcher=None):
    """Alternate flagged work across sites, then routine work, with one deadline."""
    compact = caller is None
    caller = caller or efficient.call_ollama
    batcher = batcher or (efficient.batches if compact else core.batches)
    report['review_protocol'] = efficient.VERSION if compact else 'custom-caller'
    report['inference_metrics'] = []
    began = clock()
    deadline = began + max_runtime
    report.update(model=model, ollama_url=url, analysis_budget_seconds=round(max_runtime, 1),
                  analysis_policy='Alternate sites; critical groups first within each site, then round-robin flagged sources with severity ordered within each source. Review unflagged groups after selected flagged queues are exhausted.')
    queues = {}
    sites = sorted(report['sites'])
    failed = set()
    for site in sites:
        data = report['sites'][site]
        data['analysis_seconds'] = 0
        data['review_limit_notes'] = []
        queues[site] = {}
        try:
            for priority in (0, 1, 3):
                by_source = {}
                for group in sorted(data['groups'], key=lambda group: group['priority_hint']):
                    if (group['priority_hint'] in (1, 2) if priority == 1 else group['priority_hint'] == priority):
                        by_source.setdefault(group['source'], deque()).append(group)
                ordered = []
                while any(by_source.values()):
                    for source in sorted(by_source):
                        if by_source[source]:
                            ordered.append(by_source[source].popleft())
                queues[site][priority] = deque(batcher(ordered))
        except ValueError as error:
            data['ai_errors'].append(core.clean(error, 600))
            failed.add(site)
    totals = {site: sum(len(q) for q in queues[site].values()) for site in sites}
    expired = False
    for priorities in ((0, 1), (3,)):
        while True:
            # Pick at most one batch from each site per round. A lower-priority
            # flag at work must not wait behind thousands of home error groups.
            active = [(next((priority for priority in priorities if queues[site].get(priority)), None), site)
                      for site in sites if site not in failed]
            active = sorted((priority, site) for priority, site in active if priority is not None)
            if not active:
                break
            for priority, site in active:
                remaining = deadline - clock()
                if remaining < 1:
                    expired = True
                    break
                data = report['sites'][site]
                batch = queues[site][priority].popleft()
                data['batches_attempted'] += 1
                print(site + ': analyzing batch ' + str(data['batches_attempted']) + '/' + str(totals[site]) +
                      ' (priority ' + str(priority) + ')', file=sys.stderr, flush=True)
                call_began = clock()
                try:
                    result = caller(url, model, batch, min(timeout, remaining))
                    answers = core.validate({'assessments': result}, batch)
                    if hasattr(result, 'metrics'):
                        report['inference_metrics'].append(dict(result.metrics, site=site, priority=priority))
                    data['assessments'].extend(answers)
                    data['batches_completed'] += 1
                except Exception as error:
                    if clock() >= deadline:
                        expired = True
                    else:
                        data['ai_errors'].append('Batch ' + str(data['batches_attempted']) + ': ' + core.clean(error, 600))
                        failed.add(site)
                data['analysis_seconds'] += max(0, clock() - call_began)
                if progress is not None:
                    try:
                        progress(report)
                    except Exception:
                        # A dashboard update must not change review order or stop analysis.
                        pass
                if expired:
                    break
            if expired:
                break
        if expired:
            break
    for data in report['sites'].values():
        data['analysis_seconds'] = round(data['analysis_seconds'], 1)
        unfinished = len(data['groups']) - len(data['assessments'])
        if expired and unfinished and not data['ai_errors']:
            data['review_limit_notes'].append('Runtime budget reached; ' + str(unfinished) +
                ' selected groups were not reviewed. Unreviewed groups may contain issues.')
    report['analysis_elapsed_seconds'] = round(max(0, clock() - began), 1)
    report['analysis_stop_reason'] = ('time_budget' if expired else 'ai_error' if failed else 'selected_groups_complete')
    report['status'] = 'preview_with_ai_errors' if failed else 'preview_complete'
    report['review_limited'] = any(data['groups_total'] > len(data['assessments']) or data['rows_not_grouped']
                                   for data in report['sites'].values())


def audit(report):
    return {'status': 'collection_audit', 'generator': VERSION, 'window_start_utc': core.iso(report['window_start']),
            'window_end_exclusive_utc': core.iso(report['window_end_exclusive']),
            'suppression': report.get('suppression', {}),
            'sites': {site: {
                **{key: data[key] for key in ('rows_in_window', 'rows_scanned', 'grouped_records', 'rows_not_grouped',
                    'groups_total', 'records_in_selected_groups', 'records_outside_ai_selection',
                    'flagged_groups_outside_ai_selection', 'transfer_rollup_rows', 'kernel_uptime_rows',
                    'ha_check_announcement_rows', 'family_rollup_rows', 'family_groups_collapsed', 'warnings')},
                'groups_selected': len(data['groups']),
                'suppressed_groups': len(data.get('suppressed_groups', [])),
                'suppressed_records': data.get('suppressed_records', 0),
                'retired_records': data.get('retired_records', 0),
                'sources': {source: {key: info[key] for key in ('records', 'groups_total', 'groups_selected',
                    'flagged_groups_outside_ai_selection', 'reported_critical_records', 'event_ahead_of_receive_over_5m',
                    'maximum_event_lead_seconds', 'warnings')}
                    for source, info in data['sources'].items()}}
                for site, data in report['sites'].items()}}


def render(report, zone):
    title = 'HOME + WORK LOG DIGEST - DAILY' if report.get('report_kind') == 'daily' else 'HOME + WORK LOG DIGEST - MANUAL PREVIEW'
    lines = [title, 'Generated: ' + report['generated_utc'],
             'Window: ' + core.display_time(report['window_start'], zone) + ' to ' +
             core.display_time(report['window_end_exclusive'], zone) + ' (end exclusive)',
             'Model: ' + report.get('model', 'not run'), report['scope'], report['time_basis'],
             report['coverage_note'], 'AI results are advisory; unreviewed groups can contain issues.', '']
    if report.get('executive_summary'):
        summary_spec = importlib.util.spec_from_file_location('text_summary', Path(__file__).with_name('report_summary.py'))
        summary_module = importlib.util.module_from_spec(summary_spec)
        summary_spec.loader.exec_module(summary_module)
        lines.insert(2, summary_module.render_text(report['executive_summary']))
    lifecycle = report.get('device_lifecycle', {})
    if lifecycle:
        lifecycle_lines = ['DEVICE CHANGES - LAST 7 DAYS']
        if lifecycle.get('error'):
            lifecycle_lines.append('Device changes unavailable: ' + core.clean(lifecycle['error'], 300))
        else:
            settings = lifecycle.get('settings', {})
            lifecycle_lines.append('Automatic retirement: ' + ('on' if settings.get('enabled') else 'off') +
                                   '; inactivity threshold: ' + str(settings.get('days', 10)) + ' days.')
            for change in lifecycle.get('changes', []):
                lifecycle_lines.append(core.clean(change.get('site', ''), 20) + ' / ' +
                    core.clean(change.get('name', ''), 200) + ': ' + core.clean(change.get('action', ''), 40) +
                    ' at ' + core.display_time(change.get('changed_utc'), zone))
            if not lifecycle.get('changes'): lifecycle_lines.append('No device additions, retirements or restorations in the last week.')
        lines.insert(3, '\n'.join(lifecycle_lines) + '\n')
    lines += ['PIPELINE: ' + core.clean(warning, 600) for warning in report.get('pipeline_warnings', [])]
    if 'analysis_stop_reason' in report:
        lines += ['AI review stopped: ' + report['analysis_stop_reason'] +
                  '; analysis time: ' + str(report.get('analysis_elapsed_seconds', 0)) + ' seconds.', '']
    if report.get('analysis_policy'):
        lines += ['Review order: ' + report['analysis_policy'], '']
    for site, data in report['sites'].items():
        indexed = {group['id']: group for group in data['groups']}
        assessed = {item['id'] for item in data['assessments']}
        assessed_records = sum(indexed[key]['count'] for key in assessed)
        flagged_unreviewed = data['flagged_groups_total'] - sum(indexed[key]['priority_hint'] < 3 for key in assessed)
        lines += [site.upper(), '-' * 55,
                  'Records scanned: ' + str(data['rows_scanned']) + '/' + str(data['rows_in_window']) +
                  '; ungrouped: ' + str(data['rows_not_grouped']) + '.',
                  'AI reviewed ' + str(len(assessed)) + '/' + str(data['groups_total']) +
                  ' eligible groups, representing ' + str(assessed_records) + '/' + str(data.get('eligible_records', data['rows_in_window'])) + ' eligible grouped records.',
                  'Not AI reviewed: ' + str(data['groups_total'] - len(assessed)) + ' groups; ' +
                  str(flagged_unreviewed) + ' have a severity/keyword flag. These flags are not confirmed incidents.']
        lines.append('SUPPRESSED: ' + str(data.get('suppressed_records', 0)) + ' records in ' +
                     str(len(data.get('suppressed_groups', []))) + ' recurring groups, excluded by your filters before AI review. '
                     'Collection counts still include these records. Manage filters in the report viewer.')
        lines.append('RETIRED DEVICES: ' + str(data.get('retired_records', 0)) + ' records excluded before AI review. Manage devices in the report viewer.')
        lines += ['COLLECTION: ' + core.clean(warning, 500) for warning in data['warnings']]
        lines += ['AI ERROR: ' + core.clean(error, 500) for error in data['ai_errors']]
        lines += ['REVIEW LIMIT: ' + core.clean(note, 500) for note in data.get('review_limit_notes', [])]
        if data.get('kernel_uptime_rows'):
            lines.append('Grouping: ignored only the leading kernel uptime timestamp in ' +
                         str(data['kernel_uptime_rows']) + ' records; original examples, severity, counts and event times are retained.')
        if data.get('ha_check_announcement_rows'):
            lines.append('Priority: ' + str(data['ha_check_announcement_rows']) +
                         ' Home Assistant INFO records announce named DNS checks; their names alone are not treated as failure results.')
        if data.get('family_rollup_rows'):
            lines.append('Grouping: ' + str(data['family_groups_collapsed']) +
                         ' message variants combined using named field rules. Original records remain in history; source severity is retained.')
            for rule, count in sorted(data['family_rollup_rows'].items()):
                lines.append('  ' + str(count) + ' records: ' + ROLLUP_NOTES[rule])
        lines.append('')
        for source, check in data['sources'].items():
            reviewed = sum(indexed[key]['source'] == source for key in assessed)
            lines.append(core.clean(source, 180) + ': ' + str(check['records']) + ' records; AI ' +
                         str(reviewed) + '/' + str(check['groups_total']) + ' groups; last record ' +
                         core.display_time(check['last_record'], zone) + '.')
            lines += ['  COVERAGE: ' + core.clean(warning, 500) for warning in check['warnings']]
            lines += ['  NOTE: ' + core.clean(note, 500) for note in check.get('notices', [])]
            if check['reported_critical_records']:
                lines.append('  REPORTED CRITICAL LEVEL: ' + str(check['reported_critical_records']) +
                             ' records. This is the source-reported severity, not a confirmed incident.')
        findings = [item for item in data['assessments'] if item['classification'] != 'routine']
        findings.sort(key=lambda item: ({'critical': 0, 'warning': 1, 'info': 2}[item['severity']],
                                       -indexed[item['id']]['count'], item['id']))
        if not assessed:
            lines += ['', 'No validated AI assessments; health remains unknown.']
        elif not findings:
            lines += ['', 'AI returned no issue/uncertain assessments for the reviewed sample.']
        for item in findings[:12]:
            group = indexed[item['id']]
            lines += ['', item['severity'].upper() + ' / ' + item['classification'].upper() + ' / ' + core.clean(group['source'], 180),
                      core.clean(item['summary'], 400),
                      'Evidence ' + item['id'] + ': ' + str(group['count']) + ' records, ' +
                      core.display_time(group['first'], zone) + ' through ' + core.display_time(group['last'], zone),
                      '  Example: ' + core.clean(group['example_message'], 250)]
            if item['suggested_check']:
                lines.append('Suggested investigation: ' + core.clean(item['suggested_check'], 300))
            if group.get('grouping_note'):
                lines.append('Grouping detail: ' + group['grouping_note'])
                lines.append('  Varied fields (up to three examples each): ' + core.compact(group['varied_fields']))
        if len(findings) > 12:
            lines.append(str(len(findings) - 12) + ' additional issue/uncertain assessments are in the companion JSON report.')
        routine_records = sum(indexed[item['id']]['count'] for item in data['assessments'] if item['classification'] == 'routine')
        lines += ['', 'AI-classified routine records in reviewed groups: ' + str(routine_records) + '.', '']
    return '\n'.join(lines) + '\n'


def comparison(previous, report):
    """Same-window grouping audit only. No model requests or saved-report writes."""
    result = {'status': 'grouping_comparison', 'generator': VERSION,
              'window_start_utc': core.iso(report['window_start']),
              'window_end_exclusive_utc': core.iso(report['window_end_exclusive']),
              'aggregation_seconds': report['aggregation_seconds'],
              'note': 'Same report window, current imported history. If record counts differ, changes are not due to grouping alone. No AI review was run.',
              'sites': {}}
    for site, data in report['sites'].items():
        old = previous['sites'][site]
        result['sites'][site] = {
            'previous_records': old['rows_in_window'], 'current_records': data['rows_in_window'],
            'previous_groups': old['groups_total'], 'current_groups': data['groups_total'],
            'previous_flagged_groups': old['flagged_groups_total'],
            'current_flagged_groups': data['flagged_groups_total'],
            'selected_groups': len(data['groups']),
            'selected_flagged_groups': sum(g['priority_hint'] < 3 for g in data['groups']),
            'flagged_groups_outside_selection': data['flagged_groups_outside_ai_selection'],
            'family_rollup_rows': data['family_rollup_rows'],
            'family_groups_collapsed': data['family_groups_collapsed'],
            'flagged_sources': {name: {'flagged_groups': info['flagged_groups'],
                                     'outside_selection': info['flagged_groups_outside_ai_selection']}
                               for name, info in data['sources'].items() if info['flagged_groups']}}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, default=Path('/var/lib/ai-monitor'))
    parser.add_argument('--history', type=Path)
    parser.add_argument('--output', type=Path, default=Path('/var/lib/ai-monitor/reports/balanced-preview.txt'))
    parser.add_argument('--audit-only', action='store_true')
    parser.add_argument('--compare-report', type=Path, help='With --audit-only, use this saved JSON report window and compare grouping')
    parser.add_argument('--hours', type=int, default=24)
    parser.add_argument('--max-groups-per-site', type=int, default=DEFAULT_GROUP_BUDGET)
    parser.add_argument('--freshness-hours', type=int, default=2)
    parser.add_argument('--aggregation-timeout', type=int, default=600)
    parser.add_argument('--max-runtime-seconds', type=int, default=DEFAULT_ANALYSIS_SECONDS, help='AI time budget after grouping')
    parser.add_argument('--timeout', type=int, default=180)
    parser.add_argument('--ollama-url', default=SETTINGS['ollama_url'])
    parser.add_argument('--model', default=SETTINGS['model'])
    parser.add_argument('--timezone', default=SETTINGS['timezone'])
    args = parser.parse_args()
    if args.compare_report and not args.audit_only:
        parser.error('--compare-report requires --audit-only')
    if not 1 <= args.hours <= 168 or not 1 <= args.max_groups_per_site <= 20000 or min(
            args.freshness_hours, args.aggregation_timeout, args.max_runtime_seconds, args.timeout) < 1:
        parser.error('Invalid time window, budget, or timeout; group budget must be 1-20000')
    if args.output.suffix.lower() != '.txt':
        parser.error('Use a .txt output path; the companion .json is written alongside it')
    os.umask(0o077)
    try:
        began = time.monotonic()
        previous = json.loads(args.compare_report.read_text(encoding='utf-8')) if args.compare_report else None
        window = (previous['window_start'], previous['window_end_exclusive']) if previous else None
        report = collect(args.history or args.data_dir / 'events.sqlite', args.data_dir,
                         args.hours, args.max_groups_per_site, args.freshness_hours,
                         aggregation_timeout=args.aggregation_timeout, window=window)
        report['aggregation_seconds'] = round(time.monotonic() - began, 1)
        counts = audit(report)
        counts['aggregation_seconds'] = report['aggregation_seconds']
        if args.audit_only:
            print(json.dumps(comparison(previous, report) if previous else counts, indent=2, allow_nan=False))
            return 0
        core.save_atomic(args.output.with_name(args.output.stem + '-audit.json'), json.dumps(counts, indent=2, allow_nan=False))
        analyze(report, args.ollama_url, args.model, args.timeout, max_runtime=args.max_runtime_seconds)
        core.save_atomic(args.output.with_suffix('.json'), json.dumps(report, indent=2, allow_nan=False))
        core.save_atomic(args.output, render(report, ZoneInfo(args.timezone)))
        status = {'status': report['status'], 'generator': VERSION, 'generated_utc': report['generated_utc'], 'text_report': str(args.output),
                  'json_report': str(args.output.with_suffix('.json')), 'aggregation_seconds': report['aggregation_seconds'],
                  'sites': {site: {'records': data['rows_in_window'], 'rows_scanned': data['rows_scanned'],
                    'rows_not_grouped': data['rows_not_grouped'], 'groups_total': data['groups_total'],
                    'groups_selected': len(data['groups']), 'groups_assessed': len(data['assessments']),
                    'records_in_selected_groups': data['records_in_selected_groups'],
                    'flagged_groups_outside_ai_selection': data['flagged_groups_outside_ai_selection'],
                    'sources_with_records': sum(check['records'] > 0 for check in data['sources'].values()),
                    'sources_with_selected_groups': sum(check['groups_selected'] > 0 for check in data['sources'].values()),
                    'clock_diagnostics': {source: {key: check[key] for key in (
                        'event_ahead_of_receive_over_5m', 'maximum_event_lead_seconds')}
                        for source, check in data['sources'].items() if check['maximum_event_lead_seconds'] > 0},
                    'analysis_seconds': data['analysis_seconds'], 'ai_errors': data['ai_errors'],
                    'coverage_warnings': data['warnings'] + [source + ': ' + warning
                        for source, check in data['sources'].items() for warning in check['warnings']]}
                    for site, data in report['sites'].items()}}
        core.save_atomic(args.output.with_name(args.output.stem + '-status.json'), json.dumps(status, indent=2, allow_nan=False))
        print(json.dumps(status, indent=2, allow_nan=False))
        return 2 if report['status'] == 'preview_with_ai_errors' else 0
    except Exception as error:
        print('Digest failed: ' + core.clean(error, 1000), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
