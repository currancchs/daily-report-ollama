#!/usr/bin/env python3
"""Daily collection/build and separate delivery. Run as ai-monitor in the coordinator."""
import argparse
from contextlib import contextmanager, closing
from datetime import date, datetime, time as day_time, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.request
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


HERE = Path(__file__).resolve().parent
ZONE = ZoneInfo(SETTINGS['timezone'])
PRODUCER = 'ai-monitor-daily-job-v1'
MODEL = SETTINGS['model']
OLLAMA = SETTINGS['ollama_url']
RETENTION_DAYS = 30
GROUP_CAP_PER_SITE = 7500
BUILD_LIMIT_SECONDS = 2700
FINALIZE_RESERVE_SECONDS = 60
SUMMARY_RESERVE_SECONDS = 90


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


daily = module('daily_report')
mail = module('gmail_report')
dashboard_progress = module('dashboard_progress')
summary = module('report_summary')


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def stamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError('Timestamp lacks a timezone')
    return int(parsed.timestamp())


def save(path, data):
    daily.core.save_atomic(path, json.dumps(data, indent=2, allow_nan=False) + '\n')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def report_day(now):
    return datetime.fromtimestamp(now, ZONE).date()


def window_for(day):
    # Civil dates, not a fixed 86400 seconds: DST days have 23 or 25 hours.
    start = datetime.combine(day - timedelta(days=1), day_time(3, 30), ZONE)
    end = datetime.combine(day, day_time(3, 30), ZONE)
    return int(start.timestamp()), int(end.timestamp())


def due(now, hour):
    return datetime.fromtimestamp(now, ZONE).time() >= day_time(hour)


@contextmanager
def lock(path):
    with Path(path).open('a+b') as stream:
        if os.name == 'posix':
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == 'posix':
                fcntl.flock(stream, fcntl.LOCK_UN)


def folder_for(base, day):
    folder = Path(base) / 'daily' / day.isoformat()
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return folder


def run_collection(base, folder):
    args = [sys.executable, '-I', str(HERE / 'collect_sites.py'), '--data-dir', str(base)]
    with (folder / 'collection.log').open('wb') as log:
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=(os.name == 'posix'))
        try:
            return process.wait(timeout=480)
        except subprocess.TimeoutExpired:
            # Terminate this collector and its SMB children, never other services.
            if os.name == 'posix':
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait()
            raise TimeoutError('NAS collection exceeded eight minutes; see collection.log')


def preflight():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), daily.core.NoRedirect())
    with opener.open(OLLAMA + '/api/tags', timeout=5) as response:
        payload = response.read(2 * 1024 * 1024 + 1)
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError('Ollama model list is unexpectedly large')
    if MODEL not in {item.get('name') for item in json.loads(payload).get('models', [])}:
        raise ValueError('Ollama does not list ' + MODEL)


def coverage(base, registry, bounds, began):
    warnings = []
    for site in ('home', 'work'):
        entry = registry.get('sites', {}).get(site, {})
        if entry.get('status') != 'complete':
            warnings.append(site + ': collection is ' + str(entry.get('status', 'missing')))
        if entry.get('collected_utc', 0) < began:
            warnings.append(site + ': no successful collection from this build; old history may be used')
        try:
            manifest = read(Path(base) / 'cache' / site / 'last-manifest.json')
            if manifest['run_id'] != entry['run_id']:
                raise ValueError('cached manifest does not match the collected run')
            if stamp(manifest['started_utc']) < bounds[1]:
                warnings.append(site + ': NAS export began before the 3:30 a.m. cutoff; the end of the window may be missing')
            if stamp(manifest['finished_utc']) - int(manifest['lookback_hours']) * 3600 > bounds[0]:
                warnings.append(site + ': NAS lookback may not reach the start of the report window')
        except Exception as error:
            warnings.append(site + ': cannot verify export timing: ' + daily.core.clean(error, 250))
    return warnings


def maintain(base, now):
    """Bound coordinator copies only; originals and NAS archives are never touched."""
    history = Path(base) / 'events.sqlite'
    cutoff = now - RETENTION_DAYS * 86400
    if history.exists():
        with closing(sqlite3.connect(history, timeout=15)) as db, db:
            deadline = time.monotonic() + 60
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            db.execute('DELETE FROM events WHERE COALESCE(r_utcsec,utcsec,first_seen_utc)<? '
                       'AND first_seen_utc<?', (cutoff, now - 72 * 3600))
            db.execute('DELETE FROM imports WHERE imported_utc<?', (now - 45 * 86400,))
    root = Path(base) / 'daily'
    if not root.exists():
        return
    oldest = report_day(now) - timedelta(days=RETENTION_DAYS)
    for path in root.iterdir():
        if path.is_symlink() or not path.is_dir() or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', path.name):
            continue
        if path.resolve().parent != root.resolve():
            raise ValueError('Report cleanup escaped the daily directory')
        try:
            day = date.fromisoformat(path.name)
            state = read(path / 'state.json')
        except (ValueError, OSError):
            continue
        if day < oldest and state.get('producer') == PRODUCER and state.get('report_date') == path.name:
            # Resolve and validate the exact directory before deleting our old copies.
            shutil.rmtree(path)


def verify_ready(folder, day, now):
    state = read(folder / 'state.json')
    if (state.get('producer'), state.get('report_date'), state.get('phase')) != (PRODUCER, day.isoformat(), 'ready'):
        raise ValueError('Today\'s build is not ready: ' + str(state.get('error', state.get('phase'))))
    for filename in ('report.txt', 'report.json'):
        if digest(folder / filename) != state['sha256'][filename]:
            raise ValueError('Report pair failed its checksum verification')
    if 'report.html' in state.get('sha256', {}) and digest(folder / 'report.html') != state['sha256']['report.html']:
        raise ValueError('HTML report failed its checksum verification')
    body, metadata, generated = mail.load_report(folder / 'report.txt', max_age_hours=26, now=now)
    if (metadata.get('report_kind') != 'daily' or metadata.get('report_date') != day.isoformat() or
            (metadata.get('window_start'), metadata.get('window_end_exclusive')) != window_for(day)):
        raise ValueError('Report belongs to a different day or window')
    return state, metadata


def build(base, force=False, now=None, collector=run_collection, checker=preflight,
          analyzer=None, maintenance=maintain, summarizer=None):
    build_began = time.monotonic()
    began = int(time.time() if now is None else now)
    if not due(began, 4):
        return {'phase': 'not_due', 'note': 'Build starts at 4 a.m. ' + str(ZONE)}
    day = report_day(began)
    folder = folder_for(base, day)
    with lock(Path(base) / 'daily' / '.build.lock'):
        if not force and (folder / 'state.json').exists():
            previous = read(folder / 'state.json')
            if previous.get('phase') == 'ready':
                verify_ready(folder, day, began)
                return previous
            if previous.get('phase') == 'failed':
                return previous
            if previous.get('phase') == 'building':
                # We own the lock, so the earlier process is no longer running.
                previous.update(phase='failed', error='Previous build was interrupted or exceeded its service time limit',
                                completed_utc=iso(began))
                save(folder / 'state.json', previous)
                return previous
        state = {'producer': PRODUCER, 'report_date': day.isoformat(), 'phase': 'building',
                 'started_utc': iso(began), 'group_cap_per_site': GROUP_CAP_PER_SITE,
                 'build_runtime_limit_seconds': BUILD_LIMIT_SECONDS}
        save(folder / 'state.json', state)
        progress = dashboard_progress.Tracker(folder, state['started_utc'],
                                             clock=(lambda: now) if now is not None else time.time)
        progress.stage('preparing')
        warnings = []
        try:
            try:
                maintenance(base, began)
            except Exception as error:
                warnings.append('Coordinator retention could not finish: ' + daily.core.clean(error, 350))
            if shutil.disk_usage(base).free < 2 * 1024 ** 3:
                raise OSError('Less than 2 GiB free on the coordinator; free space or expand its disk')
            print('Collecting home and work NAS exports', flush=True)
            progress.stage('collecting')
            try:
                result = collector(base, folder)
                if result:
                    warnings.append('Collector returned status ' + str(result) + '; inspect collection.log and site warnings')
            except Exception as error:
                warnings.append('Collection failed: ' + daily.core.clean(error, 400))
            registry = read(Path(base) / 'site-registry.json')
            progress.collection(base, registry)
            bounds = window_for(day)
            warnings.extend(coverage(base, registry, bounds, began))
            current = int(time.time() if now is None else now)
            progress.stage('grouping')
            report = daily.collect(Path(base) / 'events.sqlite', base, budget=GROUP_CAP_PER_SITE, now=current,
                                   registry=registry, aggregation_timeout=600, window=bounds)
            if report.get('devices', {}).get('error'):
                warnings.append(report['devices']['error'])
            if report.get('suppression', {}).get('error'):
                warnings.append(report['suppression']['error'])
            report.update(report_kind='daily', report_date=day.isoformat(), pipeline_warnings=warnings)
            report['build_runtime_limit_seconds'] = BUILD_LIMIT_SECONDS
            save(folder / 'audit.json', daily.audit(report))
            progress.counts(report)
            progress.stage('checking_ai')
            try:
                checker()
            except Exception as error:
                report['model'] = MODEL
                report['analysis_stop_reason'] = 'ollama_unavailable'
                for data in report['sites'].values():
                    data['analysis_seconds'] = 0
                    data['ai_errors'].append('Ollama unavailable: ' + daily.core.clean(error, 350))
            else:
                remaining = max(0, BUILD_LIMIT_SECONDS - FINALIZE_RESERVE_SECONDS - SUMMARY_RESERVE_SECONDS - (time.monotonic() - build_began))
                progress.stage('analyzing')
                (analyzer or daily.analyze)(report, OLLAMA, MODEL, 180, max_runtime=remaining,
                                           progress=progress.counts)
            progress.counts(report)
            progress.stage('saving')
            report['review_limited'] = any(data['groups_total'] > len(data['assessments']) or data['rows_not_grouped']
                                           for data in report['sites'].values())
            partial = report['review_limited'] or bool(warnings) or any(data['ai_errors']
                                           for data in report['sites'].values())
            report['status'] = 'daily_partial' if partial else 'daily_complete'
            # Selection/runtime limits are coverage limitations, not a failed pipeline.
            report['pipeline_issue'] = bool(warnings) or set(report['sites']) != {'home', 'work'} or any(
                data.get('ai_errors') or data.get('warnings') or data.get('rows_not_grouped') or
                any(source.get('warnings') for source in data.get('sources', {}).values())
                for data in report['sites'].values())
            try:
                if daily.devices.database_path(base).exists():
                    report['device_lifecycle'] = daily.devices.lifecycle_summary(base, current)
            except Exception as error:
                report['device_lifecycle'] = {'error': daily.core.clean(error, 300)}
            summary_time = max(0, min(SUMMARY_RESERVE_SECONDS,
                BUILD_LIMIT_SECONDS - FINALIZE_RESERVE_SECONDS - (time.monotonic() - build_began)))
            progress.stage('summarizing')
            try:
                report['executive_summary'] = (summarizer or summary.build_summary)(
                    report, base, OLLAMA, MODEL,
                    timeout=0 if report.get('analysis_stop_reason') == 'ollama_unavailable' else summary_time)
            except Exception as error:
                report['executive_summary'] = {'status': 'fallback', 'items': [],
                    'failure_type': type(error).__name__,
                    'notice': 'AI summary unavailable. Review the saved findings and coverage details below.'}
            progress.stage('saving')
            report = daily.core.privacy.record(report)
            report['sanitization'] = daily.core.privacy.VERSION
            save(folder / 'report.json', report)
            daily.core.save_atomic(folder / 'report.txt', daily.render(report, ZONE))
            mail.html_report.save(folder / 'report.html', mail.html_report.render(report))
            state.update(phase='ready', completed_utc=iso(time.time() if now is None else now),
                         report_status=report['status'], review_limited=report['review_limited'],
                         pipeline_issue=report['pipeline_issue'],
                         analysis_stop_reason=report.get('analysis_stop_reason', 'selected_groups_complete'),
                         review=daily.review_summary(report),
                         sha256={name: digest(folder / name) for name in ('report.txt', 'report.json', 'report.html')})
        except Exception as error:
            state.update(phase='failed', error=daily.core.clean(error, 800),
                         completed_utc=iso(time.time() if now is None else now))
        save(folder / 'state.json', state)
        progress.stage('complete' if state['phase'] == 'ready' else 'failed')
        return state


def fallback(folder, day, now, reason):
    start, end = window_for(day)
    metadata = {'report_kind': 'daily', 'report_date': day.isoformat(), 'status': 'daily_failed',
                'generated_utc': iso(now), 'window_start': start, 'window_end_exclusive': end}
    body = ('HOME + WORK LOG DIGEST - REPORT FAILED\nGenerated: ' + metadata['generated_utc'] +
            '\nWindow: ' + daily.core.display_time(start, ZONE) + ' to ' + daily.core.display_time(end, ZONE) +
            '\n\nToday\'s report could not be completed. Device health is UNKNOWN.\nReason: ' +
            daily.core.clean(reason, 1000) + '\n\nIn the coordinator, inspect:\n' +
            'journalctl -u ai-monitor-build.service -n 80 --no-pager\n' +
            str(folder / 'collection.log') + '\n')
    daily.core.save_atomic(folder / 'failure.txt', body)
    save(folder / 'failure.json', metadata)
    return folder / 'failure.txt'


def send(base, config_path, now=None, sender=None):
    now = int(time.time() if now is None else now)
    if not due(now, 5):
        return {'status': 'not_due', 'note': 'Delivery starts at 5 a.m. ' + str(ZONE)}
    day = report_day(now)
    folder = folder_for(base, day)
    with lock(Path(base) / 'daily' / '.delivery.lock'):
        try:
            verify_ready(folder, day, now)
            report = folder / 'report.txt'
        except Exception as error:
            report = fallback(folder, day, now, str(error))
        result = (sender or mail.send_report)(mail.load_config(config_path), report,
                Path(base) / 'reports' / 'email-state', max_age_hours=26, now=now)
        save(folder / 'delivery.json', dict(result, report_date=day.isoformat(), attempted_utc=iso(now)))
        return result


def status(base, now=None):
    now = int(time.time() if now is None else now)
    folder = Path(base) / 'daily' / report_day(now).isoformat()
    result = {'report_date': report_day(now).isoformat(), 'timezone': str(ZONE), 'folder': str(folder)}
    for name in ('state', 'delivery'):
        result[name] = read(folder / (name + '.json')) if (folder / (name + '.json')).exists() else 'not run'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, default=Path('/var/lib/ai-monitor'))
    parser.add_argument('--config', type=Path, default=Path('/etc/ai-monitor/gmail.json'))
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('build').add_argument('--force', action='store_true')
    commands.add_parser('send')
    commands.add_parser('status')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == 'build':
            result = build(args.data_dir, force=args.force)
        elif args.command == 'send':
            result = send(args.data_dir, args.config)
        else:
            result = status(args.data_dir)
        print(json.dumps(result, indent=2))
        return 1 if result.get('phase') == 'failed' else 0
    except Exception as error:
        print('Daily job failed: ' + daily.core.clean(error, 1000), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
