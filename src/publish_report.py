#!/usr/bin/env python3
"""Publish one verified, sanitized HTML digest. No collection, AI or email calls."""
import argparse
from datetime import datetime, time as day_time, timedelta
from html import escape
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import time
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


ZONE = ZoneInfo(SETTINGS['timezone'])
HERE = Path(__file__).resolve().parent


def load_job():
    spec = importlib.util.spec_from_file_location('viewer_daily_job', HERE / 'daily_job.py')
    job = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(job)
    return job


def expected_day(now):
    local = datetime.fromtimestamp(now, ZONE)
    return local.date() - timedelta(days=int(local.time() < day_time(4)))


def checked_at(now):
    return datetime.fromtimestamp(now, ZONE).strftime('%Y-%m-%d %I:%M:%S %p %Z')


def banner(day, now):
    return ('<div style="background:#11283f;color:#fff;padding:14px 20px;'
            'font:13px/1.6 Arial,Helvetica,sans-serif;text-align:center;">'
            '<strong>Latest nightly digest &middot; ' + escape(day.isoformat()) + '</strong><br>'
            'Publication check: ' + escape(checked_at(now)) + '<br>'
            'Scheduled build: 4:00 a.m. ' + escape(str(ZONE)) + '. Publication checked every five minutes.<br>'
            'This is a saved nightly report, not live device status. '
            'Refresh to see a newer publication.</div>')


MESSAGES = {
    'building': ('Report is being prepared', 'The current build is still running. Refresh after it finishes.'),
    'overdue': ('Report is overdue', 'The build has exceeded its normal 45-minute allowance. Check the build service on the coordinator.'),
    'build_failed': ('Report build failed', 'Check ai-monitor-build.service on the coordinator. No older report is being substituted.'),
    'not_ready': ('Report is not available yet', 'No completed report is available for this reporting date.'),
    'verification_failed': ('Report could not be verified', 'The report date, age, format or saved checksums did not pass verification.'),
    'component_unavailable': ('Report publisher needs attention', 'Check ai-monitor-publish.service and the installed HTML upgrade on the coordinator.'),
}


def placeholder(reason, day, now):
    title, detail = MESSAGES[reason]
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Nightly AI Logs - report unavailable</title></head>'
            '<body style="margin:0;background:#edf2f6;color:#1e293b;font-family:Arial,Helvetica,sans-serif;">'
            + banner(day, now) + '<main style="max-width:680px;margin:36px auto;padding:28px;'
            'background:white;border-top:5px solid #d97706;border-radius:8px;">'
            '<p style="color:#0f766e;font-weight:bold;letter-spacing:1px;">HOME + WORK</p>'
            '<h1>' + escape(title) + '</h1><p style="line-height:1.7;">' + escape(detail) + '</p>'
            '<p><strong>Device health is unknown.</strong></p>'
            '<p style="color:#64748b;line-height:1.7;">The scheduled report covers the period ending '
            'at 3:30 a.m. on the reporting date. Missing data does not mean there are no issues.</p>'
            '</main></body></html>')


def checked_file(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('Invalid report file')


def snapshot(base, now):
    day = expected_day(now)
    try:
        job = load_job()
    except Exception:
        return placeholder('component_unavailable', day, now), 'component_unavailable', day
    folder = Path(base) / 'daily' / day.isoformat()
    reason = 'verification_failed'
    try:
        if folder.is_symlink() or folder.parent.is_symlink():
            raise ValueError('Invalid report directory')
        state_path = folder / 'state.json'
        if not state_path.exists():
            reason = 'not_ready'
        else:
            checked_file(state_path, 256 * 1024)
            state = job.read(state_path)
            if (state.get('producer'), state.get('report_date')) != (job.PRODUCER, day.isoformat()):
                raise ValueError('Invalid report state')
            phase = state.get('phase')
            if phase == 'building':
                elapsed = now - job.stamp(state['started_utc'])
                if elapsed < -300:
                    raise ValueError('Future build timestamp')
                reason = 'building' if elapsed <= job.BUILD_LIMIT_SECONDS + 120 else 'overdue'
            elif phase == 'failed':
                reason = 'build_failed'
            elif phase == 'ready':
                for name, limit in [('report.txt', 1024 * 1024), ('report.json', 20 * 1024 * 1024)]:
                    checked_file(folder / name, limit)
                if 'report.html' in state.get('sha256', {}):
                    checked_file(folder / 'report.html', 1024 * 1024)
                verified, report = job.verify_ready(folder, day, now)
                if verified != state:
                    raise ValueError('Build changed during verification')
                # Regenerate escaped HTML from validated JSON, including pre-upgrade reports.
                # Never serve arbitrary saved HTML, raw JSON, SQLite files, or exception text.
                content = job.mail.html_report.render(report)
                checked_state, checked_report = job.verify_ready(folder, day, now)
                if checked_state != state or checked_report != report:
                    raise ValueError('Build changed during rendering')
                content, inserted = re.subn(r'(<body\b[^>]*>)',
                    lambda match: match[0] + banner(day, now), content, count=1, flags=re.I)
                if inserted != 1:
                    raise ValueError('HTML renderer produced no body')
                return content, 'published', day
            else:
                reason = 'not_ready'
    except Exception:
        reason = 'verification_failed'
    return placeholder(reason, day, now), reason, day


def save_publication(directory, content, name='index.html'):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Publication directory must already exist and must not be a symlink')
    if name not in ('index.html', 'report.html') and not re.fullmatch(r'\d{4}-\d{2}-\d{2}\.html', name):
        raise ValueError('Invalid publication name')
    if len(content.encode('utf-8')) > 1024 * 1024:
        raise ValueError('Publication is too large')
    fd, temporary = tempfile.mkstemp(prefix='.publish-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            if os.name == 'posix':
                # The setgid publication directory assigns the www-data group.
                os.fchmod(stream.fileno(), 0o640)
        os.replace(temporary, directory / name)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish(base, directory, now=None):
    now = time.time() if now is None else now
    content, status, day = snapshot(base, now)
    history_dir = Path(directory) / 'history'
    if history_dir.is_symlink():
        raise ValueError('Invalid history directory')
    # The root installer sets the www-data group and setgid bit. The service
    # runs with RestrictSUIDSGID=true, so it must not request special mode bits.
    # If recreated, this directory inherits the parent publication directory's
    # group/setgid bit through the filesystem without a chmod operation.
    history_dir.mkdir(exist_ok=True, mode=0o750)
    valid_names = set()
    try:
        spec = importlib.util.spec_from_file_location('dashboard', HERE / 'dashboard.py')
        dash = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dash)
        job = load_job()
        current = None
        history = []
        for offset in range(dash.HISTORY_DAYS):
            report_day = day - timedelta(days=offset)
            folder = Path(base) / 'daily' / report_day.isoformat()
            if not folder.exists():
                continue
            try:
                entry = dash.load_report(job, base, report_day, now, current=(offset == 0))
                if offset == 0:
                    if status != 'published':
                        raise ValueError('Current report did not pass publication checks')
                    current = entry
                name = report_day.isoformat() + '.html'
                save_publication(history_dir, dash.report_page(entry['html'], report_day, now, True), name)
                valid_names.add(name)
                history.append(dict(day=report_day, verified=True, sites=entry['sites']))
            except Exception:
                history.append(dict(day=report_day, verified=False, label='Unavailable'))
                if offset == 0 and status == 'published':
                    status = 'verification_failed'
        if current:
            content = dash.report_page(current['html'], day, now)
        else:
            content = placeholder(status if status in MESSAGES else 'not_ready', day, now)
        run_day = datetime.fromtimestamp(now, ZONE).date()
        dashboard = dash.render(day, now, status, current, history,
                                dash.timeline(base, run_day, now, job, status if run_day == day else None))
        save_publication(directory, content, 'report.html')
        save_publication(directory, dashboard)
    except Exception:
        status = 'component_unavailable'
        content = placeholder(status, day, now)
        save_publication(directory, content, 'report.html')
        save_publication(directory, content)
        valid_names.clear()
    # Remove only the dated HTML artifacts owned by this publisher, including
    # reports which were subsequently corrupted or aged out of local retention.
    for path in history_dir.iterdir():
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}\.html', path.name) and path.name not in valid_names:
            if path.is_symlink() or path.is_file():
                path.unlink()
    return {'status': status, 'report_date': day.isoformat(), 'checked_at': checked_at(now),
            'history_reports': len(valid_names), 'dashboard': 'v1'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path, default=Path('/var/lib/ai-monitor'))
    parser.add_argument('--output-dir', type=Path, default=Path('/srv/ai-monitor-report'))
    args = parser.parse_args()
    print(json.dumps(publish(args.data_dir, args.output_dir)))


if __name__ == '__main__':
    main()
