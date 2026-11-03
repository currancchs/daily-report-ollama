#!/usr/bin/env python3
"""Private LAN report viewer and reversible exact-group suppression controls."""
import hmac
import importlib.util
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException, NotFound
from werkzeug.middleware.dispatcher import DispatcherMiddleware

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('web_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publisher = load('publish_report')
rules = load('suppression_rules')
devices = load('device_inventory')
job = publisher.load_job()
html = job.mail.html_report


def current_report(base, now):
    day = publisher.expected_day(now)
    folder = Path(base) / 'daily' / day.isoformat()
    try:
        if folder.is_symlink() or folder.parent.is_symlink():
            raise ValueError('Unexpected report path')
        if not (folder / 'state.json').exists():
            return None, 'not_ready', day
        publisher.checked_file(folder / 'state.json', 256*1024)
        state = job.read(folder / 'state.json')
        if (state.get('producer'), state.get('report_date')) != (job.PRODUCER, day.isoformat()):
            raise ValueError('Invalid state')
        if state.get('phase') == 'building':
            elapsed = now - job.stamp(state['started_utc'])
            if elapsed < -300:
                raise ValueError('Future timestamp')
            return None, 'building' if elapsed <= job.BUILD_LIMIT_SECONDS + 120 else 'overdue', day
        if state.get('phase') == 'failed':
            return None, 'build_failed', day
        for name, limit in [('report.txt', 1024*1024), ('report.json', 20*1024*1024)]:
            publisher.checked_file(folder / name, limit)
        if 'report.html' in state.get('sha256', {}):
            publisher.checked_file(folder / 'report.html', 1024*1024)
        verified, report = job.verify_ready(folder, day, now)
        checked, checked_report = job.verify_ready(folder, day, now)
        if verified != state or checked != state or checked_report != report:
            raise ValueError('Report changed during verification')
        return html.privacy.record(report), 'ready', day
    except Exception:
        return None, 'verification_failed', day


def rows_for(report, active_rules, retired=None):
    visible, suppressed = [], []
    for site in ('home', 'work'):
        data = report.get('sites', {}).get(site, {})
        groups, assessments, findings = html.index_site(data)
        # Eligible findings plus groups intentionally excluded at build time.
        candidates = [(groups[item['id']], item, False) for item in findings]
        # Also show currently filtered routine/unreviewed groups on Suppressed.
        known = {group['id'] for group, _, _ in candidates}
        for group in groups.values():
            if group['id'] not in known and rules.matching(active_rules, site, group):
                candidates.append((group, assessments.get(group['id']), False))
        candidates.extend((group, None, True) for group in data.get('suppressed_groups', []))
        for group, assessment, excluded_at_build in candidates:
            key = group.get('device_id') or devices.identity(site, group['source'], group)
            if key in (retired or {}):
                continue
            rule = rules.matching(active_rules, site, group)
            try:
                rules.scope_from_group(site, group)
                can_ignore = True
            except ValueError:
                can_ignore = False
            row = {'site': site, 'group': group, 'assessment': assessment, 'rule': rule,
                   'excluded_at_build': excluded_at_build, 'can_ignore': can_ignore}
            (suppressed if rule else visible).append(row)
    rank = {'critical': 0, 'warning': 1, 'info': 2}
    def order(row):
        return (rank.get((row['assessment'] or {}).get('severity'), 3),
                -html.n(row['group'].get('count')), row['site'], row['group']['id'])
    return sorted(visible, key=order), sorted(suppressed, key=order)


TEMPLATE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · Nightly AI Logs</title>
<style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf2f6;color:#172b40;font:15px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}a{color:#0c746d;text-decoration:none}a:hover{text-decoration:underline}header{background:#11283f;color:#fff;border-top:5px solid #2dd4bf}header>div,main{max-width:1100px;margin:auto;padding:26px 24px}header small{color:#91d8d2;letter-spacing:2px;font-weight:700}h1{font-size:30px;margin:6px 0}header p{color:#cbd5e1;margin:4px 0 20px}nav{display:flex;gap:10px;flex-wrap:wrap}nav a{padding:9px 17px;color:#d8e8f2;border-radius:7px}nav a.current{background:#fff;color:#11283f;font-weight:700}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}h2{font-size:24px;margin:5px 0 18px}.muted{color:#60748a;font-size:13px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:18px 0 24px}.metric,.panel,.issue{background:#fff;border:1px solid #dce4ec;border-radius:10px;padding:22px;margin-bottom:18px}.metric{margin:0}.metric strong{display:block;font-size:28px}.metric span{color:#60748a;font-size:12px}.issue{border-left:4px solid #0f766e}.issue.warning{border-left-color:#d97706}.issue.critical{border-left-color:#be123c}.badge{display:inline-block;border-radius:5px;padding:3px 9px;background:#eef4f8;color:#405b73;font-size:12px;font-weight:700}.badge.warning{background:#fffbeb;color:#92400e}.badge.critical{background:#fff1f2;color:#9f1239}.badge.filtered{background:#eff0fe;color:#51439a}.issue h3{margin:12px 0 8px;font-size:18px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f9;padding:14px;border-radius:7px;font:12px/1.65 Consolas,monospace}button,.button{display:inline-block;padding:10px 16px;border:1px solid #0f766e;border-radius:7px;background:#0f766e;color:white;font:600 14px system-ui;cursor:pointer}.button.secondary{background:#fff;color:#0f766e}button.danger,.button.danger{background:#fff;border-color:#be123c;color:#9f1239}.actions{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:18px}.notice{border-left:4px solid #d97706;background:#fffbeb;padding:16px 20px;margin:18px 0;border-radius:5px;color:#78350f}.success{border-color:#0f766e;background:#edf9f5;color:#115e59}label{display:block;font-weight:600;margin:18px 0 6px}textarea,select{font:inherit;max-width:100%;width:100%;padding:11px;border:1px solid #bac9d6;border-radius:6px;background:#fff;color:#172b40}textarea{min-height:85px}dl{display:grid;grid-template-columns:160px 1fr;gap:8px 18px}dt{color:#60748a}dd{margin:0;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top;overflow-wrap:anywhere}.table-wrap{overflow-x:auto}footer{font-size:12px;color:#60748a;padding:15px 0 30px}details{margin-top:12px}summary{cursor:pointer;color:#0c746d}.pager{display:flex;justify-content:space-between;margin:20px 0}@media(max-width:650px){header>div,main{padding:20px 14px}.cards{grid-template-columns:1fr;gap:8px}.metric{padding:14px}.metric strong{display:inline;font-size:23px;margin-right:10px}.panel,.issue{padding:17px}dl{grid-template-columns:1fr;gap:1px}dd{margin-bottom:10px}h1{font-size:25px}}
</style></head><body><header><div><small>NIGHTLY OPERATIONS</small><h1>Home + Work</h1>
<p>Your daily log briefing, devices and issue filters</p><nav>
<a href="/">Dashboard</a>
<a href="{{ url_for('index') }}" class="{{ 'current' if view=='report' else '' }}">Report</a>
<a href="{{ url_for('suppressed') }}" class="{{ 'current' if view=='suppressed' else '' }}">Suppressed issues</a>
<a href="{{ url_for('filters_page') }}" class="{{ 'current' if view=='filters' else '' }}">Filters</a>
<a href="{{ url_for('devices_page') }}" class="{{ 'current' if view in ('devices','device_action') else '' }}">Devices</a></nav></div></header>
<main><div class="top"><h2>{{ title }}</h2><span class="muted">{{ checked_at }}</span></div>
{% if message %}<div class="notice success">{{ message }}</div>{% endif %}
{% if filter_error %}<div class="notice">Filters could not be read. No live filters are being applied to this view; changes are disabled. Check the filter database on the coordinator.</div>{% endif %}
{% if device_error %}<div class="notice">Device settings could not be read. No device exclusions are being applied to this view. Check the device database on the coordinator.</div>{% endif %}
{% if view in ('report','suppressed') %}
  {% if not report %}<section class="panel"><h3>{{ unavailable[0] }}</h3><p>{{ unavailable[1] }}</p><p>Expected report: {{ report_date }}. Device health is unknown. Filters can still be managed separately.</p></section>
  {% else %}
    <p class="muted">Report {{ report_date }} · {{ when(report.window_start) }} → {{ when(report.window_end_exclusive) }}<br>
    Saved nightly snapshot; issue filters and device retirement reflect current settings. Changes affect the next build, including the next email built from it.</p>
    {% if retired_count %}<p class="muted">{{ retired_count }} devices are retired. Their matching findings are hidden here. Previously built reports and emails remain unchanged. <a href="{{ url_for('devices_page',state='retired') }}">Manage devices</a></p>{% endif %}
    <div class="cards"><div class="metric"><strong>{{ '{:,}'.format(total_records) }}</strong><span>RECORDS COLLECTED</span></div>
    <div class="metric"><strong>{{ '{:,}'.format(total_assessed) }} / {{ '{:,}'.format(total_eligible) }}</strong><span>ELIGIBLE GROUPS AI REVIEWED AT BUILD</span></div>
    <div class="metric"><strong>{{ '{:,}'.format(suppressed_count) }}</strong><span>GROUPS HIDDEN BY CURRENT FILTERS IN THIS SNAPSHOT</span></div></div>
    {% if report.review_limited or warnings %}<div class="notice"><strong>Coverage needs attention.</strong> Some data or AI review may be missing. Suppression does not clear collection failures or review limits.
    {% if warnings %}<ul>{% for warning in warnings %}<li>{{ warning }}</li>{% endfor %}</ul>{% endif %}</div>{% endif %}
    {% if view=='suppressed' %}<p>Matching issues remain in local history. This page shows matching groups present in the saved report, including those excluded before AI review. Filters with no match appear on the Filters page.</p>{% endif %}
    <div class="top"><p class="muted">{{ row_total }} groups · page {{ page }} of {{ pages }}</p><div><a href="{{ list_url }}">Both sites</a> · <a href="{{ list_url }}?site=home">Home</a> · <a href="{{ list_url }}?site=work">Work</a></div></div>
    {% for row in rows %}{% set group=row.group %}{% set assessment=row.assessment or {} %}
    <article class="issue {{ assessment.get('severity','info') }}"><div class="top"><div><span class="badge">{{ row.site|upper }}</span> <span class="badge {{ assessment.get('severity','info') }}">{{ assessment.get('severity','not AI reviewed')|upper }}</span>{% if row.rule %} <span class="badge filtered">SUPPRESSED</span>{% endif %}</div><span class="muted">{{ '{:,}'.format(group.count) }} records</span></div>
    <h3>{{ group.source }}{% if group.program %} · {{ group.program }}{% endif %}</h3>
    {% if assessment %}<p>{{ assessment.summary }}</p>{% else %}<p>This recurring group was excluded before AI review. {% if not row.rule %}<strong>It is eligible again for the next report build.</strong>{% endif %}</p>{% endif %}
    <pre>{{ group.example_message or group.message }}</pre><p class="muted">First {{ when(group.first) }} · Last {{ when(group.last) }}</p>
    {% if assessment.get('suggested_check') %}<p><strong>Next check:</strong> {{ assessment.suggested_check }}</p>{% endif %}
    {% if row.rule %}<p class="muted">Reason: {{ row.rule.reason or 'No reason entered' }} · {{ 'Until removed' if row.rule.expires_utc is none else 'Expires '+when(row.rule.expires_utc) }}</p>
    <div class="actions"><a class="button secondary" href="{{ url_for('remove_filter',identity=row.rule.id) }}">Restore / delete filter</a><a href="{{ url_for('filters_page') }}">View filters</a></div>
    {% elif row.can_ignore and not filter_error %}<div class="actions"><a class="button secondary" href="{{ url_for('ignore',site=row.site,identity=group.id) }}">Ignore…</a><span class="muted">Review the exact scope before saving.</span></div>
    {% else %}<p class="muted">Ignore controls become available after the next report build with this upgrade.</p>{% endif %}</article>
    {% else %}<section class="panel"><h3>{{ 'No matching suppressed groups' if view=='suppressed' else 'No visible issue groups' }}</h3><p>This describes the saved report and current filters. It does not establish that all devices are healthy.</p></section>{% endfor %}
    <div class="pager">{% if page>1 %}<a href="{{ list_url }}?page={{ page-1 }}&amp;site={{ site }}">← Previous</a>{% else %}<span></span>{% endif %}{% if page<pages %}<a href="{{ list_url }}?page={{ page+1 }}&amp;site={{ site }}">Next →</a>{% endif %}</div>
    {% if view=='report' %}<section class="panel"><h3>Collection coverage</h3><div class="table-wrap"><table><thead><tr><th>Site / source</th><th>Records</th><th>Suppressed at build</th><th>Retired at build</th><th>Last record / notes</th></tr></thead><tbody>{% for item in coverage %}<tr><td>{{ item.site|title }} / {{ item.source }}</td><td>{{ item.data.records }}</td><td>{{ item.data.get('suppressed_records',0) }}</td><td>{{ item.data.get('retired_records',0) }}</td><td>{{ when(item.data.last_record) }}{% for warning in item.data.warnings %}<br>{{ warning }}{% endfor %}{% for note in item.data.get('notices',[]) %}<br><span class="muted">{{ note }}</span>{% endfor %}</td></tr>{% endfor %}</tbody></table></div></section>{% endif %}
  {% endif %}
{% elif view=='filters' %}
  <p>Filters match one recurring log group within one site and source. Deleting a filter makes matching messages eligible for future report builds. Original logs follow the existing retention policy.</p>
  <p class="muted">{{ active_count }} active · {{ expired_count }} expired · page {{ page }} of {{ pages }}</p>
  {% for rule in filter_rows %}<section class="panel"><div class="top"><div><span class="badge">{{ rule.site|upper }}</span> <span class="badge {{ 'filtered' if rule.is_active else '' }}">{{ 'ACTIVE' if rule.is_active else 'EXPIRED' }}</span></div><a class="button danger" href="{{ url_for('remove_filter',identity=rule.id) }}">Delete filter</a></div>
  <h3>{{ rule.source }} · {{ rule.scope.get('program','') }}</h3><p>{{ rule.reason or 'No reason entered' }}</p>
  <p class="muted">Created {{ when(rule.created_utc) }} · {{ 'Until removed' if rule.expires_utc is none else 'Expires '+when(rule.expires_utc) }}</p>
  <details><summary>View exact scope</summary>{{ scope_details(rule.scope) }}<p class="muted">Filter {{ rule.id }} · Signature {{ rule.signature }}</p></details></section>
  {% else %}<section class="panel"><h3>No suppression filters</h3><p>Use Ignore beside an issue in the report to create one.</p></section>{% endfor %}
  <div class="pager">{% if page>1 %}<a href="{{ url_for('filters_page') }}?page={{ page-1 }}">← Previous</a>{% else %}<span></span>{% endif %}{% if page<pages %}<a href="{{ url_for('filters_page') }}?page={{ page+1 }}">Next →</a>{% endif %}</div>
{% elif view=='devices' %}
  <p>Devices are identified by site, hostname and IP address. Case-only hostname variants with the same IP share one entry. Quiet devices remain active; silence alone is not a collection failure.</p>
  <div class="panel"><div class="top"><div><a href="{{ url_for('devices_page',state='active',site=site) }}">Active ({{ counts.active }})</a> · <a href="{{ url_for('devices_page',state='retired',site=site) }}">Retired ({{ counts.retired }})</a> · <a href="{{ url_for('devices_page',state='permanent',site=site) }}">Permanently retired ({{ counts.permanent }})</a></div><div><a href="{{ url_for('devices_page',state=state) }}">Both sites</a> · <a href="{{ url_for('devices_page',state=state,site='home') }}">Home</a> · <a href="{{ url_for('devices_page',state=state,site='work') }}">Work</a></div></div>
  <p class="muted">Inventory refreshed {{ when(refreshed_utc) }} from retained local history. {{ row_total }} {{ state_label|lower }} devices · page {{ page }} of {{ pages }}</p></div>
  {% for device in device_rows %}<section class="panel"><div class="top"><div><span class="badge">{{ device.scope.site|upper }}</span> <span class="badge {{ 'filtered' if device.state!='active' else '' }}">{{ state_label|upper }}</span></div><span class="muted">{{ device.observation }}</span></div>
  <h3>{{ device.name }}</h3><p>{{ device.scope.ip or 'NAS-local log streams' if device.scope.kind=='nas-local' else device.scope.ip or 'No IP recorded' }}</p>
  <p class="muted">First message {{ when(device.first_seen) }} · Last message {{ when(device.last_seen) }}<br>{{ '{:,}'.format(device.retained_records) }} records in retained history · Latest site collection: {{ device.collection_status }}</p>
  {% if device.reason %}<p>Reason: {{ device.reason }}</p>{% endif %}
  {% if device.collection_warnings %}<div class="notice">{% for warning in device.collection_warnings %}<p>{{ warning }}</p>{% endfor %}</div>{% endif %}
  <details><summary>{{ device.aliases|length }} observed source / hostname aliases</summary><div class="table-wrap"><table><thead><tr><th>Source / hostname</th><th>IP</th><th>Last message</th><th>NAS discovery</th></tr></thead><tbody>{% for alias in device.aliases %}<tr><td>{{ alias.source }}<br>{{ alias.host }}</td><td>{{ alias.ip }}</td><td>{{ when(alias.last_seen) }}</td><td>{{ alias.discovery_status }}{% if alias.has_live_database %} · live database{% endif %}</td></tr>{% endfor %}</tbody></table></div></details>
  <div class="actions">{% if device.state=='active' %}<a class="button secondary" href="{{ url_for('device_action',identity=device.id,action='retire') }}">Retire…</a>{% elif device.state=='retired' %}<a class="button secondary" href="{{ url_for('device_action',identity=device.id,action='restore') }}">Restore…</a><a class="button danger" href="{{ url_for('device_action',identity=device.id,action='permanent') }}">Retire permanently…</a>{% else %}<span class="muted">Permanently excluded. This identity will not be rediscovered as active and cannot be restored here.</span>{% endif %}</div></section>
  {% else %}<section class="panel"><h3>No {{ state_label|lower }} devices</h3><p>The inventory refreshes when logs are collected. Retirement does not delete historical logs.</p></section>{% endfor %}
  <div class="pager">{% if page>1 %}<a href="{{ url_for('devices_page',state=state,site=site,page=page-1) }}">← Previous</a>{% else %}<span></span>{% endif %}{% if page<pages %}<a href="{{ url_for('devices_page',state=state,site=site,page=page+1) }}">Next →</a>{% endif %}</div>
{% elif view=='device_action' %}
  <section class="panel"><h3>{{ title }}: {{ device.name }}</h3><dl><dt>Site</dt><dd>{{ device.scope.site|title }}</dd><dt>Hostname / IP</dt><dd>{{ device.scope.host }} / {{ device.scope.ip or 'NAS-local streams' }}</dd><dt>Source aliases</dt><dd>{% for alias in device.aliases %}{{ alias.source }}{% if not loop.last %}, {% endif %}{% endfor %}</dd></dl>
  {% if action=='retire' %}<p>Exclude this device's records from future AI review and reports. You can restore it later, or retire it permanently from the Retired tab. This affects the log sender, not just one issue.</p>
  {% elif action=='restore' %}<p>Make this device's records eligible for the next report build. Any separate issue filters still apply.</p>
  {% else %}<div class="notice"><strong>This cannot be undone through the web interface.</strong> Keep this device excluded permanently, even if the same identity sends more logs. A different hostname or IP will be treated as a new device.</div>{% endif %}
  <p>Historical logs remain under the existing retention policy. NAS configuration and already built reports are unchanged.</p>
  <form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="revision" value="{{ device.revision }}">
  <label for="reason">Reason (optional)</label><textarea id="reason" name="reason" maxlength="240">{{ device.reason }}</textarea>
  {% if action=='permanent' %}<label><input type="checkbox" name="confirm_permanent" value="yes" required> I understand this device cannot be restored from the web interface.</label>{% endif %}
  <div class="actions"><button type="submit" class="{{ 'danger' if action=='permanent' else '' }}">{{ title }}</button><a href="{{ url_for('devices_page',state=device.state) }}">Cancel</a></div></form></section>
{% elif view=='ignore' %}
  <section class="panel"><h3>Ignore this recurring issue?</h3><p>The match uses the full normalized log text and its site, source, host/IP, program, reported severity and tag. The AI summary is not part of the match.</p>
  {{ scope_details(scope) }}
  <form method="post" action="{{ url_for('ignore',site=target_site,identity=target_id) }}">
  <input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="report_date" value="{{ report_date }}">
  <label for="duration">Ignore for</label><select id="duration" name="duration"><option value="forever" selected>Until I remove it</option><option value="1d">24 hours</option><option value="7d">7 days</option><option value="30d">30 days</option></select>
  <label for="reason">Reason (optional)</label><textarea name="reason" id="reason" maxlength="240" placeholder="For example: patio sensor is temporarily out of service"></textarea>
  <p class="muted">This hides the issue in the current web view and excludes matching groups from the next report build. A report already built or emailed is not rewritten. Logs are retained.</p>
  <div class="actions"><button type="submit">Save ignore filter</button><a href="{{ url_for('index') }}">Cancel</a></div></form></section>
{% elif view=='remove' %}
  <section class="panel"><h3>Delete this filter and restore matching messages?</h3>{{ scope_details(rule.scope) }}
  <p>Reason: {{ rule.reason or 'No reason entered' }}</p><p>Matching records will be eligible for the next AI review and report. If this report excluded them before AI review, they will appear as awaiting review until a new report is built.</p>
  <form method="post" action="{{ url_for('remove_filter',identity=rule.id) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><div class="actions"><button class="danger" type="submit">Delete filter and restore</button><a href="{{ url_for('filters_page') }}">Cancel</a></div></form></section>
{% elif view=='error' %}<section class="panel"><h3>{{ error_title }}</h3><p>{{ error_detail }}</p><a href="{{ url_for('index') }}">Return to report</a></section>{% endif %}
<footer>{{ timezone }} · Local logs and local AI · AI findings are advisory.<br>Anyone permitted by the LAN/VPN access rules can view reports and manage filters and devices.</footer></main></body></html>'''

SCOPE_MACRO = r'''{% macro scope_details(scope) %}<dl><dt>Site / source</dt><dd>{{ scope.site|title }} / {{ scope.source }}</dd><dt>Host / IP</dt><dd>{{ scope.get('host','') }} / {{ scope.get('ip','') }}</dd><dt>Program / tag</dt><dd>{{ scope.get('program','') }} / {{ scope.get('tag','') }}</dd><dt>Reported severity</dt><dd>{{ scope.get('reported_level','') }} / {{ scope.get('reported_priority','') }}</dd></dl><p class="muted">Normalized message{{ ' excerpt (full message is used for matching)' if scope.get('message_truncated') else '' }}</p><pre>{{ scope.get('message','') }}</pre>{% if scope.get('grouping_note') or scope.get('structured_transfer_rollup') %}<div class="notice"><strong>This group combines varying fields.</strong> {{ scope.get('grouping_note','File names and sizes vary within this NAS transfer group.') }} Saving this filter suppresses all variants within this group.</div>{% endif %}{% endmacro %}'''


def create_app(base='/var/lib/ai-monitor', secret_path='/etc/ai-monitor-web/session.key', secret=None, clock=time.time):
    origin = urlsplit(publisher.SETTINGS['viewer_origin'])
    app = Flask(__name__, static_folder=None, root_path=str(HERE))
    if secret is None:
        secret = Path(secret_path).read_bytes().strip()
    if len(secret) < 32:
        raise ValueError('A persistent session secret of at least 32 bytes is required')
    app.config.update(SECRET_KEY=secret, MAX_CONTENT_LENGTH=16384, MAX_FORM_MEMORY_SIZE=16384,
                      MAX_FORM_PARTS=12, SESSION_COOKIE_NAME='ai_monitor_controls',
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=(origin.scheme == 'https'), SESSION_COOKIE_PATH='/controls', DEBUG=False)
    base = Path(base)
    path = rules.database_path(base)
    hosts = {origin.netloc}

    def page(title, view, **context):
        context.setdefault('checked_at', publisher.checked_at(clock()))
        context.setdefault('timezone', publisher.SETTINGS['timezone'])
        context.setdefault('message', None)
        context.setdefault('filter_error', False)
        context.setdefault('device_error', False)
        context.setdefault('csrf', session.get('csrf'))
        return render_template_string(SCOPE_MACRO + TEMPLATE, title=title, view=view, when=html.when, **context)

    @app.before_request
    def guard():
        if request.host not in hosts:
            abort(400, description='Use the configured viewer origin and /controls/ path.')
        if request.method not in ('GET', 'HEAD', 'POST'):
            abort(405)
        if request.method == 'POST':
            submitted_origin = request.headers.get('Origin')
            if submitted_origin is None:
                submitted_origin = request.headers.get('Referer', '')
            try:
                parsed = urlsplit(submitted_origin)
            except ValueError:
                abort(403)
            if (parsed.scheme, parsed.netloc) != (origin.scheme, request.host) or parsed.username or parsed.password:
                abort(403, description='The change must be submitted from this report page.')
            if request.headers.get('Sec-Fetch-Site') == 'cross-site':
                abort(403)
            if request.mimetype != 'application/x-www-form-urlencoded':
                abort(415)
            token = session.get('csrf', '')
            submitted = request.form.get('csrf', '')
            if not token or not submitted or not submitted.isascii() or not hmac.compare_digest(token, submitted):
                abort(403, description='The form expired. Reload the page and try again.')
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store, max-age=0'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
        response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return page('Request not completed', 'error', error_title=error.name, error_detail=error.description), error.code

    @app.errorhandler(Exception)
    def internal_error(error):
        app.logger.error('Report controls failed: %s', type(error).__name__)
        return page('Controls unavailable', 'error', error_title='The request could not be completed',
                    error_detail='Check ai-monitor-web.service on the coordinator. No log records were deleted.'), 503

    def filter_snapshot():
        if not path.is_file():
            raise ValueError('Filter database is missing')
        return rules.snapshot(path, clock())

    def pagination(items):
        number = request.args.get('page', '1')
        if not re.fullmatch(r'[1-9][0-9]{0,5}', number):
            abort(400, description='Invalid page number')
        pages = max(1, (len(items)+19)//20)
        number = min(int(number), pages)
        return items[(number-1)*20:number*20], number, pages

    def show_report(suppressed=False):
        now = clock()
        report, status, day = current_report(base, now)
        error = False
        try:
            active_rules = {rule['signature']: rule for rule in filter_snapshot()['rules']}
        except Exception:
            active_rules, error = {}, True
        try:
            retired = devices.snapshot(devices.database_path(base), now,
                required=(base/'devices'/'enabled').exists())['retired']
            device_error = False
        except Exception:
            retired, device_error = {}, True
        context = dict(report=report, report_date=day.isoformat(), filter_error=error,
                       device_error=device_error, retired_count=len(retired),
                       unavailable=publisher.MESSAGES.get(status), list_url=url_for('suppressed' if suppressed else 'index'))
        if report:
            visible, hidden = rows_for(report, active_rules, retired)
            rows = hidden if suppressed else visible
            site = request.args.get('site', 'all')
            if site not in ('all', 'home', 'work'):
                abort(400, description='Invalid site')
            rows = [row for row in rows if site == 'all' or row['site'] == site]
            selected, number, pages = pagination(rows)
            sites = report.get('sites', {})
            warnings = list(report.get('pipeline_warnings', []))
            coverage = []
            for name, data in sites.items():
                warnings.extend(name.title()+': '+str(item) for field in ('warnings', 'ai_errors', 'review_limit_notes') for item in data.get(field, []))
                coverage.extend(dict(site=name, source=source, data=info) for source, info in data.get('sources', {}).items())
            context.update(rows=selected, page=number, pages=pages, site=site, row_total=len(rows),
                suppressed_count=len(hidden), coverage=coverage, warnings=warnings,
                total_records=sum(html.n(data.get('rows_in_window')) for data in sites.values()),
                total_assessed=sum(len(html.index_site(data)[1]) for data in sites.values()),
                total_eligible=sum(html.n(data.get('groups_total')) for data in sites.values()))
        messages = {'created': 'Ignore filter saved. It applies to the next report build; this web view reflects it now.',
                    'deleted': 'Filter deleted. Matching messages are eligible for the next report build.'}
        context['message'] = messages.get(request.args.get('changed'))
        return page('Suppressed issues' if suppressed else 'Latest report', 'suppressed' if suppressed else 'report', **context)

    @app.get('/')
    def index():
        return show_report()

    @app.get('/suppressed')
    def suppressed():
        return show_report(True)

    @app.get('/devices')
    def devices_page():
        view = devices.catalog(base, clock())
        state, site = request.args.get('state', 'active'), request.args.get('site', 'all')
        if state not in ('active', 'retired', 'permanent') or site not in ('all', 'home', 'work'):
            abort(400, description='Invalid device view')
        items = [item for item in view['devices'] if site=='all' or item['scope']['site']==site]
        counts = {key: sum(item['state']==key for item in items) for key in ('active','retired','permanent')}
        rows = [item for item in items if item['state']==state]
        selected, number, pages = pagination(rows)
        labels = {'active':'Active', 'retired':'Retired', 'permanent':'Permanently retired'}
        messages = {'retire':'Device retired. Its records are excluded from the next build; you can restore it here.',
                    'restore':'Device restored. Its records are eligible for the next build.',
                    'permanent':'Device permanently retired. Historical logs remain retained.'}
        return page('Devices', 'devices', device_rows=selected, counts=counts, state=state,
                    site=site, state_label=labels[state], page=number, pages=pages, row_total=len(rows),
                    refreshed_utc=view['refreshed_utc'], message=messages.get(request.args.get('changed')))

    @app.route('/devices/<identity>/<action>', methods=['GET','POST'])
    def device_action(identity, action):
        if action not in ('retire','restore','permanent') or not re.fullmatch('[a-f0-9]{64}', identity):
            abort(404)
        device = next((item for item in devices.catalog(base, clock())['devices'] if item['id']==identity), None)
        if device is None: abort(404)
        if device['state'] != ('active' if action=='retire' else 'retired'):
            abort(409, description='That action is not available for this device.')
        if request.method == 'POST':
            if action=='permanent' and request.form.get('confirm_permanent')!='yes':
                abort(400, description='Confirm permanent retirement before saving.')
            try:
                state = devices.change(base, identity, action, request.form.get('revision',''),
                                       request.form.get('reason',''), clock())
            except ValueError as error:
                abort(409, description=str(error))
            return redirect(url_for('devices_page',state=state,changed=action), code=303)
        title = {'retire':'Retire device','restore':'Restore device','permanent':'Retire permanently'}[action]
        return page(title, 'device_action', device=device, action=action)

    @app.get('/filters')
    def filters_page():
        now = clock()
        all_rules = rules.list_rules(path)
        for rule in all_rules:
            rule['is_active'] = rules.active(rule, now)
        all_rules.sort(key=lambda rule: (not rule['is_active'], -rule['created_utc'], rule['id']))
        selected, number, pages = pagination(all_rules)
        return page('Suppression filters', 'filters', filter_rows=selected, page=number, pages=pages,
                    active_count=sum(rule['is_active'] for rule in all_rules),
                    expired_count=sum(not rule['is_active'] for rule in all_rules))

    def target(site, identity):
        report, status, day = current_report(base, clock())
        if status != 'ready' or site not in ('home', 'work'):
            abort(409, description='A verified current report is required. Return after the report is ready.')
        data = report.get('sites', {}).get(site, {})
        groups, assessed, findings = html.index_site(data)
        eligible = {item['id'] for item in findings}
        for group in data.get('suppressed_groups', []):
            groups[group['id']] = group
            eligible.add(group['id'])
        if identity not in eligible or identity not in groups:
            abort(404)
        group = groups[identity]
        try:
            _, _, scope = rules.scope_from_group(site, group)
        except ValueError as error:
            abort(409, description=str(error))
        return group, scope, day

    @app.route('/ignore/<site>/<identity>', methods=['GET', 'POST'])
    def ignore(site, identity):
        filter_snapshot()  # Do not offer changes when the database is unavailable.
        group, scope, day = target(site, identity)
        if request.method == 'POST':
            if request.form.get('report_date') != day.isoformat():
                abort(409, description='The reporting date changed. Reload the issue before saving.')
            try:
                rules.create(path, site, group, request.form.get('reason', ''), request.form.get('duration', 'forever'), clock())
            except ValueError as error:
                abort(400, description=str(error))
            return redirect(url_for('index', changed='created'), code=303)
        return page('Create ignore filter', 'ignore', scope=scope, target_site=site,
                    target_id=identity, report_date=day.isoformat())

    @app.route('/filters/<identity>/delete', methods=['GET', 'POST'])
    def remove_filter(identity):
        rule = next((rule for rule in rules.list_rules(path) if rule['id'] == identity), None)
        if rule is None:
            abort(404)
        if request.method == 'POST':
            rules.delete(path, identity, clock())
            return redirect(url_for('index', changed='deleted'), code=303)
        return page('Restore matching messages', 'remove', rule=rule)

    return app


def create_dispatcher(**kwargs):
    """Only /controls is dynamic; NGINX retains the static dashboard routes."""
    return DispatcherMiddleware(NotFound(), {'/controls': create_app(**kwargs)})
