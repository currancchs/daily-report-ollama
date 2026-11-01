#!/usr/bin/env python3
"""Render a bounded, escaped HTML email from validated local report metadata.

No scripts, remote images, tracking pixels, model-generated HTML or model URLs.
The CLI writes a browser preview only; it never sends mail or runs an AI model.
"""
import argparse
from datetime import datetime
from html import escape
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


_spec = importlib.util.spec_from_file_location('html_privacy', Path(__file__).with_name('sanitize_logs.py'))
privacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(privacy)
ZONE = ZoneInfo(SETTINGS['timezone'])
COLORS = {'critical': ('#9f1239', '#fff1f2'), 'warning': ('#92400e', '#fffbeb'),
          'info': ('#075985', '#f0f9ff')}


def e(value, limit=600):
    value = privacy.text(value)
    value = value if len(value) <= limit else value[:limit] + ' …'
    return escape(value, quote=True)


def n(value):
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError, OverflowError):
        return 0


def when(value, short=False):
    if value is None:
        return 'Not observed'
    try:
        dt = datetime.fromtimestamp(value, ZONE) if isinstance(value, (int, float)) else datetime.fromisoformat(value).astimezone(ZONE)
        return dt.strftime('%b %d, %I:%M %p %Z' if not short else '%I:%M %p %Z')
    except (ValueError, TypeError, OverflowError, OSError):
        return 'Unknown time'


def index_site(data):
    groups = {g['id']: g for g in data.get('groups', []) if isinstance(g, dict) and isinstance(g.get('id'), str)}
    assessed = {}
    for item in data.get('assessments', []):
        if (isinstance(item, dict) and item.get('id') in groups and
                item.get('classification') in ('issue', 'uncertain', 'routine') and
                item.get('severity') in COLORS):
            assessed[item['id']] = item
    findings = [a for a in assessed.values() if a['classification'] != 'routine']
    findings.sort(key=lambda a: (['critical','warning','info'].index(a['severity']),
                                -n(groups[a['id']].get('count')), a['id']))
    return groups, assessed, findings


def pill(label, color='#075985', bg='#f0f9ff'):
    return f'<span style="display:inline-block;padding:4px 9px;border-radius:5px;background:{bg};color:{color};font-size:11px;font-weight:700;letter-spacing:.3px;">{e(label,100)}</span>'


def notice(title, text):
    return f'<div style="background:#fffbeb;border-left:4px solid #d97706;padding:14px 16px;margin:18px 0;color:#78350f;font-size:13px;line-height:1.6;"><strong>{e(title,160)}</strong><br>{e(text,1800)}</div>'


def finding(item, group):
    color, bg = COLORS[item['severity']]
    classification = 'Needs verification' if item['classification']=='uncertain' else 'AI-flagged issue'
    source = e(group.get('source') or group.get('host') or 'Unknown source',100)
    example = e(group.get('example_message') or group.get('message') or '',260)
    check = item.get('suggested_check')
    return f'''<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin:12px 0;border:1px solid #dce4ec;border-radius:8px;border-collapse:separate;"><tr><td style="padding:18px;border-left:4px solid {color};">
<div>{pill(item['severity'].upper(),color,bg)} <span style="font-size:12px;color:#64748b;">{e(classification)}</span></div>
<div style="font-size:14px;font-weight:700;margin-top:12px;color:#0f172a;">{source}</div>
<div style="font-size:15px;line-height:1.6;color:#1e293b;margin:6px 0;">{e(item.get('summary'),400)}</div>
<div style="font-size:12px;color:#64748b;margin:8px 0;">{n(group.get('count')):,} observed records &nbsp;·&nbsp; {e(when(group.get('first'),True))}–{e(when(group.get('last'),True))}</div>
<div style="background:#f4f7fa;border-radius:5px;padding:10px 12px;font-family:Consolas,monospace;font-size:11px;line-height:1.6;overflow-wrap:anywhere;word-break:break-word;">{example}</div>
{('<div style="margin-top:12px;font-size:13px;line-height:1.6;"><strong>Next check</strong> &nbsp;'+e(check,300)+'</div>') if check else ''}
<div style="font-size:10px;color:#64748b;margin-top:10px;overflow-wrap:anywhere;">Evidence {e(item['id'],80)} · Counts and times come from logs; assessment is advisory.</div>
</td></tr></table>'''


def render(report, fallback_text='', dashboard_url=None, demo=False, compact=False):
    report = privacy.record(report)
    sites = report.get('sites', {})
    if not isinstance(sites, dict):
        sites = {}
    indexed = {site:index_site(sites.get(site, {})) for site in ('home','work')}
    total_records = sum(n(sites.get(site,{}).get('rows_in_window')) for site in indexed)
    total_groups = sum(n(sites.get(site,{}).get('groups_total')) for site in indexed)
    suppressed_records = sum(n(sites.get(site,{}).get('suppressed_records')) for site in indexed)
    suppressed_groups = sum(len(sites.get(site,{}).get('suppressed_groups', [])) for site in indexed)
    reviewed = sum(len(v[1]) for v in indexed.values())
    findings = sum(len(v[2]) for v in indexed.values())
    warnings = list(report.get('pipeline_warnings', []))
    for site in indexed:
        data = sites.get(site, {})
        warnings += [site.title()+': '+str(w) for key in ('warnings','ai_errors','review_limit_notes') for w in data.get(key,[])]
    source_gaps = sum(bool(c.get('warnings')) or n(c.get('records'))==0 for s in sites.values() for c in s.get('sources',{}).values())
    all_filtered = not total_groups and bool(suppressed_groups)
    limited = bool(report.get('review_limited')) or reviewed < total_groups or (not total_groups and not all_filtered) or any(n(s.get('rows_not_grouped')) for s in sites.values())
    failed = report.get('status') == 'daily_failed'
    pipeline_problem = failed or bool(warnings) or bool(source_gaps) or set(sites) != {'home','work'} or report.get('status') in ('daily_partial','preview_with_ai_errors')
    status = 'Report unavailable' if failed else 'Coverage needs attention' if pipeline_problem else 'All groups suppressed' if all_filtered else 'Limited AI review' if limited else 'Review completed'
    headline = 'The nightly report could not be completed.' if failed else 'No AI review available' if not reviewed else f'{findings:,} finding'+('s' if findings!=1 else '')+' to investigate' if findings else 'No issues identified in the reviewed groups'
    if not failed and not total_groups and suppressed_groups:
        headline = 'All grouped records were suppressed by your filters'
    date = report.get('report_date') or when(report.get('generated_utc'))
    window = when(report.get('window_start')) + ' → ' + when(report.get('window_end_exclusive'))
    banner = notice('DESIGN PREVIEW · EXAMPLE DATA', 'Illustrative content for layout review. This is not a live report or a statement about the health of either site.') if demo else ''
    limits = notice(status, 'This report has incomplete collection or review coverage. Unreviewed groups and missing sources can contain issues. Read the per-site counts and coverage notes below.') if pipeline_problem or limited else ''
    suppression_note = notice('Suppression filters applied',
        f'{suppressed_records:,} records in {suppressed_groups:,} recurring groups were excluded before AI review. '
        'Collection totals include them; AI coverage counts refer to eligible groups. Filters were evaluated when this report was built. '
        'Use the Suppressed issues and Filters pages to inspect or restore them.') if suppressed_groups else ''
    metrics = ''.join(f'<td class="stack" width="33%" style="padding:16px 10px;border:1px solid #e2e8f0;background:#f8fafc;text-align:center;"><div style="font-size:25px;font-weight:700;color:#0f172a;">{value}</div><div style="font-size:11px;color:#64748b;margin-top:5px;">{label}</div></td>' for value,label in [(f'{total_records:,}','RECORDS IN WINDOW'),(f'{reviewed:,} / {total_groups:,}','GROUPS AI REVIEWED'),(str(source_gaps),'SOURCES WITH COVERAGE NOTES')])
    sections = []
    for site, (groups, assessments, items) in indexed.items():
        data = sites.get(site,{})
        unreviewed = max(0,n(data.get('groups_total'))-len(assessments))
        flagged = max(0,n(data.get('flagged_groups_total'))-sum(n(groups[k].get('priority_hint',3))<3 for k in assessments))
        sources = data.get('sources', {})
        cap = 3 if compact else 8
        cards = ''.join(finding(item,groups[item['id']]) for item in items[:cap])
        if not cards:
            cards = '<p style="font-size:14px;color:#475569;line-height:1.7;">'+('No validated AI assessments are available. Device health is unknown.' if not assessments else 'No issue or uncertain finding in the reviewed groups. This does not establish that every device is healthy.')+'</p>'
        if len(items)>cap:
            cards += f'<p style="color:#64748b;font-size:12px;">{len(items)-cap:,} further findings are available in the local full report.</p>'
        source_rows=[]
        source_cap=12 if compact else 32
        for source,check in sorted(sources.items())[:source_cap]:
            coverage=check.get('warnings',[])
            label='Needs attention' if coverage else 'No records' if not n(check.get('records')) else 'Observed'
            color='#92400e' if coverage or not n(check.get('records')) else '#0f766e'
            reviewed_source=sum(groups[k].get('source')==source for k in assessments)
            description=e(coverage[0],170) if coverage else ''
            source_rows.append(f'<tr><td style="padding:10px 8px;border-bottom:1px solid #e2e8f0;overflow-wrap:anywhere;">{e(source,90)}<div style="font-size:10px;color:#64748b;margin-top:3px;">Last record: {e(when(check.get("last_record"),True))}</div>{("<div style=\"font-size:11px;color:#92400e;margin-top:4px;\">"+description+"</div>") if description else ""}</td><td align="right" style="padding:10px 8px;border-bottom:1px solid #e2e8f0;">{n(check.get("records")):,}<div style="font-size:10px;color:#64748b;">AI {reviewed_source}/{n(check.get("groups_total"))}</div></td><td align="right" style="padding:10px 8px;border-bottom:1px solid #e2e8f0;color:{color};font-size:11px;">{label}</td></tr>')
        source_table = '<table width="100%" cellspacing="0" cellpadding="0" style="font-size:12px;border-collapse:collapse;"><tr style="color:#64748b;background:#f8fafc;"><th align="left" style="padding:9px 8px;">SOURCE / COVERAGE</th><th align="right" style="padding:9px 8px;">RECORDS</th><th align="right" style="padding:9px 8px;">OBSERVATION</th></tr>'+''.join(source_rows)+'</table>' if source_rows else '<p style="font-size:13px;color:#92400e;">No source coverage data is available.</p>'
        if len(sources)>source_cap:
            source_table += f'<p style="font-size:12px;color:#64748b;">{len(sources)-source_cap} additional sources are listed in the local report.</p>'
        filter_line = (f'<br>Suppressed: {n(data.get("suppressed_records")):,} records in {len(data.get("suppressed_groups", [])):,} groups.' if data.get('suppressed_groups') else '')
        sections.append(f'<div style="margin-top:30px;padding-top:22px;border-top:2px solid #e2e8f0;"><div style="font-size:11px;font-weight:700;color:#0f766e;letter-spacing:1.5px;">{site.upper()} NETWORK</div><h2 style="font-size:21px;margin:7px 0 9px;color:#0f172a;">{len(items):,} findings · {len(sources):,} sources</h2><p style="font-size:12px;line-height:1.7;color:#64748b;margin:0 0 14px;">{n(data.get("rows_scanned")):,} / {n(data.get("rows_in_window")):,} records scanned · {len(assessments):,} / {n(data.get("groups_total")):,} eligible groups reviewed<br>{unreviewed:,} groups unreviewed; {flagged:,} carry a source-severity or keyword flag. Flags are not confirmed incidents.{filter_line}</p>{cards}<h3 style="font-size:13px;margin:22px 0 8px;">Collection coverage</h3>{source_table}</div>')
    note_list=''.join('<li style="margin-bottom:7px;">'+e(w,350)+'</li>' for w in warnings[:12])
    if len(warnings)>12:
        note_list+=f'<li>{len(warnings)-12} additional notes are in the local report.</li>'
    notes='<div style="margin-top:25px;background:#f8fafc;padding:16px;border-radius:6px;"><strong style="font-size:13px;">Pipeline notes</strong><ul style="padding-left:18px;font-size:12px;line-height:1.6;color:#475569;">'+note_list+'</ul></div>' if note_list else ''
    if failed:
        sections=[notice('Device health is unknown', fallback_text or 'Inspect the collection and build logs on the coordinator.')]
    action=''
    if dashboard_url:
        url=urlsplit(dashboard_url)
        if url.scheme not in ('https','http') or not url.netloc or url.username or url.password or any(ord(c)<32 for c in dashboard_url):
            raise ValueError('Dashboard URL must be an HTTP(S) URL without embedded credentials')
        action=f'<p style="margin-top:24px;"><a href="{escape(dashboard_url,quote=True)}" style="display:inline-block;background:#0f766e;color:#fff;text-decoration:none;padding:12px 18px;border-radius:6px;font-weight:700;font-size:13px;">Open monitoring dashboard</a></p>'
    html=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Home + Work · Nightly log digest</title><style>@media only screen and (max-width:600px){{.pad{{padding:22px 18px!important}}.stack{{display:block!important;width:auto!important}}.headline{{font-size:25px!important}}}} body{{margin:0;padding:0}} a{{color:#0f766e}}</style></head><body style="background:#edf2f6;color:#1e293b;font-family:Arial,Helvetica,sans-serif;margin:0;padding:0;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{e(status)} · {e(headline)} · {reviewed:,}/{total_groups:,} groups reviewed.</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:28px 10px;"><table role="presentation" width="720" cellpadding="0" cellspacing="0" style="width:100%;max-width:720px;border-collapse:separate;background:#fff;border:1px solid #dce4ec;border-radius:12px;overflow:hidden;"><tr><td class="pad" style="background:#11283f;padding:30px 34px;color:#fff;border-top:5px solid #2dd4bf;">
<div style="font-size:11px;font-weight:700;letter-spacing:2px;color:#7dd3cf;">NIGHTLY OPERATIONS</div><h1 style="font-size:29px;margin:12px 0 8px;letter-spacing:-.7px;">Home + Work</h1><div style="font-size:14px;color:#cbd5e1;">Your daily log briefing · {e(date,80)}</div></td></tr>
<tr><td class="pad" style="padding:28px 34px;">{banner}{pill(status,'#92400e','#fffbeb') if pipeline_problem or limited or suppressed_groups else pill(status,'#0f766e','#ecfdf5')}
<h2 class="headline" style="font-size:28px;line-height:1.25;letter-spacing:-.6px;color:#0f172a;margin:15px 0 12px;">{e(headline)}</h2><p style="font-size:12px;line-height:1.7;color:#64748b;margin:0 0 20px;">Window: {e(window)}<br>End exclusive · America/New_York</p>
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="table-layout:fixed;"><tr>{metrics}</tr></table>{suppression_note}{limits}{''.join(sections)}{notes}{action}
<div style="margin-top:28px;padding-top:18px;border-top:1px solid #e2e8f0;font-size:11px;line-height:1.7;color:#64748b;">Generated {e(when(report.get('generated_utc')))} · Local model: {e(report.get('model','not run'),70)}<br>Credential patterns are redacted locally. Device names and network addresses remain for troubleshooting. Redaction is not guaranteed anonymization.<br>AI findings are advisory. Counts describe log records, not unique incidents. Missing logs do not establish device health.</div></td></tr></table><p style="font-size:10px;color:#64748b;">AI Monitor · Home + Work · Private infrastructure</p></td></tr></table></body></html>'''
    if len(html.encode('utf-8'))>90000 and not compact:
        return render(report,fallback_text,dashboard_url,demo,compact=True)
    if len(html.encode('utf-8'))>90000:
        raise ValueError('HTML digest exceeds its 90 KB content budget')
    return html


def save(path, content):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix='.html-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'w',encoding='utf-8',newline='\n') as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report-json',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--dashboard-url')
    parser.add_argument('--demo',action='store_true')
    args=parser.parse_args()
    if args.output.resolve()==args.report_json.resolve():
        raise ValueError('Output must be different from the source JSON')
    if args.report_json.stat().st_size>20*1024*1024:
        raise ValueError('Report JSON exceeds 20 MiB')
    report=json.loads(args.report_json.read_text(encoding='utf-8'))
    fallback=args.report_json.with_suffix('.txt')
    text=fallback.read_text(encoding='utf-8') if fallback.is_file() and fallback.stat().st_size<=1024*1024 else ''
    save(args.output,render(report,text,args.dashboard_url,args.demo))
    print(json.dumps({'status':'rendered','output':str(args.output),'email_sent':False}))


if __name__=='__main__':
    main()
