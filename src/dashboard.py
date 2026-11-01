"""Render a read-only Home + Work dashboard from verified local report files."""
from datetime import date, datetime, time as day_time, timedelta
from html import escape
import importlib.util
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


ZONE = ZoneInfo(SETTINGS['timezone'])
PROGRESS_PRODUCER = 'ai-monitor-dashboard-progress-v1'
HISTORY_DAYS = 30
_spec = importlib.util.spec_from_file_location('dashboard_privacy', Path(__file__).with_name('sanitize_logs.py'))
privacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(privacy)

def number(value):
    return max(0, int(value or 0))

def fmt(value):
    return format(number(value), ',')

def timestamp(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError('Timestamp has no timezone')
    return parsed.timestamp()

def when(value, short=False):
    if not value:
        return 'Not recorded'
    try:
        return datetime.fromtimestamp(timestamp(value), ZONE).strftime(
            '%I:%M %p %Z' if short else '%b %d, %I:%M %p %Z').lstrip('0')
    except (ValueError, TypeError, OverflowError, OSError):
        return 'Not recorded'

def text(value, limit=500):
    return escape(privacy.text(str(value or ''))[:limit], quote=True)

def read_json(path, limit=256 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('Invalid state file')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict):
        raise ValueError('Invalid state object')
    return value

def optional_record(folder, name, day, now):
    try:
        value = read_json(folder / name)
        if value.get('report_date') != day.isoformat():
            return {}
        if name in ('progress.json', 'wake.json'):
            if value.get('producer') != PROGRESS_PRODUCER:
                return {}
            if timestamp(value.get('updated_utc')) > now + 300:
                return {}
        return value
    except (OSError, ValueError, TypeError):
        return {}

def summarize(report):
    sites = {}
    for site in ('home', 'work'):
        data = report.get('sites', {}).get(site, {})
        groups = {g['id']: g for g in data.get('groups', [])}
        assessments = {a['id']: a for a in data.get('assessments', []) if a.get('id') in groups}
        total = number(data.get('groups_total'))
        reviewed = len(assessments)
        if reviewed > total:
            raise ValueError('Invalid coverage counts')
        sources = data.get('sources', {})
        issues = sum(a.get('classification') == 'issue' for a in assessments.values())
        uncertain = sum(a.get('classification') == 'uncertain' for a in assessments.values())
        incomplete_data = bool(data.get('warnings') or data.get('rows_not_grouped') or
                               any(s.get('warnings') for s in sources.values()) or
                               not number(data.get('rows_in_window')) or
                               any(str(w).startswith(site+':') for w in report.get('pipeline_warnings', [])))
        sites[site] = dict(records=number(data.get('rows_in_window')), groups=total, reviewed=reviewed,
                           unreviewed=total-reviewed, issues=issues, uncertain=uncertain,
                           errors=len(data.get('ai_errors', [])), data_limited=incomplete_data,
                           rows_not_grouped=number(data.get('rows_not_grouped')),
                           source_count=len(sources),
                           reporting_sources=sum(number(s.get('records')) > 0 for s in sources.values()),
                           last_record=max((s.get('last_record') or 0 for s in sources.values()), default=0),
                           latest_export=max((s.get('exported_utc') or 0 for s in sources.values()), default=0),
                           sources=sources, groups_by_id=groups, assessments=assessments)
    return sites

def load_report(job, base, day, now, current=False):
    folder = Path(base) / 'daily' / day.isoformat()
    if folder.is_symlink() or folder.parent.is_symlink():
        raise ValueError('Invalid report directory')
    state = read_json(folder / 'state.json')
    for name, limit in [('report.txt', 1024**2), ('report.json', 20*1024**2)]:
        path = folder / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise ValueError('Invalid report artifact')
    if 'report.html' in state.get('sha256', {}):
        path = folder / 'report.html'
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
            raise ValueError('Invalid HTML artifact')
    # Historical reports are explicitly dated. Verify at that day's end rather
    # than weakening the 26-hour freshness check used for the current digest.
    verification_time = now if current else datetime.combine(day, day_time(23, 59, 59), ZONE).timestamp()
    checked, report = job.verify_ready(folder, day, verification_time)
    generated = timestamp(report.get('generated_utc'))
    if generated > now + 300 or datetime.fromtimestamp(generated, ZONE).date() != day:
        raise ValueError('Report generation date mismatch')
    if checked != state:
        raise ValueError('Report changed during verification')
    report = job.daily.core.privacy.record(report)
    summary = summarize(report)
    content = job.mail.html_report.render(report)
    checked_again, report_again = job.verify_ready(folder, day, verification_time)
    if checked_again != state or job.daily.core.privacy.record(report_again) != report:
        raise ValueError('Report changed during rendering')
    return dict(day=day, state=state, report=report, sites=summary, html=content)

def badge(label, tone='muted'):
    return '<span class="badge '+tone+'">'+text(label)+'</span>'

def meter(reviewed, total):
    percent = min(100, round(100*reviewed/total)) if total else 0
    return '<div class="meter" role="img" aria-label="'+text(f'{reviewed} of {total} groups reviewed')+'"><span style="width:'+str(percent)+'%"></span></div>'

def site_card(site, data):
    title = 'Home' if site == 'home' else 'Work'
    if data is None:
        return '<article class="site-card"><div class="card-top"><h2>'+title+'</h2>'+badge('Unknown')+'</div><p class="empty">No verified report for this date.</p><p class="muted">Findings and coverage will appear after a verified build.</p></article>'
    label, tone = ('Needs attention', 'warn') if data['issues'] else (
        ('Needs review', 'warn') if data['uncertain'] else (
        ('No AI review', 'muted') if not data['reviewed'] else ('No issues in reviewed groups', 'good')))
    coverage = 'Limited data' if data['data_limited'] else 'Data collected'
    review = 'Partial AI review' if data['unreviewed'] or data['errors'] else ('All groups reviewed' if data['groups'] else 'No groups')
    return '<article class="site-card"><div class="card-top"><h2>'+title+'</h2>'+badge(label,tone)+'</div><div class="big-metrics"><div><strong>'+fmt(data['issues'])+'</strong><span>issue findings</span></div><div><strong>'+fmt(data['uncertain'])+'</strong><span>uncertain findings</span></div><div><strong>'+fmt(data['records'])+'</strong><span>records in window</span></div></div><div class="card-top small"><span>AI review coverage</span><strong>'+fmt(data['reviewed'])+' / '+fmt(data['groups'])+' groups</strong></div>'+meter(data['reviewed'],data['groups'])+'<div class="chips">'+badge(coverage,'warn' if data['data_limited'] else 'muted')+badge(review,'warn' if data['unreviewed'] or data['errors'] else 'muted')+'</div><div class="card-foot"><span>'+fmt(data['reporting_sources'])+' / '+fmt(data['source_count'])+' sources with records</span><span>Last record '+text(when(data['last_record']))+'</span></div></article>'

def timeline(base, day, now, job, verification=None):
    folder = Path(base) / 'daily' / day.isoformat()
    if folder.is_symlink() or folder.parent.is_symlink():
        return '<p class="notice">Run status could not be read.</p>'
    state = optional_record(folder, 'state.json', day, now)
    if state.get('producer') != job.PRODUCER:
        state = {}
    progress = optional_record(folder, 'progress.json', day, now)
    if progress.get('started_utc') != state.get('started_utc'):
        progress = {}
    wake = optional_record(folder, 'wake.json', day, now)
    delivery = optional_record(folder, 'delivery.json', day, now)
    stages = progress.get('stages', {})
    phase = state.get('phase')
    def due(hour, minute=0):
        return datetime.combine(day, day_time(hour,minute), ZONE).timestamp()
    def elapsed():
        try:
            return max(0, (timestamp(state.get('completed_utc')) if phase in ('ready','failed') else now)-timestamp(state['started_utc']))
        except (ValueError, TypeError, KeyError):
            return None
    duration = elapsed()
    wake_label = {'ollama_ready':'AI server was ready','wake_packet_sent':'Wake packet sent',
                  'waking':'Waking AI server','wake_sent_but_ollama_not_ready':'AI server did not become ready'}.get(wake.get('status'))
    wake_label = wake_label or ('Scheduled' if now < due(3,30) else 'No wake record')
    items = [('03:30', 'Wake AI server', wake_label, when(wake.get('updated_utc'),True),
              'good' if wake.get('status')=='ollama_ready' else 'warn' if wake.get('status')=='wake_sent_but_ollama_not_ready' else 'muted')]
    export_lines=[]
    exports_complete=0
    for site in ('home','work'):
        export=progress.get('exports',{}).get(site,{})
        try:
            started=timestamp(export['started_utc']); finished=timestamp(export['finished_utc'])
            fresh=due(3,30)<=started<=finished<=now+300
            label=('Complete' if export.get('status')=='complete' else 'Partial') if fresh else 'Old export'
            if label=='Complete':
                exports_complete+=1
            export_lines.append(site.title()+': '+label+' \u00b7 '+when(finished,True))
        except (ValueError, TypeError, KeyError):
            export_lines.append(site.title()+': not confirmed')
    items.append(('03:40','NAS exports','Exports complete' if exports_complete==2 else 'Awaiting collection' if now<due(4,10) else 'Needs attention',' / '.join(export_lines),'good' if exports_complete==2 else 'muted' if now<due(4,10) else 'warn'))
    collection=stages.get('collecting',{})
    label='Collected' if collection.get('finished_utc') else 'Collecting' if progress.get('stage')=='collecting' and phase=='building' else 'Scheduled' if now<due(4) else 'No stage record'
    collection_limited=len(progress.get('exports',{}))!=2 or any(e.get('collection_status')!='complete' for e in progress.get('exports',{}).values())
    if label=='Collected' and collection_limited:
        label='Collected with warnings'
    items.append(('04:00','Collect & group',label,when(collection.get('finished_utc') or collection.get('started_utc'),True),'warn' if label=='Collected with warnings' else 'good' if label=='Collected' else 'muted'))
    stage=progress.get('stage')
    if phase=='ready':
        limited=bool(state.get('review_limited') or state.get('report_status')!='daily_complete')
        label='Saved \u00b7 limited review' if limited else 'Report saved'
        tone='warn' if limited else 'good'
        if verification in ('verification_failed','component_unavailable'):
            label,tone='Verification failed','bad'
    elif phase=='failed':
        label,tone='Build failed','bad'
    elif phase=='building':
        label,tone=('Overdue','bad') if duration is not None and duration>job.BUILD_LIMIT_SECONDS+120 else (
            {'preparing':'Preparing','collecting':'Collecting','grouping':'Grouping','checking_ai':'Checking AI','analyzing':'AI review running','saving':'Saving report'}.get(stage,'Build running'),'muted')
    else:
        label,tone=('Scheduled','muted') if now<due(4) else ('No build recorded','warn')
    detail=(str(round(duration/60,1))+' / 45 min build allowance') if duration is not None else '45-minute build allowance'
    items.append(('After collection','AI review & save',label,detail,tone))
    delivery_label={'accepted_by_smtp':'Accepted by Gmail','already_sent':'Previously accepted by Gmail',
                    'delivery_unknown':'Delivery unconfirmed'}.get(delivery.get('status'))
    delivery_label=delivery_label or ('Scheduled' if now<due(5) else 'No delivery confirmation')
    items.append(('05:00','Email digest',delivery_label,when(delivery.get('attempted_utc'),True),
                  'good' if delivery.get('status') in ('accepted_by_smtp','already_sent') else 'muted' if now<due(5) else 'warn'))
    content='<div class="timeline">'+''.join('<article class="step"><span class="step-time">'+text(schedule)+'</span><h3>'+text(title)+'</h3>'+badge(label,tone)+'<p>'+text(detail)+'</p></article>' for schedule,title,label,detail,tone in items)+'</div>'
    if phase=='building' and progress.get('sites'):
        content+='<div class="run-counts"><strong>Current build counts</strong><span>Updated '+text(when(progress.get('updated_utc'),True))+'</span>'
        for site,data in progress['sites'].items():
            content+='<p>'+text(site.title())+': '+fmt(data.get('groups_reviewed'))+' / '+fmt(data.get('groups_total'))+' groups reviewed \u00b7 '+fmt(data.get('records'))+' records</p>'
        content+='</div>'
    content+='<p class="caption">Run date '+day.isoformat()+'. Times are '+text(str(ZONE))+'. Export status becomes available when the scheduled collection reads the manifests. Older runs may lack stage records. Gmail acceptance does not confirm inbox delivery.</p>'
    return content

def coverage(sites):
    if not sites:
        return '<p class="empty">Coverage is unavailable until this report passes verification.</p>'
    result=''
    for site,data in sites.items():
        rows=[]
        for name, source in sorted(data['sources'].items()):
            reviewed=sum(data['groups_by_id'][key].get('source')==name for key in data['assessments'])
            total=number(source.get('groups_total'))
            warning=bool(source.get('warnings'))
            status='Coverage warning' if warning else 'No records' if not number(source.get('records')) else 'Partial review' if reviewed<total else 'Reviewed'
            rows.append('<tr><th scope="row">'+text(name,180)+'</th><td>'+fmt(source.get('records'))+'</td><td>'+fmt(reviewed)+' / '+fmt(total)+'</td><td>'+text(when(source.get('last_record')))+'</td><td>'+badge(status,'warn' if warning or reviewed<total else 'muted')+'</td></tr>')
        result+='<details class="source-details"><summary>'+text(site.title())+' sources <span>'+fmt(data['unreviewed'])+' groups unreviewed</span></summary><div class="table-scroll"><table><thead><tr><th>Source</th><th>Records</th><th>Groups reviewed</th><th>Last record</th><th>Coverage</th></tr></thead><tbody>'+''.join(rows)+'</tbody></table></div></details>'
    return result

CSS = '''
:root{--navy:#10283c;--ink:#173044;--muted:#607384;--line:#dfe7ec;--teal:#087f83;--bg:#f3f6f8;--orange:#a35208}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:22px}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}a{color:var(--teal)}.topbar{background:var(--navy);color:white}.top-inner{max-width:1220px;margin:auto;padding:18px 28px;display:flex;align-items:center;justify-content:space-between;gap:20px}.brand{display:flex;align-items:center;gap:11px;font-size:17px;font-weight:750;letter-spacing:.2px}.mark{display:grid;grid-template-columns:repeat(2,7px);gap:3px}.mark i{height:7px;background:#56d2c5;border-radius:2px}.mark i:last-child{opacity:.4}.topbar nav{display:flex;gap:25px}.topbar a{color:#c7d8e5;text-decoration:none;font-size:13px}.topbar a:hover{color:white}.topbar a:focus-visible,.button:focus-visible,summary:focus-visible{outline:3px solid #4fbbb8;outline-offset:5px}main{max-width:1220px;margin:auto;padding:30px 28px 42px}.eyebrow{text-transform:uppercase;letter-spacing:1.6px;font-size:11px;font-weight:800;color:var(--teal)}.hero{display:flex;justify-content:space-between;align-items:center;gap:24px;margin-bottom:24px}h1{font-size:34px;letter-spacing:-1px;line-height:1.2;margin:7px 0 10px}h2{font-size:20px;letter-spacing:-.35px;margin:0}h3{font-size:14px;margin:8px 0 10px}.sub,.muted{color:var(--muted)}.sub{margin:0;max-width:690px;font-size:14px}.actions{display:flex;gap:9px;flex-wrap:wrap}.button{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;padding:10px 15px;background:var(--teal);border:1px solid var(--teal);border-radius:7px;color:white;font-size:13px;font-weight:650;white-space:nowrap}.button.secondary{background:white;color:var(--ink);border-color:#cad6de}.notice{padding:14px 18px;border:1px solid #e9c994;background:#fff8eb;border-radius:8px;font-size:14px;margin:0 0 20px}.notice.bad{background:#fff0ef;border-color:#ebbbb7}.site-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}.site-card{background:white;border:1px solid var(--line);border-top:3px solid var(--teal);border-radius:10px;padding:23px;box-shadow:0 3px 13px #10283c04}.card-top{display:flex;align-items:center;justify-content:space-between;gap:12px}.badge{display:inline-block;font-size:11px;font-weight:650;line-height:1.5;border-radius:5px;padding:4px 8px;background:#edf2f6;color:#506879;white-space:normal}.badge.good{background:#e4f4ee;color:#1d7254}.badge.warn{background:#fff0d8;color:#94510c}.badge.bad{background:#fde6e5;color:#a33432}.big-metrics{display:grid;grid-template-columns:1fr 1fr 1.3fr;gap:10px;margin:24px 0}.big-metrics strong{display:block;font-size:30px;letter-spacing:-1px;font-weight:700}.big-metrics span{font-size:12px;color:var(--muted)}.small{font-size:12px}.meter{background:#e9eff3;height:7px;border-radius:8px;margin:9px 0 12px;overflow:hidden}.meter span{display:block;background:var(--teal);height:100%;border-radius:8px}.chips{display:flex;flex-wrap:wrap;gap:6px}.card-foot{border-top:1px solid #edf1f4;margin-top:18px;padding-top:13px;display:flex;flex-direction:column;gap:4px;color:var(--muted);font-size:11px}.section{background:white;border:1px solid var(--line);border-radius:10px;margin-top:23px;padding:24px}.section-heading{display:flex;justify-content:space-between;align-items:baseline;gap:16px;margin-bottom:20px}.section-heading p{font-size:12px;color:var(--muted);margin:0}.timeline{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:0}.step{position:relative;border-top:2px solid #dce8ec;padding:19px 15px 0 0;margin-top:7px}.step::before{content:'';position:absolute;top:-6px;left:0;width:10px;height:10px;border-radius:50%;background:var(--teal);box-shadow:0 0 0 4px white}.step-time{text-transform:uppercase;font-size:10px;letter-spacing:.6px;color:var(--muted);font-weight:700}.step p{font-size:11px;color:var(--muted);margin:9px 0 0;overflow-wrap:anywhere}.caption{font-size:11px;line-height:1.65;color:var(--muted);margin:20px 0 0}.source-details{border:1px solid var(--line);border-radius:7px;margin-top:10px;overflow:hidden}summary{cursor:pointer;font-weight:650;padding:13px 16px;font-size:14px}summary span{font-size:12px;font-weight:400;color:var(--muted);margin-left:15px}.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:12px}th,td{padding:12px 14px;border-top:1px solid #e7edf1;vertical-align:middle}thead th{background:#f6f8fa;font-weight:600;color:var(--muted);font-size:11px}tbody th{font-weight:550;max-width:260px;overflow-wrap:anywhere}td{font-variant-numeric:tabular-nums}.history a{font-weight:650;text-decoration:none}.history .date-link{color:var(--ink)}.history td:last-child{text-align:right}.history small{color:var(--muted)}.empty{padding:14px 0;color:var(--muted)}.footer{display:flex;justify-content:space-between;gap:20px;font-size:11px;color:var(--muted);margin-top:23px}.run-counts{margin-top:18px;padding:14px;background:#f1f8f8;border-radius:7px;font-size:12px}.run-counts>span{margin-left:16px;color:var(--muted)}.run-counts p{margin:5px 0 0}.example{background:#f5d174;color:#332b14;text-align:center;font-weight:750;padding:9px}.report-nav{padding:16px 24px;background:#10283c;color:white;font:14px/1.6 system-ui,sans-serif}.report-nav a{color:#84e4d8;margin-right:20px}.report-nav small{display:block;color:#cadbe5}@media(max-width:850px){.topbar nav{gap:14px}.timeline{grid-template-columns:repeat(3,minmax(0,1fr));row-gap:25px}.big-metrics strong{font-size:25px}.card-top{align-items:flex-start;flex-wrap:wrap}.hero{align-items:flex-start;flex-direction:column}}@media(max-width:580px){main{padding:22px 16px}.top-inner{padding:16px;align-items:flex-start;flex-direction:column;gap:12px}.topbar nav{gap:20px}.site-grid{grid-template-columns:1fr}.site-card,.section{padding:18px}h1{font-size:29px}.timeline{grid-template-columns:repeat(2,minmax(0,1fr))}.section-heading{flex-direction:column;gap:6px}.footer{flex-direction:column;gap:6px}summary span{display:block;margin-left:0}.big-metrics strong{font-size:30px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
'''

def report_page(content, day, now, historical=False):
    nav='<div class="report-nav" style="padding:16px 24px;background:#10283c;color:white;font:14px/1.6 system-ui,sans-serif"><a style="color:#84e4d8;margin-right:20px" href="/">&larr; Dashboard</a><strong>'+('Archived report' if historical else 'Nightly report')+' \u00b7 '+day.isoformat()+'</strong><small style="display:block;color:#cadbe5">Verified publication '+text(when(now))+'. This report describes its dated log window.</small></div>'
    return re.sub(r'(<body\b[^>]*>)', lambda match:match[0]+nav, content, count=1, flags=re.I)

def render(day, now, status, current, history, run_html, example=False):
    sites=current['sites'] if current else {}
    next_day=datetime.fromtimestamp(now,ZONE).date()
    next_build=datetime.combine(next_day,day_time(4),ZONE)
    if next_build.timestamp()<=now:
        next_build=datetime.combine(next_day+timedelta(days=1),day_time(4),ZONE)
    notice=''
    if not current:
        labels={'building':'The report is being prepared.','overdue':'The report build is overdue.',
                'build_failed':'The report build failed.','verification_failed':'The report could not be verified.',
                'component_unavailable':'The publisher needs attention.','not_ready':'No verified report is available yet.'}
        notice='<div class="notice '+('bad' if status in ('build_failed','verification_failed','overdue') else '')+'"><strong>'+labels.get(status,'Report unavailable.')+'</strong> Findings and device health are unknown for '+day.isoformat()+'. Previous reports remain explicitly dated in history.</div>'
    elif current['report'].get('pipeline_warnings') or any(s['unreviewed'] or s['data_limited'] or s['errors'] or not s['reviewed'] for s in sites.values()):
        notice='<div class="notice"><strong>Coverage needs attention.</strong> A saved report can contain partial data or limited AI review. Unreviewed groups may contain issues.</div>'
    history_rows=[]
    for entry in history:
        date_text=entry['day'].isoformat()
        if entry.get('verified'):
            h,w=entry['sites']['home'],entry['sites']['work']
            total=h['groups']+w['groups']; reviewed=h['reviewed']+w['reviewed']
            limited=reviewed<total or not total or h['data_limited'] or w['data_limited'] or h['errors'] or w['errors']
            history_rows.append('<tr><th scope="row"><a class="date-link" href="/history/'+date_text+'.html">'+date_text+'</a></th><td>'+fmt(h['issues'])+' / '+fmt(w['issues'])+'</td><td>'+fmt(reviewed)+' / '+fmt(total)+'</td><td>'+fmt(h['records']+w['records'])+'</td><td>'+badge('Limited' if limited else 'Reviewed','warn' if limited else 'good')+'</td><td><a href="/history/'+date_text+'.html">Open report &rarr;</a></td></tr>')
        else:
            history_rows.append('<tr><th scope="row">'+date_text+'</th><td>&mdash;</td><td>&mdash;</td><td>&mdash;</td><td>'+badge(entry.get('label','Unavailable'),'warn')+'</td><td><small>No verified report</small></td></tr>')
    history_html='<div class="table-scroll"><table class="history"><thead><tr><th>Report date</th><th>Issues: Home / Work</th><th>AI groups reviewed</th><th>Records</th><th>Coverage</th><th></th></tr></thead><tbody>'+''.join(history_rows)+'</tbody></table></div>' if history_rows else '<p class="empty">Saved reports will appear here after the first completed build.</p>'
    actions=('<a class="button" href="/report.html">Open latest report &rarr;</a>' if current else '')+'<a class="button secondary" href="/">Refresh status</a>'
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Home + Work \u00b7 Nightly monitor</title><style>'+CSS+'</style></head><body>'+('<div class="example">EXAMPLE DATA \u00b7 Dashboard preview</div>' if example else '')+'<header class="topbar"><div class="top-inner"><div class="brand"><span class="mark" aria-hidden="true"><i></i><i></i><i></i><i></i></span>Nightly Monitor</div><nav aria-label="Sections"><a href="#overview">Overview</a><a href="#run">Nightly run</a><a href="#coverage">Coverage</a><a href="#history">History</a></nav></div></header><main><section id="overview"><div class="hero"><div><div class="eyebrow">HOME + WORK / '+day.isoformat()+'</div><h1>Nightly overview</h1><p class="sub">What needs attention, what was reviewed, and how the nightly run went.</p></div><div class="actions">'+actions+'</div></div>'+notice+'<div class="site-grid">'+''.join(site_card(site,sites.get(site)) for site in ('home','work'))+'</div></section><section class="section" id="run"><div class="section-heading"><h2>Nightly run</h2><p>Next build '+text(when(next_build.timestamp()))+'</p></div>'+run_html+'</section><section class="section" id="coverage"><div class="section-heading"><h2>Source coverage</h2><p>Expand a site to inspect the reviewed window</p></div>'+coverage(sites)+'<p class="caption">Counts describe imported records, not unique real-world events. A quiet source does not prove that a device is healthy.</p></section><section class="section" id="history"><div class="section-heading"><h2>Report history</h2><p>Choose a date \u00b7 up to 30 days of saved reports</p></div>'+history_html+'</section><footer class="footer"><span>Publication check: '+text(when(now))+'. Refresh to load the latest publication.</span><span>Updated every 5 minutes \u00b7 Saved log findings, not live device status</span></footer></main></body></html>'
