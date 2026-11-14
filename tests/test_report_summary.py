"""Briefing evidence, honest comparisons, local-only inference, and HTML links."""
from copy import deepcopy
from datetime import date, timedelta
from html.parser import HTMLParser
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


summary = load('report_summary')
html = load('html_report')
schema=summary.response_schema([{'id':'home-valid'}])
item_schema=schema['properties']['items']['items']
assert item_schema['properties']['evidence_ids']['maxItems']==2
assert item_schema['properties']['evidence_ids']['items']['enum']==['home-valid']
assert schema['properties']['items']['maxItems']*item_schema['properties']['evidence_ids']['maxItems']==summary.MAX_EVIDENCE==16
assert not schema['additionalProperties'] and not item_schema['additionalProperties']


def sample(day='2026-11-14', count=40):
    report = {'report_date':day, 'report_kind':'daily', 'status':'daily_partial', 'pipeline_issue':False,
              'review_limited':True, 'window_start':100, 'window_end_exclusive':86500, 'sites':{}}
    for site in ('home','work'):
        groups = [{'id':site+'-dns','source':'pfSense','message':'failed to resolve host example.invalid',
                   'count':count,'first':100,'last':80000,'priority_hint':1}]
        assessments = [{'id':site+'-dns','severity':'warning','classification':'issue','summary':'A DNS lookup failed.'}]
        report['sites'][site] = {'groups':groups,'assessments':assessments,'groups_total':1,
            'rows_in_window':count,'rows_scanned':count,'rows_not_grouped':0,'sources':{},'warnings':[]}
    return report


def write_prior(base, current, days=7, count=10, incomplete=False):
    day = date.fromisoformat(current['report_date'])
    for offset in range(1, days+1):
        old = sample((day-timedelta(days=offset)).isoformat(),count)
        if incomplete:
            old['sites']['home']['groups_total'] = 9000
        folder = Path(base) / 'daily' / old['report_date']
        folder.mkdir(parents=True)
        (folder/'report.json').write_text(json.dumps(old),encoding='utf-8')


def model(url, name, payload, timeout):
    assert url == 'http://127.0.0.1:11434' and timeout <= 90
    assert all('url' not in row for row in payload)
    return {'items':[{'text':'DNS lookup failures require a check.', 'evidence_ids':[row['id'] for row in payload[:2]]}]}


with tempfile.TemporaryDirectory() as tmp:
    report = sample()
    result = summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',requester=model)
    assert result['status']=='ai' and result['history_days']==0
    assert all(e['trend']=='baseline_incomplete' for item in result['items'] for e in item['evidence'])
    assert 'comparison incomplete' in summary.render_text(result)
    write_prior(tmp,report)
    result = summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',requester=model)
    assert result['items'][0]['trend']=='increased'
    assert result['items'][0]['evidence'][0]['previous_count']==10
    assert result['items'][0]['references'][0]['url']==summary.REFERENCES['pfsense_dns']['url']
    # A complete seven-day baseline establishes first appearance, not incident onset.
    report['sites']['home']['groups'][0]['id']='home-new'
    report['sites']['home']['assessments'][0]['id']='home-new'
    result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',requester=model)
    assert next(e for i in result['items'] for e in i['evidence'] if e['id']=='home-new')['trend']=='newly_observed'
    report['executive_summary']=result
    rendered=html.render(report)
    assert rendered.index('Opening briefing') < rendered.index('RECORDS IN WINDOW')
    assert 'Limited AI review' in rendered and 'Coverage needs attention' not in rendered
    assert '/history/2026-11-14.html#'+summary.event_anchor('home','home-new') in rendered
    assert 'id="'+summary.event_anchor('home','home-new')+'"' in rendered

with tempfile.TemporaryDirectory() as tmp:
    report=sample()
    write_prior(tmp,report,incomplete=True)
    report['sites']['home']['groups'][0]['id']='home-new'
    report['sites']['home']['assessments'][0]['id']='home-new'
    result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',requester=model)
    assert next(e for i in result['items'] for e in i['evidence'] if e['id']=='home-new')['trend']=='baseline_incomplete'

with tempfile.TemporaryDirectory() as tmp:
    report=sample()
    for invalid in (
        {'items':[{'text':'Invented event','evidence_ids':['unknown']}]},
        {'items':[{'text':'Visit https://evil.invalid','evidence_ids':['home-dns']}]},
        {'items':[{'text':'<script>bad()</script>','evidence_ids':['home-dns']}]},
        {'items':[{'text':'A finding','evidence_ids':['home-dns'],'url':'https://evil.invalid'}]},
    ):
        result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',requester=lambda *args:invalid)
        assert result['status']=='fallback' and 'AI summary unavailable' in result['notice']
    assert summary.build_summary(report,tmp,'https://example.com','qwen3:8b',requester=model)['status']=='fallback'
    assert summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',timeout=0,requester=model)['status']=='fallback'
    # Critical evidence is included even when the model leaves it out.
    report['sites']['work']['groups'][0]['priority_hint']=0
    result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',requester=lambda *args:{'items':[{'text':'Home DNS failed.','evidence_ids':['home-dns']}]})
    assert result['items'][0]['urgent'] and result['items'][0]['evidence'][0]['id']=='work-dns'
    # A source's critical level does not turn an explicitly routine assessment into an urgent incident.
    report['sites']['work']['assessments'][0].update(classification='routine',severity='info')
    result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',timeout=0)
    assert result['critical_groups']==0 and result['source_critical_classified_routine']==1
    # All urgent references survive candidate/item limits; overflow is explicit.
    report=sample()
    for k in range(50):
        group=deepcopy(report['sites']['home']['groups'][0]); group.update(id='home-critical-'+str(k),priority_hint=0)
        assessment=deepcopy(report['sites']['home']['assessments'][0]); assessment.update(id=group['id'],severity='critical')
        report['sites']['home']['groups'].append(group); report['sites']['home']['assessments'].append(assessment)
    result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',timeout=0)
    assert result['critical_groups']==50 and len(result['urgent_evidence'])==50
    assert result['critical_not_in_briefing']==42 and '42 additional critical groups' in result['notice']
    rows,_,_=summary.candidates(report,[])
    output={'items':[{'text':'Synthetic critical evidence requires review.',
        'evidence_ids':[rows[2*k]['id'],rows[2*k+1]['id']]} for k in range(8)]}
    validated=summary._validate(output,rows)
    assert len(validated)==8  # More than12 valid IDs no longer rejects the whole briefing.
    with patch.object(summary,'_history',side_effect=RuntimeError('bad historical data')):
        assert summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',timeout=0)['status']=='fallback'

# A local model must not redirect requests containing private evidence.
try:
    summary.NoRedirect().redirect_request(None,None,302,'Found',{},'https://external.invalid')
    raise AssertionError('Redirect accepted')
except ValueError:
    pass

# Related media files retain one stable family comparison despite different object IDs.
with tempfile.TemporaryDirectory() as tmp:
    report=sample()
    group=report['sites']['home']['groups'][0]
    group.update(source='plexserver',message='NAT: PMP, timed out waiting for response.',id='home-new-plex')
    report['sites']['home']['assessments'][0]['id']=group['id']
    prior=deepcopy(report); prior['report_date']='2026-11-13'
    prior['sites']['home']['groups'][0]['id']='home-old-plex'
    prior['sites']['home']['assessments'][0]['id']='home-old-plex'
    folder=Path(tmp)/'daily'/'2026-11-13'; folder.mkdir(parents=True)
    (folder/'report.json').write_text(json.dumps(prior))
    result=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',timeout=0)
    item=next(i for i in result['items'] if i['evidence'][0]['site']=='home')
    assert item['trend']=='recurring' and 'Plex NAT-PMP response timeouts' in item['text']

# Summary links still have targets when their event falls outside the normal email card cap.
report=sample()
for index in range(20):
    group=deepcopy(report['sites']['home']['groups'][0]); group.update(id='home-extra-'+str(index),count=1000-index)
    assessment=deepcopy(report['sites']['home']['assessments'][0]); assessment['id']=group['id']
    report['sites']['home']['groups'].append(group); report['sites']['home']['assessments'].append(assessment)
report['sites']['home']['groups_total']=21
with tempfile.TemporaryDirectory() as tmp:
    report['executive_summary']=summary.build_summary(report,tmp,'http://127.0.0.1:11434','qwen3:8b',timeout=0)
    row={'site':'home','id':'home-dns','source':'pfSense','count':40,'previous_count':None,'trend':'baseline_incomplete',
         'url':'javascript:evil()', 'urgency_basis':''}
    report['executive_summary']['items']=[{'text':'<img src="https://evil.invalid"> password=topsecret',
        'urgent':False,'trend':'baseline_incomplete','evidence':[row],
        'references':[{'key':'pfsense_dns','url':'javascript:evil()','title':'unsafe'}]}]
    output=html.render(report)
    assert 'Supporting events from the opening briefing' in output
    assert 'id="'+summary.event_anchor('home','home-dns')+'"' in output
    assert 'javascript:' not in output and 'topsecret' not in output
    assert '&lt;img' in output and len(output.encode())<90000

report['device_lifecycle']={'settings':{'enabled':True,'days':10},'window_days':7,
    'counts':{'added':1,'retired':1,'restored':0,'permanent':0},
    'changes':[{'name':'new-device<script>','site':'home','action':'added','changed_utc':86500,
                'reason':'Automatically discovered from received NAS logs'},
               {'name':'old-device','site':'work','action':'auto_retire','changed_utc':86500,
                'reason':'No logs received for 10 days'}]}
output=html.render(report)
assert 'Device changes · last 7 days' in output and 'Auto-retired' in output
assert '10 days without received logs' in output and 'new-device&lt;script&gt;' in output
assert 'Auto-retired' in summary.render_lifecycle_text(report['device_lifecycle'])
with patch.dict(html.SETTINGS,{'timezone':'America/New_York','controls_enabled':True},clear=True):
    # Deployed older renderers retain a smaller local SETTINGS dictionary after merge.
    output=html.render(report)
    assert html.summary.SETTINGS['viewer_origin']+'/controls/devices' in output
    assert 'Device changes · last 7 days' in output
unavailable=html.lifecycle_section({'device_lifecycle':{'error':'Inventory unavailable <script>bad()</script> password=not-for-display'}})
assert 'Device changes unavailable' in unavailable and 'Inventory unavailable' in unavailable
assert '&lt;script&gt;' in unavailable and '<script>' not in unavailable and 'not-for-display' not in unavailable
assert 'No device additions' not in unavailable and 'Auto-retirement: Disabled' not in unavailable
print('PASS: bounded summary, seven-day comparisons, incomplete-baseline honesty, evidence validation, local model restriction, official links, critical fallback, safe HTML, and all summary anchor targets.')
