from contextlib import closing
from datetime import datetime
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent



def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'src'/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


daily=load('daily_report'); web=load('report_web'); rules=load('suppression_rules')
NOW=int(datetime(2026,10,31,5,tzinfo=web.job.ZONE).timestamp())
DAY=web.job.report_day(NOW); WINDOW=web.job.window_for(DAY)
HOST='http://127.0.0.1:8088'


def make_history(base):
    history=base/'events.sqlite'
    registry={'format_version':1,'sites':{site:{'status':'complete','warnings':[],
        'sources':{source:{'exported_utc':NOW,'warnings':[]} for source in
                   (['homeassistant','other-source'] if site=='home' else ['homeassistant'])}}
        for site in ('home','work')}}
    (base/'site-registry.json').write_text(json.dumps(registry))
    with closing(sqlite3.connect(history)) as db,db:
        db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
        variants=[('home','homeassistant','192.0.2.70','error','01:00:00'),
                  ('home','homeassistant','192.0.2.70','error','01:01:00'),
                  ('home','homeassistant','192.0.2.71','error','01:00:00'),
                  ('home','homeassistant','192.0.2.70','critical','01:00:00'),
                  ('work','homeassistant','192.0.2.70','error','01:00:00'),
                  ('home','other-source','192.0.2.70','error','01:00:00')]
        for index,(site,source,device,level,at) in enumerate(variants):
            raw={'msg':f'2026-10-31 {at}.123 ERROR Unable to reach patio sensor at {device}',
                 'host':'ha','ip':'192.0.2.80','prog':'homeassistant','tag':'service','llevel':level,'prio':3}
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                       (str(index),site,source,WINDOW[1]-500,WINDOW[1]-499,NOW,json.dumps(raw)))
    return history


def collect(base):
    return daily.collect(base/'events.sqlite',base,now=NOW,budget=50,window=WINDOW)


def assess(report):
    seen=[]
    def caller(url,model,batch,timeout):
        seen.extend(group['suppression_key'] for group in batch)
        return [{'id':group['id'],'classification':'issue','severity':'warning',
                 'summary':'<script>bad()</script> Sensor temporarily unavailable. password=model-secret',
                 'suggested_check':'Check device power.'} for group in batch]
    daily.analyze(report,'http://not-contacted.invalid','test',5,caller=caller,max_runtime=60)
    return seen


def save_report(base,report):
    report.update(report_kind='daily',report_date=DAY.isoformat(),status='daily_complete')
    folder=base/'daily'/DAY.isoformat(); folder.mkdir(parents=True,exist_ok=True)
    (folder/'report.json').write_text(json.dumps(report),encoding='utf-8')
    (folder/'report.txt').write_text(daily.render(report,web.job.ZONE),encoding='utf-8')
    (folder/'report.html').write_text(web.html.render(report),encoding='utf-8')
    state={'producer':web.job.PRODUCER,'report_date':DAY.isoformat(),'phase':'ready',
           'sha256':{name:hashlib.sha256((folder/name).read_bytes()).hexdigest()
                     for name in ('report.json','report.txt','report.html')}}
    (folder/'state.json').write_text(json.dumps(state))
    return folder


class Forms(HTMLParser):
    def __init__(self,text):
        super().__init__(); self.inputs={}; self.tags=[]; self.attrs=[]; self.feed(text)
    def handle_starttag(self,tag,attrs):
        self.tags.append(tag); self.attrs.extend(attrs)
        attrs=dict(attrs)
        if tag=='input' and 'name' in attrs: self.inputs[attrs['name']]=attrs.get('value','')


with tempfile.TemporaryDirectory() as temporary:
    base=Path(temporary); history=make_history(base); original_history=history.read_bytes()
    with patch.dict(daily.SETTINGS,controls_enabled=True):
        missing=collect(base)
        assert missing['suppression']['error']
        assert missing['sites']['home']['suppressed_records']==0
    path=rules.database_path(base); rules.initialize(path)
    initial=collect(base); assessed=assess(initial)
    target=next(group for group in initial['sites']['home']['groups'] if group['count']==2)
    assert target['suppression_key'] in assessed
    rule,created=rules.create(path,'home',target,'Temporarily offline token=reason-secret',now=NOW)
    assert created and rule['expires_utc'] is None and 'reason-secret' not in rule['reason']
    assert rules.create(path,'home',target,now=NOW)[1] is False
    after=collect(base)
    assert after['sites']['home']['suppressed_records']==2
    assert len(after['sites']['home']['suppressed_groups'])==1
    assert after['sites']['work']['suppressed_records']==0
    remaining=after['sites']['home']['groups']
    assert any('192.0.2.71' in group['message'] for group in remaining)
    assert any(group['reported_level']=='critical' for group in remaining)
    assert any(group['source']=='other-source' for group in remaining)
    assert target['suppression_key'] not in assess(after)
    data=after['sites']['home']
    assert data['rows_scanned']==data['eligible_records']+data['suppressed_records']+data['malformed_rows']
    assert data['groups_total_before_suppression']==data['groups_total']+1
    assert 'SUPPRESSED: 2 records in 1' in daily.render(after,web.job.ZONE)
    rendered=web.html.render(after)
    assert '2 records in 1' in rendered and 'Suppression filters applied' in rendered
    assert 'model-secret' not in rendered and '<script>' not in rendered
    folder=save_report(base,after)
    saved={name:(folder/name).read_bytes() for name in ('report.txt','report.json','report.html','state.json')}
    app=web.create_app(base,secret=b'test-secret-not-for-deployment-1234',clock=lambda:NOW)
    app.config['SESSION_COOKIE_PATH']='/'
    client=app.test_client()
    def get(url,**kwargs): return client.get(url,base_url=HOST,**kwargs)
    def post(url,data,origin=HOST,**kwargs):
        headers={'Origin':origin}
        headers.update(kwargs.pop('headers',{}))
        return client.post(url,data=data,base_url=HOST,headers=headers,content_type='application/x-www-form-urlencoded',**kwargs)

    with patch('smtplib.SMTP_SSL',side_effect=AssertionError('No SMTP')), \
         patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('No network')):
        response=get('/'); assert response.status_code==200
        assert b'Report' in response.data and b'Collection coverage' in response.data
        parsed=Forms(response.get_data(as_text=True))
        assert 'script' not in parsed.tags and not any(name.startswith('on') for name,value in parsed.attrs)
        assert b'model-secret' not in response.data
        response=get('/suppressed'); assert response.status_code==200 and b'192.0.2.70' in response.data
        response=get('/filters'); assert response.status_code==200 and b'Until removed' in response.data
        delete_url='/filters/'+rule['id']+'/delete'
        response=get(delete_url); assert response.status_code==200
        csrf=Forms(response.get_data(as_text=True)).inputs['csrf']
        assert post(delete_url,{'csrf':csrf},origin='https://evil.invalid').status_code==403
        assert post(delete_url,{}).status_code==403
        assert client.post(delete_url,data={'csrf':csrf},base_url=HOST).status_code==403
        assert client.get('/',base_url='http://evil.invalid:8088').status_code==400
        assert get('/events.sqlite').status_code==404
        assert client.delete(delete_url,base_url=HOST).status_code==405
        assert rules.snapshot(path,NOW)['rules']
        assert post(delete_url,{'csrf':csrf}).status_code==303
        assert not rules.snapshot(path,NOW)['rules']
        assert b'eligible again for the next report build' in get('/').data
        assert not rules.delete(path,rule['id'],NOW)
        assert all((folder/name).read_bytes()==value for name,value in saved.items())

        # Re-create from a verified report group; forever is the form's default.
        ignore_url='/ignore/home/'+target['id']
        response=get(ignore_url); assert response.status_code==200
        form=Forms(response.get_data(as_text=True)).inputs
        assert b'value="forever" selected' in response.data
        assert post(ignore_url,dict(form,reason='Offline for repair',duration='forever')).status_code==303
        assert len(rules.snapshot(path,NOW)['rules'])==1
        assert post(ignore_url,dict(form,reason='Offline for repair',duration='forever')).status_code==303
        assert len(rules.snapshot(path,NOW)['rules'])==1
        assert post(ignore_url,dict(form,duration='999days')).status_code==400
        assert post(ignore_url,dict(form,report_date='2026-10-30')).status_code==409
        assert post('/ignore/home/home-'+'f'*16,form).status_code==404
        assert client.get('/filters?site=x',base_url=HOST).status_code==200
        assert get('/?page=-1').status_code==400
        assert post(ignore_url,dict(form,reason='x'*17000)).status_code==413
        assert b'csrf' in get(ignore_url).data

    # Deletion restores future collection and expiry also restores eligibility.
    active=rules.snapshot(path,NOW)['rules'][0]; rules.delete(path,active['id'],NOW)
    assert collect(base)['sites']['home']['suppressed_records']==0
    expiring,_=rules.create(path,'home',target,duration='1d',now=NOW-86401)
    assert not rules.snapshot(path,NOW)['rules']
    assert collect(base)['sites']['home']['suppressed_records']==0
    assert history.read_bytes()==original_history

    # A captured filter snapshot stays fixed even if the rule is then removed.
    active,_=rules.create(path,'home',target,now=NOW)
    captured=daily.filters.snapshot(path,NOW)
    rules.delete(path,active['id'],NOW)
    with patch.object(daily.filters,'snapshot',return_value=captured):
        assert collect(base)['sites']['home']['suppressed_records']==2
    assert collect(base)['sites']['home']['suppressed_records']==0

    # Filter failure keeps logs visible and reports the failure.
    with patch.object(daily.filters,'snapshot',side_effect=sqlite3.DatabaseError('bad')):
        failure=collect(base)
        assert failure['sites']['home']['suppressed_records']==0
        assert failure['suppression']['error'] and failure['sites']['home']['warnings']
    with closing(sqlite3.connect(path)) as db:
        actions=[row[0] for row in db.execute('SELECT action FROM audit')]
        assert 'created' in actions and 'deleted' in actions

    # Intentional exclusion of everything must not claim the AI reviewed it.
    unfiltered=collect(base)
    for site,data in unfiltered['sites'].items():
        for group in data['groups']: rules.create(path,site,group,now=NOW)
    all_filtered=collect(base)
    assert assess(all_filtered)==[]
    all_filtered.update(status='daily_complete',report_kind='daily',report_date=DAY.isoformat())
    all_html=web.html.render(all_filtered)
    assert 'All grouped records were suppressed' in all_html
    assert 'Review completed' not in all_html and 'Limited AI review' not in all_html
    assert sum(data['suppressed_records'] for data in all_filtered['sites'].values())==6

    # Exercise the deployed mount, cookies and redirects, not just inner routes.
    from werkzeug.test import Client
    from werkzeug.wrappers import Response
    for rule in rules.list_rules(path): rules.delete(path,rule['id'],NOW)
    assess(unfiltered)
    save_report(base,unfiltered)
    mounted=Client(web.create_dispatcher(base=base,secret=b'synthetic-mount-secret-12345678901',clock=lambda:NOW),Response)
    listing=mounted.get('/controls/',base_url=HOST)
    assert listing.status_code==200
    parsed=Forms(listing.get_data(as_text=True))
    ignore_path=next(value for name,value in parsed.attrs if name=='href' and value.startswith('/controls/ignore/'))
    confirmation=mounted.get(ignore_path,base_url=HOST)
    fields=Forms(confirmation.get_data(as_text=True)).inputs
    assert 'Until I remove it' in confirmation.get_data(as_text=True)
    fields.update(reason='Synthetic mounted-route test',duration='forever')
    saved=mounted.post(ignore_path,base_url=HOST,data=fields,headers={'Origin':HOST})
    assert saved.status_code==303 and saved.headers['Location'].startswith('/controls/')
    hidden=mounted.get('/controls/suppressed',base_url=HOST)
    assert 'Synthetic mounted-route test' in hidden.get_data(as_text=True)
    assert 'Path=/controls' in listing.headers['Set-Cookie']
    assert mounted.get('/',base_url=HOST).status_code==404
    assert mounted.get('/controls/events.sqlite',base_url=HOST).status_code==404
    assert mounted.get('/controls/',base_url='http://evil.invalid',headers={'X-Forwarded-Host':'127.0.0.1:8088'}).status_code==400
    with patch.dict(web.publisher.SETTINGS,viewer_origin='https://10.20.30.40:8443'):
        secured=Client(web.create_dispatcher(base=base,secret=b'synthetic-mount-secret-12345678901',clock=lambda:NOW),Response)
        response=secured.get('/controls/',base_url='https://10.20.30.40:8443')
        assert response.status_code==200 and 'Secure;' in response.headers['Set-Cookie']
        assert secured.get('/controls/',base_url=HOST).status_code==400

print('PASS: exact scope/device/site/severity matching, before-AI exclusion, accounting, expiry, delete/restore, immutable reports/history, snapshot isolation, fail-open filters, CSRF/Origin/Host protections, forms and HTML escaping')
