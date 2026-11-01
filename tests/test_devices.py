"""Device lifecycle, precise exclusion, coverage, and protected web mutations."""
from contextlib import closing
from datetime import datetime
from html.parser import HTMLParser
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
def load(name):
    spec=importlib.util.spec_from_file_location('test_'+name,ROOT/'src'/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
devices=load('device_inventory'); daily=load('daily_report'); web=load('report_web')
NOW=int(datetime(2026,11,1,5,tzinfo=web.job.ZONE).timestamp())
WINDOW=web.job.window_for(web.job.report_day(NOW)); HOST='http://127.0.0.1:8088'

class Form(HTMLParser):
    def __init__(self,text): super().__init__(); self.values={}; self.feed(text)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='input' and attrs.get('name'): self.values[attrs['name']]=attrs.get('value','')

with tempfile.TemporaryDirectory() as temp:
    base=Path(temp); history=base/'events.sqlite'; path=devices.database_path(base)
    devices.initialize(path); web.rules.initialize(web.rules.database_path(base))
    with closing(sqlite3.connect(history)) as db,db:
        db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
    def add(site,source,host,ip):
        raw={'host':host,'ip':ip,'msg':'Disk failed','prog':'kernel','llevel':'crit','prio':'crit'}
        with closing(sqlite3.connect(history)) as db,db:
            key=str(db.execute('SELECT COUNT(*) FROM events').fetchone()[0])
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)',(key,site,source,WINDOW[1]-100,WINDOW[1]-99,NOW,json.dumps(raw)))
        return devices.identity(site,source,raw)
    target=add('home','AP.example','AP.example','192.0.2.6')
    assert add('home','ap.example','ap.example','192.0.2.6')==target
    reused=add('home','new.example','new.example','192.0.2.6'); assert reused!=target
    moved=add('home','AP.example','AP.example','192.0.2.7'); assert moved!=target
    remote=add('work','AP.example','AP.example','192.0.2.6'); assert remote!=target
    nas=add('home','NAS/connections','client1','192.0.2.90')
    assert add('home','NAS/transfers','client2','192.0.2.91')==nas
    hostile=add('work','<img onerror=bad()>','<img onerror=bad()>','192.0.2.8')
    def registry():
        sites={site:{'status':'complete','warnings':[],'sources':{}} for site in ('home','work')}
        with closing(sqlite3.connect(history)) as db:
            for site,source in db.execute('SELECT DISTINCT site,source FROM events'):
                sites[site]['sources'][source]={'exported_utc':NOW,'warnings':[],'notices':[],'discovery_status':'present','has_live_database':True}
        sites['home']['sources']['old-name']={'exported_utc':NOW-900000,'warnings':[],
            'discovery_status':'absent','notices':['Only retained history is available.']}
        (base/'site-registry.json').write_text(json.dumps({'format_version':1,'sites':sites}))
    registry(); devices.refresh(base,NOW)
    original=history.read_bytes()
    def item(key): return next(d for d in devices.catalog(base,NOW)['devices'] if d['id']==key)
    assert len(item(target)['aliases'])==2
    assert item(nas)['scope']['ip']=='' and item(target)['retained_records']==2
    def change(key,action,reason=''): return devices.change(base,key,action,item(key)['revision'],reason,NOW)
    def collect(): return daily.collect(history,base,now=NOW,budget=50,window=WINDOW)
    initial=collect(); assert not initial['sites']['home']['sources']['old-name']['warnings']
    initial_revision=item(target)['revision']
    assert initial['sites']['home']['sources']['old-name']['notices']
    try: change(target,'permanent'); raise AssertionError('Active device permanently retired in one step')
    except ValueError: pass
    change(target,'retire','Temporary <script>reason</script>')
    report=collect(); home=report['sites']['home']
    assert home['retired_records']==2 and report['sites']['work']['retired_records']==0
    assert {g['device_id'] for g in home['groups']}=={reused,moved,nas}
    assert home['grouped_records']+home['retired_records']+home['malformed_rows']==home['rows_scanned']
    seen=[]
    def caller(url,model,batch,timeout):
        seen.extend(g['device_id'] for g in batch)
        return [dict(id=g['id'],classification='issue',severity='warning',summary='Disk issue',suggested_check='Check disk') for g in batch]
    daily.analyze(report,'http://not-contacted.invalid','test',5,caller=caller,max_runtime=60)
    assert target not in seen and remote in seen
    assert 'Retired devices excluded' in web.html.render(report)
    assert history.read_bytes()==original
    # Build-wide snapshot: a newly retired device stays eligible in the ongoing scan.
    changed=[False]; prepare=daily.prepare
    def retire_during_scan(raw):
        if not changed[0]: change(reused,'retire'); changed[0]=True
        return prepare(raw)
    with patch.object(daily,'prepare',retire_during_scan): snapshot_report=collect()
    assert any(g['device_id']==reused for g in snapshot_report['sites']['home']['groups'])
    change(reused,'restore')
    # Genuine collection errors remain visible even when the related device is retired.
    data=json.loads((base/'site-registry.json').read_text())
    data['sites']['home'].update(status='partial',warnings=['Export checksum mismatch'])
    (base/'site-registry.json').write_text(json.dumps(data))
    assert 'Export checksum mismatch' in collect()['sites']['home']['warnings']
    registry()
    # Missing configured store fails open and is reported; no silent exclusion.
    with patch.object(daily.devices,'snapshot',side_effect=ValueError('broken')):
        failed=collect(); assert failed['devices']['error'] and failed['sites']['home']['retired_records']==0
    missing=base/'devices'/'missing.sqlite'
    try: devices.snapshot(missing,required=True); raise AssertionError('Required missing database accepted')
    except sqlite3.OperationalError: pass
    # Web actions require same-origin CSRF, a current revision, and a second confirmation.
    app=web.create_app(base,secret=b'not-a-deployment-secret-1234567890',clock=lambda:NOW)
    app.config['SESSION_COOKIE_PATH']='/'
    client=app.test_client()
    def get(url,**kw): return client.get(url,base_url=HOST,**kw)
    def post(url,data,origin=HOST): return client.post(url,data=data,base_url=HOST,headers={'Origin':origin})
    assert get('/devices').status_code==200
    assert b'<img onerror=bad()>' not in get('/devices?site=work').data
    assert b'&lt;img' in get('/devices?site=work').data
    assert get('/devices?state=invalid').status_code==400
    url='/devices/'+target+'/restore'; response=get(url); assert response.status_code==200
    form=Form(response.get_data(as_text=True)).values
    assert post(url,form,origin='https://evil.invalid').status_code==403
    assert post(url,dict(form,csrf='wrong')).status_code==403
    assert post(url,dict(form,revision='stale')).status_code==409
    assert item(target)['state']=='retired'
    assert post(url,form).status_code==303 and item(target)['state']=='active'
    assert item(target)['revision']!=initial_revision  # Same-second retire/restore invalidates old forms.
    assert collect()['sites']['home']['retired_records']==0
    url='/devices/'+target+'/retire'; form=Form(get(url).get_data(as_text=True)).values
    assert item(target)['state']=='active'  # GET only confirms.
    assert post(url,form).status_code==303
    url='/devices/'+target+'/permanent'; form=Form(get(url).get_data(as_text=True)).values
    form.pop('confirm_permanent',None)
    assert post(url,form).status_code==400
    assert post(url,dict(form,confirm_permanent='yes')).status_code==303
    assert get('/devices/'+target+'/restore').status_code==409
    assert get('/devices/'+target+'/retire').status_code==409
    assert b'cannot be restored here' in get('/devices?state=permanent').data
    add('home','AP.example','AP.example','192.0.2.6'); devices.refresh(base,NOW+1)
    assert item(target)['state']=='permanent' and collect()['sites']['home']['retired_records']==3
    assert item(reused)['state']=='active'
    # Live views remove retired findings; saved reports/history are never rewritten.
    sample={'sites':{'home':{'groups':[dict(id='g',source='AP.example',host='AP.example',ip='192.0.2.6',count=1)],
        'assessments':[dict(id='g',classification='issue',severity='warning',summary='x')]}}}
    assert web.rows_for(sample,{})[0] and not web.rows_for(sample,{},devices.snapshot(path)['retired'])[0]
    with closing(devices.connect(path)) as db:
        assert db.execute('SELECT COUNT(*) FROM audit WHERE device_id=?',(target,)).fetchone()[0]==4
    # All retired is intentional exclusion, never a claim that devices are healthy.
    for d in devices.catalog(base,NOW)['devices']:
        if d['state']=='active': change(d['id'],'retire')
    all_retired=collect(); daily.analyze(all_retired,'unused','unused',5,caller=caller,max_runtime=60)
    assert not all_retired['sites']['home']['groups']
    output=web.html.render(all_retired)
    assert 'Records were excluded by device retirement' in output and 'Retired devices excluded' in output
print('PASS: precise device identity, alias consolidation, retire/restore/permanent lifecycle, before-AI exclusion, snapshot isolation, fail-open errors, truthful coverage, protected forms and immutable history')
