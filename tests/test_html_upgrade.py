from pathlib import Path
from datetime import datetime
from html.parser import HTMLParser
from contextlib import closing
from unittest.mock import patch
import importlib.util
import json
import sqlite3
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parent.parent
def load(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'src'/(name+'.py'))
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
privacy=load('sanitize_logs'); html=load('html_report'); importer=load('import_synology'); collector=load('collect_sites')

samples=[
    ('password=super-secret-123 host=192.0.2.197','super-secret-123'),
    ('Authorization: Bearer abcDEF123456\nother event','abcDEF123456'),
    ('Cookie: sessionid=private-session\nnext','private-session'),
    ('https://user:password-value@example.invalid/path?token=secret-token&ok=1','password-value'),
    ('{"password":"escaped\\\"quote-secret","host":"192.0.2.197"}','quote-secret'),
    ('-----BEGIN PRIVATE KEY-----\nprivate-test-material\n-----END PRIVATE KEY-----','private-test-material'),
    ('bearer eyJabcdefghijk.abcdefghijklm.abcdefghijk','eyJabcdefghijk'),
    ('{"original_bytes_hex":"c2aabbcc","text_preview":"password=other-secret"}','c2aabbcc'),
]
for value,secret in samples:
    clean=privacy.text(value)
    assert secret not in clean, (value,clean)
    assert privacy.text(clean)==clean, ('not idempotent',clean,privacy.text(clean))
assert privacy.record({'api_key':'test-secret','ip':'192.0.2.197'})=={'api_key':'[REDACTED]','ip':'192.0.2.197'}
assert '02:00:00:00:00:01' in privacy.text('client 02:00:00:00:00:01 192.0.2.197')
assert 'secret-token' not in privacy.text(samples[3][0])

NOW=int(datetime(2026,10,31,4,35,tzinfo=html.ZONE).timestamp())
report={'report_kind':'daily','report_date':'2026-10-31','status':'daily_complete',
        'generated_utc':datetime.fromtimestamp(NOW,html.ZONE).isoformat(),'window_start':NOW-25*3600,
        'window_end_exclusive':NOW-3900,'model':'qwen3.6:27b','review_limited':True,'sites':{}}
for site,sources in [('home',['pfSense','ProxmoxVE','Home Assistant']),('work',['work-hypervisor','Work NAS'])]:
    groups=[]; assessments=[]
    for k in range(18 if site=='home' else 12):
        source=sources[k%len(sources)]; issue=k<2 if site=='home' else k==0
        count=4265 if site=='home' and k==0 else 280 if issue else 25+k*7
        group={'id':site+'-'+str(k),'source':source,'host':source,'count':count,
               'first':NOW-36000,'last':NOW-4000,'priority_hint':1 if issue else 3,
               'example_message':'DHCP4_INIT_REBOOT client 02:00:00:00:00:01 requests 192.0.2.197' if k==0 and site=='home' else 'Example event: service request failed' if issue else 'Example routine event'}
        groups.append(group)
        assessments.append({'id':group['id'],'classification':'uncertain' if issue else 'routine',
                            'severity':'warning' if issue else 'info',
                            'summary':'Repeated DHCP address confirmations deserve a connection-history check.' if site=='home' and k==0 else 'Repeated service errors need verification against the source logs.' if issue else 'Routine example activity.',
                            'suggested_check':'Compare the device connection history and event timestamps.' if issue else ''})
    info={s:{'records':sum(g['count'] for g in groups if g['source']==s),'groups_total':sum(g['source']==s for g in groups),
             'last_record':NOW-4000,'warnings':[]} for s in sources}
    if site=='work': info['Work NAS']['warnings']=['One archive-only source has no live database; daily coverage is uncertain.']
    count=sum(g['count'] for g in groups)
    report['sites'][site]={'groups':groups,'assessments':assessments,'groups_total':len(groups)+(4 if site=='home' else 0),
        'rows_in_window':count+(40 if site=='home' else 0),'rows_scanned':count+(40 if site=='home' else 0),
        'rows_not_grouped':0,'sources':info,'warnings':[],'ai_errors':[],'flagged_groups_total':2 if site=='home' else 1}
demo=html.render(report,demo=True)
html.save(ROOT/'examples/nightly-report-preview.html',demo)
(ROOT/'examples/nightly-report-example.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
assert 'DESIGN PREVIEW' in demo and 'Coverage needs attention' in demo and '4 groups unreviewed' in demo
assert len(demo.encode())<90000

class Tags(HTMLParser):
    def __init__(self): super().__init__(); self.tags=[]; self.attrs=[]
    def handle_starttag(self,tag,attrs): self.tags.append(tag); self.attrs.extend(attrs)
injection=json.loads(json.dumps(report))
injection['sites']['home']['assessments'][0]['summary']='<script>alert(1)</script> password=secret-in-html'
injection['sites']['home']['groups'][0]['example_message']='<img src="https://evil.invalid/pixel" onerror="bad()">'
rendered=html.render(injection)
parser=Tags(); parser.feed(rendered)
assert not {'script','img','iframe','object','form'}.intersection(parser.tags)
assert not any(k.startswith('on') for k,v in parser.attrs)
assert 'secret-in-html' not in rendered and '&lt;script&gt;' in rendered
assert 'Device health is unknown' in html.render({'status':'daily_failed'},'Error token=secret-failure')
assert 'secret-failure' not in html.render({'status':'daily_failed'},'Error token=secret-failure')
assert 'No AI review available' in html.render({'status':'daily_complete','sites':{}})
core=load('preview_report')
legacy={'id':'home-test','source':'device','host':'192.0.2.197','program':'test',
        'reported_level':'warning','reported_priority':'4','message':'api_key=old-db-secret',
        'message_truncated':False,'count':1,'first':NOW-10,'last':NOW-1}
assert 'old-db-secret' not in core.packet([legacy])
try: html.render(report,dashboard_url='javascript:alert(1)'); raise AssertionError('unsafe URL accepted')
except ValueError: pass

with tempfile.TemporaryDirectory(dir=ROOT/'work') as tmp:
    tmp=Path(tmp); dbfile=tmp/'source.DB'; history=tmp/'history.sqlite'
    fields=importer.FIELDS
    with closing(sqlite3.connect(dbfile)) as db,db:
        db.execute('CREATE TABLE logs ('+','.join(name+' TEXT' for name in fields)+')')
        db.execute('INSERT INTO logs(id,utcsec,r_utcsec,host,msg) VALUES(?,?,?,?,?)',
                   ('1',str(NOW),str(NOW),'device','password=db-secret host=192.0.2.197'))
    archive=tmp/'sample.zip'
    with zipfile.ZipFile(archive,'w') as z: z.write(dbfile,'source.DB')
    first=importer.import_archive(archive,history,'home','device')
    second=importer.import_archive(archive,history,'home','device')
    assert first['new_rows']==1 and second['new_rows']==0 and first['redacted_rows']==1
    with closing(sqlite3.connect(history)) as db:
        stored=db.execute('SELECT raw_json FROM events').fetchone()[0]
    assert 'db-secret' not in stored and '192.0.2.197' in stored
    assert b'db-secret' in dbfile.read_bytes()
    mount=tmp/'mount'; exports=mount/'home'/'AI-Monitor-Exports'; exports.mkdir(parents=True)
    manifest=exports/'home-manifest.json'; manifest.write_text('{}')
    getter=collector.mounted_getter(mount)
    if collector.os.name=='posix':
        class RO: f_flag=collector.os.ST_RDONLY
        with patch.object(collector.os,'statvfs',return_value=RO()): getter('home','home-manifest.json',tmp/'copy',None)
    else: getter('home','home-manifest.json',tmp/'copy',None)
    assert (tmp/'copy').read_text()=='{}'
    try: getter('home','../../secret',tmp/'unsafe',None); raise AssertionError('path escape accepted')
    except ValueError: pass
print('PASS: redaction, idempotence, original evidence retention, sanitized SQLite imports, deduplication, HTML injection/URL rejection, honest coverage, failure report, and mounted-path boundary; example HTML generated. No network or email used.')
