from datetime import date, datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('preview_web',ROOT/'src/report_web.py')
web=importlib.util.module_from_spec(spec); spec.loader.exec_module(web)
day=date(2026,11,1)
now=int(datetime(2026,11,1,5,tzinfo=web.job.ZONE).timestamp())
report=json.loads((ROOT/'examples/nightly-report-example.json').read_text(encoding='utf-8'))
report.update(report_date=day.isoformat(),generated_utc=web.job.iso(now),
              window_start=web.job.window_for(day)[0],window_end_exclusive=web.job.window_for(day)[1])
for site,data in report['sites'].items():
    mapping={}
    for group in data['groups']:
        signature=hashlib.sha256(('EXAMPLE DATA '+site+' '+group['id']).encode()).hexdigest()
        mapping[group['id']]=site+'-'+signature[:16]
        group.update(id=mapping[group['id']],suppression_key=signature,program='example-service',
                     reported_level='error',reported_priority='3',ip='192.0.2.80',tag='example',
                     message=group['example_message'],first=report['window_start']+3600,last=report['window_end_exclusive']-60)
    for assessment in data['assessments']: assessment['id']=mapping[assessment['id']]
target=report['sites']['home']['groups'][0]
target.update(source='Home Assistant',host='homeassistant',program='homeassistant',
              message='Timeout connecting to patio-temperature at 192.0.2.70',
              example_message='Timeout connecting to patio-temperature at 192.0.2.70')
report['sites']['home']['assessments'][0]['summary']='The patio temperature sensor is not responding.'
report['sites']['home']['assessments'][0]['suggested_check']='Check whether the sensor is powered and reachable.'

with tempfile.TemporaryDirectory() as temporary:
    base=Path(temporary); path=web.rules.database_path(base); web.rules.initialize(path)
    (ROOT/'examples/controls').mkdir(parents=True,exist_ok=True)
    rule,_=web.rules.create(path,'home',target,'Disconnected during patio repairs.',now=now)
    app=web.create_app(base,secret=b'example-only-not-a-deployment-key',clock=lambda:now)
    client=app.test_client()
    other=report['sites']['home']['groups'][1]
    routes={'report':'/','suppressed':'/suppressed','filters':'/filters',
            'ignore':'/ignore/home/'+other['id'],'restore':'/filters/'+rule['id']+'/delete'}
    with patch.object(web,'current_report',return_value=(report,'ready',day)):
        for name,route in routes.items():
            response=client.get(route,base_url='http://127.0.0.1:8088')
            assert response.status_code==200,(name,response.status_code)
            content=response.get_data(as_text=True)
            content=content.replace('<main>','<main><div class="notice"><strong>DESIGN PREVIEW · EXAMPLE DATA.</strong> This saved file is a layout example. Form buttons are disabled.</div>',1)
            content=content.replace('<title>','<title>EXAMPLE — ',1)
            content=content.replace('href="/">Dashboard</a>', 'href="../dashboard/index.html">Dashboard</a>')
            for nav,target_name in [('/','report'),('/suppressed','suppressed'),('/filters','filters')]:
                content=content.replace('href="'+nav+'"','href="'+target_name+'.html"')
            content=re.sub(r'href="/ignore/[^\"]+"','href="ignore.html"',content)
            content=re.sub(r'href="/filters/[^\"]+/delete"','href="restore.html"',content)
            content=re.sub(r'<button\b','<button disabled',content)
            content=re.sub(r'action="[^"]*"','action="#"',content)
            content='\n'.join(line.rstrip() for line in content.splitlines())+'\n'
            (ROOT/'examples/controls'/(name+'.html')).write_text(content,encoding='utf-8')
print('Five labeled, inert example pages generated; no server/browser, AI or email used.')
