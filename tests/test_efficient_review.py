"""Offline protocol/accounting checks. No network, model, mail or service changes."""
import copy
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location(name,(HERE/(name+'.py') if name == 'review_fixtures' else HERE.parent/'src'/(name+'.py')))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
engine=load('efficient_review');benchmark=load('review_fixtures');daily=load('daily_report')
groups=benchmark.synthetic_groups()
batch=groups[:4]
valid={'routine':[0,2,3],'findings':[{'index':1,'classification':'uncertain','severity':'info',
       'summary':'The command result is not shown.','suggested_check':'Review the firewall change history.'}]}
checked=engine.validate(valid,batch)
assert [a['id'] for a in checked]==[g['id'] for g in batch]
assert checked[1]['classification']=='uncertain'
bad=[]
for indices in ([0,0,3],[0,2,4],[0,2,-1],[False,2,3],[0,2],[0,2,3,4]):
    item=copy.deepcopy(valid);item['routine']=indices;bad.append(item)
for key,value in (('index',True),('classification','routine'),('summary',''),('summary','x'*161),('suggested_check','x'*121)):
    item=copy.deepcopy(valid);item['findings'][0][key]=value;bad.append(item)
item=copy.deepcopy(valid);item['extra']='ignored';bad.append(item)
for item in bad:
    try:engine.validate(item,batch)
    except ValueError:pass
    else:raise AssertionError('Invalid/partial response accepted')
packed=json.loads(engine.packet(batch))
restored=[dict(packed['shared_fields'],**dict(zip(packed['columns'],row))) for row in packed['rows']]
assert [g['index'] for g in restored]==list(range(4))
assert all('id' not in g for g in restored)
expected=json.loads(engine.core.packet(batch))['log_groups']
for index,group in enumerate(expected):
    del group['id'];group['index']=index
assert restored==expected
packets=list(engine.batches(groups));assert [g['id'] for b in packets for g in b]==[g['id'] for g in groups]
assert max(map(len,packets))>4 and all(len(b)<=12 for b in packets)
for url in ('https://example.com','http://8.8.8.8','http://user:password@127.0.0.1','http://127.0.0.1/api','http://0.0.0.0'):
    try:engine.local_origin(url)
    except ValueError:pass
    else:raise AssertionError('Invalid origin accepted')

class Response:
    def __init__(self,payload):self.payload=payload
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,*args):return json.dumps(self.payload).encode()
class Opener:
    def open(self,request,timeout):
        sent=json.loads(request.data)
        assert sent['think'] is False and sent['stream'] is False
        assert sent['format']==engine.schema(4)
        return Response({'done':True,'done_reason':'stop','message':{'content':json.dumps(valid)},'eval_count':50,'eval_duration':1000000000})
with patch.object(engine.urllib.request,'build_opener',return_value=Opener()):
    response=engine.call_ollama('http://127.0.0.1:11434','example',batch,20)
assert len(response)==4 and response.metrics['eval_count']==50

# Missing-index answers are retried in smaller batches within the same deadline.
calls=[]
def split_call(url,model,items,timeout,protocol):
    calls.append((len(items),timeout))
    if len(items)>2:
        raise engine.ReviewResponseError('missing index',{'eval_count':9})
    return engine.ReviewResult(engine.validate({'routine':list(range(len(items))),'findings':[]},items),{'eval_count':3})
with patch.object(engine,'call',side_effect=split_call):
    response=engine.call_ollama('http://127.0.0.1:11434','example',batch,20)
assert [a['id'] for a in response]==[g['id'] for g in batch]
assert [n for n,t in calls]==[4,2,2]
assert all(0<t<=20 for n,t in calls)
assert response.metrics['requests']==3 and response.metrics['split_retries']==1 and response.metrics['eval_count']==15
with patch.object(engine,'call',side_effect=OSError('unreachable')) as call:
    try:engine.call_ollama('http://127.0.0.1:11434','example',batch,20)
    except OSError:pass
    else:raise AssertionError('Network failure was hidden')
    assert call.call_count==1

report={'sites':{}}
for site in ('home','work'):
    entries=copy.deepcopy(groups)
    for group in entries:group['id']=site+'-'+group['id'].split('-',1)[1]
    report['sites'][site]=dict(groups=entries,groups_total=len(entries),rows_not_grouped=0,
        assessments=[],ai_errors=[],batches_attempted=0,batches_completed=0,
        flagged_groups_total=sum(g['priority_hint']<3 for g in entries))
def caller(url,model,batch,timeout):
    answers=engine.validate({'routine':list(range(len(batch))),'findings':[]},batch)
    return engine.ReviewResult(answers,{'protocol':'compact','groups':len(batch),'eval_count':len(batch)*3})
daily.analyze(report,'http://127.0.0.1','example',30,caller=caller,batcher=engine.batches)
assert not report['review_limited'] and report['analysis_stop_reason']=='selected_groups_complete'
assert len(report['inference_metrics'])==sum(s['batches_completed'] for s in report['sites'].values())
assert all(len(s['assessments'])==len(groups) for s in report['sites'].values())
print('PASS: complete numeric-ID mapping, invalid/missing/duplicate responses rejected, evidence retained, bounded batching, local endpoint restrictions, metrics and two-site review accounting')
