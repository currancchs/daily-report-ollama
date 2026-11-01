"""Regression checks for narrowly scoped error/logout grouping."""
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('rules',Path(__file__).resolve().parent.parent/'src/event_rollups.py')
rules=importlib.util.module_from_spec(spec);spec.loader.exec_module(rules)
message=('SECURITY[1763]: res_security_log.c:114 in security_event_stasis_cb: '
 'SecurityEvent="RequestNotAllowed",EventTV="2026-10-31T16:07:08.009-0400",Severity="Error",'
 'Service="AMI",EventVersion="1",AccountID="example",SessionID="0x1234",'
 'LocalAddress="IPV4/TCP/127.0.0.1/5038",RemoteAddress="IPV4/TCP/127.0.0.1/37110",'
 'RequestType="Action: getVar",SessionTV="2026-10-30T20:17:43.607-0400"')
raw={'prog':'asterisk','llevel':'error'}
original=rules.rollup(raw,message)
assert original[1]=='ami_denied_session'
variant=message.replace('[1763]','[9999]').replace('.009-0400','.555-0400').replace('0x1234','0x5678').replace('/37110','/39999')
assert rules.rollup(raw,variant)[0]==original[0]
for old,new in [('getVar','Command'),('AccountID="example"','AccountID="other"'),('/5038','/9999'),('RemoteAddress="IPV4/TCP/127.0.0.1','RemoteAddress="IPV4/TCP/192.0.2.1')]:
    assert rules.rollup(raw,message.replace(old,new))[0]!=original[0]
for bad in [message+',Extra="error"',message.replace('Severity="Error"','Severity="Informational"'),message.replace('2026-10-31T16:07:08.009-0400','invalid'),message.replace('RequestNotAllowed','InvalidPassword')]:
    assert rules.rollup(raw,bad)==(bad,'',{})
assert rules.rollup({'prog':'other'},message)==(message,'',{})
logout='User [example] from [192.0.2.1] logged out the server via [FTP] with totally [   96.50 MB] uploaded and [0 bytes] downloaded.'
raw={'prog':'Connection','llevel':'info'}
first=rules.rollup(raw,logout)
assert first[1]=='nas_ftp_logout_bytes'
assert rules.rollup(raw,logout.replace('96.50 MB','1.25 GB').replace('0 bytes','20 KB'))[0]==first[0]
for old,new in [('example','other'),('192.0.2.1','192.0.2.2'),('FTP','SFTP')]:
    assert rules.rollup(raw,logout.replace(old,new))[0]!=first[0]
for suffix in [' Failed',' Error']:
    assert rules.rollup(raw,logout+suffix)==(logout+suffix,'',{})
assert rules.rollup(dict(raw,llevel='warning'),logout)==(logout,'',{})
wrapped=json.dumps({'luser':'example','msg':logout,'synology_table':'connection_log'})
group=rules.rollup(raw,wrapped)
assert group[1]=='nas_ftp_logout_bytes' and json.loads(group[0])['luser']=='example'
assert json.loads(group[0])['msg']==first[0]
print('PASS: repeat grouping retains identities, actions, error outcomes and original varied fields; unknown/failure formats stay separate.')
