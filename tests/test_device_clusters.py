"""DNS consolidation preserves original identities, exclusions and physical-device counts."""
from contextlib import closing
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('cluster_test_devices', ROOT/'src'/'device_inventory.py')
devices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(devices)
NOW = 1794657600
DAY = 86400


def healthy(now):
    return {site: {'status':'complete','warnings':[],'collected_utc':now,'exported_utc':now,
            'sources':{'receiver':{'warnings':[]}}} for site in ('home','work')}


with tempfile.TemporaryDirectory() as folder:
    base=Path(folder); history=base/'events.sqlite'; path=devices.database_path(base)
    devices.initialize(path)
    with closing(sqlite3.connect(history)) as db,db:
        db.execute('CREATE TABLE events(site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
    identities={}
    def add(host,ip,received,site='home',source=None):
        source=source or host
        raw={'host':host,'ip':ip,'msg':'Synthetic device observation'}
        with closing(sqlite3.connect(history)) as db,db:
            db.execute('INSERT INTO events VALUES(?,?,?,?,?,?)',(site,source,received,received,NOW,json.dumps(raw)))
        key=devices.identity(site,source,raw)
        identities[key]=devices.scope(site,source,raw)
        return key
    old=add('router.home.lan','10.0.0.1',NOW-20*DAY)
    recent=add('router','10.0.0.1',NOW-60)
    work=add('router.work.lan','10.0.0.1',NOW-60,site='work')
    nas=add('router','10.0.0.1',NOW-60,source='NAS/system')
    def result(keys,now,canonical='router.home.lan',conflicts=()):
        bindings={}
        for key in keys:
            scope=identities[key]
            name='router.work.lan' if scope['site']=='work' else canonical
            bindings[key]={'cluster_key':hashlib.sha256((scope['site']+'\0'+name).encode()).hexdigest(),
                'canonical':name,'ip':scope['ip'],'verified_utc':now,'expires_utc':now+300}
        return {'bindings':bindings,'conflicts':list(conflicts),'checked_utc':now,
                'resolvers':['10.0.0.53'],'queries':4,'errors':[],'complete':True}
    def refresh(now=NOW,keys=None,conflicts=(),canonical='router.home.lan'):
        keys=[old,recent,work,nas] if keys is None else keys
        return devices.refresh(base,now,collection=healthy(now),
            dns_lookup=lambda observations,**kw: result(keys,now,canonical,conflicts))
    def item(key):
        return next(item for item in devices.catalog(base,NOW)['devices'] if key in item['members'])
    original=history.read_bytes()
    refresh()
    row=item(old)
    assert row['member_count']==2 and set(row['members'])=={old,recent}
    assert row['name']=='router.home.lan' and row['ips']==['10.0.0.1']
    assert row['state']=='active'  # A stale alias cannot retire while another alias has recent logs.
    assert item(work)['member_count']==1 and item(nas)['member_count']==1
    assert len(devices.catalog(base,NOW)['devices'])==3
    assert devices.lifecycle_summary(base,NOW)['counts']['added']==3
    assert history.read_bytes()==original
    # One physical-device action writes all original exclusions and one report change.
    devices.change(base,row['id'],'retire',row['revision'],'Maintenance',NOW)
    excluded=devices.snapshot(path,NOW)['retired']
    assert set(excluded)=={old,recent}
    summary=devices.lifecycle_summary(base,NOW)
    assert summary['counts']['retired']==1
    event=next(change for change in summary['changes'] if change['action']=='retire')
    assert event['name']=='router.home.lan' and event['member_count']==2
    stale=item(old)['revision']
    third=add('router-alias.home.lan','10.0.0.2',NOW+1)
    refresh(NOW+2,[old,recent,third,work])
    row=item(old)
    assert row['member_count']==3 and row['state']=='retired'
    assert set(devices.snapshot(path,NOW)['retired'])=={old,recent,third}
    assert devices.lifecycle_summary(base,NOW+2)['counts']['added']==3  # Adding an alias is not a device arrival.
    try:
        devices.change(base,row['id'],'restore',stale,now=NOW+2)
        raise AssertionError('Changed cluster accepted stale confirmation')
    except ValueError:
        pass
    devices.change(base,row['id'],'restore',row['revision'],now=NOW+3)
    assert not devices.snapshot(path,NOW)['retired']
    refresh(NOW+4,[old,recent,third,work])
    assert item(old)['state']=='active'
    assert devices.lifecycle_summary(base,NOW+4)['counts']['restored']==1
    # A transient DNS outage leaves the prior verified relationship intact.
    devices.refresh(base,NOW+5,collection=healthy(NOW+5),dns_lookup=lambda *a,**kw:
        {'bindings':{},'conflicts':[],'checked_utc':NOW+5,'resolvers':['10.0.0.53'],
         'queries':1,'errors':['DNS unavailable'],'complete':False})
    assert item(old)['member_count']==3
    # Mixed manual/permanent states take the most restrictive state, never revive exclusions.
    row=item(old)
    devices.change(base,row['id'],'retire',row['revision'],now=NOW+6)
    devices.change(base,row['id'],'permanent',item(old)['revision'],now=NOW+7)
    fourth=add('router-new.home.lan','10.0.0.3',NOW+8)
    refresh(NOW+9,[old,recent,third,fourth,work])
    assert item(fourth)['state']=='permanent'
    assert set(devices.snapshot(path,NOW)['retired'])=={old,recent,third,fourth}
    assert devices.lifecycle_summary(base,NOW+9)['counts']['permanent']==1
    # Contradictory DNS detaches even the cluster representative; exclusions persist.
    representative=item(old)['id']
    rest=[key for key in (old,recent,third,fourth) if key!=representative]
    refresh(NOW+10,rest+[work],conflicts=[representative])
    assert item(representative)['member_count']==1 and item(representative)['dns_conflict']
    assert item(rest[0])['member_count']==3
    assert set(devices.snapshot(path,NOW)['retired'])=={old,recent,third,fourth}
    # A positively verified new canonical name replaces a stale link without erasing retirement.
    changed=result([rest[0]],NOW+11,canonical='different.home.lan')
    devices.refresh(base,NOW+11,collection=healthy(NOW+11),dns_lookup=lambda *a,**kw:changed)
    assert item(rest[0])['member_count']==1 and item(rest[0])['state']=='permanent'
    assert item(rest[0])['name']=='different.home.lan'
    assert devices.lifecycle_summary(base,NOW+11)['counts']['permanent']==1  # Later DNS changes cannot multiply an earlier physical-device action.

with tempfile.TemporaryDirectory() as folder:
    # Automatic retirement/restoration uses physical-device receive time, not per-alias clocks.
    base=Path(folder); history=base/'events.sqlite'; path=devices.database_path(base)
    devices.initialize(path)
    identities={}
    with closing(sqlite3.connect(history)) as db,db:
        db.execute('CREATE TABLE events(site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
    old=add('router.home.lan','10.0.0.1',NOW-30*DAY)
    recent=add('router','10.0.0.1',NOW-10*DAY)
    devices.refresh(base,NOW,verify_dns=True,dns_lookup=lambda *a,**kw:result([old,recent],NOW))
    assert item(old)['member_count']==2 and item(old)['state']=='active'
    assert not devices.snapshot(path,NOW)['retired']  # DNS-only refresh cannot authorize retirement.
    devices.refresh(base,NOW,collection=healthy(NOW),dns_lookup=lambda *a,**kw:result([old,recent],NOW))
    assert item(old)['state']=='retired'
    assert devices.lifecycle_summary(base,NOW)['counts']['retired']==1
    add('router','10.0.0.1',NOW+1)
    devices.refresh(base,NOW+2,verify_dns=True,dns_lookup=lambda *a,**kw:result([old,recent],NOW+2))
    assert item(old)['state']=='retired'  # DNS-only refresh cannot authorize restoration either.
    devices.refresh(base,NOW+2,collection=healthy(NOW+2),dns_lookup=lambda *a,**kw:result([old,recent],NOW+2))
    assert item(old)['state']=='active' and not devices.snapshot(path,NOW)['retired']
    assert devices.lifecycle_summary(base,NOW+2)['counts']['restored']==1
    # Existing baseline plus a new alias must not be reported as a newly added physical device.
    with closing(devices.connect(path,write=True)) as db,db:
        db.execute('UPDATE lifecycle SET added_utc=NULL WHERE device_id=?',(old,))
    assert devices.lifecycle_summary(base,NOW+2)['counts']['added']==0

with tempfile.TemporaryDirectory() as folder:
    base=Path(folder); history=base/'events.sqlite'; path=devices.database_path(base)
    devices.initialize(path); identities={}
    with closing(sqlite3.connect(history)) as db,db:
        db.execute('CREATE TABLE events(site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
    old=add('router.home.lan','10.0.0.1',NOW-20*DAY)
    devices.refresh(base,NOW,collection=healthy(NOW),dns_lookup=lambda *a,**kw:result([old],NOW))
    assert item(old)['state']=='retired'
    recent=add('router','10.0.0.1',NOW-60)
    devices.refresh(base,NOW+1,verify_dns=True,dns_lookup=lambda *a,**kw:result([old,recent],NOW+1))
    row=item(old)
    assert row['state']=='active' and row['partial_retirement'] and row['member_count']==2
    assert set(devices.snapshot(path,NOW)['retired'])=={old}
    with closing(devices.connect(path)) as db:
        assert db.execute('SELECT state FROM devices WHERE id=?',(recent,)).fetchone()[0]=='active'
    devices.refresh(base,NOW+2,collection=healthy(NOW+2),dns_lookup=lambda *a,**kw:result([old,recent],NOW+2))
    assert item(old)['state']=='active' and not item(old)['partial_retirement']
    assert not devices.snapshot(path,NOW)['retired']

print('PASS: DNS cluster display/actions, site/NAS isolation, receipt clocks, immutable IDs/history, exclusions, stale forms, single device-change counts, alias discovery, DNS outages and contradictions')
