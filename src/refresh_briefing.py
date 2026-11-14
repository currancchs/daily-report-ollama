#!/usr/bin/env python3
"""Refresh only today's opening briefing using saved evidence; never sends mail."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import time

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('briefing_job',HERE/'daily_job.py')
job=importlib.util.module_from_spec(spec); spec.loader.exec_module(job)

def refresh(base, timeout=90):
    now=int(time.time()); base=Path(base); day=job.report_day(now)
    folder=job.folder_for(base,day)
    with job.lock(base/'daily/.build.lock'), job.lock(base/'daily/.delivery.lock'):
        state, report=job.verify_ready(folder,day,now)
        backup_root=base/'reports'/'briefing-backups'
        backup_root.mkdir(parents=True,exist_ok=True,mode=0o700)
        backup=Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-'),dir=backup_root))
        names=('report.json','report.txt','report.html','state.json')
        for name in names:
            if (folder/name).is_file(): shutil.copy2(folder/name,backup/name)
        try:
            report['pipeline_issue']=bool(report.get('pipeline_warnings')) or set(report.get('sites',{}))!={'home','work'} or any(
                data.get('ai_errors') or data.get('warnings') or data.get('rows_not_grouped') or
                any(source.get('warnings') for source in data.get('sources',{}).values())
                for data in report.get('sites',{}).values())
            report['device_lifecycle']=job.daily.devices.lifecycle_summary(base,now)
            report['executive_summary']=job.summary.build_summary(report,base,job.OLLAMA,job.MODEL,timeout=timeout)
            report['briefing_updated_utc']=job.iso(time.time())
            report=job.daily.core.privacy.record(report)
            job.save(folder/'report.json',report)
            job.daily.core.save_atomic(folder/'report.txt',job.daily.render(report,job.ZONE))
            job.mail.html_report.save(folder/'report.html',job.mail.html_report.render(report))
            state['sha256']={name:job.digest(folder/name) for name in names if name!='state.json'}
            state['pipeline_issue']=report['pipeline_issue']
            state['briefing_updated_utc']=report['briefing_updated_utc']
            job.save(folder/'state.json',state)
            job.verify_ready(folder,day,now)
        except Exception:
            for name in names:
                if (backup/name).is_file(): shutil.copy2(backup/name,folder/name)
            raise
    return {'date':day.isoformat(),'summary_status':report['executive_summary']['status'],
            'items':len(report['executive_summary'].get('items',[])),
            'pipeline_issue':report['pipeline_issue'],'backup':str(backup),'email_sent':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir',type=Path,default=Path('/var/lib/ai-monitor'))
    parser.add_argument('--timeout',type=int,default=90)
    args=parser.parse_args()
    if not 0<=args.timeout<=90: parser.error('Timeout must be 0 through 90 seconds')
    print(json.dumps(refresh(args.data_dir,args.timeout)))
