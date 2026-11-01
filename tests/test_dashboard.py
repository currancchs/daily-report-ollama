"""Offline dashboard verification. No NAS, Ollama, SMTP or service calls."""
from datetime import date, datetime, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent.parent/'src'
def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value

p=module('publish_report');dash=module('dashboard');job=p.load_job()
NOW=int(datetime(2026,11,1,5,10,tzinfo=p.ZONE).timestamp())
DAY=date(2026,11,1)

def fixture(base, day=DAY, partial=True):
    generated=int(datetime.combine(day,datetime.min.time(),p.ZONE).replace(hour=4,minute=35).timestamp())
    start,end=job.window_for(day)
    report=dict(report_kind='daily',report_date=day.isoformat(),status='daily_complete',
                generated_utc=job.iso(generated),window_start=start,window_end_exclusive=end,
                model='example-model',review_limited=partial,sites={})
    for site in ('home','work'):
        group=dict(id=site+'-1',source='example-router',host='example-router',count=120,
                   first=end-3600,last=end-60,priority_hint=1,example_message='Example connection warning')
        assessment=dict(id=group['id'],classification='issue',severity='warning',
                        summary='Example connection warning',suggested_check='Inspect connection history')
        report['sites'][site]=dict(groups=[group],assessments=[assessment],groups_total=5 if partial else 1,
            rows_in_window=200 if partial else 120,rows_scanned=200 if partial else 120,rows_not_grouped=0,
            sources={'example-router':dict(records=200 if partial else 120,groups_total=5 if partial else 1,
                last_record=end-60,exported_utc=end+600,warnings=[])},warnings=[],ai_errors=[],flagged_groups_total=1)
    folder=base/'daily'/day.isoformat();folder.mkdir(parents=True,exist_ok=True)
    def write_report():
        (folder/'report.json').write_text(json.dumps(report),encoding='utf-8')
        (folder/'report.txt').write_text('HOME + WORK\nGenerated: '+report['generated_utc']+'\n',encoding='utf-8')
        (folder/'report.html').write_text('<script>UNSAFE_SAVED_HTML</script>',encoding='utf-8')
        state=dict(producer=job.PRODUCER,report_date=day.isoformat(),phase='ready',
                   started_utc=job.iso(generated-1800),completed_utc=job.iso(generated),
                   report_status='daily_complete',review_limited=partial,
                   sha256={name:hashlib.sha256((folder/name).read_bytes()).hexdigest()
                           for name in ('report.txt','report.json','report.html')})
        (folder/'state.json').write_text(json.dumps(state))
        return state
    state=write_report()
    return folder,state,report,write_report

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name);self.base=self.root/'private';self.base.mkdir()
        self.public=self.root/'public';self.public.mkdir()
        self.network=patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('No network allowed'))
        self.smtp=patch('smtplib.SMTP_SSL',side_effect=AssertionError('No email allowed'))
        self.network.start();self.smtp.start()
    def tearDown(self):
        self.smtp.stop();self.network.stop();self.temporary.cleanup()
    def publish(self,now=NOW):
        return p.publish(self.base,self.public,now)
    def page(self):
        return (self.public/'index.html').read_text(encoding='utf-8')
    def test_history_and_coverage(self):
        fixture(self.base);fixture(self.base,DAY-timedelta(days=3),False)
        result=self.publish()
        self.assertEqual(result['history_reports'],2)
        self.assertIn('Partial AI review',self.page())
        self.assertIn('1 / 5 groups',self.page())
        self.assertIn('2026-10-29.html',self.page())
        self.assertIn('Archived report',(self.public/'history/2026-10-29.html').read_text())
        self.assertNotIn('UNSAFE_SAVED_HTML',(self.public/'report.html').read_text())
        self.assertEqual({f.suffix for f in self.public.rglob('*') if f.is_file()},{'.html'})
    def test_publication_with_special_permission_changes_blocked(self):
        fixture(self.base)
        original_mkdir=p.os.mkdir
        original_chmod=p.os.chmod
        def guarded_mkdir(path,mode=0o777,*args,**kwargs):
            if mode & 0o6000:
                raise PermissionError('Service forbids setting SUID/SGID bits')
            return original_mkdir(path,mode,*args,**kwargs)
        def guarded_chmod(path,mode,*args,**kwargs):
            if mode & 0o6000:
                raise PermissionError('Service forbids setting SUID/SGID bits')
            return original_chmod(path,mode,*args,**kwargs)
        with patch.object(p.os,'mkdir',side_effect=guarded_mkdir), \
             patch.object(p.os,'chmod',side_effect=guarded_chmod):
            for attempt in range(2):
                result=self.publish()
                self.assertEqual(result['status'],'published')
                self.assertEqual(result['history_reports'],1)
                self.assertIn('Nightly overview',self.page())
    def test_corrupt_and_missing_never_reuse_old_report(self):
        folder,_,_,_=fixture(self.base);self.publish()
        (folder/'report.json').write_text('{}')
        self.assertEqual(self.publish()['status'],'verification_failed')
        self.assertIn('could not be verified',self.page())
        self.assertNotIn('Example connection warning',(self.public/'report.html').read_text())
        self.assertFalse((self.public/'history/2026-11-01.html').exists())
        self.assertEqual(self.publish(NOW+86400)['status'],'not_ready')
    def test_injection_and_redaction(self):
        folder,state,report,write=fixture(self.base)
        report['sites']['home']['assessments'][0]['summary']='<script>bad()</script> password=VERY_SECRET'
        report['sites']['home']['sources']['<img onerror=bad()>']=dict(records=0,groups_total=0,last_record=None,warnings=[])
        report['sites']['home']['sources']['password=SOURCE_SECRET']=dict(records=0,groups_total=0,last_record=None,warnings=[])
        write();self.publish()
        pages=''.join(f.read_text(encoding='utf-8') for f in self.public.rglob('*.html'))
        self.assertNotIn('VERY_SECRET',pages);self.assertNotIn('<script>',pages)
        self.assertNotIn('SOURCE_SECRET',pages)
        self.assertNotIn('<img onerror',pages);self.assertIn('&lt;img',pages)
        self.assertNotIn('1969',pages)
    def test_missing_site_is_unknown_not_healthy(self):
        _,_,report,write=fixture(self.base);report['sites'].pop('work');write();self.publish()
        self.assertIn('No AI review',self.page());self.assertIn('Limited data',self.page())
    def test_site_warning_does_not_mark_other_site_incomplete(self):
        _,_,report,_=fixture(self.base,partial=False)
        report['pipeline_warnings']=['home: NAS export began before the cutoff']
        sites=dash.summarize(report)
        self.assertTrue(sites['home']['data_limited'])
        self.assertFalse(sites['work']['data_limited'])
    def test_dst_boundary(self):
        early=int(datetime(2026,11,1,3,59,tzinfo=p.ZONE).timestamp())
        self.assertEqual(p.expected_day(early),date(2026,10,31))
        fixture(self.base,date(2026,10,31))
        self.assertEqual(self.publish(early)['status'],'published')
        self.assertEqual(self.publish(early+60)['status'],'not_ready')
        self.assertEqual((job.window_for(DAY)[1]-job.window_for(DAY)[0])/3600,25)
    def test_progress_and_overdue(self):
        folder,state,_,_=fixture(self.base)
        state.update(phase='building',started_utc=job.iso(NOW-900));state.pop('completed_utc')
        (folder/'state.json').write_text(json.dumps(state))
        tracker=job.dashboard_progress.Tracker(folder,state['started_utc'],clock=lambda:NOW-30)
        tracker.stage('analyzing')
        tracker.value['sites']={'home':dict(groups_reviewed=6,groups_total=100,records=4000)}
        tracker.stage('analyzing')
        self.assertEqual(self.publish()['status'],'building')
        self.assertIn('6 / 100 groups reviewed',self.page())
        self.assertEqual(self.publish(NOW+3000)['status'],'overdue')
    def test_old_progress_ignored_and_partial_collection_visible(self):
        folder,state,_,_=fixture(self.base)
        tracker=job.dashboard_progress.Tracker(folder,'old-build',clock=lambda:NOW)
        tracker.stage('collecting');tracker.stage('analyzing')
        self.publish();self.assertIn('No stage record',self.page())
        tracker.value['started_utc']=state['started_utc']
        tracker.value['exports']={'home':dict(collection_status='partial')}
        tracker.stage('complete');self.publish()
        self.assertIn('Collected with warnings',self.page())
    def test_publication_stops_on_symlink(self):
        fixture(self.base)
        try:
            (self.public/'history').symlink_to(self.base,target_is_directory=True)
        except OSError:
            self.skipTest('Symlink privilege unavailable on this host')
        with self.assertRaises(ValueError):self.publish()
    def test_progress_failure_does_not_abort_analysis(self):
        _,_,report,_=fixture(self.base)
        for data in report['sites'].values():
            data.update(batches_attempted=0,batches_completed=0,assessments=[])
            for group in data['groups']:
                group.update(program='example',reported_level='info',reported_priority='info',
                             message='Example routine message',message_truncated=False)
        def answers(url,model,batch,timeout):
            return [dict(id=g['id'],classification='routine',severity='info',
                         summary='Example routine message',suggested_check='') for g in batch]
        def broken_progress(report):
            raise OSError('Example status disk failure')
        job.daily.analyze(report,'http://example.invalid','example',10,
                          caller=answers,progress=broken_progress,max_runtime=30)
        self.assertEqual(report['analysis_stop_reason'],'selected_groups_complete')
        self.assertTrue(all(len(s['assessments'])==1 for s in report['sites'].values()))

if __name__=='__main__':unittest.main()
