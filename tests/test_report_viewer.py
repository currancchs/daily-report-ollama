from datetime import date, datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('publisher', ROOT/'src/publish_report.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
job = p.load_job()
NOW = int(datetime(2026, 10, 31, 5, tzinfo=p.ZONE).timestamp())


def ready(base, day, generated):
    folder = base/'daily'/day.isoformat()
    folder.mkdir(parents=True, exist_ok=True)
    report = json.loads((ROOT/'examples/nightly-report-example.json').read_text())
    report.update(report_date=day.isoformat(), generated_utc=job.iso(generated),
                  window_start=job.window_for(day)[0], window_end_exclusive=job.window_for(day)[1])
    report['sites']['home']['assessments'][0]['summary'] = '<script>bad()</script> password=hidden-secret'
    (folder/'report.json').write_text(json.dumps(report), encoding='utf-8')
    (folder/'report.txt').write_text('HOME + WORK\nGenerated: '+report['generated_utc']+'\npassword=private-text', encoding='utf-8')
    # Even saved HTML with a valid hash must be regenerated, not directly served.
    (folder/'report.html').write_text('<script>unsafe_saved_html()</script>', encoding='utf-8')
    state = {'producer':job.PRODUCER, 'report_date':day.isoformat(), 'phase':'ready',
             'sha256':{name:hashlib.sha256((folder/name).read_bytes()).hexdigest()
                       for name in ('report.txt','report.json','report.html')}}
    (folder/'state.json').write_text(json.dumps(state))
    return folder, state


with tempfile.TemporaryDirectory() as temporary:
    base=Path(temporary)/'private'; base.mkdir()
    public=Path(temporary)/'public'; public.mkdir()
    with patch('smtplib.SMTP_SSL', side_effect=AssertionError('No email allowed')), \
         patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('No network allowed')):
        result=p.publish(base,public,NOW)
        assert result['status']=='not_ready'
        folder,state=ready(base,date(2026,10,31),NOW-1200)
        result=p.publish(base,public,NOW)
        page=(public/'report.html').read_text(encoding='utf-8')
        assert result['status']=='published'
        assert 'Verified publication' in page and '2026-10-31' in page
        assert 'hidden-secret' not in page and 'private-text' not in page
        assert '<script>' not in page and 'unsafe_saved_html' not in page
        assert '&lt;script&gt;' in page
        dashboard=(public/'index.html').read_text(encoding='utf-8')
        assert 'Coverage needs attention' in dashboard and 'unreviewed' in dashboard.lower()
        assert {x.name for x in public.iterdir()}=={'index.html','report.html','history'}
        assert {x.name for x in (public/'history').iterdir()}=={'2026-10-31.html'}

        # Corruption replaces the formerly valid page with an honest placeholder.
        (folder/'report.json').write_text('{}')
        assert p.publish(base,public,NOW)['status']=='verification_failed'
        page=(public/'report.html').read_text()
        assert 'Device health is unknown' in page and 'finding' not in page
        assert 'hidden-secret' not in page

        folder,state=ready(base,date(2026,10,31),NOW-1200)
        state.update(phase='failed',error='password=do-not-publish')
        (folder/'state.json').write_text(json.dumps(state))
        assert p.publish(base,public,NOW)['status']=='build_failed'
        assert 'do-not-publish' not in (public/'index.html').read_text()

        state.update(phase='building',started_utc=job.iso(NOW-600))
        (folder/'state.json').write_text(json.dumps(state))
        assert p.publish(base,public,NOW)['status']=='building'
        assert p.publish(base,public,NOW+3000)['status']=='overdue'

        # Before 4 a.m. the prior day's digest remains expected, including DST.
        early=int(datetime(2026,11,1,3,59,tzinfo=p.ZONE).timestamp())
        assert p.expected_day(early)==date(2026,10,31)
        ready(base,date(2026,10,31),NOW)
        assert p.publish(base,public,early)['status']=='published'
        due=int(datetime(2026,11,1,4,tzinfo=p.ZONE).timestamp())
        assert p.expected_day(due)==date(2026,11,1)
        assert p.publish(base,public,due)['status']=='not_ready'
        assert '2026-11-01' in (public/'index.html').read_text()

        # Failed dependency loading also replaces any old publication.
        with patch.object(p,'load_job',side_effect=ImportError('password=dependency-secret')):
            assert p.publish(base,public,NOW)['status']=='component_unavailable'
        assert 'dependency-secret' not in (public/'index.html').read_text()

        # Concurrent rebuilding is detected before a report can be published.
        folder,state=ready(base,date(2026,10,31),NOW-1200)
        original=job.verify_ready
        calls=[]
        def changing(*args):
            result=original(*args)
            calls.append(1)
            if len(calls)==1:
                state.update(phase='building',started_utc=job.iso(NOW))
                (folder/'state.json').write_text(json.dumps(state))
            return result
        with patch.object(p,'load_job',return_value=job), patch.object(job,'verify_ready',side_effect=changing):
            assert p.publish(base,public,NOW)['status']=='verification_failed'

print('PASS: verified publication, redaction, HTML escaping, failure/stale states, DST boundary, concurrent rebuild, no network/email, only dashboard/current report/verified dated HTML published')
