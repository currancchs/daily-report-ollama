import copy
import importlib.util
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('report', ROOT / 'src/daily_report.py')
daily = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daily)


def group(site, priority, source, n):
    return {'id': site + '-' + str(priority) + '-' + source + '-' + str(n),
            'source': source, 'host': 'device', 'program': 'test', 'reported_level': 'error',
            'reported_priority': '', 'message': 'Example event', 'message_truncated': False, 'count': 1,
            'first': 1793370000, 'last': 1793370000, 'priority_hint': priority}


def report():
    result = {'sites': {}}
    for site in ('home', 'work'):
        groups = [group(site, priority, source, n) for priority in (3, 1, 0, 2)
                  for source in ('noisy', 'quiet') for n in range(5)]
        result['sites'][site] = dict(groups=groups, groups_total=len(groups), rows_not_grouped=0,
            assessments=[], ai_errors=[], batches_attempted=0, batches_completed=0,
            flagged_groups_total=sum(g['priority_hint'] < 3 for g in groups))
    return result


class Clock:
    value = 0

    def __call__(self):
        return self.value


def answers(batch):
    return [{'id': g['id'], 'classification': 'routine', 'severity': 'info',
             'summary': 'Synthetic fixture', 'suggested_check': ''} for g in batch]


# Full completion: priority order within each site, site alternation and source representation.
r = report()
clock = Clock()
calls = []


def successful(url, model, batch, timeout):
    priorities = {g['priority_hint'] for g in batch}
    calls.append((batch[0]['id'].split('-')[0], 1 if priorities <= {1, 2} else min(priorities), [g['source'] for g in batch], timeout))
    assert priorities in ({0}, {3}) or priorities <= {1, 2}
    clock.value += 2
    return answers(batch)


daily.analyze(r, 'http://test', 'mock', 180, caller=successful, max_runtime=120, clock=clock)
assert r['analysis_stop_reason'] == 'selected_groups_complete'
assert r['review_limited'] is False
assert all(len(d['assessments']) == d['groups_total'] for d in r['sites'].values())
assert [c[1] for c in calls] == sorted(c[1] for c in calls)
assert [c[0] for c in calls[:6]] == ['home', 'work'] * 3
assert calls[0][2] == ['noisy', 'quiet', 'noisy', 'quiet']

# Regression for the real run: a large home error queue must not delay work's
# few keyword flags until the deadline. Routine work waits behind flagged work.
imbalanced = {'sites': {}}
for site, groups in (
        ('home', [group('home', 1, 'noisy', n) for n in range(1600)]),
        ('work', [group('work', 0, 'quiet', n) for n in range(6)] +
                 [group('work', 2, 'quiet', n) for n in range(2)] +
                 [group('work', 3, 'routine', n) for n in range(100)])):
    imbalanced['sites'][site] = dict(groups=groups, groups_total=len(groups), rows_not_grouped=0,
        assessments=[], ai_errors=[], batches_attempted=0, batches_completed=0,
        flagged_groups_total=sum(g['priority_hint'] < 3 for g in groups))
clock.value = 0
calls.clear()
daily.analyze(imbalanced, 'http://test', 'mock', 180, caller=successful, max_runtime=12, clock=clock)
assert len(imbalanced['sites']['work']['assessments']) == 8
assert daily.review_summary(imbalanced)['work']['flagged_groups_unreviewed'] == 0
assert all(priority < 3 for _, priority, _, _ in calls)
assert len(imbalanced['sites']['home']['assessments']) == 12

# Deadline stops further calls, retains completed evidence and is not called an AI outage.
r = report()
clock.value = 0
calls.clear()
daily.analyze(r, 'http://test', 'mock', 180, caller=successful, max_runtime=8, clock=clock)
assert len(calls) == 4 and calls[-1][3] == 2
assert r['analysis_stop_reason'] == 'time_budget' and r['review_limited']
assert all(len(d['assessments']) == 8 and d['review_limit_notes'] for d in r['sites'].values())
assert all(not d['ai_errors'] for d in r['sites'].values())
assert all(d['time_limit_reached'] and d['groups_unreviewed'] == 32 for d in daily.review_summary(r).values())

# Home errors cannot suppress work's entire review, and invalid AI answers are never accepted.
r = report()
clock.value = 0


def broken_home(url, model, batch, timeout):
    clock.value += 1
    if batch[0]['id'].startswith('home-'):
        return []
    return answers(batch)


daily.analyze(r, 'http://test', 'mock', 180, caller=broken_home, max_runtime=120, clock=clock)
assert not r['sites']['home']['assessments'] and r['sites']['home']['ai_errors']
assert len(r['sites']['work']['assessments']) == 40
assert r['analysis_stop_reason'] == 'ai_error'

# A request running into the time limit preserves other completed batches.
r = report()
clock.value = 0


def deadline_timeout(url, model, batch, timeout):
    clock.value += timeout
    raise TimeoutError('Synthetic deadline')


daily.analyze(r, 'http://test', 'mock', 180, caller=deadline_timeout, max_runtime=5, clock=clock)
assert r['analysis_stop_reason'] == 'time_budget'
assert all(d['review_limit_notes'] and not d['ai_errors'] for d in r['sites'].values())

# No remaining analysis budget makes no model request; even unflagged omitted groups are disclosed.
r = report()
daily.analyze(r, 'http://test', 'mock', 180, caller=lambda *a: (_ for _ in ()).throw(AssertionError()), max_runtime=0)
assert r['analysis_stop_reason'] == 'time_budget'
r = report()
for data in r['sites'].values():
    data['groups_total'] += 10
clock.value = 0
daily.analyze(r, 'http://test', 'mock', 180, caller=successful, max_runtime=120, clock=clock)
assert r['review_limited'] and all(d['groups_unreviewed'] == 10 for d in daily.review_summary(r).values())

# The daily runner's 45-minute build budget subtracts collection/aggregation time and reserves output time.
job_spec = importlib.util.spec_from_file_location('job', ROOT / 'src/daily_job.py')
job = importlib.util.module_from_spec(job_spec)
job_spec.loader.exec_module(job)
assert job.GROUP_CAP_PER_SITE == daily.DEFAULT_GROUP_BUDGET == 2000
assert job.BUILD_LIMIT_SECONDS == daily.DEFAULT_ANALYSIS_SECONDS == 2700 and job.FINALIZE_RESERVE_SECONDS == 60
assert 'TimeoutStartSec=45min' in (ROOT / 'systemd/ai-monitor-build.service').read_text()
print('PASS: severity within each site; cross-site flagged fairness; actual imbalanced-queue regression; routine work after flagged work; source balancing; validated completion; deadline and partial evidence; per-site failure isolation; truthful review-limit counts; 2000/site and 45-minute build settings. No network calls.')
