"""Offline boundary and aggregation checks; no network, AI, or email."""
import importlib.util
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent/'src'
spec = importlib.util.spec_from_file_location('work_daily', ROOT / 'daily_report.py')
daily = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daily)
CONFIG = 'INFO:2026-10-31 20:54:50,617:hass_configurator.configurator:127.0.0.1 - "GET / HTTP/1.1" 200 -'
HEAD = 'INFO  [kea-dhcp4.leases.0x432ad6c79810] '
CLIENT = ' [hwtype=1 02:00:00:00:00:01], cid=[01:02:00:00:00:00:01], tid=0xe77dac60: '
LEASE = HEAD + 'DHCP4_LEASE_REUSE' + CLIENT + 'lease 192.0.2.2 has been reused for 6389 seconds'
NOW = 1793494502


def roll(message, prog='kea-dhcp4', level='info'):
    return daily.family_rollup(dict(prog=prog, llevel=level), message)


class WorkRules(unittest.TestCase):
    def test_configurator_timestamp_only(self):
        first = roll(CONFIG, 'app_core_configurator')
        second = roll(CONFIG.replace('20:54:50,617', '21:00:00,001'), 'app_core_configurator')
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], 'configurator_local_http200')
        self.assertEqual(first[2], {'log_timestamp': '2026-10-31 20:54:50,617'})
        self.assertIn(first[1], daily.ROLLUP_NOTES)

    def test_configurator_other_requests_and_errors_remain(self):
        for old, new in [('GET / ', 'GET /api/ '), ('GET / ', 'POST / '),
                         (' 200 ', ' 401 '), (' 200 ', ' 500 '),
                         ('127.0.0.1', '192.0.2.10'), ('INFO:', 'ERROR:'),
                         ('2026-10-31', '2026-02-31')]:
            value = CONFIG.replace(old, new)
            self.assertEqual(roll(value, 'app_core_configurator'), (value, '', {}))
        for value in [CONFIG + ' denied', CONFIG + '\nextra', CONFIG.replace('HTTP/1.1', 'HTTP/2')]:
            self.assertEqual(roll(value, 'app_core_configurator'), (value, '', {}))
        for program, level in [('other', 'info'), ('app_core_configurator', 'warning')]:
            self.assertEqual(roll(CONFIG, program, level), (CONFIG, '', {}))

    def test_short_kea_volatility_and_evidence(self):
        first = roll(LEASE)
        second = roll(LEASE.replace('0x432ad6c79810', '0xabcd').replace('0xe77dac60', '0x123').replace('6389', '6000'))
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], 'kea_dhcp4_info')
        self.assertEqual(set(first[2]), {'thread_id', 'transaction_id', 'remaining_lease_seconds'})
        self.assertTrue(first[0].startswith('INFO [kea-dhcp4.leases.<varies>]'))

    def test_short_kea_identity_and_duration_preserved(self):
        first = roll(LEASE)[0]
        for old, new in [('02:00:00:00:00:01', '02:00:00:00:00:02'),
                         ('cid=[01:', 'cid=[02:'), ('192.0.2.2', '192.0.2.3'),
                         ('kea-dhcp4.leases.', 'kea-dhcp4.other.')]:
            self.assertNotEqual(first, roll(LEASE.replace(old, new))[0])
        alloc = HEAD + 'DHCP4_LEASE_ALLOC' + CLIENT + 'lease 192.0.2.2 has been allocated for 7200 seconds'
        self.assertNotEqual(roll(alloc)[0], roll(alloc.replace('7200', '3600'))[0])
        for event, detail in [('DHCP4_INIT_REBOOT', 'client is in INIT-REBOOT state and requests address 192.0.2.2'),
                              ('DHCP4_LEASE_OFFER', 'lease 192.0.2.2 will be offered')]:
            self.assertEqual(roll(HEAD + event + CLIENT + detail)[1], 'kea_dhcp4_info')

    def test_short_kea_unknown_formats_and_failures_remain(self):
        for value in [LEASE.replace('INFO', 'ERROR'), LEASE.replace('LEASE_REUSE', 'LEASE_FAILED'),
                      LEASE + ' failure', LEASE.replace('192.0.2.2', '999.0.0.1'),
                      LEASE.replace('tid=0xe77dac60', 'tid=unknown'), LEASE.replace('kea-dhcp4', 'unknown')]:
            self.assertEqual(roll(value), (value, '', {}))
        for program, level in [('1', 'info'), ('other', 'info'), ('kea-dhcp4', 'warning'), ('kea-dhcp4', '')]:
            self.assertEqual(roll(LEASE, program, level), (LEASE, '', {}))

    def test_integration_counts_identity_flags_and_packet_budget(self):
        with tempfile.TemporaryDirectory(prefix='work-grouping-test-') as name:
            base = Path(name)
            history = base / 'events.sqlite'
            rows = []
            def add(message, source='HA', site='work', level='info', host='ha', program='app_core_configurator'):
                n = len(rows)
                raw = dict(host=host, ip='192.0.2.10', prog=program, llevel=level,
                           prio=6 if level == 'info' else 3, tag='logs', msg=message)
                rows.append((str(n), site, source, NOW-100+n, NOW-100+n, NOW, json.dumps(raw)))
            for second in range(20):
                add(CONFIG.replace('20:54:50,617', '20:54:%02d,617' % second))
            add(CONFIG, source='HA-other')
            add(CONFIG, host='ha-other')
            add(CONFIG, level='error')
            add(CONFIG, site='home')
            for n in range(5):
                add(LEASE.replace('0xe77dac60', '0x%x' % n), source='FW', host='fw', program='kea-dhcp4')
            with closing(sqlite3.connect(history)) as db:
                db.execute('CREATE TABLE events(fingerprint TEXT PRIMARY KEY,site TEXT,source TEXT,utcsec INTEGER,r_utcsec INTEGER,first_seen_utc INTEGER,raw_json TEXT)')
                db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)', rows)
                db.commit()
            before = history.read_bytes()
            registry = {'format_version': 1, 'sites': {
                site: {'status': 'complete', 'warnings': [], 'sources': {
                    source: {'exported_utc': NOW, 'warnings': []} for source in ('HA', 'HA-other', 'FW')}}
                for site in ('home', 'work')}}
            report = daily.collect(history, base, now=NOW, registry=registry, window=(NOW-200, NOW+1))
            work = report['sites']['work']
            self.assertEqual(work['rows_scanned'], 28)
            self.assertEqual(work['grouped_records'], 28)
            self.assertEqual(work['groups_total'], 5)
            self.assertEqual(work['flagged_groups_total'], 1)
            group = next(g for g in work['groups'] if g['count'] == 20)
            self.assertEqual(group['first'], NOW-100)
            self.assertEqual(group['last'], NOW-81)
            self.assertEqual(group['message_variants'], 20)
            self.assertEqual(group['varied_fields']['log_timestamp']['distinct'], 20)
            self.assertEqual(len(group['varied_fields']['log_timestamp']['examples']), 3)
            self.assertIn('20:54:19,617', group['example_message'])
            self.assertEqual(report['sites']['home']['groups_total'], 1)
            self.assertEqual(history.read_bytes(), before)
            for data in report['sites'].values():
                for batch in daily.core.batches(data['groups']):
                    self.assertTrue(daily.core.fits(batch))


if __name__ == '__main__':
    unittest.main()
