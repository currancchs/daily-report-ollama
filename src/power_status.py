#!/usr/bin/env python3
"""Read-only, signed report completion endpoint for the Ollama PC. No shutdown API."""
import argparse
from datetime import datetime
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
from pathlib import Path
import re
import time
from urllib.parse import parse_qs, urlsplit
from zoneinfo import ZoneInfo

SPEC = importlib.util.spec_from_file_location('power_daily_job', Path(__file__).with_name('daily_job.py'))
job = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(job)
ZONE = job.ZONE


def completion(base, now=None):
    now = int(time.time() if now is None else now)
    local = datetime.fromtimestamp(now, ZONE)
    result = dict(version=1, issued_utc=now, report_date=local.date().isoformat(),
                  ready=False, reason='outside_shutdown_window', started_utc=0, completed_utc=0)
    # A late manual build must not cause an unexpected daytime shutdown.
    if not 4 <= local.hour < 6:
        return result
    try:
        folder = Path(base) / 'daily' / result['report_date']
        # Do not contend with the scheduled build's initial lock acquisition.
        # Only a report that already claims readiness needs verification.
        if job.read(folder / 'state.json').get('phase') != 'ready':
            raise ValueError('Report is not ready')
        # The existing job takes this lock for its complete build. Merely seeing
        # an older ready file while a forced rebuild is active is insufficient.
        with job.lock(Path(base) / 'daily' / '.build.lock'):
            state, metadata = job.verify_ready(folder, local.date(), now)
            started = job.stamp(state['started_utc'])
            finished = job.stamp(state['completed_utc'])
            if not 0 <= now - finished <= 7200 or not 0 < finished - started <= 3600:
                raise ValueError('Report times are not recent and ordered')
            if datetime.fromtimestamp(started, ZONE).date() != local.date():
                raise ValueError('Build was not started today')
            # A failed/offline model should leave the PC available for diagnosis.
            if metadata.get('model') != job.MODEL or metadata.get('ollama_url') != job.OLLAMA:
                raise ValueError('Report did not use the configured Ollama server')
            if metadata.get('analysis_stop_reason') not in ('selected_groups_complete', 'time_budget'):
                raise ValueError('AI review did not finish normally')
            if set(metadata['sites']) != {'home', 'work'}:
                raise ValueError('Both sites must be present in the report')
            if any(site.get('ai_errors') for site in metadata['sites'].values()):
                raise ValueError('AI review contains errors')
            result.update(ready=True, reason='report_ready', started_utc=started, completed_utc=finished)
    except Exception:
        result['reason'] = 'report_not_verified_or_build_running'
    return result


def signed_envelope(payload, key, nonce):
    data = dict(payload, nonce=nonce)
    # Sign this exact UTF-8 string. Windows verifies it before parsing any fields.
    encoded = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    signature = hmac.new(key, encoded.encode('utf-8'), hashlib.sha256).hexdigest()
    return dict(payload=encoded, signature=signature)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # No per-minute log noise, query strings or credentials in the journal.

    def do_GET(self):
        if self.client_address[0] != self.server.allowed_client:
            self.send_error(403)
            return
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        nonce = query.get('nonce', [''])[0]
        if (parsed.path != '/completion' or set(query) != {'nonce'} or
                len(query['nonce']) != 1 or not re.fullmatch('[0-9a-f]{64}', nonce)):
            self.send_error(400)
            return
        body = json.dumps(signed_envelope(completion(self.server.base), self.server.key, nonce)).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, default=Path('/var/lib/ai-monitor'))
    parser.add_argument('--key', type=Path, default=Path('/etc/ai-monitor/power.key'))
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8766)
    parser.add_argument('--client', default='127.0.0.1')
    args = parser.parse_args()
    key_text = args.key.read_text().strip()
    if not re.fullmatch('[0-9a-fA-F]{64}', key_text):
        raise ValueError('Power pairing key must be 32 bytes encoded as hexadecimal')
    server = Server((args.bind, args.port), Handler)
    server.base, server.key, server.allowed_client = args.base, bytes.fromhex(key_text), args.client
    print('Read-only power status ready; allowed client ' + args.client, flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
