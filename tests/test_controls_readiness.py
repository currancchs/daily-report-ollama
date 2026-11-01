"""Offline readiness regressions; never calls the NAS, LXC, or model."""
import importlib.util
import io
from pathlib import Path
import urllib.error
import urllib.request

root = Path(__file__).resolve().parent
helper = root.parent / 'src/controls_readiness.py'
spec = importlib.util.spec_from_file_location('deployment_probe', helper)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Clock:
    now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Response(io.BytesIO):
    def getcode(self):
        return 200


class Opener:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, int):
            raise urllib.error.HTTPError(request.full_url, reply, 'test', {}, io.BytesIO())
        if isinstance(reply, Exception):
            raise reply
        return Response(reply)


page = b'<!doctype html><html><title>Suppression filters &middot; Nightly AI Logs</title>'
clock = Clock()
opener = Opener(urllib.error.URLError('refused'), 404, 502, page)
assert probe.wait_for_controls('http://127.0.0.1:8088', 'http://127.0.0.1:8088', 'Reload regression', seconds=5, opener=opener,
                               clock=clock, sleep=clock.sleep) == 4
assert clock.now == 3
for request, timeout in opener.calls:
    assert request.full_url == 'http://127.0.0.1:8088/controls/filters'
    assert request.get_method() == 'GET'
    assert request.get_header('Host') == '127.0.0.1:8088'
    assert request.get_header('Connection') == 'close'
    assert 0 < timeout <= 3

for reply, expected in [(404, 'HTTP 404'), (301, 'HTTP 301'),
                        (b'<title>Old dashboard</title>', 'expected filters page missing')]:
    clock = Clock()
    opener = Opener(reply)
    try:
        probe.wait_for_controls('http://127.0.0.1:8088', 'http://127.0.0.1:8088', 'Failure regression', seconds=3,
                                opener=opener, clock=clock, sleep=clock.sleep)
    except RuntimeError as error:
        assert expected in str(error)
    else:
        raise AssertionError('Persistent unhealthy route must stop installation')
    assert clock.now == 3 and len(opener.calls) == 3

assert probe.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://example.invalid/') is None
for origin in ('http://example.com', 'http://8.8.8.8', 'http://127.0.0.1/unexpected', 'http://0.0.0.0'):
    try:
        probe.wait_for_controls(origin, 'http://127.0.0.1:8088', 'Invalid target')
    except ValueError:
        pass
    else:
        raise AssertionError('Unexpected target accepted')
print('PASS: reload/startup recovery, bounded failure, exact page check, local-only GET and no redirects')
