"""Bounded, read-only readiness checks for the local suppression service."""
import argparse
from pathlib import Path
import runpy
import time
from urllib.parse import urlsplit
import urllib.error
import urllib.request


settings = runpy.run_path(str(Path(__file__).with_name('settings.py')))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def wait_for_controls(origin, viewer_origin, label, *, seconds=25, opener=None,
                      clock=time.monotonic, sleep=time.sleep):
    """Wait for the real filters page, including after an asynchronous reload."""
    origin = settings['local_url'](origin, 'readiness target')
    host = urlsplit(settings['local_url'](viewer_origin, 'viewer')).netloc
    if not 0 < seconds <= 30:
        raise ValueError('Unexpected readiness time limit')
    if opener is None:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(
        origin + '/controls/filters',
        headers={'Host': host, 'Connection': 'close'},
        method='GET')
    deadline = clock() + seconds
    attempts = 0
    last = 'no response'
    while clock() < deadline:
        attempts += 1
        try:
            with opener.open(request, timeout=min(3, deadline - clock())) as response:
                status = response.getcode()
                body = response.read(131072)
                if status == 200 and b'<title>Suppression filters' in body:
                    print('%s ready (HTTP 200, filters page verified; %d check%s).' %
                          (label, attempts, '' if attempts == 1 else 's'), flush=True)
                    return attempts
                last = 'HTTP %s%s' % (
                    status, ', expected filters page missing' if status == 200 else '')
        except urllib.error.HTTPError as error:
            last = 'HTTP %s' % error.code
            error.close()
        except (urllib.error.URLError, OSError) as error:
            # Do not print response bodies or potentially sensitive error details.
            last = 'connection unavailable (%s)' % type(error).__name__
        remaining = deadline - clock()
        if remaining > 0:
            sleep(min(1, remaining))
    raise RuntimeError('%s did not become ready within %ss (%s, %d checks)' %
                       (label, seconds, last, attempts))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=('backend', 'viewer'), required=True)
    args = parser.parse_args()
    viewer = settings['load']()['viewer_origin']
    origin = 'http://127.0.0.1:8767' if args.target == 'backend' else viewer
    wait_for_controls(origin, viewer, 'Suppression ' + args.target)
