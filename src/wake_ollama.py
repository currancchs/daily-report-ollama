#!/usr/bin/env python3
"""Send Wake-on-LAN to the Ollama PC and optionally check its API."""
import argparse
import importlib.util
from datetime import datetime
import json
import os
from pathlib import Path
import re
import socket
import time
import urllib.request
from zoneinfo import ZoneInfo

import runpy
_settings_module = runpy.run_path(str(Path(__file__).with_name('settings.py')))
SETTINGS = _settings_module['load']()


MAC = os.environ.get('AI_MONITOR_WAKE_MAC', '')
URL = SETTINGS['ollama_url'] + '/api/tags'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError('Unexpected redirect from Ollama')


def magic_packet(mac):
    compact = mac.replace('-', '').replace(':', '')
    if not re.fullmatch('[0-9a-fA-F]{12}', compact):
        raise ValueError('Invalid MAC address')
    return b'\xff' * 6 + bytes.fromhex(compact) * 16


def wake(mac=MAC, broadcast=None, sender=None):
    broadcast = broadcast or os.environ.get('AI_MONITOR_WAKE_BROADCAST')
    if not broadcast: raise ValueError('Set AI_MONITOR_WAKE_BROADCAST explicitly')
    packet = magic_packet(mac)
    if sender:
        sender(packet, (broadcast, 9))
        return
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(3):
            connection.sendto(packet, (broadcast, 9))
            time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait', type=int, default=0, help='Seconds to wait for Ollama; zero only sends the packet')
    parser.add_argument('--scheduled', action='store_true', help='Permit scheduled wake only from 03:30 to 04:00 in the configured timezone')
    args = parser.parse_args()
    if not 0 <= args.wait <= 600:
        parser.error('--wait must be 0 through 600')
    local = datetime.now(ZoneInfo(SETTINGS['timezone']))
    if args.scheduled and not (local.hour == 3 and local.minute >= 30):
        print(json.dumps({'status': 'skipped_outside_wake_window'}))
        return 0
    def record(status):
        if not args.scheduled:
            return
        try:
            path = Path(__file__).with_name('dashboard_progress.py')
            spec = importlib.util.spec_from_file_location('wake_progress', path)
            progress = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(progress)
            progress.wake_status(Path('/var/lib/ai-monitor/daily') / local.date().isoformat(), status)
        except Exception:
            pass
    record('waking')
    wake()
    if not args.wait:
        record('wake_packet_sent')
        print(json.dumps({'status': 'wake_packet_sent', 'mac': MAC}))
        return 0
    deadline = time.monotonic() + args.wait
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    while time.monotonic() < deadline:
        try:
            with opener.open(URL, timeout=min(5, max(0.1, deadline - time.monotonic()))) as response:
                value = json.loads(response.read(2 * 1024 * 1024 + 1))
            if SETTINGS['model'] in {item.get('name') for item in value.get('models', [])}:
                record('ollama_ready')
                print(json.dumps({'status': 'ollama_ready', 'mac': MAC}))
                return 0
        except Exception:
            pass
        time.sleep(min(3, max(0, deadline - time.monotonic())))
    record('wake_sent_but_ollama_not_ready')
    print(json.dumps({'status': 'wake_sent_but_ollama_not_ready', 'wait_seconds': args.wait}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
